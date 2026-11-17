//! Kubernetes metadata cache: informer-fed DashMaps plus pure lookup logic.
//!
//! Cache mutation and lookup are decoupled from the kube runtime: informers
//! (Task 3) convert API objects into snapshots and call `apply_*`/`remove_*`,
//! while `enrich` answers questions purely from cache state. This keeps the
//! hard-to-test parts (watch bookkeeping) separate from the easy-to-test
//! parts (traversal, TTL, label fallbacks).

use std::collections::HashMap;
use std::net::IpAddr;
use std::time::Instant;

use dashmap::DashMap;

/// Stale entries are evicted lazily on lookup after this long without an
/// update (watch DELETE is the primary eviction path; this is the safety net
/// for IP reuse after aggressive rescheduling).
const TTL_SECS: u64 = 600;

/// A pod as seen by the informer, keyed by one of its pod IPs.
#[derive(Debug, Clone)]
pub struct PodSnapshot {
    pub name: String,
    pub namespace: String,
    /// UID of the owning workload controller (RS/STS/DS), if any.
    pub owner_uid: Option<String>,
    pub labels: HashMap<String, String>,
    pub node: String,
    pub updated_at: Instant,
}

/// One workload controller in the ownership graph.
#[derive(Debug, Clone)]
pub enum OwnerKind {
    ReplicaSet,
    StatefulSet,
    DaemonSet,
}

#[derive(Debug, Clone)]
pub struct OwnerRef {
    pub kind: OwnerKind,
    pub name: String,
    /// UID of the parent Deployment (ReplicaSet only; others are None).
    pub parent: Option<String>,
}

/// A Service reachable at a given cluster IP (or load-balancer IP).
#[derive(Debug, Clone)]
pub struct ServiceRef {
    pub name: String,
    pub namespace: String,
}

/// Enrichment answer for one endpoint IP.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EndpointMetadata {
    pub namespace: Option<String>,
    pub pod: Option<String>,
    pub deployment: Option<String>,
    pub service: Option<String>,
    pub app: Option<String>,
}

/// Normalize IPv4 into its IPv6-mapped form so cache keys match FlowRow's
/// IPv6 representation for all addresses.
pub(crate) fn normalize_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V4(v4) => IpAddr::V6(v4.to_ipv6_mapped()),
        v6 => v6,
    }
}

pub struct KubernetesEnricher {
    /// Pod IP (normalized) -> pod snapshot.
    pods_by_ip: DashMap<IpAddr, PodSnapshot>,
    /// Workload controller UID -> owner reference.
    owners: DashMap<String, OwnerRef>,
    /// Deployment UID -> deployment name.
    deployments: DashMap<String, String>,
    /// Service or load-balancer IP (normalized) -> service.
    service_by_ip: DashMap<IpAddr, ServiceRef>,
}

impl KubernetesEnricher {
    pub fn new() -> Self {
        Self {
            pods_by_ip: DashMap::new(),
            owners: DashMap::new(),
            deployments: DashMap::new(),
            service_by_ip: DashMap::new(),
        }
    }

    /// Register or refresh one pod IP. ADD and UPDATE both land here.
    pub fn apply_pod(&self, ip: IpAddr, pod: PodSnapshot) {
        self.pods_by_ip.insert(normalize_ip(ip), pod);
    }

    /// Watch DELETE eviction: the pod (and its IP) left the cluster.
    pub fn remove_pod(&self, ip: IpAddr) {
        self.pods_by_ip.remove(&normalize_ip(ip));
    }

    /// Register a workload controller (ReplicaSet/StatefulSet/DaemonSet).
    pub fn apply_owner(&self, uid: String, owner: OwnerRef) {
        self.owners.insert(uid, owner);
    }

    /// Register a Deployment name under its UID.
    pub fn apply_deployment(&self, uid: String, name: String) {
        self.deployments.insert(uid, name);
    }

    /// Register a service-reachable IP (ClusterIP or LoadBalancer IP).
    pub fn apply_service_ip(&self, ip: IpAddr, service: ServiceRef) {
        self.service_by_ip.insert(normalize_ip(ip), service);
    }

    /// Watch DELETE for a service IP.
    pub fn remove_service_ip(&self, ip: IpAddr) {
        self.service_by_ip.remove(&normalize_ip(ip));
    }

    /// Number of tracked pod IPs (the gauge's source of truth).
    pub fn cache_size(&self) -> usize {
        self.pods_by_ip.len()
    }

    /// Resolve one endpoint IP. Stale pod entries (older than `TTL_SECS`)
    /// are evicted on sight; everything else is answered from cache state.
    pub fn enrich(&self, ip: &IpAddr, now: Instant) -> Option<EndpointMetadata> {
        let normalized = normalize_ip(*ip);
        let mut metadata = EndpointMetadata::default();

        if let Some(snapshot) = self.pods_by_ip.get(&normalized) {
            if now.duration_since(snapshot.updated_at).as_secs() >= TTL_SECS {
                drop(snapshot);
                self.pods_by_ip.remove(&normalized);
            } else {
                metadata.namespace = Some(snapshot.namespace.clone());
                metadata.pod = Some(snapshot.name.clone());
                metadata.deployment = self.resolve_deployment(&snapshot.owner_uid);
                metadata.app = snapshot
                    .labels
                    .get("app.kubernetes.io/name")
                    .or_else(|| snapshot.labels.get("app"))
                    .cloned();
            }
        }

        if metadata.namespace.is_none()
            && let Some(service) = self.service_by_ip.get(&normalized)
        {
            metadata.namespace = Some(service.namespace.clone());
            metadata.service = Some(service.name.clone());
        }

        if metadata.namespace.is_some() { Some(metadata) } else { None }
    }

    /// pod owner UID -> Deployment name. ReplicaSets climb to their parent
    /// Deployment; StatefulSets and DaemonSets resolve to themselves (spec D4).
    fn resolve_deployment(&self, owner_uid: &Option<String>) -> Option<String> {
        let uid = owner_uid.as_deref()?;
        let owner = self.owners.get(uid)?;
        match owner.kind {
            OwnerKind::ReplicaSet => owner
                .parent
                .as_deref()
                .and_then(|parent_uid| self.deployments.get(parent_uid).map(|n| n.clone())),
            OwnerKind::StatefulSet | OwnerKind::DaemonSet => Some(owner.name.clone()),
        }
    }
}

impl Default for KubernetesEnricher {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pod(name: &str, labels: &[(&str, &str)], owner: Option<&str>) -> PodSnapshot {
        PodSnapshot {
            name: name.to_string(),
            namespace: "default".to_string(),
            owner_uid: owner.map(|uid| uid.to_string()),
            labels: labels.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect(),
            node: "node-1".to_string(),
            updated_at: Instant::now(),
        }
    }

    #[test]
    fn enrich_resolves_pod_namespace_and_app() {
        let enricher = KubernetesEnricher::new();
        let ip: IpAddr = "10.0.0.1".parse().unwrap();
        enricher.apply_pod(ip, pod("api-abc", &[("app", "api")], Some("rs-uid")));
        let got = enricher.enrich(&ip, Instant::now()).unwrap();
        assert_eq!(got.namespace.as_deref(), Some("default"));
        assert_eq!(got.pod.as_deref(), Some("api-abc"));
        assert_eq!(got.app.as_deref(), Some("api"));
    }

    #[test]
    fn enrich_prefers_recommended_app_label() {
        let enricher = KubernetesEnricher::new();
        let ip: IpAddr = "10.0.0.1".parse().unwrap();
        enricher.apply_pod(
            ip,
            pod("api-abc", &[("app", "legacy-name"), ("app.kubernetes.io/name", "api")], None),
        );
        assert_eq!(enricher.enrich(&ip, Instant::now()).unwrap().app.as_deref(), Some("api"));
    }

    #[test]
    fn deployment_resolves_through_replicaset_parent() {
        let enricher = KubernetesEnricher::new();
        let ip: IpAddr = "10.0.0.1".parse().unwrap();
        enricher.apply_pod(ip, pod("api-abc", &[], Some("rs-uid")));
        enricher.apply_owner(
            "rs-uid".to_string(),
            OwnerRef {
                kind: OwnerKind::ReplicaSet,
                name: "api-rs".to_string(),
                parent: Some("deploy-uid".to_string()),
            },
        );
        enricher.apply_deployment("deploy-uid".to_string(), "api".to_string());
        assert_eq!(
            enricher.enrich(&ip, Instant::now()).unwrap().deployment.as_deref(),
            Some("api")
        );
    }

    #[test]
    fn statefulset_and_daemonset_resolve_to_their_own_name() {
        let enricher = KubernetesEnricher::new();
        let ip: IpAddr = "10.0.0.2".parse().unwrap();
        enricher.apply_pod(ip, pod("db-0", &[], Some("sts-uid")));
        enricher.apply_owner(
            "sts-uid".to_string(),
            OwnerRef { kind: OwnerKind::StatefulSet, name: "db".to_string(), parent: None },
        );
        assert_eq!(enricher.enrich(&ip, Instant::now()).unwrap().deployment.as_deref(), Some("db"));
    }

    #[test]
    fn unknown_owner_uid_leaves_deployment_none() {
        let enricher = KubernetesEnricher::new();
        let ip: IpAddr = "10.0.0.3".parse().unwrap();
        enricher.apply_pod(ip, pod("orphan", &[], Some("missing-uid")));
        assert!(enricher.enrich(&ip, Instant::now()).unwrap().deployment.is_none());
    }

    #[test]
    fn service_ip_resolves_directly() {
        let enricher = KubernetesEnricher::new();
        let ip: IpAddr = "10.96.0.10".parse().unwrap();
        enricher.apply_service_ip(
            ip,
            ServiceRef { name: "kube-dns".to_string(), namespace: "kube-system".to_string() },
        );
        let got = enricher.enrich(&ip, Instant::now()).unwrap();
        assert_eq!(got.service.as_deref(), Some("kube-dns"));
        assert!(got.pod.is_none());
        assert_eq!(got.namespace.as_deref(), Some("kube-system"));
    }

    #[test]
    fn delete_evicts_before_lookup() {
        let enricher = KubernetesEnricher::new();
        let ip: IpAddr = "10.0.0.4".parse().unwrap();
        enricher.apply_pod(ip, pod("gone", &[], None));
        enricher.remove_pod(ip);
        assert!(enricher.enrich(&ip, Instant::now()).is_none());
    }

    #[test]
    fn stale_entries_expire_after_ttl() {
        let enricher = KubernetesEnricher::new();
        let ip: IpAddr = "10.0.0.5".parse().unwrap();
        let mut stale = pod("stale", &[], None);
        stale.updated_at = Instant::now() - std::time::Duration::from_secs(TTL_SECS + 1);
        enricher.apply_pod(ip, stale);
        assert!(enricher.enrich(&ip, Instant::now()).is_none());
        assert_eq!(enricher.cache_size(), 0, "stale entry must be removed on lookup");
    }

    #[test]
    fn ipv4_queries_reach_ipv6_mapped_keys() {
        let enricher = KubernetesEnricher::new();
        let v4: IpAddr = "10.0.0.6".parse().unwrap();
        enricher.apply_pod(v4, pod("mapped", &[], None));
        // The cache stores the mapped form; a raw v4 lookup must still hit.
        assert!(enricher.enrich(&v4, Instant::now()).is_some());
    }

    #[test]
    fn cache_size_counts_pods_only() {
        let enricher = KubernetesEnricher::new();
        let ip: IpAddr = "10.0.0.7".parse().unwrap();
        enricher.apply_pod(ip, pod("one", &[], None));
        enricher.apply_pod(ip, pod("one-updated", &[], None));
        enricher.apply_service_ip(
            ip,
            ServiceRef { name: "svc".to_string(), namespace: "default".to_string() },
        );
        assert_eq!(enricher.cache_size(), 1);
    }
}
