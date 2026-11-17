//! Informer wiring: converts Kubernetes API objects into cache snapshots and
//! keeps one watcher task per resource kind alive.

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use futures::StreamExt;
use k8s_openapi::api::apps::v1::{DaemonSet, Deployment, ReplicaSet, StatefulSet};
use k8s_openapi::api::core::v1::Pod;
use k8s_openapi::api::discovery::v1::EndpointSlice;
use kube::runtime::watcher;
use kube::{Api, Client};

use crate::kubernetes::{KubernetesEnricher, OwnerKind, OwnerRef, PodSnapshot, ServiceRef};
use sentinel_sensor::metrics::SensorMetrics;

/// One snapshot per pod IP; pods without IPs (Pending) contribute nothing.
///
/// Both `status.podIP` and `status.podIPs` are consulted because older API
/// servers only populate the former, while newer ones keep both in sync; the
/// duplicate address is collapsed so a pod is never counted twice.
pub(crate) fn pod_to_snapshots(pod: &Pod, now: Instant) -> Vec<(IpAddr, PodSnapshot)> {
    let Some(status) = &pod.status else {
        return Vec::new();
    };
    let meta = &pod.metadata;
    let owner_uid =
        meta.owner_references.as_ref().and_then(|refs| refs.first()).map(|owner| owner.uid.clone());
    let labels: HashMap<String, String> =
        meta.labels.clone().unwrap_or_default().into_iter().collect();
    let node = pod.spec.as_ref().and_then(|spec| spec.node_name.clone()).unwrap_or_default();

    let mut snapshots = Vec::new();
    let mut seen = HashSet::new();
    let ips =
        status.pod_ips.iter().flatten().map(|entry| entry.ip.clone()).chain(status.pod_ip.clone());
    for raw_ip in ips {
        let Ok(ip) = raw_ip.parse::<IpAddr>() else {
            continue;
        };
        if !seen.insert(ip) {
            continue;
        }
        snapshots.push((
            ip,
            PodSnapshot {
                name: meta.name.clone().unwrap_or_default(),
                namespace: meta.namespace.clone().unwrap_or_default(),
                owner_uid: owner_uid.clone(),
                labels: labels.clone(),
                node: node.clone(),
                updated_at: now,
            },
        ));
    }
    snapshots
}

pub(crate) fn replica_set_to_owner(rs: &ReplicaSet) -> Option<(String, OwnerRef)> {
    let meta = &rs.metadata;
    Some((
        meta.uid.clone()?,
        OwnerRef {
            kind: OwnerKind::ReplicaSet,
            name: meta.name.clone().unwrap_or_default(),
            parent: meta
                .owner_references
                .as_ref()
                .and_then(|refs| refs.iter().find(|r| r.kind == "Deployment"))
                .map(|r| r.uid.clone()),
        },
    ))
}

pub(crate) fn stateful_set_to_owner(sts: &StatefulSet) -> Option<(String, OwnerRef)> {
    let meta = &sts.metadata;
    Some((
        meta.uid.clone()?,
        OwnerRef {
            kind: OwnerKind::StatefulSet,
            name: meta.name.clone().unwrap_or_default(),
            parent: None,
        },
    ))
}

pub(crate) fn daemon_set_to_owner(ds: &DaemonSet) -> Option<(String, OwnerRef)> {
    let meta = &ds.metadata;
    Some((
        meta.uid.clone()?,
        OwnerRef {
            kind: OwnerKind::DaemonSet,
            name: meta.name.clone().unwrap_or_default(),
            parent: None,
        },
    ))
}

pub(crate) fn deployment_to_entry(dep: &Deployment) -> Option<(String, String)> {
    let meta = &dep.metadata;
    Some((meta.uid.clone()?, meta.name.clone()?))
}

/// One service entry per endpoint address; slices without the service-name
/// label (manual endpoints, no owning Service) contribute nothing.
pub(crate) fn endpointslice_to_services(es: &EndpointSlice) -> Vec<(IpAddr, ServiceRef)> {
    let meta = &es.metadata;
    let Some(service_name) =
        meta.labels.as_ref().and_then(|labels| labels.get("kubernetes.io/service-name"))
    else {
        return Vec::new();
    };
    let service = ServiceRef {
        name: service_name.clone(),
        namespace: meta.namespace.clone().unwrap_or_default(),
    };
    let mut entries = Vec::new();
    for endpoint in &es.endpoints {
        for address in &endpoint.addresses {
            if let Ok(ip) = address.parse::<IpAddr>() {
                entries.push((ip, service.clone()));
            }
        }
    }
    entries
}

fn apply_pod_event(pod: &Pod, enricher: &KubernetesEnricher, metrics: &SensorMetrics) {
    // Restarted events re-list everything; upserts make that idempotent.
    for (ip, snapshot) in pod_to_snapshots(pod, Instant::now()) {
        enricher.apply_pod(ip, snapshot);
    }
    metrics.kubernetes_cache_size.set(enricher.cache_size() as i64);
}

fn remove_pod_event(pod: &Pod, enricher: &KubernetesEnricher, metrics: &SensorMetrics) {
    for (ip, _) in pod_to_snapshots(pod, Instant::now()) {
        enricher.remove_pod(ip);
    }
    metrics.kubernetes_cache_size.set(enricher.cache_size() as i64);
}

fn apply_replica_set_event(
    rs: &ReplicaSet,
    enricher: &KubernetesEnricher,
    _metrics: &SensorMetrics,
) {
    if let Some((uid, owner)) = replica_set_to_owner(rs) {
        enricher.apply_owner(uid, owner);
    }
}

fn apply_stateful_set_event(
    sts: &StatefulSet,
    enricher: &KubernetesEnricher,
    _metrics: &SensorMetrics,
) {
    if let Some((uid, owner)) = stateful_set_to_owner(sts) {
        enricher.apply_owner(uid, owner);
    }
}

fn apply_daemon_set_event(ds: &DaemonSet, enricher: &KubernetesEnricher, _metrics: &SensorMetrics) {
    if let Some((uid, owner)) = daemon_set_to_owner(ds) {
        enricher.apply_owner(uid, owner);
    }
}

fn apply_deployment_event(
    dep: &Deployment,
    enricher: &KubernetesEnricher,
    _metrics: &SensorMetrics,
) {
    if let Some((uid, name)) = deployment_to_entry(dep) {
        enricher.apply_deployment(uid, name);
    }
}

fn apply_service_ip_event(
    es: &EndpointSlice,
    enricher: &KubernetesEnricher,
    _metrics: &SensorMetrics,
) {
    for (ip, service) in endpointslice_to_services(es) {
        enricher.apply_service_ip(ip, service);
    }
}

fn remove_service_ip_event(
    es: &EndpointSlice,
    enricher: &KubernetesEnricher,
    _metrics: &SensorMetrics,
) {
    for (ip, _) in endpointslice_to_services(es) {
        enricher.remove_service_ip(ip);
    }
}

/// Owners and deployments have no removal entry point in the cache; a deleted
/// controller's UID is never reused, so leaving the stale entry is harmless.
fn ignore_event<K>(_: &K, _: &KubernetesEnricher, _: &SensorMetrics) {}

/// One watcher task per resource kind. A stream that ends (connection loss) is
/// restarted after a delay, so transient watch failures self-heal with a
/// warning instead of stopping enrichment (spec §4.5). Startup connection
/// failures surface via `Client::try_default()` in the caller (fail-fast).
macro_rules! spawn_kind {
    ($client:expr, $enricher:expr, $metrics:expr, $task_name:literal, $api_type:ty, $on_applied:expr, $on_deleted:expr) => {{
        let client = $client.clone();
        let enricher = $enricher.clone();
        let metrics = $metrics.clone();
        let on_applied = $on_applied;
        let on_deleted = $on_deleted;
        tokio::spawn(async move {
            loop {
                let api = Api::<$api_type>::all(client.clone());
                let mut stream = watcher(api, watcher::Config::default()).boxed();
                while let Some(event) = stream.next().await {
                    match event {
                        Ok(watcher::Event::Apply(object))
                        | Ok(watcher::Event::InitApply(object)) => {
                            on_applied(&object, &enricher, &metrics);
                        }
                        Ok(watcher::Event::Delete(object)) => {
                            on_deleted(&object, &enricher, &metrics);
                        }
                        // Re-list boundaries: objects arrive via InitApply, and the
                        // completed list needs no separate action because upserts
                        // are idempotent.
                        Ok(watcher::Event::Init | watcher::Event::InitDone) => {}
                        Err(error) => tracing::warn!(
                            kind = $task_name,
                            error = %error,
                            "kubernetes watch error; watcher recovers on the next poll"
                        ),
                    }
                }
                tracing::warn!("{} watch stream ended; restarting in 5s", $task_name);
                tokio::time::sleep(Duration::from_secs(5)).await;
            }
        })
    }};
}

/// Registry of the watcher tasks started for one cluster.
pub struct KubernetesRuntime;

impl KubernetesRuntime {
    pub fn start(
        client: Client,
        enricher: Arc<KubernetesEnricher>,
        metrics: Arc<SensorMetrics>,
    ) -> anyhow::Result<Vec<tokio::task::JoinHandle<()>>> {
        let mut handles = Vec::with_capacity(6);
        handles.push(spawn_kind!(
            client,
            enricher,
            metrics,
            "pods",
            Pod,
            apply_pod_event,
            remove_pod_event
        ));
        handles.push(spawn_kind!(
            client,
            enricher,
            metrics,
            "replicasets",
            ReplicaSet,
            apply_replica_set_event,
            ignore_event::<ReplicaSet>
        ));
        handles.push(spawn_kind!(
            client,
            enricher,
            metrics,
            "statefulsets",
            StatefulSet,
            apply_stateful_set_event,
            ignore_event::<StatefulSet>
        ));
        handles.push(spawn_kind!(
            client,
            enricher,
            metrics,
            "daemonsets",
            DaemonSet,
            apply_daemon_set_event,
            ignore_event::<DaemonSet>
        ));
        handles.push(spawn_kind!(
            client,
            enricher,
            metrics,
            "deployments",
            Deployment,
            apply_deployment_event,
            ignore_event::<Deployment>
        ));
        handles.push(spawn_kind!(
            client,
            enricher,
            metrics,
            "endpointslices",
            EndpointSlice,
            apply_service_ip_event,
            remove_service_ip_event
        ));
        Ok(handles)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn now() -> Instant {
        Instant::now()
    }

    const POD_JSON: &str = r#"{
        "metadata": {
            "name": "api-abcde",
            "namespace": "default",
            "uid": "pod-uid",
            "labels": {"app": "api"},
            "ownerReferences": [{"uid": "rs-uid", "kind": "ReplicaSet", "name": "api-rs"}]
        },
        "spec": {"nodeName": "node-1"},
        "status": {"podIPs": [{"ip": "10.0.0.1"}]}
    }"#;

    #[test]
    fn pod_becomes_one_snapshot_per_pod_ip() {
        let pod: Pod = serde_json::from_str(POD_JSON).unwrap();
        let snapshots = pod_to_snapshots(&pod, now());
        assert_eq!(snapshots.len(), 1);
        let (ip, snapshot) = &snapshots[0];
        assert_eq!(ip.to_string(), "10.0.0.1");
        assert_eq!(snapshot.name, "api-abcde");
        assert_eq!(snapshot.namespace, "default");
        assert_eq!(snapshot.owner_uid.as_deref(), Some("rs-uid"));
        assert_eq!(snapshot.node, "node-1");
        assert_eq!(snapshot.labels.get("app").map(String::as_str), Some("api"));
    }

    const POD_NO_IP_JSON: &str = r#"{
        "metadata": {"name": "pending", "namespace": "default", "uid": "u"},
        "spec": {},
        "status": {}
    }"#;

    #[test]
    fn pod_without_ip_yields_no_snapshot() {
        let pod: Pod = serde_json::from_str(POD_NO_IP_JSON).unwrap();
        assert!(pod_to_snapshots(&pod, now()).is_empty());
    }

    const POD_REPEATED_IP_JSON: &str = r#"{
        "metadata": {"name": "api-fghij", "namespace": "default", "uid": "pod-uid-2"},
        "spec": {"nodeName": "node-2"},
        "status": {"podIP": "10.0.0.2", "podIPs": [{"ip": "10.0.0.2"}]}
    }"#;

    #[test]
    fn pod_with_repeated_pod_ip_yields_one_snapshot() {
        let pod: Pod = serde_json::from_str(POD_REPEATED_IP_JSON).unwrap();
        let snapshots = pod_to_snapshots(&pod, now());
        assert_eq!(snapshots.len(), 1);
        assert_eq!(snapshots[0].0.to_string(), "10.0.0.2");
    }

    const RS_JSON: &str = r#"{
        "metadata": {"name": "api-rs", "namespace": "default", "uid": "rs-uid",
            "ownerReferences": [{"uid": "deploy-uid", "kind": "Deployment", "name": "api"}]}
    }"#;

    #[test]
    fn replicaset_carries_deployment_parent() {
        let rs: ReplicaSet = serde_json::from_str(RS_JSON).unwrap();
        let (uid, owner) = replica_set_to_owner(&rs).unwrap();
        assert_eq!(uid, "rs-uid");
        assert_eq!(owner.name, "api-rs");
        assert_eq!(owner.parent.as_deref(), Some("deploy-uid"));
    }

    const STS_JSON: &str = r#"{
        "metadata": {"name": "db", "namespace": "default", "uid": "sts-uid"}
    }"#;

    #[test]
    fn statefulset_resolves_to_itself() {
        let sts: StatefulSet = serde_json::from_str(STS_JSON).unwrap();
        let (uid, owner) = stateful_set_to_owner(&sts).unwrap();
        assert_eq!(uid, "sts-uid");
        assert!(matches!(owner.kind, OwnerKind::StatefulSet));
        assert_eq!(owner.name, "db");
        assert!(owner.parent.is_none());
    }

    const DS_JSON: &str = r#"{
        "metadata": {"name": "node-agent", "namespace": "kube-system", "uid": "ds-uid"}
    }"#;

    #[test]
    fn daemonset_resolves_to_itself() {
        let ds: DaemonSet = serde_json::from_str(DS_JSON).unwrap();
        let (uid, owner) = daemon_set_to_owner(&ds).unwrap();
        assert_eq!(uid, "ds-uid");
        assert!(matches!(owner.kind, OwnerKind::DaemonSet));
        assert_eq!(owner.name, "node-agent");
    }

    const DEPLOY_JSON: &str = r#"{
        "metadata": {"name": "api", "namespace": "default", "uid": "deploy-uid"}
    }"#;

    #[test]
    fn deployment_maps_uid_to_name() {
        let dep: Deployment = serde_json::from_str(DEPLOY_JSON).unwrap();
        let (uid, name) = deployment_to_entry(&dep).unwrap();
        assert_eq!(uid, "deploy-uid");
        assert_eq!(name, "api");
    }

    const SLICE_JSON: &str = r#"{
        "metadata": {
            "name": "api-slice",
            "namespace": "default",
            "labels": {"kubernetes.io/service-name": "api"}
        },
        "endpoints": [
            {"addresses": ["10.0.0.1", "10.0.0.2"]}
        ]
    }"#;

    #[test]
    fn endpointslice_maps_every_address_to_its_service() {
        let es: EndpointSlice = serde_json::from_str(SLICE_JSON).unwrap();
        let entries = endpointslice_to_services(&es);
        assert_eq!(entries.len(), 2);
        assert!(entries.iter().all(|(_, service)| service.name == "api"));
        assert!(entries.iter().all(|(_, service)| service.namespace == "default"));
        assert!(entries.iter().any(|(ip, _)| ip.to_string() == "10.0.0.1"));
    }

    const SLICE_NO_SERVICE_JSON: &str = r#"{
        "metadata": {"name": "orphan-slice", "namespace": "default"},
        "endpoints": [{"addresses": ["10.0.0.3"]}]
    }"#;

    #[test]
    fn endpointslice_without_service_label_yields_nothing() {
        let es: EndpointSlice = serde_json::from_str(SLICE_NO_SERVICE_JSON).unwrap();
        assert!(endpointslice_to_services(&es).is_empty());
    }
}
