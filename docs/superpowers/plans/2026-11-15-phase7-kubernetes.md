# Phase 7: Kubernetes Metadata Enrichment — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Enrich every exported flow with full Kubernetes pod metadata (namespace, pod, deployment, service, app) at sensor export time, persisted as 10 nullable ClickHouse columns on `network_flows`.

**Architecture:** `sentinel-enrichment` is rebuilt in place: kube informers (pods + 4 workload kinds + endpointslices) maintain DashMap caches, pure apply/lookup functions decouple cache logic from the API server, and the sensor mutates each `ExportedFlow` right after the processor emits it. Metadata rides on `ExportedFlow` through the whole Phase 6 pipeline (FlowRow → Kafka JSON → sink adapter) unchanged, so the sink and Kafka store need no logic changes — only field copies.

**Tech Stack:** kube 0.87 / k8s-openapi 0.21 (already workspace deps, unused until now), dashmap, existing clickhouse 0.11 / prometheus / tokio stack.

**Spec:** `docs/superpowers/specs/2026-11-15-phase7-kubernetes-design.md`

## Global Constraints

- Rust 2024 workspace; `cargo fmt` max_width = 100.
- Gates before every commit (all must be clean): `cargo nextest run --workspace`, `cargo clippy --workspace --all-targets --all-features -- -D warnings`, `cargo fmt --all -- --check`.
- Baseline test count is **128 passed**; it must stay green at every task boundary.
- Never use `--no-verify`; pre-commit hooks must pass (a stash-conflict rollback aborts a commit silently — re-run `git add <files> && git commit` and it succeeds).
- Conventional Commits; no AI attribution (no Co-Authored-By).
- Stage ONLY the files listed in each task. The user's uncommitted files (`README.md` modified, untracked `docs/configuration.md`, `docs/posts/`, `.ua/`) must never be staged or modified.
- `kubernetes.enabled: false` (the default) must be behaviorally identical to today: no K8s client is built, all 10 columns write NULL, and no existing test may change behavior expectations. New code is additive.
- The 10 metadata columns are `Nullable(LowCardinality(String))`; FlowRow fields are `Option<String>` appended at the END of the struct (RowBinary column order = struct order). Field order is frozen by the spec §5: source_namespace, source_pod, source_deployment, source_service, source_app, destination_namespace, destination_pod, destination_deployment, destination_service, destination_app.
- The Phase 6 lossless invariant (`FlowRow → ExportedFlow → FlowRow` round-trip, which Fix B's pending-counter drain depends on) must now also cover metadata: the sink adapter copies all 10 fields.
- kube 0.87 API facts must be verified against the crate source (`~/.cargo/registry/src/*/kube-0.87*/`, `k8s-openapi-0.21*/`) before writing informer code; record any deviation in the task report like Phase 6 did.
- No test may require a live Kubernetes API server. Unit tests use pure functions over snapshots; ClickHouse IT tests self-skip without a server (REQUIRE_CLICKHOUSE pattern); the kind E2E is a manual runbook (Task 7), not CI.
- Delivery semantics and all Phase 6 behaviors (pending counter, commit gating, NonDroppingStore) are untouched by this plan.
- No subagents inside an implementing task; report deviations with reasons instead of improvising silently.

**Spec decisions encoded verbatim (D1-D9):** flows-only (10 columns, `security_events.source_pod` deferred); idempotent `ALTER ADD COLUMN IF NOT EXISTS` in ensure_schema; `kubernetes.enabled` default false with fail-fast on initial connection failure when enabled; ownerReferences traversal pod→RS/STS/DS→Deployment (STS/DS resolve to their own name); EndpointSlice endpoint IP→Service; watch DELETE eviction + 10-min TTL (lookup removes stale entries); deploy/k8s/rbac.yaml + daemonset.yaml; unit mock-cache tests + manual kind E2E runbook (acceptance: `countIf(source_pod IS NOT NULL)/count() >= 95%`); enrichment at sensor export time.

## File Structure

| File | Task | Responsibility |
|---|---|---|
| `crates/sentinel-flow/src/export.rs` | 1 | 10 `Option<String>` metadata fields on `ExportedFlow`; `from_flow` fills `None` |
| `crates/sentinel-flow/src/lib.rs`, flow/entry/key modules | 1 | only what Task 1 touches; no logic changes |
| `crates/sentinel-enrichment/src/kubernetes.rs` | 2 | types + DashMap caches + pure apply/lookup functions + unit tests (no kube runtime) |
| `crates/sentinel-enrichment/src/informer.rs`, `lib.rs` | 3 | kube informer wiring, Client::try_default, fail-fast, reconnect loop, gauge update |
| `crates/sentinel-enrichment/Cargo.toml` | 2, 3 | kube/k8s-openapi/kube-runtime deps (Task 3); workspace already has them |
| `crates/sentinel-sensor/src/output/row.rs` | 4 | 10 `Option<String>` FlowRow fields + TryFrom copies |
| `crates/sentinel-sensor/src/output/clickhouse.rs` | 4 | DDL 10 columns + idempotent ALTERs + test updates |
| `crates/sentinel-sensor/src/config.rs`, `config/sensor.yaml` | 5 | `kubernetes: {enabled: bool}` default false |
| `crates/sentinel-sensor/src/metrics.rs` | 3 | `sentinel_kubernetes_cache_size` IntGauge |
| `crates/sentinel-sensor/src/main.rs` | 5 | enricher build (fail-fast when enabled) + metadata wiring at 3 export sites |
| `crates/sentinel-sink/src/adapter.rs` | 6 | 10 metadata copies in `flow_row_to_exported` + roundtrip test |
| `deploy/k8s/rbac.yaml`, `deploy/k8s/daemonset.yaml` | 7 | read-only RBAC + sensor DaemonSet manifests |
| `docs/runbooks/kubernetes-e2e.md` | 7 | manual kind E2E + 95% acceptance query |
| `Cargo.lock` | 1-3, 5 | mechanical |

---

### Task 1: ExportedFlow metadata fields (pipeline-compatible payloads)

`ExportedFlow` is the single payload type for direct and Kafka output. Ten `Option<String>` fields ride on it; every existing struct-literal site must compile with `None` defaults so Phase 6 behavior is unchanged.

**Files:**
- Modify: `crates/sentinel-flow/src/export.rs`
- Modify: `crates/sentinel-sensor/src/output/row.rs` (`sample_flow` test helper only — struct literal gains 10 fields)
- Modify: `crates/sentinel-sink/src/adapter.rs` (`sample_exported` test helper only)

**Interfaces:**
- Consumes: `ExportedFlow` as it exists today (fields frozen by Phase 5/6).
- Produces (for Tasks 4/5/6): `ExportedFlow` with TEN pub `Option<String>` fields appended in this exact order after `sensor_node`: `source_namespace`, `source_pod`, `source_deployment`, `source_service`, `source_app`, `destination_namespace`, `destination_pod`, `destination_deployment`, `destination_service`, `destination_app`. `ExportedFlow::from_flow` fills all ten with `None` (no call-site changes possible). Kafka JSON: `null` for `None` (serde default), sink decode unaffected (Task 6 makes the copies explicit).

- [ ] **Step 1: Write the failing test**

Append to the existing `#[cfg(test)] mod tests` in `crates/sentinel-flow/src/export.rs` (follow the construction style of `test_export_flow` — build the flow through the same helper that test uses):

```rust
    #[test]
    fn from_flow_leaves_metadata_empty() {
        let flow = test_flow(); // the same construction `test_export_flow` uses
        assert!(flow.source_namespace.is_none());
        assert!(flow.source_pod.is_none());
        assert!(flow.source_deployment.is_none());
        assert!(flow.source_service.is_none());
        assert!(flow.source_app.is_none());
        assert!(flow.destination_namespace.is_none());
        assert!(flow.destination_pod.is_none());
        assert!(flow.destination_deployment.is_none());
        assert!(flow.destination_service.is_none());
        assert!(flow.destination_app.is_none());
    }

    #[test]
    fn metadata_fields_serialize_as_null_when_none() {
        let flow = test_flow();
        let json = serde_json::to_string(&flow).unwrap();
        assert!(json.contains("\"source_pod\":null"));
        assert!(json.contains("\"destination_app\":null"));
    }
```

(If `test_export_flow` builds its flow inline instead of via a helper, extract the construction into `fn test_flow() -> ExportedFlow` in the test module and reuse it in both tests; report the mechanical refactor.)

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo nextest run -p sentinel-flow`
Expected: FAIL with compile errors `no field 'source_namespace'` (missing fields count as red).

- [ ] **Step 3: Add the ten fields to ExportedFlow**

In `crates/sentinel-flow/src/export.rs`, append to `ExportedFlow` after `sensor_node` (doc comments: first line states the field is None unless Kubernetes enrichment populated it):

```rust
    /// Source namespace from Kubernetes metadata; None when not enriched.
    pub source_namespace: Option<String>,
    /// Source pod name; None when not enriched.
    pub source_pod: Option<String>,
    /// Source workload's owning Deployment name; None when not enriched.
    pub source_deployment: Option<String>,
    /// Source Service name; None when not enriched.
    pub source_service: Option<String>,
    /// Source pod's app label (`app.kubernetes.io/name`); None when absent.
    pub source_app: Option<String>,
    /// Destination namespace; None when not enriched.
    pub destination_namespace: Option<String>,
    /// Destination pod name; None when not enriched.
    pub destination_pod: Option<String>,
    /// Destination Deployment name; None when not enriched.
    pub destination_deployment: Option<String>,
    /// Destination Service name; None when not enriched.
    pub destination_service: Option<String>,
    /// Destination app label; None when absent.
    pub destination_app: Option<String>,
```

- [ ] **Step 4: Fix every struct-literal site to compile**

Run: `cargo build --workspace 2>&1 | grep "missing field" | sort -u`
Fix each site mechanically:
- `ExportedFlow::from_flow` in `export.rs`: append all ten fields as `None` (fields derive from flow data only; enrichment happens later in the sensor).
- `crates/sentinel-sensor/src/output/row.rs` `sample_flow`: append the ten as `None` (Task 4's metadata test will flip some to `Some`).
- `crates/sentinel-sink/src/adapter.rs` `sample_exported` test helper: append the ten as `None` (Task 6 flips them to `Some`).
Do not invent other sites; the grep list is the complete set. Report the list in the task report.

- [ ] **Step 5: Run tests to verify they pass**

Run: `cargo nextest run -p sentinel-flow`
Expected: PASS (baseline flow tests + 2 new).

- [ ] **Step 6: Run all gates**

Run: `cargo nextest run --workspace && cargo clippy --workspace --all-targets --all-features -- -D warnings && cargo fmt --all -- --check`
Expected: 130 passed (128 + 2); clippy/fmt clean.

- [ ] **Step 7: Commit**

```bash
git add Cargo.lock crates/sentinel-flow/src/export.rs crates/sentinel-sensor/src/output/row.rs crates/sentinel-sink/src/adapter.rs
git commit -m "feat(flow): optional kubernetes metadata fields on exported flows"
```

### Task 2: sentinel-enrichment cache and lookup layer (pure functions, no kube runtime)

The skeleton in `crates/sentinel-enrichment/src/kubernetes.rs` is replaced by the real cache layer. All cache mutations and lookups are pure functions over resource snapshots, so everything in this task is unit-testable without an API server or even the kube dependency.

**Files:**
- Replace: `crates/sentinel-enrichment/src/kubernetes.rs`
- Modify: `crates/sentinel-enrichment/src/lib.rs` (no change needed if it keeps `pub mod kubernetes; pub use kubernetes::KubernetesEnricher;` — adjust only if names change)
- Modify: `crates/sentinel-enrichment/Cargo.toml` (only if `std::time` / `dashmap` features require it — likely no change)

**Interfaces:**
- Consumes: nothing (std + dashmap only).
- Produces (for Task 3, informers; Task 5, sensor wiring):
  - `KubernetesEnricher::new() -> Self` (Default too, for config-disabled paths)
  - `pub fn apply_pod(&self, ip: IpAddr, pod: PodSnapshot)` / `pub fn remove_pod(&self, ip: IpAddr)`
  - `pub fn apply_owner(&self, uid: String, owner: OwnerRef)` / `pub fn apply_deployment(&self, uid: String, name: String)`
  - `pub fn apply_service_ip(&self, ip: IpAddr, service: ServiceRef)` / `pub fn remove_service_ip(&self, ip: IpAddr)`
  - `pub fn enrich(&self, ip: &IpAddr, now: Instant) -> Option<EndpointMetadata>`
  - `pub fn cache_size(&self) -> usize` (pods_by_ip length; Task 5 feeds the gauge)
  - Types: `PodSnapshot { name: String, namespace: String, owner_uid: Option<String>, labels: HashMap<String, String>, node: String, updated_at: Instant }`; `OwnerRef { kind: OwnerKind, name: String, parent: Option<String> }`; `OwnerKind::{ReplicaSet, StatefulSet, DaemonSet}`; `ServiceRef { name: String, namespace: String }`; `EndpointMetadata { namespace: Option<String>, pod: Option<String>, deployment: Option<String>, service: Option<String>, app: Option<String> }`.
  - Normalization rule (Task 3 must use it): every incoming IP is normalized via `match ip { IpAddr::V4(v4) => IpAddr::V6(v4.to_ipv6_mapped()), v6 => v6 }` before touching a cache — define `pub(crate) fn normalize_ip(ip: IpAddr) -> IpAddr` in this task and use it inside apply/remove/enrich so callers can pass raw IPs.
- Semantics frozen by spec: TTL 10 minutes enforced at lookup (`enrich` removes entries older than `TTL` and returns None); app label = `labels["app.kubernetes.io/name"]` fallback `labels["app"]`; deployment resolution = owner traversal — ReplicaSet → `parent` uid → deployments map → name; StatefulSet/DaemonSet → own name; owner_uid None or unknown uid → None.

- [ ] **Step 1: Write the failing tests**

Replace `crates/sentinel-enrichment/src/kubernetes.rs` entirely with imports, the type definitions, and this test module (implementations come in Step 4 — compile errors are the red):

```rust
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
            labels: labels
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
            node: "node-1".to_string(),
            updated_at: Instant::now(),
        }
    }

    #[test]
    fn enrich_resolves_pod_namespace_and_app() {
        let enricher = KubernetesEnricher::new();
        let ip: IpAddr = "10.0.0.1".parse().unwrap();
        enricher.apply_pod(
            ip,
            pod("api-abc", &[("app", "api")], Some("rs-uid")),
        );
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
            pod(
                "api-abc",
                &[("app", "legacy-name"), ("app.kubernetes.io/name", "api")],
                None,
            ),
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
            OwnerRef {
                kind: OwnerKind::StatefulSet,
                name: "db".to_string(),
                parent: None,
            },
        );
        assert_eq!(
            enricher.enrich(&ip, Instant::now()).unwrap().deployment.as_deref(),
            Some("db")
        );
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
        enricher.apply_service_ip(ip, ServiceRef { name: "svc".to_string(), namespace: "default".to_string() });
        assert_eq!(enricher.cache_size(), 1);
    }
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo nextest run -p sentinel-enrichment`
Expected: FAIL — `new`/`apply_pod`/`enrich` etc. do not exist (compile error counts as red).

- [ ] **Step 3: Implement the methods**

Append to the same file (above the test module):

```rust
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

        if metadata.namespace.is_none() {
            if let Some(service) = self.service_by_ip.get(&normalized) {
                metadata.namespace = Some(service.namespace.clone());
                metadata.service = Some(service.name.clone());
            }
        }

        if metadata.namespace.is_some() {
            Some(metadata)
        } else {
            None
        }
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
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo nextest run -p sentinel-enrichment`
Expected: 10 tests PASS.

- [ ] **Step 5: Run all gates**

Run: `cargo nextest run --workspace && cargo clippy --workspace --all-targets --all-features -- -D warnings && cargo fmt --all -- --check`
Expected: 140 passed (130 + 10); clippy/fmt clean. If clippy complains about the `default` impl pattern (`derivable_impls`) or map-get clone idioms, fix mechanically in keeping with the workspace style and report.

- [ ] **Step 6: Commit**

```bash
git add crates/sentinel-enrichment/src/kubernetes.rs
git commit -m "feat(enrichment): kubernetes metadata cache with pure lookups"
```

### Task 3: kube informers, fail-fast startup, and the cache-size gauge

The informer layer converts API objects into Task 2's snapshots and keeps the caches fed. `kube`/`k8s-openapi`/`kube-runtime` become live dependencies (they are already workspace deps, referenced by nothing until now).

**Files:**
- Create: `crates/sentinel-enrichment/src/informer.rs`
- Modify: `crates/sentinel-enrichment/src/lib.rs` (declare + re-export)
- Modify: `crates/sentinel-enrichment/Cargo.toml`
- Modify: `crates/sentinel-sensor/src/metrics.rs` (gauge)
- Modify: workspace `Cargo.toml` + `Cargo.lock` (only if a sub-feature must be added — `kube` workspace dep already exists)

**Interfaces:**
- Consumes: `KubernetesEnricher::{apply_pod, remove_pod, apply_owner, apply_deployment, apply_service_ip, remove_service_ip, cache_size}` (Task 2); workspace `kube = 0.87`, `k8s-openapi = 0.21` (features `v1_28`).
- Produces (for Task 5):
  - `pub struct KubernetesRuntime;` `KubernetesRuntime::start(client: kube::Client, enricher: Arc<KubernetesEnricher>, metrics: Arc<SensorMetrics>) -> anyhow::Result<Vec<tokio::task::JoinHandle<()>>>` — spawns one watcher loop per resource kind (6 kinds), each task keeps its own retry loop, returns the handles so the caller can abort them at shutdown. Building the `Client` itself happens in Task 5 via `kube::Client::try_default().await` (fail-fast at sensor startup, spec §4.5).
  - Conversion functions (pure, unit-tested): `pub(crate) fn pod_to_snapshots(pod: &Pod, now: Instant) -> Vec<(IpAddr, PodSnapshot)>`, `pub(crate) fn replica_set_to_owner(rs: &ReplicaSet) -> Option<(String, OwnerRef)>`, `pub(crate) fn stateful_set_to_owner(sts: &StatefulSet) -> Option<(String, OwnerRef)>`, `pub(crate) fn daemon_set_to_owner(ds: &DaemonSet) -> Option<(String, OwnerRef)>`, `pub(crate) fn deployment_to_entry(dep: &Deployment) -> Option<(String, String)>`, `pub(crate) fn endpointslice_to_services(es: &EndpointSlice) -> Vec<(IpAddr, ServiceRef)>`.
  - Metric: `SensorMetrics.kubernetes_cache_size: IntGauge` — `sentinel_kubernetes_cache_size`, help "Pod IPs currently tracked by the Kubernetes enrichment cache"; registered in `new()` alongside the kafka counters; stays 0 when enrichment is disabled (struct keeps `#[allow(dead_code)]`).
- kube 0.87 note (verify before coding): resource types come from `k8s_openapi::api::core::v1::{Pod, EndpointSlice}`, `k8s_openapi::api::apps::v1::{ReplicaSet, StatefulSet, DaemonSet, Deployment}`; `EndpointSlice` is `k8s_openapi::api::discovery::v1::EndpointSlice` in 0.21. Watch stream: `kube::runtime::watcher(api, watcher::Config::default())` yields `watcher::Event::{Applied, Deleted, Restarted}`; `Restarted` (re-list) must re-apply every object. Verify exact paths against `~/.cargo/registry/src/*/kube-0.87*/src/` and adapt mechanically, reporting deviations.

- [ ] **Step 1: Write the failing conversion tests**

Create `crates/sentinel-enrichment/src/informer.rs` with imports, function signatures returning `unimplemented!()`-free stubs is NOT allowed — instead write only the imports plus this test module first (compile error = red):

```rust
//! Informer wiring: converts Kubernetes API objects into cache snapshots and
//! keeps one watcher task per resource kind alive.

use std::net::IpAddr;
use std::sync::Arc;
use std::time::Instant;

use k8s_openapi::api::apps::v1::{DaemonSet, Deployment, ReplicaSet, StatefulSet};
use k8s_openapi::api::core::v1::Pod;
use k8s_openapi::api::discovery::v1::EndpointSlice;
use kube::runtime::watcher;

use crate::kubernetes::{KubernetesEnricher, OwnerKind, OwnerRef, PodSnapshot, ServiceRef};
use sentinel_sensor::metrics::SensorMetrics;

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
```

- [ ] **Step 2: Add the kube deps to the enrichment crate**

In `crates/sentinel-enrichment/Cargo.toml`, add:

```toml
kube = { workspace = true }
k8s-openapi = { workspace = true }
serde_json = { workspace = true }
sentinel-sensor = { path = "../sentinel-sensor" }
```

(`serde_json` is for the conversion tests; `sentinel-sensor` for the gauge. If the workspace `kube` dep lacks features the code needs — e.g. `runtime`, `rustls-tls` — adjust the WORKSPACE kube line once, keeping `default-features = false` style consistent with the rest of the file, and report.)

- [ ] **Step 3: Implement the conversion functions**

Append above the test module in `informer.rs`:

```rust
/// One snapshot per pod IP; pods without IPs (Pending) contribute nothing.
pub(crate) fn pod_to_snapshots(pod: &Pod, now: Instant) -> Vec<(IpAddr, PodSnapshot)> {
    let Some(meta) = &pod.metadata else { return Vec::new() };
    let Some(status) = &pod.status else { return Vec::new() };
    let owner_uid = meta
        .owner_references
        .as_ref()
        .and_then(|refs| refs.first())
        .map(|owner| owner.uid.clone());
    let mut snapshots = Vec::new();
    let ips = status
        .pod_ips
        .iter()
        .flatten()
        .filter_map(|entry| entry.ip.clone())
        .chain(status.pod_ip.clone().into_iter());
    for raw_ip in ips.collect::<Vec<_>>() {
        let Ok(ip) = raw_ip.parse::<IpAddr>() else { continue };
        snapshots.push((
            ip,
            PodSnapshot {
                name: meta.name.clone().unwrap_or_default(),
                namespace: meta.namespace.clone().unwrap_or_default(),
                owner_uid: owner_uid.clone(),
                labels: meta.labels.clone().unwrap_or_default(),
                node: pod.spec.as_ref().and_then(|spec| spec.node_name.clone()).unwrap_or_default(),
                updated_at: now,
            },
        ));
    }
    snapshots
}

fn owner_reference(meta: &k8s_openapi::api::apps::v1::ObjectMetaLike) -> ... // SEE STEP 3b
```

**Step 3b — build the four remaining converters with this shape** (the k8s-openapi metadata accessor surface is version-sensitive; write the four functions using `resource.metadata.as_ref()`-style access after checking the actual generated types in `~/.cargo/registry/src/*/k8s-openapi-0.21*/src/api/apps/v1/`):

```rust
pub(crate) fn replica_set_to_owner(rs: &ReplicaSet) -> Option<(String, OwnerRef)> {
    let meta = rs.metadata.as_ref()?;
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
    let meta = sts.metadata.as_ref()?;
    Some((
        meta.uid.clone()?,
        OwnerRef { kind: OwnerKind::StatefulSet, name: meta.name.clone().unwrap_or_default(), parent: None },
    ))
}

pub(crate) fn daemon_set_to_owner(ds: &DaemonSet) -> Option<(String, OwnerRef)> {
    let meta = ds.metadata.as_ref()?;
    Some((
        meta.uid.clone()?,
        OwnerRef { kind: OwnerKind::DaemonSet, name: meta.name.clone().unwrap_or_default(), parent: None },
    ))
}

pub(crate) fn deployment_to_entry(dep: &Deployment) -> Option<(String, String)> {
    let meta = dep.metadata.as_ref()?;
    Some((meta.uid.clone()?, meta.name.clone()?))
}

/// One service entry per endpoint address; slices without the service-name
/// label (manual endpoints, no owning Service) contribute nothing.
pub(crate) fn endpointslice_to_services(es: &EndpointSlice) -> Vec<(IpAddr, ServiceRef)> {
    let Some(meta) = &es.metadata else { return Vec::new() };
    let Some(service_name) = meta
        .labels
        .as_ref()
        .and_then(|labels| labels.get("kubernetes.io/service-name"))
    else {
        return Vec::new();
    };
    let namespace = meta.namespace.clone().unwrap_or_default();
    let service = ServiceRef { name: service_name.clone(), namespace };
    let mut entries = Vec::new();
    for endpoint in es.endpoints.iter().flatten() {
        for address in endpoint.addresses.iter().flatten() {
            if let Ok(ip) = address.parse::<IpAddr>() {
                entries.push((ip, service.clone()));
            }
        }
    }
    entries
}
```

Mechanical verification loop: `cargo build -p sentinel-enrichment` after each compile error; fix accessor shapes (e.g. `metadata` may be `ObjectMeta` directly rather than `Option<ObjectMeta>`; `pod_ips` element type may be `PodIP { ip: Option<String> }`; `endpoint.addresses: Option<Vec<String>>`) against the real generated types, and REPORT each adaptation.

- [ ] **Step 4: Run the conversion tests**

Run: `cargo nextest run -p sentinel-enrichment informer`
Expected: 9 tests PASS.

- [ ] **Step 5: Add the gauge to SensorMetrics**

In `crates/sentinel-sensor/src/metrics.rs` (after the kafka counters, same pattern), add to the struct:

```rust
    pub kubernetes_cache_size: IntGauge,
```

and in `new()`:

```rust
        let kubernetes_cache_size = IntGauge::with_opts(prometheus::int_gauge_opts!(
            "sentinel_kubernetes_cache_size",
            "Pod IPs currently tracked by the Kubernetes enrichment cache"
        ))?;
        registry.register(Box::new(kubernetes_cache_size.clone()))?;
```

- [ ] **Step 6: Implement the watcher loops**

Append to `informer.rs`:

```rust
/// Starts one watcher task per resource kind. Each task loops forever:
/// a watcher stream that ends (connection loss) is restarted after a delay,
/// so transient watch failures self-heal with a warning instead of stopping
/// enrichment (spec §4.5). Startup connection failures surface via
/// `Client::try_default()` in the caller (fail-fast).
pub struct KubernetesRuntime;

impl KubernetesRuntime {
    pub fn start(
        client: kube::Client,
        enricher: Arc<KubernetesEnricher>,
        metrics: Arc<SensorMetrics>,
    ) -> anyhow::Result<Vec<tokio::task::JoinHandle<()>>> {
        let mut handles = Vec::new();
        handles.push(spawn_watch(
            "pods",
            move || {
                Api::all(client.clone())
            },
            Box::new(move |event, enricher, metrics| {
                apply_pod_event(event, &enricher, &metrics)
            }),
        ));
        // The remaining five kinds follow the same shape; see Step 6b.
        Ok(handles)
    }
}
```

**Step 6b — the generic watcher task** (one implementation, six instantiations — avoid six copies by making the event-adapter a boxed closure over `watcher::Event<DynamicWatched>`-erased events; if boxing event types across kinds fights the type system, implement `spawn_watch` six times via a small macro `spawn_kind!` — macro is the preferred route, report the choice):

```rust
macro_rules! spawn_kind {
    ($task_name:literal, $api_type:ty, $event_fn:expr) => {
        tokio::spawn(async move {
            loop {
                let api: Api<$api_type> = Api::all(client.clone());
                let mut stream = watcher(api, watcher::Config::default()).boxed();
                while let Some(event) = stream.next().await {
                    match event {
                        watcher::Event::Applied(obj) | watcher::Event::Restarted(obj) => {
                            $event_fn(&obj, &enricher, &metrics);
                        }
                        watcher::Event::Deleted(obj) => {
                            $event_fn(&obj, &enricher, &metrics);
                        }
                    }
                }
                tracing::warn!("{} watch stream ended; restarting in 5s", $task_name);
                tokio::time::sleep(Duration::from_secs(5)).await;
            }
        })
    };
}
```

Concrete event adapters (file-local functions, using the converters from Step 3):

```rust
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

fn apply_owner_event(owner: &ReplicaSet, enricher: &KubernetesEnricher) {
    if let Some((uid, owner_ref)) = replica_set_to_owner(owner) {
        enricher.apply_owner(uid, owner_ref);
    }
}

fn apply_deployment_event(dep: &Deployment, enricher: &KubernetesEnricher) {
    if let Some((uid, name)) = deployment_to_entry(dep) {
        enricher.apply_deployment(uid, name);
    }
}

fn apply_service_ip_event(es: &EndpointSlice, enricher: &KubernetesEnricher) {
    for (ip, service) in endpointslice_to_services(es) {
        enricher.apply_service_ip(ip, service);
    }
}
```

Watch-table (6 tasks): pods (Pod, apply/remove by pod event), replicasets (ReplicaSet, apply_owner_event), statefulsets (StatefulSet, sts converter), daemonsets (DaemonSet, ds converter), deployments (Deployment, apply_deployment_event), endpointslices (EndpointSlice, apply_service_ip_event). The six spawn sites must live in `KubernetesRuntime::start`; use `Api::all` (all namespaces, read-only per RBAC).

- [ ] **Step 7: Re-export and run all gates**

In `crates/sentinel-enrichment/src/lib.rs`, add `pub mod informer; pub use informer::KubernetesRuntime;` (keep the existing kubernetes re-exports).

Run: `cargo nextest run --workspace && cargo clippy --workspace --all-targets --all-features -- -D warnings && cargo fmt --all -- --check`
Expected: 149 passed (140 + 9); clippy/fmt clean; no dead-code warnings (`KubernetesRuntime` is unused until Task 5 — if clippy flags it dead, that means Task 5 has not happened yet; the task order is deliberate, so if `dead_code` fires at THIS task's gate, wire a one-line `pub use` or keep the type `pub` from the lib root and re-check; report exactly what you did). The gauge test comes with the metrics change: extend the pattern of `kafka_metrics_registered` with a `kubernetes_cache_size_registered` test asserting `sentinel_kubernetes_cache_size 0` after `SensorMetrics::new()` (that is +1 test; expected total then 150).

- [ ] **Step 8: Commit**

```bash
git add Cargo.lock Cargo.toml crates/sentinel-enrichment/ crates/sentinel-sensor/src/metrics.rs
git commit -m "feat(enrichment): kube informers feed the metadata cache"
```

<!-- PLAN-CONTINUES -->
