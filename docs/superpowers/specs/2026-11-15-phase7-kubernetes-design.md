# Phase 7: Kubernetes Metadata Enrichment — Design Spec

- **Date:** 2026-11-15
- **Status:** Approved design (brainstorming, all sections user-approved)
- **Roadmap source:** `docs/architecture.md` §20 Phase 7, §10.2, §10.3, §7.4, metrics plan
- **Acceptance (§20):** 95%+ of flows enriched with pod/namespace/service metadata

## 1. Goal

Enrich exported network flows with Kubernetes workload metadata — namespace, pod,
deployment, service, and app — for both source and destination IPs, and persist it
in ClickHouse so that every flow query can answer "which pod/service produced
this traffic".

## 2. Decisions (user-approved)

| # | Decision | Choice |
|---|---|---|
| D1 | ClickHouse scope | `network_flows` only (10 columns); `security_events.source_pod` deferred |
| D2 | Schema migration | Idempotent `ALTER TABLE ... ADD COLUMN IF NOT EXISTS` in `ensure_schema` |
| D3 | Non-K8s behavior | `kubernetes.enabled` config flag, default `false`; disabled ⇒ all columns NULL |
| D4 | Deployment resolution | ownerReferences traversal (pod → RS/STS/DS → Deployment) |
| D5 | Service resolution | EndpointSlice IP → Service mapping |
| D6 | IP reuse protection | watch DELETE eviction + TTL safety net (10 min) |
| D7 | K8s manifests | `deploy/k8s/` RBAC + DaemonSet YAML included |
| D8 | Acceptance validation | Unit tests (mock cache) + manual kind E2E runbook; no live cluster in CI |
| D9 | Enrichment site | Sensor at flow export time (architecture §10.2); metadata rides on `ExportedFlow` |

## 3. Architecture and data flow

```
[K8s API] --Informer(list+watch)--> KubernetesEnricher (sentinel-enrichment)
                                        |  3 caches: pods_by_ip / owners / service_by_ip
                                        v
sensor: at ExportedFlow creation, resolve src/dst IP metadata into new
        ExportedFlow fields (all None when disabled or cache miss)
                                        |
FlowRow::try_from copies the metadata columns --direct--> ClickHouse (10 new cols)
                                        +--kafka----> JSON 1-row-1-message (Phase 6 contract intact)
sink: FlowRow -> ExportedFlow -> FlowRow roundtrip stays lossless (metadata included)
```

### 3.1 Metadata rides on `ExportedFlow` (key design point)

`sentinel-flow::ExportedFlow` gains ten `Option<String>` fields:

```
source_namespace, source_pod, source_deployment, source_service, source_app,
destination_namespace, destination_pod, destination_deployment,
destination_service, destination_app
```

- Default `None`; additive change, existing constructors/uses unaffected.
- Enrichment happens at exactly one call site (sensor export time), so
  `FlowWriter`, `KafkaFlowStore`, and sink logic need **no changes** —
  `FlowRow::try_from` copies the fields, the sink adapter copies them back,
  and the Kafka JSON roundtrip stays byte-exact.
- The Phase 6 invariant "FlowRow → ExportedFlow → FlowRow is lossless" now
  covers metadata, preserving the pending-counter drain assumption (Fix B).

### 3.2 Enrichment call site

In the sensor, where an `ExportedFlow` is produced (packet path and sweep path
both funnel through the same export handling), if enrichment is enabled the
sensor asks the enricher for both IPs and writes the ten fields before the flow
is forwarded to the output channel. A cache miss leaves fields `None`
(→ ClickHouse NULL), which the acceptance metric tolerates.

## 4. sentinel-enrichment crate design

The existing skeleton (`KubernetesEnricher` with a `DashMap<String, PodMetadata>`)
is replaced by the real implementation in the same crate.

### 4.1 Watches (kube-runtime)

| Resource | Purpose |
|---|---|
| pods (core) | IP → pod name/namespace/labels/owner/node |
| replicasets (apps) | owner traversal RS → Deployment |
| deployments (apps) | uid → deployment name |
| statefulsets, daemonsets (apps) | owner traversal (owner is itself the workload) |
| endpointslices (discovery) | endpoint IP → Service name |

`kube::Client::try_default()` is used: in-cluster config first, kubeconfig
fallback (works for the kind E2E). RBAC §10.3 covers exactly these reads.

### 4.2 Cache structures

- `pods_by_ip: DashMap<IpAddr, PodSnapshot>` —
  `PodSnapshot { name, namespace, owner_uid, labels, node, updated_at }`
- `owners: DashMap<String, OwnerRef>` (uid → kind + name + parent owner) and a
  deployment uid→name map — used to resolve `deployment`
- `service_by_ip: DashMap<IpAddr, ServiceRef>` — EndpointSlice endpoints →
  owning Service name

IP keys are normalized through `to_ipv6_mapped` so v4-mapped addresses match
`FlowRow`'s `Ipv6Addr` storage.

### 4.3 Lookup logic (pure functions, informer-decoupled)

- `namespace`, `pod`, `node`: direct from `pods_by_ip`
- `deployment`: owner uid → ReplicaSet's ownerReferences → Deployment name;
  StatefulSet/DaemonSet-owned pods resolve to the STS/DS name itself
- `service`: direct from `service_by_ip`
- `app`: label `app.kubernetes.io/name`, fallback `app`, else `None`

Cache update handlers (apply ADD/UPDATE/DELETE events into the caches) are
pure functions taking the resource snapshots, so the full lifecycle is unit
testable without an API server.

### 4.4 TTL and IP reuse

Watch DELETE events evict immediately. As a safety net for missed events
(watch reconnection gaps), every lookup treats an entry older than
**TTL = 10 minutes** as a miss and removes it.

### 4.5 Failure behavior

- `enabled = true` and initial connection failure → **fail-fast** at startup
  (same policy as detection rules).
- Mid-run watch failures: kube-runtime reconnects automatically; the sensor
  logs warnings and keeps serving with stale/missing cache entries (bounded
  staleness per architecture §10.2).

### 4.6 Metrics

- `sentinel_kubernetes_cache_size` (Gauge, pods_by_ip length) — matches the
  architecture metrics plan.
- Zero enrichment traffic when disabled: the gauge stays registered but 0.

## 5. ClickHouse schema changes

New columns appended to `network_flows` (order matches §7.4; appended at the
end so RowBinary struct order and ALTER behavior agree):

```sql
ALTER TABLE network_flows ADD COLUMN IF NOT EXISTS source_namespace Nullable(LowCardinality(String));
-- ... source_pod, source_deployment, source_service, source_app,
--     destination_namespace, destination_pod, destination_deployment,
--     destination_service, destination_app
```

- Fresh deployments: the new `CREATE TABLE IF NOT EXISTS` DDL includes the
  columns at the end.
- Existing deployments: `ensure_schema` runs the ten idempotent ALTERs;
  no data loss, existing queries unaffected (new columns are NULL for old rows).
- `FlowRow` fields appended at the end (RowBinary column order = struct order).

## 6. Configuration

`SensorConfig` gains:

```yaml
kubernetes:
  enabled: false   # default; true requires a reachable K8s API at startup
```

`validate()` gains no extra rules beyond the flag (connection is validated by
the fail-fast startup behavior in §4.5).

## 7. Deliverables

| Artifact | Location |
|---|---|
| Enricher implementation | `crates/sentinel-enrichment/src/` (informer wiring + cache + lookup) |
| ExportedFlow fields | `crates/sentinel-flow` |
| FlowRow + DDL + ALTER | `crates/sentinel-sensor/src/output/{row,clickhouse}.rs` |
| Export-time wiring | sensor flow export path + config |
| Sink adapter metadata copy | `crates/sentinel-sink/src/adapter.rs` |
| RBAC + DaemonSet manifests | `deploy/k8s/rbac.yaml`, `deploy/k8s/daemonset.yaml` |
| E2E runbook | `docs/runbooks/kubernetes-e2e.md` |
| Metrics | `sentinel_kubernetes_cache_size` gauge in sensor metrics |

## 8. Testing

- **Unit (CI):** cache apply functions (ADD/UPDATE/DELETE lifecycle), TTL
  expiry, owner traversal, EndpointSlice service mapping, app label fallback;
  FlowRow/adapter roundtrip with metadata; config default (disabled) wiring.
- **IT (REQUIRE_CLICKHOUSE, self-skip):** DDL + ALTER path and row roundtrip
  including metadata columns.
- **Manual E2E (kind, CI 外):** runbook steps — kind cluster, apply RBAC +
  DaemonSet + ClickHouse, generate traffic, then
  `SELECT countIf(source_pod IS NOT NULL) / count()` must meet **95%+**;
  also demonstrates deployment/service columns populated.
- No live K8s API in CI (Phase 6 precedent).

## 9. Out of scope (deferred)

- `security_events.source_pod` enrichment (D1).
- DNS monitoring (OQ-006, Phase 7+).
- Enrichment of host-network / non-pod IPs (columns stay NULL by design).
- Automatic manifest installation tooling (YAML + runbook only).

## 10. Open risks

| Risk | Mitigation |
|---|---|
| Large clusters raise memory footprint of the caches | caches hold only needed fields; TTL bounds churn; gauge exposes size |
| EndpointSlice churn on scaling events | watch-driven; TTL safety net bounds staleness |
| kube 0.87 runtime API drift at implementation time | plan verifies against crate source and records deviations like Phase 6 |
