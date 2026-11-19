# Kubernetes enrichment E2E runbook

Manual acceptance for the Phase 7 enrichment (spec D8): ≥ 95% of flows
carrying pod metadata. Runs outside CI; needs kind, kubectl, Docker, and a
ClickHouse endpoint reachable from the cluster.

## 1. Create the cluster and load the image

```bash
kind create cluster --name sentinel
docker build -f deploy/Dockerfile.sensor -t sentinel-sensor:e2e .   # build once
kind load docker-image sentinel-sensor:e2e --name sentinel
```

## 2. Apply RBAC and the DaemonSet

```bash
kubectl create namespace sentinel
kubectl apply -f deploy/k8s/rbac.yaml
kubectl create configmap sentinel-sensor-config --from-file=sensor.yaml=config/sensor.yaml -n sentinel
# config/sensor.yaml must have kubernetes.enabled: true for this run
# (and an output target reachable from the cluster, e.g. the Kafka transport)
kubectl apply -f deploy/k8s/daemonset.yaml
```

Wait for the sensor to be ready and confirm the informers connected:

```bash
kubectl -n sentinel logs daemonset/sentinel-sensor | head -50
kubectl -n sentinel get pods -o wide
```

## 3. Generate traffic inside the cluster

Run a pod that talks to a Service so the flow IPs resolve to pod/endpoint
metadata (e.g. two busybox pods exchanging HTTP over an in-cluster service).

## 4. Verify the acceptance query in ClickHouse

```sql
SELECT
  countIf(source_pod IS NOT NULL) AS enriched,
  count() AS total,
  enriched / total AS ratio
FROM network_flows;
```

Acceptance: `ratio >= 0.95`.

Known caveat (by design): host-network flows (node IPs) carry NULL metadata;
exclude them from the denominator if they dominate:

```sql
SELECT countIf(source_pod IS NOT NULL) / count()
FROM network_flows
WHERE source_namespace != '';
```

## 5. Tear down

```bash
kind delete cluster --name sentinel
```
