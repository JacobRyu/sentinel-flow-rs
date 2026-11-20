# Kubernetes enrichment E2E runbook

Manual acceptance for the Phase 7 enrichment (spec D8): ≥ 95% of flows
carrying pod metadata. Runs outside CI; needs kind, kubectl, Docker, and a
ClickHouse endpoint reachable from the cluster.

## 1. Create the cluster and load the image

```bash
kind create cluster --name sentinel
docker build -f Dockerfile.sensor -t sentinel-sensor:e2e .   # build once
kind load docker-image sentinel-sensor:e2e --name sentinel
```

## 2. Apply RBAC and the DaemonSet

1. Enable `kubernetes.enabled: true` in `config/sensor.yaml` and make sure its
   output target is reachable from inside the cluster (e.g. the Kafka
   transport):

   ```bash
   # Repo default: kubernetes.enabled is false in config/sensor.yaml.
   sed -i.bak 's/^  enabled: false$/  enabled: true/' config/sensor.yaml && rm -f config/sensor.yaml.bak
   ```

   Verify with `grep -A1 '^kubernetes:' config/sensor.yaml`; the `enabled:` line
   must read `true`.

2. Create the namespace and apply RBAC:

```bash
kubectl create namespace sentinel
kubectl apply -f deploy/k8s/rbac.yaml
```

3. Create the configmap, apply the DaemonSet, then override the published
   image with the local e2e build:

```bash
kubectl create configmap sentinel-sensor-config --from-file=sensor.yaml=config/sensor.yaml -n sentinel
kubectl apply -f deploy/k8s/daemonset.yaml
kubectl -n sentinel set image daemonset/sentinel-sensor sensor=sentinel-sensor:e2e
```

4. Verify the sensor started with the mounted config (the log line is
   `Loaded configuration from /etc/sentinel/sensor.yaml` from `main.rs`):

```bash
kubectl -n sentinel logs daemonset/sentinel-sensor | head -50
kubectl -n sentinel get pods -o wide
```

Look for the `Loaded configuration from /etc/sentinel/sensor.yaml` line and no
config error; pods should become Ready. Confirm the informers connected
before proceeding to section 3.

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
