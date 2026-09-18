# Local Development Infrastructure Guide

> **Version**: 0.1.0
> **Status**: Draft
> **Last Updated**: 2026-09-16

---

## Table of Contents

1. [Overview](#1-overview)
2. [Prerequisites](#2-prerequisites)
3. [Kubernetes Cluster Setup](#3-kubernetes-cluster-setup)
4. [Infrastructure Components](#4-infrastructure-components)
5. [Sensor Deployment](#5-sensor-deployment)
6. [Development Workflow](#6-development-workflow)
7. [Troubleshooting](#7-troubleshooting)
8. [Reference](#8-reference)

---

## 1. Overview

This guide describes how to set up a local Kubernetes environment for developing and testing SentinelFlow-rs. The local environment mirrors the production architecture as closely as possible while remaining lightweight enough for development work.

### Architecture

```text
┌─────────────────────────────────────────────────────┐
│                  Local Kubernetes                    │
│                                                     │
│  ┌──────────────────────────────────────────┐      │
│  │       Rust Security Sensor (DaemonSet)    │      │
│  │   Packet Capture → Flow Engine → Batch    │      │
│  └──────────────────────┬───────────────────┘      │
└─────────────────────────┼────────────────────────────┘
                          │
               ┌──────────┴──────────┐
               │    ClickHouse        │
               │  (StatefulSet)       │
               └──────────┬──────────┘
                          │
               ┌──────────┴──────────┐
               │   Grafana            │
               │  (Deployment)        │
               └─────────────────────┘
```

---

## 2. Prerequisites

### Required Tools

| Tool | Version | Purpose | Install |
|---|---|---|---|
| **Docker** | 24.0+ | Container runtime | [docker.com](https://docs.docker.com/get-docker/) |
| **kubectl** | 1.28+ | Kubernetes CLI | [kubernetes.io](https://kubernetes.io/docs/tasks/tools/) |
| **Helm** | 3.14+ | Package manager | [helm.sh](https://helm.sh/docs/intro/install/) |
| **Rust** | 1.75+ (stable) | Building sensor | [rustup.rs](https://rustup.rs/) |
| **cargo-nextest** | latest | Test runner | `cargo install cargo-nextest` |

### Optional Tools

| Tool | Version | Purpose | Install |
|---|---|---|---|
| **k9s** | latest | Kubernetes dashboard | `brew install k9s` |
| **kubectx** | latest | Context switching | `brew install kubectx` |
| **stern** | latest | Multi-pod log tailing | `brew install stern` |

### Verify Installation

```bash
# Check all tools
docker --version
kubectl version --client
helm version
rustc --version
cargo nextest --version
```

---

## 3. Kubernetes Cluster Setup

### Option A: kind (Recommended)

[kind](https://kind.sigs.k8s.io/) is recommended for local development. It runs Kubernetes inside Docker containers, providing a realistic cluster environment with minimal resource usage.

#### Installation

```bash
# macOS
brew install kind

# Linux
curl -Lo ./kind https://kind.sigs.k8s.io/dl/v0.22.0/kind-linux-amd64
chmod +x ./kind
sudo mv ./kind /usr/local/bin/kind
```

#### Create Cluster

```bash
# Create cluster with kind config
cat <<EOF | kind create cluster --config=-
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
nodes:
- role: control-plane
  kubeadmConfigPatches:
  - |
    kind: InitConfiguration
    nodeRegistration:
      kubeletExtraArgs:
        node-labels: "ingress-ready=true"
  extraPortMappings:
  - containerPort: 30000
    hostPort: 8123
    protocol: TCP
  - containerPort: 30001
    hostPort: 9000
    protocol: TCP
  - containerPort: 30002
    hostPort: 3000
    protocol: TCP
- role: worker
EOF
```

#### Verify Cluster

```bash
kubectl cluster-info --context kind-kind
kubectl get nodes
```

### Option B: k3d

[k3d](https://k3d.io/) runs k3s (lightweight Kubernetes) in Docker. Faster startup than kind.

```bash
# Install
brew install k3d

# Create cluster
k3d cluster create sentinel-flow \
  --api-port 6550 \
  -p "8123:8123@loadbalancer" \
  -p "9000:9000@loadbalancer" \
  -p "3000:3000@loadbalancer" \
  --agents 2
```

### Option C: minikube

[minikube](https://minikube.sigs.k8s.io/) runs a single-node cluster.

```bash
# Install
brew install minikube

# Start cluster
minikube start --driver=docker --cpus=4 --memory=8192

# Enable required addons
minikube addons enable ingress
```

### Comparison

| Feature | kind | k3d | minikube |
|---|---|---|---|
| **Startup Time** | ~30s | ~15s | ~45s |
| **Resource Usage** | Low | Very Low | Medium |
| **Multi-node** | Yes | Yes | No |
| **Realism** | High | High | Medium |
| **LoadBalancer** | Port mapping | Port mapping | MetalLB addon |
| **Recommended** | Yes | Yes (fast iteration) | No |

---

## 4. Infrastructure Components

### 4.1 Namespace

```bash
kubectl apply -f - <<EOF
apiVersion: v1
kind: Namespace
metadata:
  name: sentinel-flow
  labels:
    app.kubernetes.io/part-of: sentinel-flow
EOF
```

### 4.2 ClickHouse

#### Installation via Helm

```bash
# Add repo
helm repo add clickhouse https://clickhouse.github.io/bitnami-charts
helm repo update

# Install ClickHouse
helm install clickhouse clickhouse/clickhouse \
  --namespace sentinel-flow \
  --set auth.username=default \
  --set auth.password=clickhouse \
  --set persistence.size=10Gi \
  --set resources.requests.cpu=250m \
  --set resources.requests.memory=512Mi \
  --set resources.limits.cpu=1 \
  --set resources.limits.memory=1Gi
```

#### Verify ClickHouse

```bash
# Check pods
kubectl get pods -n sentinel-flow -l app.kubernetes.io/name=clickhouse

# Port forward
kubectl port-forward -n sentinel-flow svc/clickhouse 8123:8123 &

# Test connection
curl http://localhost:8123/?query=SELECT%20version()
```

#### Create Schema

```bash
kubectl exec -n sentinel-flow -it clickhouse-0 -- clickhouse-client --password clickhouse <<'EOF'
CREATE DATABASE IF NOT EXISTS sentinel;

CREATE TABLE IF NOT EXISTS sentinel.network_flows
(
    flow_id           UUID,
    timestamp_start   DateTime64(3, 'UTC'),
    timestamp_end     DateTime64(3, 'UTC'),
    source_ip         IPv6,
    destination_ip    IPv6,
    source_port       UInt16,
    destination_port  UInt16,
    protocol          Enum8('TCP' = 1, 'UDP' = 2, 'ICMP' = 3, 'OTHER' = 4),
    packets_forward   UInt32,
    packets_reverse   UInt32,
    bytes_forward     UInt64,
    bytes_reverse     UInt64,
    duration_ms       UInt32,
    tcp_flags_seen    Array(UInt8),
    sensor_node       LowCardinality(String),
    source_namespace      Nullable(LowCardinality(String)),
    source_pod            Nullable(LowCardinality(String)),
    source_deployment     Nullable(LowCardinality(String)),
    source_service        Nullable(LowCardinality(String)),
    source_app            Nullable(LowCardinality(String)),
    destination_namespace Nullable(LowCardinality(String)),
    destination_pod       Nullable(LowCardinality(String)),
    destination_deployment Nullable(LowCardinality(String)),
    destination_service   Nullable(LowCardinality(String)),
    destination_app       Nullable(LowCardinality(String))
)
ENGINE = ReplicatedMergeTree()
PARTITION BY toYYYYMM(timestamp_start)
ORDER BY (source_ip, destination_ip, timestamp_start, source_port, destination_port, protocol)
TTL timestamp_start + INTERVAL 30 DAY
SETTINGS index_granularity = 8192;

CREATE TABLE IF NOT EXISTS sentinel.security_events
(
    event_id          UUID,
    timestamp         DateTime64(3, 'UTC'),
    event_type        LowCardinality(String),
    severity          Enum8('low' = 1, 'medium' = 2, 'high' = 3, 'critical' = 4),
    confidence        Float32,
    source_flow_ids   Array(UUID),
    source_ip         IPv6,
    source_pod        Nullable(LowCardinality(String)),
    destination_ip    IPv6,
    destination_port  UInt16,
    protocol          LowCardinality(String),
    description       String,
    rule_id           LowCardinality(String),
    rule_name         LowCardinality(String),
    tags              Array(LowCardinality(String)),
    mitigation_suggestions Array(String)
)
ENGINE = ReplicatedMergeTree()
PARTITION BY toYYYYMM(timestamp)
ORDER BY (event_type, severity, timestamp)
TTL timestamp + INTERVAL 365 DAY
SETTINGS index_granularity = 8192;
EOF
```

### 4.3 Grafana

#### Installation via Helm

```bash
# Add repo
helm repo add grafana https://grafana.github.io/helm-charts
helm repo update

# Install Grafana
helm install grafana grafana/grafana \
  --namespace sentinel-flow \
  --set adminUser=admin \
  --set adminPassword=admin \
  --set persistence.size=1Gi \
  --set service.type=LoadBalancer \
  --set service.port=3000
```

#### Verify Grafana

```bash
# Check pods
kubectl get pods -n sentinel-flow -l app.kubernetes.io/name=grafana

# Get password
kubectl get secret -n sentinel-flow grafana -o jsonpath="{.data.admin-password}" | base64 -d
```

#### Add ClickHouse Data Source

```bash
kubectl apply -f - <<EOF
apiVersion: v1
kind: ConfigMap
metadata:
  name: grafana-datasource
  namespace: sentinel-flow
  labels:
    grafana_datasource: "1"
data:
  sentinel-flow.yaml: |
    apiVersion: 1
    datasources:
      - name: ClickHouse
        type: grafana-clickhouse-datasource
        access: proxy
        url: http://clickhouse:8123
        jsonData:
          defaultDatabase: sentinel
          port: 9000
          protocol: http
          tlsSkipVerify: true
        secureJsonData:
          password: clickhouse
EOF
```

### 4.4 Test Application (Optional)

Deploy a simple test application to generate network traffic:

```bash
kubectl apply -f - <<EOF
apiVersion: apps/v1
kind: Deployment
metadata:
  name: test-app
  namespace: sentinel-flow
  labels:
    app: test-app
spec:
  replicas: 2
  selector:
    matchLabels:
      app: test-app
  template:
    metadata:
      labels:
        app: test-app
    spec:
      containers:
      - name: nginx
        image: nginx:alpine
        ports:
        - containerPort: 80
        resources:
          requests:
            cpu: 50m
            memory: 64Mi
          limits:
            cpu: 100m
            memory: 128Mi
---
apiVersion: v1
kind: Service
metadata:
  name: test-app
  namespace: sentinel-flow
spec:
  selector:
    app: test-app
  ports:
  - port: 80
    targetPort: 80
  type: ClusterIP
EOF
```

---

## 5. Sensor Deployment

### 5.1 Build Sensor Image

```bash
# Build for local architecture
docker build -t sentinel-flow-sensor:local -f Dockerfile.sensor .

# Load into kind cluster
kind load docker-image sentinel-flow-sensor:local --name kind
```

### 5.2 Kubernetes Manifests

#### ServiceAccount

```yaml
# deploy/kubernetes/serviceaccount.yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: sentinel-flow-sensor
  namespace: sentinel-flow
```

#### ClusterRole

```yaml
# deploy/kubernetes/clusterrole.yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: sentinel-flow-sensor
rules:
  - apiGroups: [""]
    resources: ["pods", "services", "namespaces", "nodes", "endpoints"]
    verbs: ["get", "list", "watch"]
  - apiGroups: ["apps"]
    resources: ["deployments", "replicasets", "daemonsets", "statefulsets"]
    verbs: ["get", "list", "watch"]
```

#### ClusterRoleBinding

```yaml
# deploy/kubernetes/clusterrolebinding.yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: sentinel-flow-sensor
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: sentinel-flow-sensor
subjects:
  - kind: ServiceAccount
    name: sentinel-flow-sensor
    namespace: sentinel-flow
```

#### ConfigMap

```yaml
# deploy/kubernetes/configmap.yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: sentinel-flow-config
  namespace: sentinel-flow
data:
  sensor.yaml: |
    capture:
      interface: eth0
      buffer_size: 4096
      snap_len: 65535
    flow:
      inactive_timeout_secs: 30
      active_timeout_secs: 300
      max_flows: 100000
    output:
      clickhouse_url: "http://clickhouse:8123"
      clickhouse_database: "sentinel"
      batch_size: 1000
      batch_timeout_ms: 1000
    detection:
      enabled: true
      rules_path: "/etc/sentinel-flow/rules"
    metrics:
      enabled: true
      port: 9090
```

#### DaemonSet

```yaml
# deploy/kubernetes/daemonset.yaml
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: sentinel-flow-sensor
  namespace: sentinel-flow
  labels:
    app: sentinel-flow-sensor
spec:
  selector:
    matchLabels:
      app: sentinel-flow-sensor
  template:
    metadata:
      labels:
        app: sentinel-flow-sensor
      annotations:
        prometheus.io/scrape: "true"
        prometheus.io/port: "9090"
    spec:
      serviceAccountName: sentinel-flow-sensor
      hostNetwork: false
      containers:
      - name: sensor
        image: sentinel-flow-sensor:local
        imagePullPolicy: Never
        args:
          - "--config"
          - "/etc/sentinel-flow/sensor.yaml"
        securityContext:
          capabilities:
            add:
              - NET_RAW
            drop:
              - ALL
          readOnlyRootFilesystem: true
          runAsNonRoot: false
          seccompProfile:
            type: RuntimeDefault
        resources:
          requests:
            cpu: 100m
            memory: 128Mi
          limits:
            cpu: 500m
            memory: 256Mi
        ports:
        - name: metrics
          containerPort: 9090
          protocol: TCP
        livenessProbe:
          httpGet:
            path: /healthz
            port: 9090
          initialDelaySeconds: 10
          periodSeconds: 10
          failureThreshold: 3
        readinessProbe:
          httpGet:
            path: /readyz
            port: 9090
          initialDelaySeconds: 5
          periodSeconds: 5
          failureThreshold: 2
        volumeMounts:
        - name: config
          mountPath: /etc/sentinel-flow
          readOnly: true
        - name: tmp
          mountPath: /tmp
      volumes:
      - name: config
        configMap:
          name: sentinel-flow-config
      - name: tmp
        emptyDir: {}
      tolerations:
      - key: node-role.kubernetes.io/control-plane
        effect: NoSchedule
```

### 5.3 Deploy All Resources

```bash
kubectl apply -f deploy/kubernetes/serviceaccount.yaml
kubectl apply -f deploy/kubernetes/clusterrole.yaml
kubectl apply -f deploy/kubernetes/clusterrolebinding.yaml
kubectl apply -f deploy/kubernetes/configmap.yaml
kubectl apply -f deploy/kubernetes/daemonset.yaml
```

Or deploy all at once:

```bash
kubectl apply -f deploy/kubernetes/
```

### 5.4 Verify Deployment

```bash
# Check DaemonSet status
kubectl get daemonset -n sentinel-flow

# Check sensor pods
kubectl get pods -n sentinel-flow -l app=sentinel-flow-sensor

# Check logs
kubectl logs -n sentinel-flow -l app=sentinel-flow-sensor -f

# Check metrics
kubectl port-forward -n sentinel-flow ds/sentinel-flow-sensor 9090:9090 &
curl http://localhost:9090/metrics
```

---

## 6. Development Workflow

### 6.1 Build and Deploy Cycle

```bash
# 1. Make code changes
vim crates/sentinel-sensor/src/main.rs

# 2. Run tests locally
cargo nextest run

# 3. Build new image
docker build -t sentinel-flow-sensor:local -f Dockerfile.sensor .

# 4. Load into kind
kind load docker-image sentinel-flow-sensor:local --name kind

# 5. Restart sensor pods
kubectl rollout restart daemonset/sentinel-flow-sensor -n sentinel-flow

# 6. Verify
kubectl logs -n sentinel-flow -l app=sentinel-flow-sensor -f --tail=100
```

### 6.2 Quick Development Script

```bash
#!/bin/bash
# scripts/dev-deploy.sh

set -euo pipefail

IMAGE_NAME="sentinel-flow-sensor:local"
NAMESPACE="sentinel-flow"

echo "Building sensor..."
docker build -t $IMAGE_NAME -f Dockerfile.sensor .

echo "Loading into kind..."
kind load docker-image $IMAGE_NAME --name kind

echo "Restarting sensor pods..."
kubectl rollout restart daemonset/sentinel-flow-sensor -n $NAMESPACE

echo "Waiting for rollout..."
kubectl rollout status daemonset/sentinel-flow-sensor -n $NAMESPACE --timeout=60s

echo "Following logs..."
kubectl logs -n $NAMESPACE -l app=sentinel-flow-sensor -f --tail=100
```

### 6.3 Local Development Without Kubernetes

For faster iteration, run the sensor directly on the host:

```bash
# Run sensor with local config
cargo run --bin sentinel-sensor -- --config config/sensor-local.yaml

# Run tests
cargo nextest run

# Run linter
cargo clippy --workspace --all-targets --all-features -- -D warnings

# Format code
cargo fmt --all
```

### 6.4 Debugging

#### Port Forwarding

```bash
# ClickHouse
kubectl port-forward -n sentinel-flow svc/clickhouse 8123:8123

# Grafana
kubectl port-forward -n sentinel-flow svc/grafana 3000:80

# Sensor metrics
kubectl port-forward -n sentinel-flow ds/sentinel-flow-sensor 9090:9090
```

#### Log Analysis

```bash
# Follow all sensor logs
kubectl logs -n sentinel-flow -l app=sentinel-flow-sensor -f

# Filter by node
kubectl logs -n sentinel-flow -l app=sentinel-flow-sensor --field-selector spec.nodeName=node1

# Search logs
kubectl logs -n sentinel-flow -l app=sentinel-flow-sensor | grep "flow_export"
```

#### ClickHouse Queries

```bash
# Connect to ClickHouse
kubectl exec -n sentinel-flow -it clickhouse-0 -- clickhouse-client --password clickhouse

# Query recent flows
SELECT * FROM sentinel.network_flows
WHERE timestamp_start > now() - INTERVAL 5 MINUTE
ORDER BY timestamp_start DESC
LIMIT 10;

# Query security events
SELECT * FROM sentinel.security_events
ORDER BY timestamp DESC
LIMIT 10;

# Flow count by source
SELECT source_ip, count() as flow_count
FROM sentinel.network_flows
GROUP BY source_ip
ORDER BY flow_count DESC;
```

---

## 7. Troubleshooting

### Common Issues

#### Sensor Pod Not Starting

```bash
# Check events
kubectl describe pod -n sentinel-flow -l app=sentinel-flow-sensor

# Common causes:
# - CAP_NET_RAW not available (check Docker Desktop settings)
# - Image not found (verify kind load)
# - ConfigMap not mounted
```

#### No Flow Data in ClickHouse

```bash
# Check sensor logs
kubectl logs -n sentinel-flow -l app=sentinel-flow-sensor --tail=100

# Common causes:
# - Wrong network interface (check capture.interface in config)
# - ClickHouse connection failed
# - No network traffic on the node
```

#### ClickHouse Connection Refused

```bash
# Check ClickHouse pod
kubectl get pods -n sentinel-flow -l app.kubernetes.io/name=clickhouse

# Test connection from sensor pod
kubectl exec -n sentinel-flow -it <sensor-pod> -- \
  curl -s http://clickhouse:8123/?query=SELECT%201

# Check ClickHouse logs
kubectl logs -n sentinel-flow clickhouse-0
```

#### Memory Pressure

```bash
# Check sensor memory usage
kubectl top pod -n sentinel-flow -l app=sentinel-flow-sensor

# Reduce flow table size in config
# flow.max_flows: 50000 (default: 100000)
```

### Debug Commands

```bash
# Full cluster status
kubectl get all -n sentinel-flow

# Sensor pod details
kubectl describe pod -n sentinel-flow -l app=sentinel-flow-sensor

# Real-time sensor metrics
kubectl exec -n sentinel-flow -it <sensor-pod> -- \
  curl -s http://localhost:9090/metrics | grep sentinel

# Network connectivity test
kubectl exec -n sentinel-flow -it <sensor-pod> -- \
  curl -v http://clickhouse:8123
```

---

## 8. Reference

### Configuration Reference

| Parameter | Default | Description |
|---|---|---|
| `capture.interface` | `eth0` | Network interface to capture |
| `capture.buffer_size` | `4096` | AF_PACKET buffer size |
| `capture.snap_len` | `65535` | Maximum packet length |
| `flow.inactive_timeout_secs` | `30` | Export flow after N seconds of inactivity |
| `flow.active_timeout_secs` | `300` | Export flow after N seconds (active) |
| `flow.max_flows` | `100000` | Maximum concurrent flows |
| `output.clickhouse_url` | `http://clickhouse:8123` | ClickHouse HTTP endpoint |
| `output.clickhouse_database` | `sentinel` | Target database |
| `output.batch_size` | `1000` | Flows per batch |
| `output.batch_timeout_ms` | `1000` | Max time before flush |
| `detection.enabled` | `true` | Enable detection engine |
| `metrics.enabled` | `true` | Enable Prometheus metrics |
| `metrics.port` | `9090` | Metrics endpoint port |

### Useful Commands

```bash
# Cluster management
kind create cluster --config kind-config.yaml
kind delete cluster --name kind

# Namespace
kubectl create namespace sentinel-flow
kubectl delete namespace sentinel-flow

# Helm
helm list -n sentinel-flow
helm uninstall clickhouse -n sentinel-flow
helm uninstall grafana -n sentinel-flow

# Cleanup
kubectl delete -f deploy/kubernetes/ --ignore-not-found
```

### Links

- [kind Documentation](https://kind.sigs.k8s.io/)
- [ClickHouse Helm Chart](https://github.com/bitnami/charts/tree/main/bitnami/clickhouse)
- [Grafana Helm Chart](https://github.com/grafana/helm-charts)
- [Kubernetes Documentation](https://kubernetes.io/docs/)
