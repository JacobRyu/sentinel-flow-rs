#!/bin/bash
# scripts/dev-deploy.sh
# Quick deploy script for local development

set -euo pipefail

IMAGE_NAME="sentinel-flow-sensor:local"
NAMESPACE="sentinel-flow"
CLUSTER_NAME="kind"

echo "=== SentinelFlow-rs Development Deploy ==="

# Check if kind cluster exists
if ! kind get clusters | grep -q "^${CLUSTER_NAME}$"; then
    echo "Creating kind cluster..."
    kind create cluster --config kind-config.yaml --name ${CLUSTER_NAME}
fi

# Build image
echo "Building sensor image..."
docker build -t ${IMAGE_NAME} -f Dockerfile.sensor .

# Load into kind
echo "Loading image into kind..."
kind load docker-image ${IMAGE_NAME} --name ${CLUSTER_NAME}

# Apply Kubernetes manifests
echo "Applying Kubernetes manifests..."
kubectl apply -f deploy/kubernetes/namespace.yaml
kubectl apply -f deploy/kubernetes/serviceaccount.yaml
kubectl apply -f deploy/kubernetes/clusterrole.yaml
kubectl apply -f deploy/kubernetes/clusterrolebinding.yaml
kubectl apply -f deploy/kubernetes/configmap.yaml
kubectl apply -f deploy/kubernetes/daemonset.yaml

# Wait for rollout
echo "Waiting for sensor rollout..."
kubectl rollout status daemonset/sentinel-flow-sensor -n ${NAMESPACE} --timeout=120s

echo "=== Deploy Complete ==="
echo ""
echo "Useful commands:"
echo "  kubectl logs -n ${NAMESPACE} -l app=sentinel-flow-sensor -f"
echo "  kubectl port-forward -n ${NAMESPACE} ds/sentinel-flow-sensor 9090:9090"
echo "  kubectl port-forward -n ${NAMESPACE} svc/clickhouse 8123:8123"
echo "  kubectl port-forward -n ${NAMESPACE} svc/grafana 3000:80"
