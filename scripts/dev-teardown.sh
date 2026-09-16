#!/bin/bash
# scripts/dev-teardown.sh
# Teardown local development environment

set -euo pipefail

CLUSTER_NAME="kind"

echo "=== SentinelFlow-rs Development Teardown ==="

# Delete kind cluster
echo "Deleting kind cluster..."
kind delete cluster --name ${CLUSTER_NAME}

echo "=== Teardown Complete ==="
