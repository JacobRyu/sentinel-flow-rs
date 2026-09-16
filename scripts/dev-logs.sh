#!/bin/bash
# scripts/dev-logs.sh
# Tail logs from all sensor pods

set -euo pipefail

NAMESPACE="sentinel-flow"

echo "=== SentinelFlow-rs Sensor Logs ==="
echo "Press Ctrl+C to stop"
echo ""

kubectl logs -n ${NAMESPACE} -l app=sentinel-flow-sensor -f --tail=100
