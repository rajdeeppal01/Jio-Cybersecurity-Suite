#!/bin/bash
set -e

echo "[1/4] Starting Ollama..."
sudo systemctl start ollama

echo "[2/4] Starting Minikube..."
minikube start --driver=docker

echo "[3/4] Waiting for all deployments to be ready..."
DEPLOYMENTS=(netraai-gateway redis postgres netraai-worker-t1 netraai-worker-t2 netraai-worker-t3)

for dep in "${DEPLOYMENTS[@]}"; do
    echo "  → Waiting for $dep..."
    kubectl rollout status deployment/$dep -n netraai --timeout=120s
done

echo "[4/4] All pods ready. Starting port-forward..."
pkill -f 'kubectl port-forward' 2>/dev/null || true

nohup bash -c '
  export NO_PROXY=localhost,127.0.0.1,192.168.49.2,10.63.92.0/25
  export no_proxy=localhost,127.0.0.1,192.168.49.2,10.63.92.0/25
  kubectl port-forward svc/gateway 8000:8000 --address 0.0.0.0 -n netraai
' > /tmp/port_forward.log 2>&1 &

echo ""
echo "✅ JCS is live → http://10.63.92.151:8000/dashboard"
