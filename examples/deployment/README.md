# Deployment Examples

These examples show a hardened starting point for running the AgentShield enterprise API in private enterprise environments.

## Docker

Build the image from the repository root:

```bash
docker build -t terraguard-agentshield:local .
```

Run the API:

```bash
docker run --rm \
  --read-only \
  --user 10001:10001 \
  --cap-drop ALL \
  --security-opt no-new-privileges:true \
  --tmpfs /tmp:size=64m,noexec,nosuid,nodev \
  -v agentshield-data:/var/lib/agentshield \
  -p 8000:8000 \
  terraguard-agentshield:local
```

## Docker Compose

```bash
cd examples/deployment
docker compose up --build
curl http://127.0.0.1:8080/health
```

The Compose example places Nginx in front of the API for rate limiting and security headers. In enterprise rollout, put SSO, mTLS, VPN, or private ingress controls in front of Nginx.

## Kubernetes

```bash
kubectl apply -f examples/deployment/kubernetes/agentshield-api.yaml
kubectl -n agentshield get pods
kubectl -n agentshield port-forward svc/agentshield-api 8000:8000
curl http://127.0.0.1:8000/health
```

Before production use, replace the image tag with an immutable digest and connect the service to your private ingress, identity-aware proxy, or API gateway.
