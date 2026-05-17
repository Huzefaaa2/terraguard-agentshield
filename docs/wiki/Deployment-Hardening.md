# Deployment Hardening

AgentShield evidence can contain repository paths, policy decisions, tool identifiers, and change-management metadata. Treat the API and evidence storage as internal security infrastructure.

## Recommended Controls

| Area | Recommendation |
| --- | --- |
| Network | Keep the API private behind VPN, ZTNA, service mesh, or internal ingress |
| Identity | Put SSO, mTLS, API gateway auth, or reverse proxy auth in front of the API |
| Runtime | Run as non-root, drop Linux capabilities, block privilege escalation |
| Filesystem | Use read-only root filesystem and mount only evidence storage as writable |
| Data | Store signed evidence bundles in controlled storage with retention policy |
| Secrets | Keep signing keys in CI/secret manager, not in image layers |
| Images | Pin production images by digest after release validation |
| Logging | Forward container and access logs to SIEM with request IDs |

## Docker Pilot

```bash
docker build -t terraguard-agentshield:local .

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

## Docker Compose Pilot

```bash
cd examples/deployment
docker compose up --build
curl http://127.0.0.1:8080/health
```

The Compose example includes Nginx rate limiting, security headers, a read-only API container, dropped capabilities, and persistent evidence storage.

## Kubernetes Pilot

```bash
kubectl apply -f examples/deployment/kubernetes/agentshield-api.yaml
kubectl -n agentshield rollout status deployment/agentshield-api
```

The Kubernetes manifest includes non-root security context, read-only root filesystem, dropped capabilities, probes, PVC-backed evidence storage, ClusterIP service, and NetworkPolicy.

## Production Checklist

- API is private and authenticated.
- Evidence storage has backup and retention configured.
- Policy and evidence signing keys are managed outside containers.
- Image is pinned by digest and scanned in CI.
- Logs are shipped to SIEM.
- NetworkPolicy or equivalent segmentation is enabled.
- Branch protection requires AgentShield evidence before merge.
