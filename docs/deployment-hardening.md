# Deployment Hardening

This guide covers the recommended enterprise deployment posture for the AgentShield API and webhook/SIEM receivers.

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
| Availability | Use readiness/liveness checks and at least two replicas for shared environments |

## Container Image

The repository includes a root `Dockerfile` for the AgentShield API:

```bash
docker build -t ghcr.io/huzefaaa2/terraguard-agentshield:0.1.0 .
```

The image:

- runs as UID/GID `10001`;
- exposes the API on port `8000`;
- uses `/var/lib/agentshield` as the evidence data directory;
- includes a `/health` healthcheck;
- starts `terraguard-agentshield api serve --host 0.0.0.0`.

## Docker Compose Pilot

Use the hardened local pilot stack:

```bash
cd examples/deployment
docker compose up --build
curl http://127.0.0.1:8080/health
```

The Compose example includes:

- AgentShield API container with read-only root filesystem;
- non-root user;
- dropped capabilities;
- `no-new-privileges`;
- tmpfs for temporary paths;
- persistent evidence volume;
- Nginx reverse proxy with rate limiting and security headers.

## Kubernetes Pilot

Apply the example manifest:

```bash
kubectl apply -f examples/deployment/kubernetes/agentshield-api.yaml
kubectl -n agentshield rollout status deployment/agentshield-api
```

The manifest includes:

- namespace;
- ConfigMap;
- PVC for evidence storage;
- two API replicas;
- non-root pod and container security contexts;
- read-only root filesystem;
- dropped capabilities;
- readiness and liveness probes;
- ClusterIP service;
- NetworkPolicy limiting ingress to namespaces labelled `agentshield-client=true`.

For production, replace the sample image tag with an immutable digest and connect it to your enterprise ingress and identity layer.

## Receiver Hardening

Webhook/SIEM receivers in `examples/siem/` are intentionally dependency-light examples. When deploying receivers:

- validate `X-AgentShield-Signature` when HMAC is configured;
- reject unsigned traffic from untrusted networks;
- enforce idempotency on `session_id` or evidence bundle ID;
- store raw payloads before enrichment;
- return `2xx` only after durable persistence;
- avoid logging secrets or full payloads to stdout in production;
- use managed identities or secret manager references for SIEM tokens.

## Evidence Storage Layout

The API reads signed bundles from:

```text
/var/lib/agentshield/evidence/*.json
```

Create bundles into that directory:

```bash
terraguard-agentshield evidence bundle \
  --session-id <session-id> \
  --audit-dir .terraguard/audit \
  --private-key .terraguard/keys/evidence-private.pem \
  --output /var/lib/agentshield/evidence/evidence-<session-id>.json
```

## Production Checklist

- API is private and authenticated.
- Evidence storage has backup and retention configured.
- Policy and evidence signing keys are managed outside containers.
- Image is pinned by digest and scanned in CI.
- Logs are shipped to SIEM.
- Readiness and liveness checks are enabled.
- NetworkPolicy or equivalent segmentation is enabled.
- Branch protection requires AgentShield evidence before merge.
