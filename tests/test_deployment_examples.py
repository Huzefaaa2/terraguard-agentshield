from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_dockerfile_runs_as_non_root_with_healthcheck() -> None:
    dockerfile = (ROOT / "Dockerfile").read_text(encoding="utf-8")

    assert "USER 10001:10001" in dockerfile
    assert "HEALTHCHECK" in dockerfile
    assert "TERRAGUARD_AGENTSHIELD_DATA_DIR=/var/lib/agentshield" in dockerfile
    assert "--host\", \"0.0.0.0\"" in dockerfile


def test_compose_example_has_container_hardening() -> None:
    compose = (
        ROOT / "examples/deployment/docker-compose.yml"
    ).read_text(encoding="utf-8")

    assert "read_only: true" in compose
    assert "no-new-privileges:true" in compose
    assert "cap_drop:" in compose
    assert "- ALL" in compose
    assert "tmpfs:" in compose
    assert "healthcheck:" in compose


def test_kubernetes_example_has_pod_security_and_network_policy() -> None:
    manifest = (
        ROOT / "examples/deployment/kubernetes/agentshield-api.yaml"
    ).read_text(encoding="utf-8")

    assert "kind: NetworkPolicy" in manifest
    assert "runAsNonRoot: true" in manifest
    assert "readOnlyRootFilesystem: true" in manifest
    assert "allowPrivilegeEscalation: false" in manifest
    assert "automountServiceAccountToken: false" in manifest
    assert "- terraguard-agentshield" in manifest
    assert "livenessProbe:" in manifest
    assert "readinessProbe:" in manifest


def test_deployment_docs_link_to_examples() -> None:
    docs = (ROOT / "docs/deployment-hardening.md").read_text(encoding="utf-8")

    assert "examples/deployment" in docs
    assert "examples/siem/" in docs
    assert "Production Checklist" in docs
