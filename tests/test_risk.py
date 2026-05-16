import json
from pathlib import Path

from typer.testing import CliRunner

from terraguard_agentshield.cli import app
from terraguard_agentshield.risk import (
    SemanticRiskClassifier,
    should_fail_for_risk,
)


runner = CliRunner()


def test_classifies_public_exposure_and_iam_privilege() -> None:
    diff = """diff --git a/main.tf b/main.tf
--- a/main.tf
+++ b/main.tf
@@ -1,3 +1,8 @@
+resource "aws_security_group_rule" "ssh" {
+  type = "ingress"
+  cidr_blocks = ["0.0.0.0/0"]
+}
+policy = {"Action": "*", "Resource": "*"}
"""

    summary = SemanticRiskClassifier().classify_diff(diff)
    categories = {finding.category for finding in summary.findings}

    assert summary.decision == "block"
    assert summary.max_risk == "critical"
    assert "public-exposure" in categories
    assert "privilege-expansion" in categories


def test_classifies_removed_encryption_and_logging() -> None:
    diff = """diff --git a/storage.tf b/storage.tf
--- a/storage.tf
+++ b/storage.tf
@@ -10,4 +10,2 @@
-  kms_key_id = aws_kms_key.main.arn
-  logging_enabled = true
"""

    summary = SemanticRiskClassifier().classify_diff(diff)
    categories = {finding.category for finding in summary.findings}

    assert summary.decision == "require_approval"
    assert "encryption" in categories
    assert "logging" in categories


def test_classifies_sensitive_source_changes() -> None:
    diff = """diff --git a/src/auth/token.py b/src/auth/token.py
--- a/src/auth/token.py
+++ b/src/auth/token.py
@@ -1,2 +1,3 @@
+requests.get(url, verify=False)
+digest = md5(password.encode()).hexdigest()
+auth_mode = "local"
"""

    summary = SemanticRiskClassifier().classify_diff(diff)
    categories = {finding.category for finding in summary.findings}

    assert summary.max_risk == "high"
    assert "tls" in categories
    assert "crypto" in categories
    assert "sensitive-code" in categories


def test_should_fail_for_risk_threshold() -> None:
    diff = """diff --git a/.env b/.env
--- a/.env
+++ b/.env
@@ -0,0 +1 @@
+API_TOKEN=secret
"""
    summary = SemanticRiskClassifier().classify_diff(diff)

    assert should_fail_for_risk(summary, "medium")
    assert should_fail_for_risk(summary, "high")
    assert not should_fail_for_risk(summary, "critical")


def test_risk_diff_cli_outputs_json_and_fails_on_threshold(tmp_path: Path) -> None:
    diff_path = tmp_path / "change.diff"
    output_path = tmp_path / "risk.json"
    diff_path.write_text(
        """diff --git a/main.tf b/main.tf
--- a/main.tf
+++ b/main.tf
@@ -0,0 +1 @@
+cidr_blocks = ["0.0.0.0/0"]
""",
        encoding="utf-8",
    )

    result = runner.invoke(
        app,
        [
            "risk",
            "diff",
            str(diff_path),
            "--format",
            "json",
            "--output",
            str(output_path),
            "--fail-on",
            "high",
        ],
    )

    payload = json.loads(output_path.read_text(encoding="utf-8"))
    assert result.exit_code == 1
    assert payload["decision"] == "block"
    assert payload["max_risk"] == "critical"
