"""Exit codes of `zsbom upload`; the generated GitHub workflow keys on them."""

import json
from unittest.mock import patch

from typer.testing import CliRunner

from depclass.cli import app
from depclass.upload.models import ThresholdResult, UploadResult

runner = CliRunner()
ENV = {"ZERBERUS_LICENSE_KEY": "ZRB-test", "ZERBERUS_API_URL": "https://api.test"}
BLOCKED = ThresholdResult(
    threshold_exceeded=True,
    should_fail_build=True,
    calculated_score=60,
    max_threshold=50,
    failure_reason="CVE severity score 60 exceeds threshold 50",
)


def _flat(text):
    return " ".join(text.split())


def _upload(result, env=ENV):
    with runner.isolated_filesystem():
        with open("scan_metadata.json", "w") as f:
            json.dump({"statistics": {}}, f)
        with patch("depclass.cli.EnvironmentDetector") as detector, patch(
            "depclass.cli.UploadOrchestrator"
        ) as orchestrator:
            detector.return_value.detect_scan_files.return_value = {"sbom.json": "sbom.json"}
            orchestrator.return_value.execute_upload_workflow.return_value = result
            return runner.invoke(app, ["upload"], env=env)


def test_clean_upload_exits_0():
    assert _upload(UploadResult(success=True, report_url="https://app/x")).exit_code == 0


def test_threshold_violation_exits_1():
    result = _upload(UploadResult(success=True, report_url="https://app/x", threshold_result=BLOCKED))
    assert result.exit_code == 1


def test_upload_failure_exits_2_with_the_reason():
    result = _upload(UploadResult(success=False, error="403 Forbidden: Tool integration is not active"))
    assert result.exit_code == 2
    assert "Tool integration is not active" in _flat(result.output)


def test_upload_failure_wins_over_threshold_violation():
    result = _upload(UploadResult(success=False, error="Upload incomplete", threshold_result=BLOCKED))
    assert result.exit_code == 2
    assert "CVE severity score 60 exceeds threshold 50" in _flat(result.output)


def test_missing_license_key_exits_2():
    result = _upload(UploadResult(success=True), env={"ZERBERUS_LICENSE_KEY": "", "ZERBERUS_API_URL": "https://api.test"})
    assert result.exit_code == 2
