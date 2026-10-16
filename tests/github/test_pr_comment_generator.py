"""The PR comment ZSBOM posts: CVE severity only, no risk while risk is off."""

import json

import pytest

from depclass.github.pr_comment_generator import PRCommentGenerator
from depclass.upload.models import ThresholdResult

HIGH_RISK = [{"package": "leftpad", "ecosystem": "npm", "risk_level": "high", "final_score": 20.0}]
CVES = {
    "total_packages": 42,
    "ecosystems": {
        "npm": {
            "cve_issues": [
                {"severity": "CRITICAL", "package_name": "a", "id": "CVE-1"},
                {"severity": "CRITICAL", "package_name": "b", "id": "CVE-2"},
                {"severity": "HIGH", "package_name": "c", "id": "CVE-3"},
            ]
        }
    },
}
CONFIG = {
    "enabled": True,
    "high_severity_weight": 5,
    "medium_severity_weight": 3,
    "low_severity_weight": 1,
    "max_score_threshold": 50,
    "fail_on_critical": True,
}


@pytest.fixture
def reports(tmp_path):
    def write(validation=CVES, risk=()):
        validation_path = tmp_path / "validation_report.json"
        risk_path = tmp_path / "risk_report.json"
        validation_path.write_text(json.dumps(validation))
        risk_path.write_text(json.dumps(list(risk)))
        return str(validation_path), str(risk_path)

    return write


def _comment(paths, statistics=None, threshold_result=None, threshold_config=None):
    return PRCommentGenerator(
        validation_report_path=paths[0],
        risk_report_path=paths[1],
        scan_metadata={"statistics": statistics or {}},
        threshold_result=threshold_result,
        report_url="https://app.zerberus.ai/trace-ai/dashboard",
        threshold_config=threshold_config,
    ).generate()


def test_risk_table_hidden_when_risk_assessment_is_off(reports):
    comment = _comment(reports(risk=HIGH_RISK), statistics={"risk_assessment_enabled": False})
    assert "High-Risk Packages" not in comment


def test_risk_table_still_shown_for_older_scans(reports):
    comment = _comment(reports(risk=HIGH_RISK))
    assert "High-Risk Packages" in comment


def test_total_packages_come_from_the_validation_report(reports):
    comment = _comment(reports(), statistics={"risk_assessment_enabled": False})
    assert "**Total Packages**: 42 analyzed" in comment


def test_critical_only_block_names_the_criticals(reports):
    result = ThresholdResult(
        threshold_exceeded=False,
        should_fail_build=True,
        calculated_score=10,
        max_threshold=50,
        failure_reason="Critical vulnerabilities found: 2",
        critical_vulnerabilities_found=True,
        critical_count=2,
    )
    comment = _comment(reports(), threshold_result=result, threshold_config=CONFIG)
    assert "**Build Status: :x: BLOCKED** - 2 critical CVE(s) found" in comment
    assert "-40" not in comment


def test_score_block_uses_cve_wording_and_shows_the_settings(reports):
    result = ThresholdResult(
        threshold_exceeded=True,
        should_fail_build=True,
        calculated_score=60,
        max_threshold=50,
        failure_reason="CVE severity score 60 exceeds threshold 50",
    )
    comment = _comment(reports(), threshold_result=result, threshold_config=CONFIG)
    assert "CVE severity score 60 exceeds threshold 50" in comment
    assert "| Max Score Threshold | 50 |" in comment
    assert "Exceeded By" not in comment


def test_failed_upload_is_not_reported_as_passed(reports):
    reason = "422 error from ack: Upload incomplete: missing required file(s): dependencies.json"
    comment = PRCommentGenerator(
        validation_report_path=reports(validation={"total_packages": 3, "ecosystems": {}})[0],
        risk_report_path="missing-risk-report.json",
        scan_metadata={"statistics": {"risk_assessment_enabled": False}},
        threshold_result=None,
        report_url="https://app.zerberus.ai/trace-ai/dashboard",
        upload_error=reason,
    ).generate()

    assert "PASSED" not in comment
    assert f"**Build Status: :x: UPLOAD FAILED** - {reason}" in comment
    assert "**Scan Status**: :x: Failed" in comment
