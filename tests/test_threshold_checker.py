"""The pipeline gate counts CVEs by severity; its message must say so."""

from depclass.threshold_checker import ThresholdChecker, ThresholdConfig


def test_score_breach_reason_names_the_cve_severity_score():
    report = {"ecosystems": {"python": {"cve_issues": [{"severity": "HIGH", "package_name": "p"}]}}}

    result = ThresholdChecker(ThresholdConfig(enabled=True, max_score_threshold=4)).check_thresholds(report)

    assert result.failure_reason == "CVE severity score 5 exceeds threshold 4"
