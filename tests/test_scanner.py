"""Risk scoring is off by default; it can still be turned back on."""

import json
from unittest.mock import patch

import pytest
import yaml

from depclass.scanner import ScannerService

EXTRACTED = {
    "dependencies": {},
    "dependencies_analysis": {
        "resolution_details": {"python": {"requests": "2.31.0"}},
        "dependency_tree": {"python": {"requests==2.31.0": {"type": "direct"}}},
    },
}


@pytest.fixture
def scan(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)

    def run(config=None):
        if config is not None:
            (tmp_path / "zsbom.config.yaml").write_text(yaml.safe_dump(config))
        with patch("depclass.scanner.extract", return_value=EXTRACTED), patch.object(
            ScannerService, "_enhance_dependencies", return_value={"enhanced_data": {}, "enhancement_metadata": {}}
        ), patch("depclass.scanner.validate", return_value={"ecosystems": {}}), patch(
            "depclass.scanner.generate"
        ), patch("depclass.scanner.score_packages", return_value=[]) as score:
            exit_code, _ = ScannerService().execute_scan()
        return exit_code, score

    return run


def test_risk_assessment_is_off_by_default(scan, tmp_path, capsys):
    exit_code, score = scan()

    assert exit_code == 0
    score.assert_not_called()
    assert json.loads((tmp_path / "risk_report.json").read_text()) == []
    metadata = json.loads((tmp_path / "scan_metadata.json").read_text())
    assert metadata["statistics"]["risk_assessment_enabled"] is False
    assert "Risk assessment completed" not in capsys.readouterr().out


def test_risk_assessment_can_be_turned_back_on(scan, tmp_path):
    exit_code, score = scan({"risk_assessment": {"enabled": True}})

    assert exit_code == 0
    score.assert_called_once()
    metadata = json.loads((tmp_path / "scan_metadata.json").read_text())
    assert metadata["statistics"]["risk_assessment_enabled"] is True


@pytest.mark.parametrize("value", [False, None])
def test_risk_setting_written_as_false_or_left_empty_does_not_crash_the_scan(scan, tmp_path, value):
    exit_code, score = scan({"risk_assessment": value})

    assert exit_code == 0
    score.assert_not_called()
    assert json.loads((tmp_path / "risk_report.json").read_text()) == []
