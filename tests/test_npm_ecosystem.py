import json
import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from depclass.extract import extract_dependencies
from depclass.ecosystems.npm.normalise import normalise_name
from depclass.risk_calculator import WeightedRiskCalculator
from depclass.sbom import generate_sbom


def test_normalise_name():
    assert normalise_name("Left_Pad") == "left-pad"


def test_extract_dependencies_npm(tmp_path):
    data = {
        "name": "demo",
        "version": "1.0.0",
        "dependencies": {"Left-Pad": "^1.0.0"},
    }
    (tmp_path / "package.json").write_text(json.dumps(data))
    packages, meta = extract_dependencies(tmp_path, ecosystem="npm")
    assert packages == {"left-pad": "^1.0.0"}
    assert meta["ecosystem"] == "npm"
    assert meta["graph_partial"] == {"Left-Pad": "^1.0.0"}


def test_risk_calculator_registers_npm_scorers():
    calc = WeightedRiskCalculator()
    for key in [
        "npm_typosquat",
        "npm_dep_confusion",
        "npm_hygiene",
        "npm_lock_discipline",
        "npm_abandonment",
    ]:
        assert key in calc.scorers


def test_generate_sbom_npm(tmp_path):
    deps = {"left-pad": "1.0.0"}
    cve_data = {"cve_issues": []}
    config = {"output": {"sbom_file": str(tmp_path / "sbom.json")}, "ecosystem": "npm"}
    generate_sbom(deps, cve_data, config)
    content = (tmp_path / "sbom.json").read_text()
    assert "pkg:npm/left-pad@1.0.0" in content
