"""Which enrichment sources run, and what they add to dependencies.json."""

from unittest.mock import MagicMock, patch

from depclass.config_manager import ConfigManager
from depclass.enhancers import orchestrator as orchestrator_module
from depclass.enhancers.orchestrator import EnhancerOrchestrator

ANALYSIS = {"resolution_details": {"python": {"requests": "2.31.0"}}}


def _provider(source):
    provider = MagicMock()
    provider.stats = {"cache_hits": 0}
    provider.enhance.return_value = {"requests": {"enhanced": True, "source": source}}
    return provider


def _run(config):
    with patch.object(orchestrator_module, "DepsDevProvider", return_value=_provider("deps_dev")), patch.object(
        orchestrator_module, "OSVProvider", return_value=_provider("osv")
    ), patch.object(orchestrator_module, "GitHubProvider", return_value=_provider("github")) as github:
        result = EnhancerOrchestrator(config).enhance_dependencies(ANALYSIS)
    package = next(iter(result["enhanced_data"]["python"].values()))
    return package, github


def test_enhancement_has_no_mitre_weakness_phase():
    package, _ = _run({"risk_assessment": {"enabled": True}})

    assert package["metadata"]["source"] == "deps_dev"
    assert package["vulnerability"]["source"] == "osv"
    assert "weakness" not in package


def test_default_config_has_no_mitre_settings():
    config = ConfigManager().load_package_default_config()

    assert "enable_mitre_check" not in config["validation_rules"]
    assert "mitre_weaknesses" not in config["sources"]["cwe"]
