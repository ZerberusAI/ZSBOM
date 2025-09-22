"""Tests for enhanced risk scoring with declared vs installed analysis."""

import pytest
from unittest.mock import patch, MagicMock

from depclass.risk import (
    parse_package_specifications,
    get_primary_declared_version,
    score_packages
)
from depclass.risk_model import RiskModel


class TestPackageSpecificationParsing:
    """Test package specification parsing functions."""

    def test_parse_package_specifications(self):
        """Test parsing of package specifications from dependency files."""
        dependencies = {
            "pyproject.toml": {
                "requests": ">=2.28.0,<3.0.0",
                "numpy": "^1.21.0"
            },
            "requirements.txt": {
                "requests": "==2.28.1",
                "flask": ">=2.0.0"
            },
            "runtime": {
                "requests": "2.28.1",
                "numpy": "1.21.5",
                "flask": "2.2.0"
            }
        }
        
        specs = parse_package_specifications(dependencies)
        
        # Should exclude runtime packages
        assert "runtime" not in specs
        assert "pyproject.toml" in specs
        assert "requirements.txt" in specs
        
        # Should preserve original specifications
        assert specs["pyproject.toml"]["requests"] == ">=2.28.0,<3.0.0"
        assert specs["requirements.txt"]["requests"] == "==2.28.1"

    def test_get_primary_declared_version(self):
        """Test getting primary declared version based on file priority."""
        package_specs = {
            "requirements.txt": {"requests": "==2.25.0"},
            "pyproject.toml": {"requests": ">=2.28.0,<3.0.0"},
            "setup.py": {"requests": ">=2.20.0"}
        }
        
        # pyproject.toml has highest priority
        primary = get_primary_declared_version("requests", package_specs)
        assert primary == ">=2.28.0,<3.0.0"
        
        # Package not found
        primary = get_primary_declared_version("nonexistent", package_specs)
        assert primary is None
        
        # Only in lower priority file
        package_specs_limited = {
            "requirements.txt": {"flask": ">=2.0.0"}
        }
        primary = get_primary_declared_version("flask", package_specs_limited)
        assert primary == ">=2.0.0"

    def test_parse_package_specifications_empty_files(self):
        """Test parsing with empty or missing files."""
        dependencies = {
            "pyproject.toml": {},
            "requirements.txt": {"requests": ">=2.28.0"},
            "runtime": {"requests": "2.28.1"}
        }
        
        specs = parse_package_specifications(dependencies)
        
        assert "pyproject.toml" not in specs  # Empty file should be excluded
        assert "requirements.txt" in specs
        assert "runtime" not in specs


class TestEnhancedRiskScoring:
    """Test enhanced risk scoring with full dependency analysis."""

    @patch('depclass.risk._package_cve_issues')
    def test_score_packages_basic(self, mock_cve_issues):
        """Test basic enhanced scoring functionality."""
        # Setup mocks
        mock_cve_issues.return_value = []
        
        # Test data
        validation_results = {
            "cve_issues": [],
            "typosquatting_whitelist": []
        }
        
        dependencies = {
            "pyproject.toml": {
                "requests": ">=2.28.0,<3.0.0",
                "numpy": "^1.21.0"
            },
            "requirements.txt": {
                "requests": "==2.28.1"
            },
            "runtime": {
                "requests": "2.28.1",
                "numpy": "1.21.5"
            }
        }

        transitive_analysis = {
            "resolution_details": {
                "python": {
                    "requests": "2.28.1",
                    "numpy": "1.21.5"
                }
            },
            "dependency_tree": {
                "python": {
                    "requests==2.28.1": {"type": "direct"},
                    "numpy==1.21.5": {"type": "direct"}
                }
            }
        }

        model = RiskModel()
        scores = score_packages(validation_results, dependencies, transitive_analysis, model)
        
        # Should return scores for processed packages
        assert len(scores) == 1
        
        # Find the package score (only one returned)
        package_score = scores[0]

        # Verify basic structure
        assert "final_score" in package_score
        assert "risk_level" in package_score
        assert "dimension_details" in package_score
        assert "declared_vs_installed" in package_score["dimension_details"]

    @patch('depclass.risk._package_cve_issues')
    def test_score_packages_with_conflicts(self, mock_cve_issues):
        """Test enhanced scoring with cross-file conflicts."""
        # Setup mocks
        mock_cve_issues.return_value = []
        
        validation_results = {
            "cve_issues": [],
            "typosquatting_whitelist": []
        }
        
        # Create conflicting specifications
        dependencies = {
            "pyproject.toml": {
                "requests": ">=1.0.0,<2.0.0"  # Incompatible with installed version
            },
            "requirements.txt": {
                "requests": ">=3.0.0,<4.0.0"  # Also incompatible, and conflicts with pyproject.toml
            },
            "runtime": {
                "requests": "2.28.1"  # This version satisfies neither spec
            }
        }
        
        transitive_analysis = {
            "resolution_details": {
                "requests": "2.28.1"
            }
        }
        
        model = RiskModel()
        scores = score_packages(validation_results, dependencies, transitive_analysis, model)
        
        # Should still process the package
        assert len(scores) == 1
        requests_score = scores[0]
        
        # Check declared vs installed details
        dvi_details = requests_score["dimension_details"]["declared_vs_installed"]
        
        # Should have low score due to conflicts and range violations
        assert dvi_details["score"] < 5.0
        assert dvi_details["details"]["consistency_status"] == "major_conflicts"

    @patch('depclass.risk._package_cve_issues')
    def test_score_packages_with_cves(self, mock_cve_issues):
        """Test enhanced scoring with CVE data."""
        # Setup mocks
        
        # Mock CVE data
        def cve_side_effect(package, cve_list):
            if package == "requests":
                return [{
                    "package_name": "requests",
                    "vuln_id": "CVE-2023-1234",
                    "severity": "HIGH",
                    "cvss_score": 8.5
                }]
            return []
        
        mock_cve_issues.side_effect = cve_side_effect
        
        validation_results = {
            "cve_issues": [{
                "package_name": "requests",
                "vuln_id": "CVE-2023-1234",
                "severity": "HIGH",
                "cvss_score": 8.5
            }],
            "typosquatting_whitelist": []
        }
        
        dependencies = {
            "pyproject.toml": {
                "requests": ">=2.28.0,<3.0.0"
            },
            "runtime": {
                "requests": "2.28.1"
            }
        }
        
        transitive_analysis = {
            "resolution_details": {
                "requests": "2.28.1"
            }
        }
        
        model = RiskModel()
        scores = score_packages(validation_results, dependencies, transitive_analysis, model)
        
        requests_score = scores[0]
        
        # Should have CVE information
        cve_details = requests_score["dimension_details"]["known_cves"]
        assert cve_details["cve_count"] > 0
        assert any(cve["vuln_id"] == "CVE-2023-1234" for cve in cve_details["cves"])

    def test_score_packages_no_declared_versions(self):
        """Test enhanced scoring when no declared versions are found."""
        validation_results = {
            "cve_issues": [],
            "typosquatting_whitelist": []
        }
        
        # Only runtime packages, no declared versions
        dependencies = {
            "runtime": {
                "requests": "2.28.1",
                "numpy": "1.21.5"
            }
        }
        
        transitive_analysis = {
            "resolution_details": {
                "requests": "2.28.1",
                "numpy": "1.21.5"
            }
        }
        
        model = RiskModel()
        
        with patch('depclass.risk._package_cve_issues', return_value=[]):
            
            scores = score_packages(validation_results, dependencies, transitive_analysis, model)
            
            # Should process all packages
            assert len(scores) == 2
            
            # Check declared vs installed scoring
            for score in scores:
                dvi_details = score["dimension_details"]["declared_vs_installed"]
                # Should have low precision score due to no declared versions
                assert dvi_details["factors"]["version_match_precision"] == 0.0
                assert dvi_details["factors"]["specification_completeness"] == 0.0
                # But should have consistent cross-file score
                assert dvi_details["factors"]["cross_file_consistency"] == 3.0

    def test_score_packages_with_model_configuration(self):
        """Test enhanced scoring with custom risk model configuration."""
        validation_results = {
            "cve_issues": [],
            "typosquatting_whitelist": []
        }
        
        dependencies = {
            "pyproject.toml": {
                "requests": ">=2.28.0,<3.0.0"
            },
            "runtime": {
                "requests": "2.28.1"
            }
        }
        
        transitive_analysis = {
            "resolution_details": {
                "requests": "2.28.1"
            }
        }
        
        # Custom model with different weights
        model = RiskModel(
            weight_declared_vs_installed=25.0,  # Increased weight
            weight_known_cves=25.0,
            weight_cwe_coverage=20.0,
            weight_package_abandonment=15.0,
            weight_typosquat_heuristics=15.0,
            low_risk_threshold=85.0,
            medium_risk_threshold=60.0
        )
        
        with patch('depclass.risk._package_cve_issues', return_value=[]):
            
            scores = score_packages(validation_results, dependencies, transitive_analysis, model)
            
            requests_score = scores[0]
            
            # Should use custom weights
            metadata = requests_score["calculation_metadata"]
            assert metadata["weights_used"]["declared_vs_installed"] == 25.0
            assert metadata["thresholds_used"]["low_risk_threshold"] == 85.0


class TestRiskScoringIntegration:
    """Test integration between various components."""

    def test_end_to_end_scoring_pipeline(self):
        """Test complete scoring pipeline from dependency extraction to risk calculation."""
        # This would be an integration test that creates temporary files
        # and runs the complete pipeline
        pass  # Implementation would require more complex setup

