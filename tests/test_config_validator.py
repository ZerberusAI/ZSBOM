"""Test configuration validation."""

import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import pytest
from depclass.config_validator import ConfigValidator
from depclass.risk_model import RiskModel


class TestConfigValidator:
    """Test the ConfigValidator class."""
    
    def test_valid_config(self):
        """Test validation of a valid configuration."""
        validator = ConfigValidator()
        
        valid_config = {
            "risk_model": {
                "weights": {
                    "declared_vs_installed": 15,
                    "known_cves": 30,
                    "cwe_coverage": 20,
                    "package_abandonment": 20,
                    "typosquat_heuristics": 15,
                },
                "risk_thresholds": {
                    "low_risk_threshold": 80,
                    "medium_risk_threshold": 50,
                }
            }
        }
        
        errors = validator.validate_config(valid_config)
        assert len(errors) == 0
    
    def test_weights_not_sum_to_100(self):
        """Test validation when weights don't sum to 100%."""
        validator = ConfigValidator()
        
        invalid_config = {
            "risk_model": {
                "weights": {
                    "declared_vs_installed": 15,
                    "known_cves": 30,
                    "cwe_coverage": 20,
                    "package_abandonment": 20,
                    "typosquat_heuristics": 20,  # This makes total 105%
                },
                "risk_thresholds": {
                    "low_risk_threshold": 80,
                    "medium_risk_threshold": 50,
                }
            }
        }
        
        errors = validator.validate_config(invalid_config)
        assert len(errors) > 0
        assert any("must sum to 100%" in error for error in errors)
    
    def test_missing_dimension_weights(self):
        """Test validation when dimension weights are missing."""
        validator = ConfigValidator()
        
        invalid_config = {
            "risk_model": {
                "weights": {
                    "declared_vs_installed": 15,
                    "known_cves": 30,
                    # Missing other dimensions
                },
                "risk_thresholds": {
                    "low_risk_threshold": 80,
                    "medium_risk_threshold": 50,
                }
            }
        }
        
        errors = validator.validate_config(invalid_config)
        assert len(errors) > 0
        assert any("Missing weights for dimensions" in error for error in errors)
    
    def test_negative_weights(self):
        """Test validation with negative weights."""
        validator = ConfigValidator()
        
        invalid_config = {
            "risk_model": {
                "weights": {
                    "declared_vs_installed": -5,  # Negative weight
                    "known_cves": 30,
                    "cwe_coverage": 20,
                    "package_abandonment": 20,
                    "typosquat_heuristics": 35,  # Adjusted to sum to 100
                },
                "risk_thresholds": {
                    "low_risk_threshold": 80,
                    "medium_risk_threshold": 50,
                }
            }
        }
        
        errors = validator.validate_config(invalid_config)
        assert len(errors) > 0
        assert any("cannot be negative" in error for error in errors)
    
    def test_invalid_threshold_ordering(self):
        """Test validation with invalid threshold ordering."""
        validator = ConfigValidator()
        
        invalid_config = {
            "risk_model": {
                "weights": {
                    "declared_vs_installed": 15,
                    "known_cves": 30,
                    "cwe_coverage": 20,
                    "package_abandonment": 20,
                    "typosquat_heuristics": 15,
                },
                "risk_thresholds": {
                    "low_risk_threshold": 50,    # Should be higher than medium
                    "medium_risk_threshold": 80,  # Should be lower than low
                }
            }
        }
        
        errors = validator.validate_config(invalid_config)
        assert len(errors) > 0
        assert any("must be higher than medium risk threshold" in error for error in errors)
    
    def test_missing_risk_model_section(self):
        """Test validation with missing risk_model section."""
        validator = ConfigValidator()
        
        invalid_config = {
            "validation_rules": {
                "enable_cve_check": True
            }
            # Missing risk_model section
        }
        
        errors = validator.validate_config(invalid_config)
        assert len(errors) > 0
        assert any("Missing 'risk_model' section" in error for error in errors)
    
    def test_validate_risk_model_instance(self):
        """Test validation of a RiskModel instance."""
        validator = ConfigValidator()
        
        # Test valid model
        valid_model = RiskModel()
        errors = validator.validate_risk_model(valid_model)
        assert len(errors) == 0
        
        # Test invalid model
        invalid_model = RiskModel(
            weight_declared_vs_installed=15,
            weight_known_cves=30,
            weight_cwe_coverage=20,
            weight_package_abandonment=20,
            weight_typosquat_heuristics=20,  # This makes total 105%
        )
        errors = validator.validate_risk_model(invalid_model)
        assert len(errors) > 0
        assert any("must sum to 100%" in error for error in errors)
    
    def test_suggest_fixes(self):
        """Test fix suggestions for common errors."""
        validator = ConfigValidator()
        
        errors = [
            "Weights must sum to 100%, got 105%",
            "Missing weights for dimensions: package_abandonment",
            "Low risk threshold (50) must be higher than medium risk threshold (80)",
        ]
        
        suggestions = validator.suggest_fixes(errors)
        assert len(suggestions) == 3
        assert any("total exactly 100%" in suggestion for suggestion in suggestions)
        assert any("Add missing dimension weights" in suggestion for suggestion in suggestions)
        assert any("low_risk_threshold" in suggestion for suggestion in suggestions)