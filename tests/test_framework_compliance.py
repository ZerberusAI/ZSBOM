"""Comprehensive framework compliance validation tests."""

import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import pytest
from depclass.risk_calculator import WeightedRiskCalculator
from depclass.risk_model import RiskModel


class TestFrameworkCompliance:
    """Test compliance with ZSBOM Risk Scoring Framework v1.0."""

    def test_framework_calculation_example(self):
        """Test the exact calculation example from framework requirements."""
        model = RiskModel()
        calculator = WeightedRiskCalculator(model)
        
        # Simulate the framework example scores
        dimension_scores = {
            'declared_vs_installed': 8.0,
            'known_cves': 10.0,
            'cwe_coverage': 10.0,
            'package_abandonment': 2.0,
            'typosquat_heuristics': 10.0
        }
        
        # Test individual weighted contributions
        weighted_contributions = calculator._apply_weights(dimension_scores)
        
        # Framework expected values
        expected_contributions = {
            'declared_vs_installed': 12.0,  # 8 × 15% × 10
            'known_cves': 30.0,            # 10 × 30% × 10
            'cwe_coverage': 20.0,          # 10 × 20% × 10
            'package_abandonment': 4.0,    # 2 × 20% × 10
            'typosquat_heuristics': 15.0   # 10 × 15% × 10
        }
        
        for dimension, expected in expected_contributions.items():
            assert weighted_contributions[dimension] == expected, f"Expected {expected} for {dimension}, got {weighted_contributions[dimension]}"
        
        # Test total score
        total_score = sum(weighted_contributions.values())
        assert total_score == 81.0, f"Expected total score 81.0, got {total_score}"

    def test_risk_band_classifications(self):
        """Test risk band classifications match framework exactly."""
        model = RiskModel()
        calculator = WeightedRiskCalculator(model)
        
        # Test boundary conditions
        test_cases = [
            (100.0, "low"),    # Perfect score
            (80.0, "low"),     # Low risk threshold
            (79.9, "medium"),  # Just below low threshold
            (50.0, "medium"),  # Medium risk threshold
            (49.9, "high"),    # Just below medium threshold
            (0.0, "high"),     # Worst score
        ]
        
        for score, expected_risk in test_cases:
            risk_level = calculator._determine_risk_level(score)
            assert risk_level == expected_risk, f"Score {score} should be {expected_risk}, got {risk_level}"

    def test_weight_percentages_sum_to_100(self):
        """Test that all dimension weights sum to exactly 100%."""
        model = RiskModel()
        weights = model.get_weights_dict()
        
        total_weight = sum(weights.values())
        assert abs(total_weight - 100.0) < 0.01, f"Weights must sum to 100%, got {total_weight}%"

    def test_dimension_score_ranges(self):
        """Test that all dimension scores are in 0-10 range."""
        model = RiskModel()
        calculator = WeightedRiskCalculator(model)
        
        # Test with various package scenarios
        test_scenarios = [
            # Clean package
            {
                'package': 'clean_package',
                'installed_version': '1.0.0',
                'declared_version': '1.0.0',
                'cve_list': [],
                'typosquat_blacklist': [],
                'repo_path': None
            },
            # Risky package
            {
                'package': 'risky_package',
                'installed_version': '1.0.0',
                'declared_version': '2.0.0',
                'cve_list': [{'package_name': 'risky_package', 'vuln_id': 'CVE-2023-1234', 'severity': 'CRITICAL'}],
                'typosquat_blacklist': ['risky_package'],
                'repo_path': None
            }
        ]
        
        for scenario in test_scenarios:
            result = calculator.calculate_score(**scenario)
            
            # Check final score range
            assert 0.0 <= result['final_score'] <= 100.0, f"Final score {result['final_score']} outside 0-100 range"
            
            # Check dimension scores
            for dimension, score in result['dimension_scores'].items():
                assert 0.0 <= score <= 10.0, f"Dimension {dimension} score {score} outside 0-10 range"

    def test_package_abandonment_scoring_breakdown(self):
        """Test package abandonment scoring follows framework 5+3+2 breakdown."""
        model = RiskModel()
        calculator = WeightedRiskCalculator(model)
        
        result = calculator.calculate_score(
            package='test_package',
            installed_version='1.0.0',
            declared_version='1.0.0',
            cve_list=[],
            typosquat_blacklist=[],
            repo_path=None
        )
        
        abandonment_details = result['dimension_details']['package_abandonment']
        components = abandonment_details['components']
        
        # Check component max scores
        assert components['last_commit']['max_score'] == 5, "Last commit should have max 5 points"
        assert components['commit_frequency']['max_score'] == 3, "Commit frequency should have max 3 points"
        assert components['release_frequency']['max_score'] == 2, "Release frequency should have max 2 points"
        
        # Check total doesn't exceed 10
        total_component_score = (
            components['last_commit']['score'] +
            components['commit_frequency']['score'] +
            components['release_frequency']['score']
        )
        assert total_component_score <= 10.0, f"Total component score {total_component_score} exceeds 10"

    def test_output_format_compliance(self):
        """Test output format matches framework requirements."""
        model = RiskModel()
        calculator = WeightedRiskCalculator(model)
        
        result = calculator.calculate_score(
            package='test_package',
            installed_version='1.2.3',
            declared_version='1.2.3',
            cve_list=[],
            typosquat_blacklist=[],
            repo_path=None
        )
        
        # Check required fields
        required_fields = [
            'package', 'installed_version', 'declared_version',
            'final_score', 'risk_level', 'dimension_scores',
            'weighted_contributions', 'dimension_details', 'calculation_metadata'
        ]
        
        for field in required_fields:
            assert field in result, f"Missing required field: {field}"
        
        # Check dimension_scores structure
        expected_dimensions = {
            'declared_vs_installed', 'known_cves', 'cwe_coverage',
            'package_abandonment', 'typosquat_heuristics'
        }
        assert set(result['dimension_scores'].keys()) == expected_dimensions
        
        # Check weighted_contributions structure
        assert set(result['weighted_contributions'].keys()) == expected_dimensions
        
        # Check calculation_metadata
        metadata = result['calculation_metadata']
        assert 'weights_used' in metadata
        assert 'thresholds_used' in metadata
        assert 'framework_version' in metadata
        assert metadata['framework_version'] == "1.0"

    def test_edge_cases_and_error_handling(self):
        """Test edge cases and error handling."""
        model = RiskModel()
        calculator = WeightedRiskCalculator(model)
        
        # Test with missing data
        result = calculator.calculate_score(
            package='',  # Empty package name
            installed_version='1.0.0',
            declared_version=None,  # No declared version
            cve_list=None,  # No CVE list
            typosquat_blacklist=None,  # No typosquat blacklist
            repo_path=None  # No repo path
        )
        
        # Should still produce valid result
        assert 'final_score' in result
        assert 'risk_level' in result
        assert result['risk_level'] in ['low', 'medium', 'high']
        
        # Test with invalid version format
        result = calculator.calculate_score(
            package='test_package',
            installed_version='invalid_version',
            declared_version='also_invalid',
            cve_list=[],
            typosquat_blacklist=[],
            repo_path=None
        )
        
        # Should handle gracefully
        assert 'final_score' in result
        assert 0.0 <= result['final_score'] <= 100.0

    def test_weight_validation(self):
        """Test weight validation functionality."""
        model = RiskModel()
        calculator = WeightedRiskCalculator(model)
        
        # Test valid model
        errors = calculator.validate_model()
        assert len(errors) == 0, f"Valid model should have no errors, got: {errors}"
        
        # Test invalid model (weights don't sum to 100)
        invalid_model = RiskModel(
            weight_declared_vs_installed=10.0,
            weight_known_cves=20.0,
            weight_cwe_coverage=30.0,
            weight_package_abandonment=25.0,
            weight_typosquat_heuristics=20.0  # Total = 105%
        )
        
        invalid_calculator = WeightedRiskCalculator(invalid_model)
        errors = invalid_calculator.validate_model()
        assert len(errors) > 0, "Invalid model should have validation errors"
        assert any("must sum to 100%" in error for error in errors)

    def test_framework_info(self):
        """Test framework information matches documentation."""
        model = RiskModel()
        calculator = WeightedRiskCalculator(model)
        
        info = calculator.get_framework_info()
        
        # Check framework version
        assert info['framework_version'] == "1.0"
        
        # Check score ranges
        assert info['score_range'] == "0-100"
        assert info['dimension_score_range'] == "0-10"
        
        # Check risk levels
        assert set(info['risk_levels']) == {'low', 'medium', 'high'}
        
        # Check thresholds
        thresholds = info['risk_thresholds']
        assert "80" in thresholds['low']
        assert "50" in thresholds['medium']
        assert "0" in thresholds['high']
        
        # Check weights
        weights = info['weights']
        assert abs(sum(weights.values()) - 100.0) < 0.01