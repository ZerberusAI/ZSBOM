import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import depclass.risk as risk
from depclass.risk_model import RiskModel
from depclass.risk_calculator import WeightedRiskCalculator


def test_compute_package_score_high():
    """Test that packages with multiple risk factors get high risk scores."""
    pkg = 'foo'
    res = risk.compute_package_score(
        package=pkg,
        installed_version='1.0',
        declared_version='0.9',
        cve_list=[{'package_name': pkg, 'vuln_id': 'CVE-1', 'cwes': ['CWE-79'], 'severity': 'HIGH'}],
        typosquatting_whitelist=[],
        repo_path=None,
        model=RiskModel()
    )
    assert res['risk'] == 'high'
    assert res['score'] <= 49  # High risk is 0-49 in new framework


def test_compute_package_score_low():
    """Test that packages with no risk factors get low risk scores."""
    pkg = 'safe_package'
    res = risk.compute_package_score(
        package=pkg,
        installed_version='1.0',
        declared_version='==1.0',  # Exact match
        cve_list=[],  # No CVEs
        typosquatting_whitelist=[pkg],  # Add to whitelist to ensure high typosquatting score
        repo_path=None,
        model=RiskModel()
    )

    assert res['risk'] == 'low'
    assert res['score'] >= 80  # Low risk is 80+ in new framework


def test_parse_declared_versions():
    """Test parsing of declared versions from different sources."""
    deps = {
        'requirements.txt': ['foo==1.2'],
        'pyproject.toml': {'bar': '2.0'}
    }
    versions = risk.parse_declared_versions(deps)
    assert versions['foo'] == '1.2'
    assert versions['bar'] == '2.0'


def test_weighted_risk_calculator():
    """Test the new WeightedRiskCalculator with framework requirements."""
    model = RiskModel()
    calculator = WeightedRiskCalculator(model)
    
    # Test framework validation
    validation_errors = calculator.validate_model()
    assert len(validation_errors) == 0, f"Model validation failed: {validation_errors}"
    
    # Test calculation
    result = calculator.calculate_score(
        package='test_package',
        installed_version='1.0.0',
        declared_version='1.0.0',
        cve_list=[],
        typosquatting_whitelist=[],
        repo_path=None,
    )
    
    # Verify output structure
    assert 'final_score' in result
    assert 'risk_level' in result
    assert 'dimension_scores' in result
    assert 'weighted_contributions' in result
    assert 'dimension_details' in result
    assert 'calculation_metadata' in result
    
    # Verify score range
    assert 0 <= result['final_score'] <= 100
    assert result['risk_level'] in ['low', 'medium', 'high']
    
    # Verify dimension scores
    for dimension, score in result['dimension_scores'].items():
        assert 0 <= score <= 10, f"Dimension {dimension} score {score} out of range"
    
    # Verify weighted contributions sum to final score
    total_weighted = sum(result['weighted_contributions'].values())
    assert abs(total_weighted - result['final_score']) < 0.1  # Allow small floating point errors


def test_risk_model_weights():
    """Test that RiskModel weights sum to 100%."""
    model = RiskModel()
    weights = model.get_weights_dict()
    total_weight = sum(weights.values())
    assert abs(total_weight - 100.0) < 0.01, f"Weights sum to {total_weight}, not 100%"


def test_risk_thresholds():
    """Test risk threshold classification."""
    model = RiskModel()
    calculator = WeightedRiskCalculator(model)
    
    # Test high risk (0-49)
    assert calculator._determine_risk_level(0) == 'high'
    assert calculator._determine_risk_level(49) == 'high'
    
    # Test medium risk (50-79)
    assert calculator._determine_risk_level(50) == 'medium'
    assert calculator._determine_risk_level(79) == 'medium'
    
    # Test low risk (80-100)
    assert calculator._determine_risk_level(80) == 'low'
    assert calculator._determine_risk_level(100) == 'low'
