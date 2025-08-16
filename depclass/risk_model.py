from dataclasses import dataclass
from typing import Any, Dict, Optional

from .models import RiskDimension


@dataclass
class RiskModel:
    """Configurable weights and thresholds for ZSBOM Risk Scoring Framework v1.0."""

    # Percentage weights (must total 100%)
    weight_declared_vs_installed: float = 15.0  # Version mismatch between declared and installed
    weight_known_cves: float = 30.0            # CVEs mapped from OSV.dev/NVD feeds
    weight_cwe_coverage: float = 20.0          # Mapped CWEs and their severity classifications
    weight_package_abandonment: float = 20.0   # Commit activity, release frequency, last commit timing
    weight_typosquat_heuristics: float = 15.0  # Fuzzy matching and typo-detection
    
    # Risk thresholds (0-100 scale)
    low_risk_threshold: float = 80.0    # 80-100 = Low Risk
    medium_risk_threshold: float = 50.0 # 50-79 = Medium Risk (0-49 = High Risk)

    def get_weights_dict(self) -> Dict[RiskDimension, float]:
        """Get weights keyed by RiskDimension."""
        return {
            RiskDimension.DECLARED_VS_INSTALLED: self.weight_declared_vs_installed,
            RiskDimension.KNOWN_CVES: self.weight_known_cves,
            RiskDimension.CWE_COVERAGE: self.weight_cwe_coverage,
            RiskDimension.PACKAGE_ABANDONMENT: self.weight_package_abandonment,
            RiskDimension.TYPOSQUAT_HEURISTICS: self.weight_typosquat_heuristics,
        }

    def get_thresholds_dict(self) -> Dict[str, float]:
        """Get thresholds as a dictionary for easy access."""
        return {
            "low_risk_threshold": self.low_risk_threshold,
            "medium_risk_threshold": self.medium_risk_threshold,
        }

    def validate_weights(self) -> bool:
        """Validate that weights sum to 100%."""
        total_weight = sum(self.get_weights_dict().values())
        return abs(total_weight - 100.0) < 0.01  # Allow small floating point errors


def load_model(data: Optional[Dict[str, Any]] = None) -> RiskModel:
    """Create a RiskModel from a configuration dictionary."""
    if not data:
        return RiskModel()

    weights = data.get("weights", {})
    thresholds = data.get("risk_thresholds", {})
    
    kwargs = {
        "weight_declared_vs_installed": weights.get("declared_vs_installed", 15.0),
        "weight_known_cves": weights.get("known_cves", 30.0),
        "weight_cwe_coverage": weights.get("cwe_coverage", 20.0),
        "weight_package_abandonment": weights.get("package_abandonment", 20.0),
        "weight_typosquat_heuristics": weights.get("typosquat_heuristics", 15.0),
        "low_risk_threshold": thresholds.get("low_risk_threshold", 80.0),
        "medium_risk_threshold": thresholds.get("medium_risk_threshold", 50.0),
    }
    return RiskModel(**kwargs)
