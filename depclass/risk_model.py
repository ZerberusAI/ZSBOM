from dataclasses import dataclass
from typing import Any, Dict, Optional


@dataclass
class RiskModel:
    """Configurable weights for risk scoring."""

    weight_version_mismatch: int = 1
    weight_cve: int = 3
    weight_cwe: int = 1
    weight_abandonment: int = 2
    weight_typosquat: int = 2
    high_threshold: int = 6
    medium_threshold: int = 3


def load_model(data: Optional[Dict[str, Any]] = None) -> RiskModel:
    """Create a RiskModel from a configuration dictionary."""
    if not data:
        return RiskModel()

    weights = data.get("weights", {})
    kwargs = {
        "weight_version_mismatch": weights.get("version_mismatch", 1),
        "weight_cve": weights.get("cve", 3),
        "weight_cwe": weights.get("cwe", 1),
        "weight_abandonment": weights.get("abandonment", 2),
        "weight_typosquat": weights.get("typosquat", 2),
        "high_threshold": data.get("high_threshold", 6),
        "medium_threshold": data.get("medium_threshold", 3),
    }
    return RiskModel(**kwargs)
