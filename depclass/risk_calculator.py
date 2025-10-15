"""Weighted Risk Calculator for ZSBOM risk assessment."""

from typing import Any, Dict, List, Optional, Type

from .dimension_scorers import (
    DeclaredVsInstalledScorer,
    KnownCVEsScorer,
    CWECoverageScorer,
    PackageAbandonmentScorer,
    TyposquatHeuristicsScorer,
    DimensionScorer,
)
from .models import PackageRef, RiskDimension
from .risk_model import RiskModel

# Pluggable scorer registry
SCORER_REGISTRY: Dict[RiskDimension, Type[DimensionScorer]] = {}


def register_scorer(dimension: RiskDimension, scorer_cls: Type[DimensionScorer]) -> None:
    """Register a scorer implementation for a risk dimension."""
    SCORER_REGISTRY[dimension] = scorer_cls


# Register default scorers
register_scorer(RiskDimension.DECLARED_VS_INSTALLED, DeclaredVsInstalledScorer)
register_scorer(RiskDimension.KNOWN_CVES, KnownCVEsScorer)
register_scorer(RiskDimension.CWE_COVERAGE, CWECoverageScorer)
register_scorer(RiskDimension.PACKAGE_ABANDONMENT, PackageAbandonmentScorer)
register_scorer(RiskDimension.TYPOSQUAT_HEURISTICS, TyposquatHeuristicsScorer)


class WeightedRiskCalculator:
    """Calculates weighted risk scores using the ZSBOM Risk Scoring Framework v1.0."""

    def __init__(
        self,
        model: Optional[RiskModel] = None,
        scorer_registry: Optional[Dict[RiskDimension, Type[DimensionScorer]]] = None,
    ):
        self.model = model or RiskModel()
        registry = scorer_registry or SCORER_REGISTRY
        self.scorers = {dim: cls() for dim, cls in registry.items()}

    def calculate_score(
        self,
        package: PackageRef | str,
        installed_version: str | None = None,
        declared_version: Optional[str] = None,
        cve_list: Optional[List[Dict[str, Any]]] = None,
        typosquatting_whitelist: Optional[List[str]] = None,
        ecosystem: str = "python",
        **kwargs: Any,
    ) -> Dict[str, Any]:
        """Calculate comprehensive risk score for a package."""
        if isinstance(package, PackageRef):
            pkg = package
        else:
            pkg = PackageRef(name=package, installed_version=installed_version or "", declared_version=declared_version)

        dimension_scores: Dict[RiskDimension, float] = {}
        dimension_details: Dict[RiskDimension, Dict[str, Any]] = {}

        # Add ecosystem to kwargs for all scorers
        kwargs['ecosystem'] = ecosystem

        for dim, scorer in self.scorers.items():
            dimension_scores[dim] = scorer.score(
                pkg.name,
                pkg.installed_version,
                pkg.declared_version,
                cve_list=cve_list,
                typosquatting_whitelist=typosquatting_whitelist,
                **kwargs,
            )
            dimension_details[dim] = scorer.get_details(
                pkg.name,
                pkg.installed_version,
                pkg.declared_version,
                cve_list=cve_list,
                typosquatting_whitelist=typosquatting_whitelist,
                **kwargs,
            )

        weighted_contributions = self._apply_weights(dimension_scores)
        final_score = sum(weighted_contributions.values())
        risk_level = self._determine_risk_level(final_score)

        return {
            "package": pkg.name,
            "installed_version": pkg.installed_version,
            "declared_version": pkg.declared_version,
            "final_score": round(final_score, 2),
            "risk_level": risk_level,
            "dimension_scores": {k.value: round(v, 2) for k, v in dimension_scores.items()},
            "weighted_contributions": {k.value: round(v, 2) for k, v in weighted_contributions.items()},
            "dimension_details": {k.value: v for k, v in dimension_details.items()},
            "calculation_metadata": {
                "weights_used": {k.value: v for k, v in self.model.get_weights_dict().items()},
                "thresholds_used": self.model.get_thresholds_dict(),
                "framework_version": "1.0",
            },
        }

    def _apply_weights(
        self, dimension_scores: Dict[RiskDimension, float]
    ) -> Dict[RiskDimension, float]:
        """Apply percentage weights to dimension scores."""
        weights = self.model.get_weights_dict()
        weighted_contributions: Dict[RiskDimension, float] = {}
        for dimension, score in dimension_scores.items():
            weight_percentage = weights.get(dimension, 0) / 100.0
            weighted_contribution = score * weight_percentage * 10
            weighted_contributions[dimension] = weighted_contribution
        return weighted_contributions

    def _determine_risk_level(self, final_score: float) -> str:
        if final_score >= self.model.low_risk_threshold:
            return "low"
        elif final_score >= self.model.medium_risk_threshold:
            return "medium"
        else:
            return "high"

    def validate_model(self) -> List[str]:
        errors = []
        weights = self.model.get_weights_dict()
        total_weight = sum(weights.values())
        if abs(total_weight - 100.0) > 0.01:
            errors.append(f"Weights must sum to 100%, got {total_weight}%")
        required_dimensions = set(SCORER_REGISTRY.keys())
        for dimension in required_dimensions:
            if dimension not in weights:
                errors.append(f"Missing weight for dimension: {dimension.value}")
            elif weights[dimension] < 0:
                errors.append(f"Weight for {dimension.value} cannot be negative")
        if self.model.low_risk_threshold <= self.model.medium_risk_threshold:
            errors.append("Low risk threshold must be higher than medium risk threshold")
        if self.model.medium_risk_threshold < 0 or self.model.low_risk_threshold > 100:
            errors.append("Risk thresholds must be between 0 and 100")
        return errors

    def get_framework_info(self) -> Dict[str, Any]:
        return {
            "framework_version": "1.0",
            "dimensions": [d.value for d in self.scorers.keys()],
            "score_range": "0-100",
            "dimension_score_range": "0-10",
            "risk_levels": ["low", "medium", "high"],
            "risk_thresholds": {
                "low": f"{self.model.low_risk_threshold}+",
                "medium": f"{self.model.medium_risk_threshold}-{self.model.low_risk_threshold-1}",
                "high": f"0-{self.model.medium_risk_threshold-1}",
            },
            "weights": {k.value: v for k, v in self.model.get_weights_dict().items()},
        }
