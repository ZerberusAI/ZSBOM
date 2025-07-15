"""Weighted Risk Calculator for ZSBOM risk assessment."""

from typing import Any, Dict, List, Optional

from .dimension_scorers import (
    DeclaredVsInstalledScorer,
    KnownCVEsScorer,
    CWECoverageScorer,
    PackageAbandonmentScorer,
    TyposquatHeuristicsScorer,
)
from .risk_model import RiskModel


class WeightedRiskCalculator:
    """Calculates weighted risk scores using the ZSBOM Risk Scoring Framework v1.0.
    
    Formula: Weighted Score = (Dimension Score × Weight Percentage)
    Final Score: Sum of all weighted scores (0-100 scale)
    """

    def __init__(self, model: Optional[RiskModel] = None):
        """Initialize the risk calculator.
        
        Args:
            model: RiskModel with weights and thresholds
        """
        self.model = model or RiskModel()
        
        # Initialize dimension scorers
        self.scorers = {
            "declared_vs_installed": DeclaredVsInstalledScorer(),
            "known_cves": KnownCVEsScorer(),
            "cwe_coverage": CWECoverageScorer(),
            "package_abandonment": PackageAbandonmentScorer(),
            "typosquat_heuristics": TyposquatHeuristicsScorer(),
        }

    def calculate_score(
        self,
        package: str,
        installed_version: str,
        declared_version: Optional[str] = None,
        cve_list: Optional[List[Dict[str, Any]]] = None,
        typosquat_blacklist: Optional[List[str]] = None,
        repo_path: Optional[str] = None,
        **kwargs: Any
    ) -> Dict[str, Any]:
        """Calculate comprehensive risk score for a package.
        
        Args:
            package: Package name
            installed_version: Currently installed version
            declared_version: Version declared in requirements
            cve_list: List of CVE dictionaries
            typosquat_blacklist: List of known typosquatting packages
            repo_path: Path to local git repository
            **kwargs: Additional arguments
            
        Returns:
            Dictionary containing scores, risk level, and detailed breakdown
        """
        # Calculate individual dimension scores (0-10 scale)
        dimension_scores = {}
        dimension_details = {}
        
        # Declared vs Installed dimension
        dimension_scores["declared_vs_installed"] = self.scorers["declared_vs_installed"].score(
            package, installed_version, declared_version, **kwargs
        )
        dimension_details["declared_vs_installed"] = self.scorers["declared_vs_installed"].get_details(
            package, installed_version, declared_version, **kwargs
        )
        
        # Known CVEs dimension
        dimension_scores["known_cves"] = self.scorers["known_cves"].score(
            package, installed_version, declared_version, cve_list=cve_list, **kwargs
        )
        dimension_details["known_cves"] = self.scorers["known_cves"].get_details(
            package, installed_version, declared_version, cve_list=cve_list, **kwargs
        )
        
        # CWE Coverage dimension
        dimension_scores["cwe_coverage"] = self.scorers["cwe_coverage"].score(
            package, installed_version, declared_version, cve_list=cve_list, **kwargs
        )
        dimension_details["cwe_coverage"] = self.scorers["cwe_coverage"].get_details(
            package, installed_version, declared_version, cve_list=cve_list, **kwargs
        )
        
        # Package Abandonment dimension
        dimension_scores["package_abandonment"] = self.scorers["package_abandonment"].score(
            package, installed_version, declared_version, repo_path=repo_path, **kwargs
        )
        dimension_details["package_abandonment"] = self.scorers["package_abandonment"].get_details(
            package, installed_version, declared_version, repo_path=repo_path, **kwargs
        )
        
        # Typosquat Heuristics dimension
        dimension_scores["typosquat_heuristics"] = self.scorers["typosquat_heuristics"].score(
            package, installed_version, declared_version, typosquat_blacklist=typosquat_blacklist, **kwargs
        )
        dimension_details["typosquat_heuristics"] = self.scorers["typosquat_heuristics"].get_details(
            package, installed_version, declared_version, typosquat_blacklist=typosquat_blacklist, **kwargs
        )
        
        # Apply weights to get weighted contributions
        weighted_contributions = self._apply_weights(dimension_scores)
        
        # Calculate final score (0-100 scale)
        final_score = sum(weighted_contributions.values())
        
        # Determine risk level
        risk_level = self._determine_risk_level(final_score)
        
        return {
            "package": package,
            "installed_version": installed_version,
            "declared_version": declared_version,
            "final_score": round(final_score, 2),
            "risk_level": risk_level,
            "dimension_scores": {k: round(v, 2) for k, v in dimension_scores.items()},
            "weighted_contributions": {k: round(v, 2) for k, v in weighted_contributions.items()},
            "dimension_details": dimension_details,
            "calculation_metadata": {
                "weights_used": self.model.get_weights_dict(),
                "thresholds_used": self.model.get_thresholds_dict(),
                "framework_version": "1.0",
            },
        }

    def _apply_weights(self, dimension_scores: Dict[str, float]) -> Dict[str, float]:
        """Apply percentage weights to dimension scores.
        
        Formula: Weighted Score = (Dimension Score × Weight Percentage)
        
        Args:
            dimension_scores: Dictionary of dimension scores (0-10 scale)
            
        Returns:
            Dictionary of weighted contributions (0-100 scale)
        """
        weights = self.model.get_weights_dict()
        weighted_contributions = {}
        
        for dimension, score in dimension_scores.items():
            weight_percentage = weights.get(dimension, 0) / 100.0
            # Framework formula: score (0-10) * weight_percentage * 10 to get 0-100 scale
            weighted_contribution = score * weight_percentage * 10
            weighted_contributions[dimension] = weighted_contribution
        
        return weighted_contributions

    def _determine_risk_level(self, final_score: float) -> str:
        """Determine risk level based on final score.
        
        Args:
            final_score: Final risk score (0-100 scale)
            
        Returns:
            Risk level string ('low', 'medium', or 'high')
        """
        if final_score >= self.model.low_risk_threshold:
            return "low"
        elif final_score >= self.model.medium_risk_threshold:
            return "medium"
        else:
            return "high"

    def validate_model(self) -> List[str]:
        """Validate the risk model configuration.
        
        Returns:
            List of validation error messages (empty if valid)
        """
        errors = []
        
        # Check that weights sum to 100%
        weights = self.model.get_weights_dict()
        total_weight = sum(weights.values())
        if abs(total_weight - 100.0) > 0.01:  # Allow small floating point errors
            errors.append(f"Weights must sum to 100%, got {total_weight}%")
        
        # Check that all required dimensions have weights
        required_dimensions = {
            "declared_vs_installed",
            "known_cves",
            "cwe_coverage",
            "package_abandonment",
            "typosquat_heuristics",
        }
        
        for dimension in required_dimensions:
            if dimension not in weights:
                errors.append(f"Missing weight for dimension: {dimension}")
            elif weights[dimension] < 0:
                errors.append(f"Weight for {dimension} cannot be negative")
        
        # Check threshold values
        if self.model.low_risk_threshold <= self.model.medium_risk_threshold:
            errors.append("Low risk threshold must be higher than medium risk threshold")
        
        if self.model.medium_risk_threshold < 0 or self.model.low_risk_threshold > 100:
            errors.append("Risk thresholds must be between 0 and 100")
        
        return errors

    def get_framework_info(self) -> Dict[str, Any]:
        """Get information about the risk scoring framework.
        
        Returns:
            Dictionary containing framework information
        """
        return {
            "framework_version": "1.0",
            "dimensions": list(self.scorers.keys()),
            "score_range": "0-100",
            "dimension_score_range": "0-10",
            "risk_levels": ["low", "medium", "high"],
            "risk_thresholds": {
                "low": f"{self.model.low_risk_threshold}+",
                "medium": f"{self.model.medium_risk_threshold}-{self.model.low_risk_threshold-1}",
                "high": f"0-{self.model.medium_risk_threshold-1}",
            },
            "weights": self.model.get_weights_dict(),
        }