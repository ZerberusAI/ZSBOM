"""Abstract base class for dimension scorers."""

from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional


class DimensionScorer(ABC):
    """Abstract base class for risk dimension scorers.
    
    Each dimension scorer evaluates a specific aspect of package risk
    and returns a score between 0.0 and 10.0, where:
    - 0.0 = Highest risk (worst score)
    - 10.0 = Lowest risk (best score)
    """

    @abstractmethod
    def score(
        self,
        package: str,
        installed_version: str,
        declared_version: Optional[str] = None,
        **kwargs: Any
    ) -> float:
        """Calculate risk score for this dimension.
        
        Args:
            package: Package name
            installed_version: Currently installed version
            declared_version: Version declared in requirements (optional)
            **kwargs: Additional data specific to each dimension
            
        Returns:
            Score between 0.0 (highest risk) and 10.0 (lowest risk)
        """
        pass

    @abstractmethod
    def get_details(
        self,
        package: str,
        installed_version: str,
        declared_version: Optional[str] = None,
        **kwargs: Any
    ) -> Dict[str, Any]:
        """Get detailed information about the scoring decision.
        
        Args:
            package: Package name
            installed_version: Currently installed version
            declared_version: Version declared in requirements (optional)
            **kwargs: Additional data specific to each dimension
            
        Returns:
            Dictionary containing scoring details and metadata
        """
        pass

    def validate_score(self, score: float) -> float:
        """Validate and clamp score to valid range [0.0, 10.0].
        
        Args:
            score: Raw score value
            
        Returns:
            Validated score clamped to [0.0, 10.0]
        """
        return max(0.0, min(10.0, score))