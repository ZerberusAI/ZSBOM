"""Declared vs Installed version dimension scorer."""

import re
from typing import Any, Dict, Optional

from .base import DimensionScorer


class DeclaredVsInstalledScorer(DimensionScorer):
    """Scores packages based on version match between declared and installed versions.
    
    Scoring criteria:
    - Perfect match (declared == installed): 10.0
    - Minor version difference: 7.0-9.0
    - Major version difference: 3.0-6.0
    - No declared version: 5.0 (neutral)
    - Significant version drift: 0.0-2.0
    """

    def __init__(self):
        self.version_pattern = re.compile(r'^(\d+)\.(\d+)\.(\d+)(?:[-\.].*)?$')

    def score(
        self,
        package: str,
        installed_version: str,
        declared_version: Optional[str] = None,
        **kwargs: Any
    ) -> float:
        """Calculate version mismatch score.
        
        Args:
            package: Package name
            installed_version: Currently installed version
            declared_version: Version declared in requirements
            **kwargs: Additional data (unused)
            
        Returns:
            Score between 0.0 (highest risk) and 10.0 (lowest risk)
        """
        if not declared_version:
            return 5.0  # Neutral score for missing declaration
        
        if declared_version == installed_version:
            return 10.0  # Perfect match
        
        # Parse version numbers
        declared_parts = self._parse_version(declared_version)
        installed_parts = self._parse_version(installed_version)
        
        if not declared_parts or not installed_parts:
            return 2.0  # Invalid version format
        
        # Calculate version difference
        major_diff = abs(declared_parts[0] - installed_parts[0])
        minor_diff = abs(declared_parts[1] - installed_parts[1])
        patch_diff = abs(declared_parts[2] - installed_parts[2])
        
        # Score based on version difference magnitude
        if major_diff > 1:
            return 0.0  # Major version drift
        elif major_diff == 1:
            return 3.0  # One major version difference
        elif minor_diff > 5:
            return 4.0  # Significant minor version drift
        elif minor_diff > 2:
            return 6.0  # Moderate minor version difference
        elif minor_diff > 0:
            return 8.0  # Small minor version difference
        elif patch_diff > 10:
            return 7.0  # Large patch version difference
        elif patch_diff > 0:
            return 9.0  # Small patch version difference
        
        return 10.0  # Should not reach here

    def get_details(
        self,
        package: str,
        installed_version: str,
        declared_version: Optional[str] = None,
        **kwargs: Any
    ) -> Dict[str, Any]:
        """Get detailed scoring information.
        
        Args:
            package: Package name
            installed_version: Currently installed version
            declared_version: Version declared in requirements
            **kwargs: Additional data (unused)
            
        Returns:
            Dictionary containing scoring details
        """
        score = self.score(package, installed_version, declared_version, **kwargs)
        
        details = {
            "dimension": "declared_vs_installed",
            "score": score,
            "declared_version": declared_version,
            "installed_version": installed_version,
            "exact_match": declared_version == installed_version if declared_version else False,
            "has_declared_version": declared_version is not None,
        }
        
        if declared_version and declared_version != installed_version:
            declared_parts = self._parse_version(declared_version)
            installed_parts = self._parse_version(installed_version)
            
            if declared_parts and installed_parts:
                details["version_diff"] = {
                    "major": abs(declared_parts[0] - installed_parts[0]),
                    "minor": abs(declared_parts[1] - installed_parts[1]),
                    "patch": abs(declared_parts[2] - installed_parts[2]),
                }
        
        return details

    def _parse_version(self, version_str: str) -> Optional[tuple[int, int, int]]:
        """Parse version string into major, minor, patch components.
        
        Args:
            version_str: Version string to parse
            
        Returns:
            Tuple of (major, minor, patch) or None if invalid
        """
        if not version_str:
            return None
        
        match = self.version_pattern.match(version_str.strip())
        if not match:
            return None
        
        try:
            major = int(match.group(1))
            minor = int(match.group(2))
            patch = int(match.group(3))
            return (major, minor, patch)
        except ValueError:
            return None