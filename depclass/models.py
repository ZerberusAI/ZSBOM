from dataclasses import dataclass
from enum import Enum
from typing import Optional


class RiskDimension(str, Enum):
    """Enumeration of supported risk scoring dimensions."""
    DECLARED_VS_INSTALLED = "declared_vs_installed"
    KNOWN_CVES = "known_cves"
    CWE_COVERAGE = "cwe_coverage"
    PACKAGE_ABANDONMENT = "package_abandonment"
    TYPOSQUAT_HEURISTICS = "typosquat_heuristics"


@dataclass
class PackageRef:
    """Reference to a package being analyzed."""
    name: str
    installed_version: str
    declared_version: Optional[str] = None
    dependency_type: Optional[str] = None
