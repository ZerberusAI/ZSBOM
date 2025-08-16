"""Dimension scorers for ZSBOM risk assessment."""

from .base import DimensionScorer
from .declared_vs_installed import DeclaredVsInstalledScorer
from .known_cves import KnownCVEsScorer
from .cwe_coverage import CWECoverageScorer
from .package_abandonment import PackageAbandonmentScorer
from .typosquat_heuristics import TyposquatHeuristicsScorer
from .npm_typosquat import NpmTyposquatScorer
from .npm_dep_confusion import NpmDepConfusionScorer
from .npm_hygiene import NpmHygieneScorer
from .npm_lock_discipline import NpmLockDisciplineScorer
from .npm_abandonment import NpmAbandonmentScorer

__all__ = [
    "DimensionScorer",
    "DeclaredVsInstalledScorer",
    "KnownCVEsScorer",
    "CWECoverageScorer",
    "PackageAbandonmentScorer",
    "TyposquatHeuristicsScorer",
    "NpmTyposquatScorer",
    "NpmDepConfusionScorer",
    "NpmHygieneScorer",
    "NpmLockDisciplineScorer",
    "NpmAbandonmentScorer",
]