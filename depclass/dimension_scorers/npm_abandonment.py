"""NPM package abandonment scorer (placeholder)."""

from .base import DimensionScorer


class NpmAbandonmentScorer(DimensionScorer):
    """Placeholder scorer measuring project abandonment on NPM."""

    def score(self, package: str, installed_version: str, declared_version: str | None = None, **kwargs) -> float:
        return 10.0

    def get_details(self, package: str, installed_version: str, declared_version: str | None = None, **kwargs):
        return {"score": 10.0, "reason": "placeholder"}
