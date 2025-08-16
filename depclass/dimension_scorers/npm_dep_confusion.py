"""NPM dependency confusion scorer (placeholder)."""

from .base import DimensionScorer


class NpmDepConfusionScorer(DimensionScorer):
    """Placeholder scorer for dependency confusion checks in NPM."""

    def score(self, package: str, installed_version: str, declared_version: str | None = None, **kwargs) -> float:
        return 10.0

    def get_details(self, package: str, installed_version: str, declared_version: str | None = None, **kwargs):
        return {"score": 10.0, "reason": "placeholder"}
