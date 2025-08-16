"""NPM package hygiene scorer (placeholder)."""

from .base import DimensionScorer


class NpmHygieneScorer(DimensionScorer):
    """Placeholder implementation scoring package hygiene."""

    def score(self, package: str, installed_version: str, declared_version: str | None = None, **kwargs) -> float:
        return 10.0

    def get_details(self, package: str, installed_version: str, declared_version: str | None = None, **kwargs):
        return {"score": 10.0, "reason": "placeholder"}
