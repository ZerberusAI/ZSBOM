"""NPM specific typosquatting scorer (placeholder)."""

from .base import DimensionScorer


class NpmTyposquatScorer(DimensionScorer):
    """Very small placeholder scorer for NPM typosquatting.

    The real implementation would analyse NPM package names and metadata to
    detect potential typosquatting.  For unit tests we simply return the maximum
    score indicating low risk.
    """

    def score(self, package: str, installed_version: str, declared_version: str | None = None, **kwargs) -> float:
        return 10.0

    def get_details(self, package: str, installed_version: str, declared_version: str | None = None, **kwargs):
        return {"score": 10.0, "reason": "placeholder"}
