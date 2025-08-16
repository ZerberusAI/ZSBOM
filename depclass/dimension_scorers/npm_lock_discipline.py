"""NPM lock-file discipline scorer (placeholder)."""

from .base import DimensionScorer


class NpmLockDisciplineScorer(DimensionScorer):
    """Placeholder scorer for lock file discipline in NPM projects."""

    def score(self, package: str, installed_version: str, declared_version: str | None = None, **kwargs) -> float:
        return 10.0

    def get_details(self, package: str, installed_version: str, declared_version: str | None = None, **kwargs):
        return {"score": 10.0, "reason": "placeholder"}
