"""Package Abandonment dimension scorer."""

from datetime import datetime, timezone
from typing import Any, Dict, Optional

from .base import DimensionScorer
from .enhanced_data_utils import extract_repository_data, extract_metadata


class PackageAbandonmentScorer(DimensionScorer):
    """Scores packages based on maintenance activity and abandonment indicators.
    
    Scoring criteria (0-10 scale):
    - Time Since Last Commit (max 5 points):
      - ≤30 days = 5 pts
      - 31-90 days = 3 pts
      - 91-180 days = 1 pt
      - >180 days = 0 pts
    - Commit Frequency (max 3 points):
      - ≥2 commits/month = 3 pts
      - 1-2/month = 2 pts
      - <1/month = 1 pt
    - Release Frequency (max 2 points):
      - ≥1 release in last 6 months = 2 pts
      - 6-12 months = 1 pt
      - >12 months = 0 pts
    """

    def __init__(self):
        pass

    def score(
        self,
        package: str,
        installed_version: str,
        declared_version: Optional[str] = None,
        **kwargs: Any
    ) -> float:
        """Calculate package abandonment risk score using enhanced data.

        Args:
            package: Package name
            installed_version: Currently installed version
            declared_version: Version declared in requirements
            **kwargs: Additional data including enhanced_data from enhancers

        Returns:
            Score between 0.0 (highest risk) and 10.0 (lowest risk)
        """
        score = 0.0

        # Extract enhanced data from kwargs
        enhanced_data = kwargs.get("enhanced_data")
        ecosystem = kwargs.get("ecosystem", "python")

        # Extract repository and metadata using shared utilities
        repository_data = extract_repository_data(enhanced_data, package, ecosystem, installed_version)
        metadata_data = extract_metadata(enhanced_data, package, ecosystem, installed_version)

        # Factor 1: Time since last commit (max 5 points)
        commit_score = self._score_last_commit(repository_data)
        score += commit_score

        # Factor 2: Commit frequency (max 3 points)
        frequency_score = self._score_commit_frequency(repository_data)
        score += frequency_score

        # Factor 3: Release frequency (max 2 points)
        release_score = self._score_release_frequency(metadata_data)
        score += release_score

        return self.validate_score(score)

    def get_details(
        self,
        package: str,
        installed_version: str,
        declared_version: Optional[str] = None,
        **kwargs: Any
    ) -> Dict[str, Any]:
        """Get detailed package abandonment scoring information.

        Args:
            package: Package name
            installed_version: Currently installed version
            declared_version: Version declared in requirements
            **kwargs: Additional data including enhanced_data from enhancers

        Returns:
            Dictionary containing scoring details
        """
        score = self.score(package, installed_version, declared_version, **kwargs)

        # Extract enhanced data from kwargs
        enhanced_data = kwargs.get("enhanced_data")
        ecosystem = kwargs.get("ecosystem", "python")

        # Extract repository and metadata using shared utilities
        repository_data = extract_repository_data(enhanced_data, package, ecosystem, installed_version)
        metadata_data = extract_metadata(enhanced_data, package, ecosystem, installed_version)

        # Get detailed information from enhanced data
        last_commit_info = self._get_last_commit_info(repository_data)
        commit_frequency_info = self._get_commit_frequency_info(repository_data)
        release_frequency_info = self._get_release_frequency_info(metadata_data)

        return {
            "dimension": "package_abandonment",
            "score": score,
            "components": {
                "last_commit": {
                    "score": self._score_last_commit(repository_data),
                    "max_score": 5,
                    "days_since_last_commit": last_commit_info.get("days_since_last_commit"),
                    "last_commit_date": last_commit_info.get("last_commit_date"),
                },
                "commit_frequency": {
                    "score": self._score_commit_frequency(repository_data),
                    "max_score": 3,
                    "commits_per_month": commit_frequency_info.get("commits_per_month"),
                    "total_commits": commit_frequency_info.get("total_commits"),
                },
                "release_frequency": {
                    "score": self._score_release_frequency(metadata_data),
                    "max_score": 2,
                    "days_since_last_release": release_frequency_info.get("days_since_last_release"),
                    "last_release_date": release_frequency_info.get("last_release_date"),
                },
            },
            "repository_available": repository_data is not None,
            "repository_url": repository_data.get("repository_url") if repository_data else None,
            "enhanced_data_available": enhanced_data is not None,
        }

    def _score_last_commit(self, repository_data: Optional[Dict]) -> float:
        """Score based on time since last commit (max 5 points).

        Args:
            repository_data: Repository data from GitHub enhancer

        Returns:
            Score between 0.0 and 5.0
        """
        if not repository_data:
            return 2.5  # Default moderate score when no repository data available

        commit_activity = repository_data.get("commit_activity", {})
        latest_commit = commit_activity.get("latest_commit", {})
        days_since_last_commit = latest_commit.get("days_ago")

        if days_since_last_commit is None:
            # Could not determine last commit (private repo, auth issues, etc.)
            # Return moderate score rather than 0 to avoid penalizing inaccessible repos
            return 2.5

        if days_since_last_commit <= 30:
            return 5.0
        elif days_since_last_commit <= 90:
            return 3.0
        elif days_since_last_commit <= 180:
            return 1.0
        else:
            return 0.0

    def _score_commit_frequency(self, repository_data: Optional[Dict]) -> float:
        """Score based on commit frequency (max 3 points).

        Args:
            repository_data: Repository data from GitHub enhancer

        Returns:
            Score between 0.0 and 3.0
        """
        if not repository_data:
            return 1.5  # Default moderate score when no repository data available

        commit_activity = repository_data.get("commit_activity", {})
        frequency = commit_activity.get("frequency", {})
        commits_per_month = frequency.get("commits_per_month")

        if commits_per_month is None:
            # Could not determine commit frequency (private repo, auth issues, etc.)
            # Return moderate score rather than 0 to avoid penalizing inaccessible repos
            return 1.5

        if commits_per_month >= 2.0:
            return 3.0
        elif commits_per_month >= 1.0:
            return 2.0
        elif commits_per_month > 0:
            return 1.0
        else:
            return 0.0

    def _score_release_frequency(self, metadata_data: Optional[Dict]) -> float:
        """Score based on release frequency from deps.dev data (max 2 points).

        Args:
            metadata_data: Metadata from deps.dev enhancer

        Returns:
            Score between 0.0 and 2.0
        """
        if not metadata_data:
            return 1.0  # Default moderate score when metadata unavailable

        # Check for release activity data from deps.dev enhancer
        release_activity = metadata_data.get("release_activity")
        if release_activity and release_activity.get("has_releases"):
            latest_release = release_activity.get("latest_release", {})
            days_since_last_release = latest_release.get("days_ago")

            if days_since_last_release is not None:
                if days_since_last_release <= 180:  # 6 months
                    return 2.0
                elif days_since_last_release <= 365:  # 12 months
                    return 1.0
                else:
                    return 0.0

        # Fallback: Return moderate score if no release data available
        return 1.0

    def _get_last_commit_info(self, repository_data: Optional[Dict]) -> Dict[str, Any]:
        """Get information about the last commit from enhanced data.

        Args:
            repository_data: Repository data from GitHub enhancer

        Returns:
            Dictionary with last commit information
        """
        if not repository_data:
            return {}

        commit_activity = repository_data.get("commit_activity", {})
        latest_commit = commit_activity.get("latest_commit", {})

        return {
            "days_since_last_commit": latest_commit.get("days_ago"),
            "last_commit_date": latest_commit.get("date"),
        }

    def _get_commit_frequency_info(self, repository_data: Optional[Dict]) -> Dict[str, Any]:
        """Get information about commit frequency from enhanced data.

        Args:
            repository_data: Repository data from GitHub enhancer

        Returns:
            Dictionary with commit frequency information
        """
        if not repository_data:
            return {}

        commit_activity = repository_data.get("commit_activity", {})
        frequency = commit_activity.get("frequency", {})

        return {
            "commits_per_month": frequency.get("commits_per_month"),
            "total_commits": frequency.get("total_commits_last_year"),
        }

    def _get_release_frequency_info(self, metadata_data: Optional[Dict]) -> Dict[str, Any]:
        """Get information about release frequency from enhanced data.

        Args:
            metadata_data: Metadata from deps.dev enhancer

        Returns:
            Dictionary with release frequency information
        """
        if not metadata_data:
            return {}

        # Check for release activity from deps.dev enhancer
        release_activity = metadata_data.get("release_activity")
        if release_activity and release_activity.get("has_releases"):
            latest_release = release_activity.get("latest_release", {})
            return {
                "days_since_last_release": latest_release.get("days_ago"),
                "last_release_date": latest_release.get("published_at"),
            }

        return {}

