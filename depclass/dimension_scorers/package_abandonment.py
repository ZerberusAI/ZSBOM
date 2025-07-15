"""Package Abandonment dimension scorer."""

import subprocess
import requests
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from .base import DimensionScorer


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
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'ZSBOM/1.0 (Package Risk Assessment)'
        })

    def score(
        self,
        package: str,
        installed_version: str,
        declared_version: Optional[str] = None,
        repo_path: Optional[str] = None,
        **kwargs: Any
    ) -> float:
        """Calculate package abandonment risk score.
        
        Args:
            package: Package name
            installed_version: Currently installed version
            declared_version: Version declared in requirements
            repo_path: Path to local git repository (optional)
            **kwargs: Additional data (unused)
            
        Returns:
            Score between 0.0 (highest risk) and 10.0 (lowest risk)
        """
        score = 0.0
        
        # Factor 1: Time since last commit (max 5 points)
        commit_score = self._score_last_commit(repo_path)
        score += commit_score
        
        # Factor 2: Commit frequency (max 3 points)
        frequency_score = self._score_commit_frequency(repo_path)
        score += frequency_score
        
        # Factor 3: Release frequency (max 2 points)
        release_score = self._score_release_frequency(package)
        score += release_score
        
        return self.validate_score(score)

    def get_details(
        self,
        package: str,
        installed_version: str,
        declared_version: Optional[str] = None,
        repo_path: Optional[str] = None,
        **kwargs: Any
    ) -> Dict[str, Any]:
        """Get detailed package abandonment scoring information.
        
        Args:
            package: Package name
            installed_version: Currently installed version
            declared_version: Version declared in requirements
            repo_path: Path to local git repository (optional)
            **kwargs: Additional data (unused)
            
        Returns:
            Dictionary containing scoring details
        """
        score = self.score(package, installed_version, declared_version, repo_path, **kwargs)
        
        # Get individual component scores and details
        last_commit_info = self._get_last_commit_info(repo_path)
        commit_frequency_info = self._get_commit_frequency_info(repo_path)
        release_frequency_info = self._get_release_frequency_info(package)
        
        return {
            "dimension": "package_abandonment",
            "score": score,
            "components": {
                "last_commit": {
                    "score": self._score_last_commit(repo_path),
                    "max_score": 5,
                    "days_since_last_commit": last_commit_info.get("days_since_last_commit"),
                    "last_commit_date": last_commit_info.get("last_commit_date"),
                },
                "commit_frequency": {
                    "score": self._score_commit_frequency(repo_path),
                    "max_score": 3,
                    "commits_per_month": commit_frequency_info.get("commits_per_month"),
                    "total_commits": commit_frequency_info.get("total_commits"),
                },
                "release_frequency": {
                    "score": self._score_release_frequency(package),
                    "max_score": 2,
                    "days_since_last_release": release_frequency_info.get("days_since_last_release"),
                    "last_release_date": release_frequency_info.get("last_release_date"),
                },
            },
            "repository_available": repo_path is not None,
            "pypi_data_available": release_frequency_info.get("pypi_data_available", False),
        }

    def _score_last_commit(self, repo_path: Optional[str]) -> float:
        """Score based on time since last commit (max 5 points).
        
        Args:
            repo_path: Path to local git repository
            
        Returns:
            Score between 0.0 and 5.0
        """
        if not repo_path:
            return 0.0  # No repository data available
        
        last_commit_info = self._get_last_commit_info(repo_path)
        days_since_last_commit = last_commit_info.get("days_since_last_commit")
        
        if days_since_last_commit is None:
            return 0.0  # Could not determine last commit
        
        if days_since_last_commit <= 30:
            return 5.0
        elif days_since_last_commit <= 90:
            return 3.0
        elif days_since_last_commit <= 180:
            return 1.0
        else:
            return 0.0

    def _score_commit_frequency(self, repo_path: Optional[str]) -> float:
        """Score based on commit frequency (max 3 points).
        
        Args:
            repo_path: Path to local git repository
            
        Returns:
            Score between 0.0 and 3.0
        """
        if not repo_path:
            return 0.0  # No repository data available
        
        frequency_info = self._get_commit_frequency_info(repo_path)
        commits_per_month = frequency_info.get("commits_per_month")
        
        if commits_per_month is None:
            return 0.0  # Could not determine commit frequency
        
        if commits_per_month >= 2.0:
            return 3.0
        elif commits_per_month >= 1.0:
            return 2.0
        elif commits_per_month > 0:
            return 1.0
        else:
            return 0.0

    def _score_release_frequency(self, package: str) -> float:
        """Score based on release frequency (max 2 points).
        
        Args:
            package: Package name
            
        Returns:
            Score between 0.0 and 2.0
        """
        release_info = self._get_release_frequency_info(package)
        days_since_last_release = release_info.get("days_since_last_release")
        
        if days_since_last_release is None:
            return 0.0  # Could not determine release frequency
        
        if days_since_last_release <= 180:  # 6 months
            return 2.0
        elif days_since_last_release <= 365:  # 12 months
            return 1.0
        else:
            return 0.0

    def _get_last_commit_info(self, repo_path: Optional[str]) -> Dict[str, Any]:
        """Get information about the last commit.
        
        Args:
            repo_path: Path to local git repository
            
        Returns:
            Dictionary with last commit information
        """
        if not repo_path:
            return {}
        
        try:
            # Try main branch first, then master
            for branch in ["main", "master"]:
                try:
                    timestamp_str = subprocess.check_output(
                        ["git", "-C", repo_path, "log", branch, "-1", "--format=%ct"],
                        text=True,
                        stderr=subprocess.DEVNULL
                    ).strip()
                    
                    if timestamp_str:
                        timestamp = int(timestamp_str)
                        last_commit_date = datetime.fromtimestamp(timestamp, timezone.utc)
                        days_since_last_commit = (datetime.now(timezone.utc) - last_commit_date).days
                        
                        return {
                            "days_since_last_commit": days_since_last_commit,
                            "last_commit_date": last_commit_date.isoformat(),
                        }
                except subprocess.CalledProcessError:
                    continue
            
            return {}
        except (subprocess.CalledProcessError, ValueError, OSError):
            return {}

    def _get_commit_frequency_info(self, repo_path: Optional[str]) -> Dict[str, Any]:
        """Get information about commit frequency.
        
        Args:
            repo_path: Path to local git repository
            
        Returns:
            Dictionary with commit frequency information
        """
        if not repo_path:
            return {}
        
        try:
            # Get commits from last 12 months
            one_year_ago = datetime.now(timezone.utc).replace(year=datetime.now().year - 1)
            since_date = one_year_ago.strftime("%Y-%m-%d")
            
            # Try main branch first, then master
            for branch in ["main", "master"]:
                try:
                    commit_count_str = subprocess.check_output(
                        ["git", "-C", repo_path, "rev-list", "--count", branch, f"--since={since_date}"],
                        text=True,
                        stderr=subprocess.DEVNULL
                    ).strip()
                    
                    if commit_count_str:
                        total_commits = int(commit_count_str)
                        commits_per_month = total_commits / 12.0
                        
                        return {
                            "commits_per_month": commits_per_month,
                            "total_commits": total_commits,
                        }
                except subprocess.CalledProcessError:
                    continue
            
            return {}
        except (subprocess.CalledProcessError, ValueError, OSError):
            return {}

    def _get_release_frequency_info(self, package: str) -> Dict[str, Any]:
        """Get information about release frequency from PyPI.
        
        Args:
            package: Package name
            
        Returns:
            Dictionary with release frequency information
        """
        try:
            # Query PyPI API for package information
            response = self.session.get(
                f"https://pypi.org/pypi/{package}/json",
                timeout=10
            )
            
            if response.status_code == 200:
                data = response.json()
                releases = data.get("releases", {})
                
                if releases:
                    # Find the most recent release
                    release_dates = []
                    for version, release_info in releases.items():
                        if release_info:  # Skip empty releases
                            for release_file in release_info:
                                upload_time = release_file.get("upload_time")
                                if upload_time:
                                    try:
                                        release_date = datetime.fromisoformat(upload_time.replace("Z", "+00:00"))
                                        release_dates.append(release_date)
                                    except ValueError:
                                        continue
                    
                    if release_dates:
                        last_release_date = max(release_dates)
                        days_since_last_release = (datetime.now(timezone.utc) - last_release_date).days
                        
                        return {
                            "days_since_last_release": days_since_last_release,
                            "last_release_date": last_release_date.isoformat(),
                            "pypi_data_available": True,
                        }
            
            return {"pypi_data_available": False}
            
        except (requests.RequestException, ValueError, KeyError):
            return {"pypi_data_available": False}