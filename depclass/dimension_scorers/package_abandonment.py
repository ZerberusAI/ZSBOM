"""Package Abandonment dimension scorer."""

import subprocess
import tempfile
import shutil
import os
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from .base import DimensionScorer
from ..services import get_pypi_service


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
        self.pypi_service = get_pypi_service()
        self._repo_cache = {}  # Cache for repository analysis

    def score(
        self,
        package: str,
        installed_version: str,
        declared_version: Optional[str] = None,
        **kwargs: Any
    ) -> float:
        """Calculate package abandonment risk score.
        
        Args:
            package: Package name
            installed_version: Currently installed version
            declared_version: Version declared in requirements
            **kwargs: Additional data (unused)
            
        Returns:
            Score between 0.0 (highest risk) and 10.0 (lowest risk)
        """
        score = 0.0
        
        # Get repository URL from PyPI metadata
        repo_url = self.pypi_service.get_repository_url(package)
        
        # Factor 1: Time since last commit (max 5 points)
        commit_score = self._score_last_commit(repo_url)
        score += commit_score
        
        # Factor 2: Commit frequency (max 3 points)
        frequency_score = self._score_commit_frequency(repo_url)
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
        **kwargs: Any
    ) -> Dict[str, Any]:
        """Get detailed package abandonment scoring information.
        
        Args:
            package: Package name
            installed_version: Currently installed version
            declared_version: Version declared in requirements
            **kwargs: Additional data (unused)
            
        Returns:
            Dictionary containing scoring details
        """
        score = self.score(package, installed_version, declared_version, **kwargs)
        
        # Get repository URL and individual component scores and details
        repo_url = self.pypi_service.get_repository_url(package)
        last_commit_info = self._get_last_commit_info(repo_url)
        commit_frequency_info = self._get_commit_frequency_info(repo_url)
        release_frequency_info = self.pypi_service.get_release_info(package)
        
        return {
            "dimension": "package_abandonment",
            "score": score,
            "components": {
                "last_commit": {
                    "score": self._score_last_commit(repo_url),
                    "max_score": 5,
                    "days_since_last_commit": last_commit_info.get("days_since_last_commit"),
                    "last_commit_date": last_commit_info.get("last_commit_date"),
                },
                "commit_frequency": {
                    "score": self._score_commit_frequency(repo_url),
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
            "repository_available": repo_url is not None,
            "repository_url": repo_url,
            "pypi_data_available": release_frequency_info.get("pypi_data_available", False),
        }

    def _score_last_commit(self, repo_url: Optional[str]) -> float:
        """Score based on time since last commit (max 5 points).
        
        Args:
            repo_url: URL to git repository
            
        Returns:
            Score between 0.0 and 5.0
        """
        if not repo_url:
            return 2.5  # Default moderate score when no repository data available
        
        last_commit_info = self._get_last_commit_info(repo_url)
        days_since_last_commit = last_commit_info.get("days_since_last_commit")
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

    def _score_commit_frequency(self, repo_url: Optional[str]) -> float:
        """Score based on commit frequency (max 3 points).
        
        Args:
            repo_url: URL to git repository
            
        Returns:
            Score between 0.0 and 3.0
        """
        if not repo_url:
            return 1.5  # Default moderate score when no repository data available
        
        frequency_info = self._get_commit_frequency_info(repo_url)
        commits_per_month = frequency_info.get("commits_per_month")
        
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

    def _score_release_frequency(self, package: str) -> float:
        """Score based on release frequency (max 2 points).
        
        Args:
            package: Package name
            
        Returns:
            Score between 0.0 and 2.0
        """
        release_info = self.pypi_service.get_release_info(package)
        days_since_last_release = release_info.get("days_since_last_release")
        
        if days_since_last_release is None:
            return 1.0  # Default moderate score when PyPI unavailable (1.0 out of 2.0 max for this component)
        
        if days_since_last_release <= 180:  # 6 months
            return 2.0
        elif days_since_last_release <= 365:  # 12 months
            return 1.0
        else:
            return 0.0

    def _get_last_commit_info(self, repo_url: Optional[str]) -> Dict[str, Any]:
        """Get information about the last commit.
        
        Args:
            repo_url: URL to git repository
            
        Returns:
            Dictionary with last commit information
        """
        if not repo_url:
            return {}
        
        # Check cache first
        cache_key = f"last_commit_{repo_url}"
        if cache_key in self._repo_cache:
            return self._repo_cache[cache_key]
        
        result = {}
        
        # For GitHub repos, use API first (more reliable and no auth needed)
        if "github.com" in repo_url:
            result = self._get_github_commit_info_via_api(repo_url)
            if result:
                self._repo_cache[cache_key] = result
                return result
        
        # Fallback to git ls-remote for non-GitHub repos or when API fails
        try:
            # Set environment variables to prevent any credential prompts
            env = os.environ.copy()
            env['GIT_ASKPASS'] = 'echo'  # Provide empty credentials
            env['GIT_TERMINAL_PROMPT'] = '0'  # Disable terminal prompts entirely
            
            # Use git ls-remote to get commit info without cloning
            # Try main branch first, then master
            for branch in ["main", "master"]:
                try:
                    output = subprocess.check_output(
                        ["git", "ls-remote", repo_url, f"refs/heads/{branch}"],
                        text=True,
                        stderr=subprocess.DEVNULL,
                        timeout=10,  # Optimized timeout for parallel execution
                        env=env
                    ).strip()
                    
                    if output:
                        commit_hash = output.split()[0]
                        
                        # Get commit timestamp using GitHub API if it's a GitHub repo
                        if "github.com" in repo_url:
                            result = self._get_github_commit_info(repo_url, commit_hash)
                        else:
                            # For non-GitHub repos, we don't have a reliable way to get timestamp
                            # without cloning, so return empty result
                            result = {}
                        
                        if result:
                            break
                            
                except subprocess.CalledProcessError:
                    continue
            
            # Cache the result for 1 hour
            self._repo_cache[cache_key] = result
            return result
            
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired, ValueError, OSError):
            # Return empty result - scoring will handle this gracefully
            self._repo_cache[cache_key] = {}
            return {}

    def _get_github_commit_info_via_api(self, repo_url: str) -> Dict[str, Any]:
        """Get latest commit information from GitHub API without needing commit hash.
        
        Args:
            repo_url: GitHub repository URL
            
        Returns:
            Dictionary with latest commit information
        """
        try:
            # Extract owner/repo from GitHub URL
            import re
            match = re.search(r'github\.com[/:]([^/]+)/([^/]+?)(?:\.git)?/?$', repo_url)
            if not match:
                return {}
            
            owner, repo = match.groups()
            
            # Get latest commit from main/master branch directly
            for branch in ["main", "master"]:
                api_url = f"https://api.github.com/repos/{owner}/{repo}/commits/{branch}"
                
                try:
                    response = self.pypi_service.session.get(api_url, timeout=10)
                    if response.status_code == 200:
                        data = response.json()
                        commit_date_str = data['commit']['committer']['date']
                        commit_date = datetime.fromisoformat(commit_date_str.replace('Z', '+00:00'))
                        days_since_last_commit = (datetime.now(timezone.utc) - commit_date).days
                        
                        return {
                            "days_since_last_commit": days_since_last_commit,
                            "last_commit_date": commit_date.isoformat(),
                        }
                except Exception:
                    # Try next branch if this one fails
                    continue
                    
        except Exception:
            pass
        
        return {}

    def _get_github_commit_info(self, repo_url: str, commit_hash: str) -> Dict[str, Any]:
        """Get commit information from GitHub API.
        
        Args:
            repo_url: GitHub repository URL
            commit_hash: Commit hash
            
        Returns:
            Dictionary with commit information
        """
        try:
            # Extract owner/repo from GitHub URL
            import re
            match = re.search(r'github\.com[/:]([^/]+)/([^/]+?)(?:\.git)?/?$', repo_url)
            if not match:
                return {}
            
            owner, repo = match.groups()
            api_url = f"https://api.github.com/repos/{owner}/{repo}/commits/{commit_hash}"
            
            response = self.pypi_service.session.get(api_url, timeout=10)
            if response.status_code == 200:
                data = response.json()
                commit_date_str = data['commit']['committer']['date']
                commit_date = datetime.fromisoformat(commit_date_str.replace('Z', '+00:00'))
                days_since_last_commit = (datetime.now(timezone.utc) - commit_date).days
                
                return {
                    "days_since_last_commit": days_since_last_commit,
                    "last_commit_date": commit_date.isoformat(),
                }
        except Exception:
            pass
        
        return {}

    def _get_commit_frequency_info(self, repo_url: Optional[str]) -> Dict[str, Any]:
        """Get information about commit frequency.
        
        Args:
            repo_url: URL to git repository
            
        Returns:
            Dictionary with commit frequency information
        """
        if not repo_url:
            return {}
        
        # Check cache first
        cache_key = f"commit_frequency_{repo_url}"
        if cache_key in self._repo_cache:
            return self._repo_cache[cache_key]
        
        result = {}
        try:
            # For GitHub repos, use the API to get commit activity
            if "github.com" in repo_url:
                result = self._get_github_commit_frequency(repo_url)
            else:
                # For non-GitHub repos, we'd need more complex analysis
                # For now, return empty result
                result = {}
            
            # Cache the result for 1 hour
            self._repo_cache[cache_key] = result
            return result
            
        except Exception:
            self._repo_cache[cache_key] = {}
            return {}

    def _get_github_commit_frequency(self, repo_url: str) -> Dict[str, Any]:
        """Get commit frequency from GitHub API.
        
        Args:
            repo_url: GitHub repository URL
            
        Returns:
            Dictionary with commit frequency information
        """
        try:
            # Extract owner/repo from GitHub URL
            import re
            match = re.search(r'github\.com[/:]([^/]+)/([^/]+?)(?:\.git)?/?$', repo_url)
            if not match:
                return {}
            
            owner, repo = match.groups()
            
            # Get commit activity for the last year
            one_year_ago = datetime.now(timezone.utc).replace(year=datetime.now().year - 1)
            since_date = one_year_ago.isoformat()
            
            # GitHub API for commits with since parameter
            api_url = f"https://api.github.com/repos/{owner}/{repo}/commits"
            params = {
                'since': since_date,
                'per_page': 100,  # Get up to 100 commits to estimate frequency
            }
            
            response = self.pypi_service.session.get(api_url, params=params, timeout=10)
            if response.status_code == 200:
                commits = response.json()
                total_commits = len(commits)
                
                # If we got exactly 100, there might be more (this is a rough estimate)
                if total_commits == 100:
                    # Try to get total count from headers or make additional requests
                    # For simplicity, we'll use 100 as a conservative estimate
                    pass
                
                commits_per_month = total_commits / 12.0
                
                return {
                    "commits_per_month": commits_per_month,
                    "total_commits": total_commits,
                }
        except Exception:
            pass
        
        return {}

