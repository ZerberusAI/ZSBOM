"""
Simplified GitHub repository provider.

Handles repository activity analysis, statistics, and metrics collection
from the GitHub API for packages hosted on GitHub.
"""

import logging
import re
import requests
import time
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

from ..db.vulnerability import VulnerabilityCache
from .mixins import CacheableMixin
from .utils import create_http_session


class RateLimitExceeded(Exception):
    """Exception raised when GitHub API rate limit is exceeded."""
    pass


class GitHubProvider(CacheableMixin):
    """
    Repository provider for GitHub API integration.

    Handles repository activity analysis, statistics, and metrics collection.
    """

    def __init__(self, config: Dict, cache: Optional[VulnerabilityCache] = None):
        self.config = config
        self.logger = logging.getLogger(self.__class__.__name__)

        # Initialize cache
        if cache is None and config.get("caching", {}).get("enabled", False):
            cache_path = config.get("caching", {}).get("path", ".cache/zsbom.db")
            self.cache = VulnerabilityCache(cache_path)
        else:
            self.cache = cache

        # GitHub API configuration
        github_config = config.get("enhancers", {}).get("github", {})
        self.github_token = github_config.get("token")
        self.api_base_url = "https://api.github.com"

        # HTTP session
        self.session = self._create_session()

        # Rate limiting
        self.rate_limit_per_hour = 5000 if self.github_token else 60
        self.requests_made = 0
        self.rate_limit_window_start = time.time()

        self.stats = {"api_calls": 0, "cache_hits": 0, "errors": 0}

    def _create_session(self) -> requests.Session:
        timeout = self.config.get("enhancers", {}).get("timeout_seconds", 30)
        return create_http_session(
            user_agent="ZSBOM-GitHubProvider/1.0",
            timeout=timeout,
            max_retries=3,
            auth_token=self.github_token
        )

    def enhance(self, packages: List[Tuple[str, str]], ecosystem: str, context: Dict) -> Dict[str, Any]:
        """Enhance packages with GitHub repository data."""
        if not packages:
            return {}

        results = {}

        # Group packages by repository URL to avoid duplicate API calls
        repo_groups = self._group_packages_by_repository(packages, context)

        for repo_url, repo_packages in repo_groups.items():
            if not self._is_github_repository(repo_url):
                continue

            try:
                repo_data = self._get_repository_data(repo_url)

                # Apply the same repository data to all packages from this repo
                for package, version in repo_packages:
                    package_repo_data = repo_data.copy()
                    package_repo_data.update({
                        "package": package,
                        "version": version,
                        "ecosystem": ecosystem
                    })
                    results[package] = package_repo_data

            except Exception as e:
                self.logger.warning(f"Repository analysis failed for {repo_url}: {e}")
                # Mark all packages from this repo as failed
                for package, version in repo_packages:
                    results[package] = self._get_fallback_repo_data(package, version, ecosystem, repo_url, e)

        return results

    def _group_packages_by_repository(self, packages: List[Tuple[str, str]], context: Dict) -> Dict[str, List[Tuple[str, str]]]:
        """Group packages by their repository URL to optimize API calls."""
        repo_groups = {}

        for package, version in packages:
            # Get repository URL from metadata context
            package_metadata = context.get("metadata", {}).get(package, {})
            repository_info = package_metadata.get("repository", {})
            repo_url = repository_info.get("normalized_url") or repository_info.get("url")

            if repo_url and self._is_github_repository(repo_url):
                if repo_url not in repo_groups:
                    repo_groups[repo_url] = []
                repo_groups[repo_url].append((package, version))

        return repo_groups

    def _is_github_repository(self, repo_url: str) -> bool:
        """Check if repository URL is a GitHub repository."""
        if not repo_url:
            return False
        try:
            parsed = urlparse(repo_url)
            return "github.com" in parsed.netloc.lower()
        except Exception:
            return False

    def _get_repository_data(self, repo_url: str) -> Dict[str, Any]:
        """Get repository data from GitHub API."""
        # Check cache first
        cache_key = f"github_repo:{repo_url}"
        cached_data = self._get_cached_data(cache_key, 4)  # 4 hours
        if cached_data:
            self.stats["cache_hits"] += 1
            return cached_data

        # Extract owner and repo from URL
        owner, repo = self._parse_github_url(repo_url)
        if not owner or not repo:
            raise ValueError(f"Invalid GitHub URL: {repo_url}")

        # Check rate limit
        self._check_rate_limit()

        # Get repository information
        repo_api_url = f"{self.api_base_url}/repos/{owner}/{repo}"
        response = self._make_request("GET", repo_api_url)
        repo_info = response.json()

        # Get additional data
        commits_data = self._get_commit_activity(owner, repo)

        result = {
            "enhanced": True,
            "source": "github",
            "repository_url": repo_url,
            "repository": {
                "owner": owner,
                "name": repo,
                "full_name": f"{owner}/{repo}",
                "description": repo_info.get("description", ""),
                "stars": repo_info.get("stargazers_count", 0),
                "forks": repo_info.get("forks_count", 0),
                "open_issues": repo_info.get("open_issues_count", 0),
                "language": repo_info.get("language", ""),
                "created_at": repo_info.get("created_at", ""),
                "updated_at": repo_info.get("updated_at", ""),
                "pushed_at": repo_info.get("pushed_at", ""),
                "default_branch": repo_info.get("default_branch", "main")
            },
            "activity": {
                "commits": commits_data
            }
        }

        # Cache result
        self._cache_data(cache_key, result)
        self.stats["api_calls"] += 1
        return result

    def _parse_github_url(self, repo_url: str) -> Tuple[Optional[str], Optional[str]]:
        """Parse GitHub URL to extract owner and repository name."""
        try:
            # Handle various GitHub URL formats
            patterns = [
                r'github\.com[/:]([^/]+)/([^/]+?)(?:\.git)?/?$',
                r'^https://github\.com/([^/]+)/([^/]+?)(?:\.git)?/?$',
                r'^git@github\.com:([^/]+)/([^/]+?)(?:\.git)?/?$'
            ]

            for pattern in patterns:
                match = re.search(pattern, repo_url)
                if match:
                    return match.group(1), match.group(2)

            return None, None
        except Exception:
            return None, None

    def _get_commit_activity(self, owner: str, repo: str) -> Dict[str, Any]:
        """Get commit activity data."""
        try:
            # Get recent commits (last 30 days)
            since_date = (datetime.now(timezone.utc) - timedelta(days=30)).isoformat()
            commits_url = f"{self.api_base_url}/repos/{owner}/{repo}/commits"
            params = {"since": since_date, "per_page": 100}

            response = self._make_request("GET", commits_url, params=params)
            commits = response.json()

            return {
                "recent_commits_count": len(commits),
                "last_commit_date": commits[0].get("commit", {}).get("author", {}).get("date", "") if commits else "",
                "has_recent_activity": len(commits) > 0
            }
        except Exception as e:
            self.logger.warning(f"Failed to get commit activity for {owner}/{repo}: {e}")
            return {"recent_commits_count": 0, "last_commit_date": "", "has_recent_activity": False}


    def _check_rate_limit(self):
        """Check rate limit and skip if exceeded."""
        current_time = time.time()

        # Reset window if needed
        if current_time - self.rate_limit_window_start >= 3600:  # 1 hour
            self.requests_made = 0
            self.rate_limit_window_start = current_time

        # Check if we're at the limit
        if self.requests_made >= self.rate_limit_per_hour - 10:  # Safety buffer
            self.logger.warning(f"GitHub rate limit reached ({self.requests_made}/{self.rate_limit_per_hour}). Skipping remaining requests.")
            raise RateLimitExceeded("GitHub API rate limit reached")

    def _make_request(self, method: str, url: str, **kwargs) -> requests.Response:
        """Make HTTP request with rate limiting."""
        self.requests_made += 1
        response = self.session.request(method, url, **kwargs)
        response.raise_for_status()
        return response

    def _get_fallback_repo_data(self, package: str, version: str, ecosystem: str, repo_url: str, error: Exception) -> Dict[str, Any]:
        """Generate fallback repository data."""
        return {
            "enhanced": False,
            "source": "github",
            "error": str(error),
            "package": package,
            "version": version,
            "ecosystem": ecosystem,
            "repository_url": repo_url,
            "repository": {},
            "activity": {
                "commits": {"recent_commits_count": 0, "last_commit_date": "", "has_recent_activity": False}
            }
        }