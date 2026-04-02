"""
Simplified deps.dev metadata provider.

Handles package metadata, licensing, repository URLs, and scorecard data
from the deps.dev API for multiple ecosystems.
"""

import logging
import time
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import quote, urlparse

import requests

from ..db.vulnerability import VulnerabilityCache
from ..utils.api_error_handler import handle_external_api_errors
from .formatters import PackageKeyFormatter
from .constants import DEPSDEV_ECOSYSTEM_MAPPING
from .mixins import CacheableMixin
from .utils import create_http_session


class DepsDevProvider(CacheableMixin):
    """
    Metadata provider for deps.dev API supporting multiple ecosystems.

    Handles package metadata, licensing, repository URLs, and scorecard data.
    """

    # API Configuration Constants
    BATCH_SIZE = 100  # deps.dev API limit is 100 packages per batch request
    RATE_LIMIT_DELAY = 0.1  # seconds between requests
    CACHE_TTL_BATCH = 12  # hours for batch results
    CACHE_TTL_STANDARD = 24  # hours for individual results

    def __init__(
        self, config: Dict[str, Any], cache: Optional[VulnerabilityCache] = None
    ):
        self.config = config
        self.logger = logging.getLogger(self.__class__.__name__)

        # Initialize cache
        if cache is None and config.get("caching", {}).get("enabled", False):
            cache_path = config.get("caching", {}).get("path", ".cache/zsbom.db")
            self.cache = VulnerabilityCache(cache_path)
        else:
            self.cache = cache

        # API configuration
        self.base_url = "https://api.deps.dev"
        self.api_version = "v3alpha"

        # HTTP session
        self.session = self._create_session()

        # Ecosystem mapping (use shared constant)
        self.ecosystem_mapping = DEPSDEV_ECOSYSTEM_MAPPING

        self.last_request_time = 0
        self.stats = {"api_calls": 0, "cache_hits": 0, "errors": 0}

    def _create_session(self) -> requests.Session:
        return create_http_session(
            user_agent="ZSBOM-DepsDevProvider/1.0",
            timeout=30,
            max_retries=3
        )

    def enhance(
        self, packages: List[Tuple[str, str]], ecosystem: str, context: Dict
    ) -> Dict[str, Any]:
        """Enhance packages with metadata from deps.dev API."""
        if not packages:
            return {}

        ecosystem_lower = ecosystem.lower()
        if ecosystem_lower not in self.ecosystem_mapping:
            return {}

        # Use batch API for efficiency
        try:
            return self._get_metadata_batch(packages, ecosystem)
        except Exception as e:
            self.logger.error(
                f"Batch metadata fetch failed for {ecosystem} "
                f"({len(packages)} packages): {e}"
            )
            # Return fallback data for all packages
            return {
                pkg: self._get_fallback_data(pkg, ver, ecosystem, e)
                for pkg, ver in packages
            }

    @handle_external_api_errors(service="deps.dev", return_on_error={})
    def get_dependency_graph(
        self, package: str, version: str, ecosystem: str
    ) -> Dict[str, Any]:
        """
        Get dependency graph (nodes and edges) from deps.dev API.

        This endpoint provides parent-child dependency relationships
        for building dependency trees.

        Args:
            package: Package name
            version: Package version
            ecosystem: Ecosystem name (maven, npm, pypi, cargo, etc.)

        Returns:
            Dict with 'nodes' and 'edges' representing dependency graph.
            Returns empty dict if API call fails or package not found.
        """
        ecosystem_lower = ecosystem.lower()
        if ecosystem_lower not in self.ecosystem_mapping:
            self.logger.warning(f"Unsupported ecosystem for dependency graph: {ecosystem}")
            return {}

        deps_ecosystem = self.ecosystem_mapping[ecosystem_lower]

        # Check cache first
        cache_key = f"depsdev_graph:{deps_ecosystem}:{package}:{version}"
        cached_data = self._get_cached_data(cache_key, self.CACHE_TTL_STANDARD)
        if cached_data:
            self.stats["cache_hits"] += 1
            return cached_data

        # Build API URL
        encoded_package = quote(package, safe='')
        url = f"{self.base_url}/{self.api_version}/systems/{deps_ecosystem}/packages/{encoded_package}/versions/{version}:dependencies"

        # Make API request (decorator handles all exceptions)
        response = self._make_request("GET", url)
        graph_data = response.json()

        # Cache the result
        self._cache_data(cache_key, graph_data)
        self.stats["api_calls"] += 1

        return graph_data

    def _get_metadata_batch(
        self, packages: List[Tuple[str, str]], ecosystem: str
    ) -> Dict[str, Dict[str, Any]]:
        """Get metadata using batch API with batch splitting."""
        # Check cache for batch results
        batch_key = PackageKeyFormatter.create_batch_key(packages, ecosystem)
        cache_key = f"depsdev_batch:{batch_key}"
        cached_data = self._get_cached_data(cache_key, self.CACHE_TTL_BATCH)
        if cached_data:
            self.stats["cache_hits"] += len(packages)
            return cached_data

        deps_ecosystem = self.ecosystem_mapping[ecosystem.lower()]

        # Split into batches to handle large package lists
        all_results = {}
        total_batches = (len(packages) + self.BATCH_SIZE - 1) // self.BATCH_SIZE

        for i in range(0, len(packages), self.BATCH_SIZE):
            batch_packages = packages[i : i + self.BATCH_SIZE]
            batch_num = i // self.BATCH_SIZE + 1

            self.logger.info(
                f"Processing deps.dev batch {batch_num}/{total_batches}: "
                f"{len(batch_packages)} packages"
            )

            batch_results = self._process_single_batch(
                batch_packages, deps_ecosystem, ecosystem
            )
            all_results.update(batch_results)

        # Cache combined results
        self._cache_data(cache_key, all_results)
        return all_results

    def _process_single_batch(
        self, packages: List[Tuple[str, str]], deps_ecosystem: str, ecosystem: str
    ) -> Dict[str, Dict[str, Any]]:
        """Process a single batch of packages."""
        # Build batch query
        version_queries = []
        for package, version in packages:
            version_queries.append(
                {
                    "versionKey": {
                        "system": deps_ecosystem,
                        "name": package,
                        "version": version,
                    }
                }
            )

        # Make batch request
        batch_url = f"{self.base_url}/{self.api_version}/versionbatch"
        response = self._make_request(
            "POST", batch_url, json={"requests": version_queries}
        )
        batch_results = response.json()

        # Build response map using versionKey for accurate matching
        # deps.dev API may omit responses for non-existent packages
        response_map = {}
        unique_project_ids = set()

        for response in batch_results.get("responses", []):
            # Get the request info to identify which package this response is for
            request_info = response.get("request", {}).get("versionKey", {})
            request_key = (
                request_info.get("system"),
                request_info.get("name"),
                request_info.get("version")
            )

            # Check for error responses
            if "error" in response:
                self.logger.warning(
                    f"API error for {request_key[1]}@{request_key[2]}: "
                    f"{response.get('error')}"
                )
                continue

            version_info = response.get("version", {})
            if not version_info:
                # Package doesn't exist in deps.dev
                self.logger.debug(
                    f"Package not in deps.dev: {request_key[1]}@{request_key[2]}"
                )
                continue

            # Success - extract version key and add to map
            version_key = version_info.get("versionKey", {})
            key = (
                version_key.get("system"),
                version_key.get("name"),
                version_key.get("version")
            )
            response_map[key] = response

            # Collect project IDs
            for project in version_info.get("relatedProjects", []):
                project_id = project.get("projectKey", {}).get("id")
                if project_id:
                    unique_project_ids.add(project_id)

        # Log batch statistics
        self.logger.info(
            f"Batch results: requested {len(packages)}, "
            f"received {len(batch_results.get('responses', []))} responses, "
            f"matched {len(response_map)} packages"
        )

        # Fetch all projects in batch
        projects_data = self._get_project_batch(unique_project_ids)

        # Fetch all package info in batch for release data
        unique_packages = {pkg for pkg, _ in packages}
        packages_info_data = self._get_package_info_batch(unique_packages, deps_ecosystem)

        # Process results with project data using key-based lookup
        results = {}
        for package, version in packages:
            key = (deps_ecosystem, package, version)
            if key in response_map:
                version_data = response_map[key]
                results[package] = self._process_version_data(
                    package, version, ecosystem, version_data, projects_data, packages_info_data
                )
            else:
                self.logger.debug(f"No deps.dev data for: {package}@{version}")
                results[package] = self._get_fallback_data(
                    package,
                    version,
                    ecosystem,
                    Exception(f"Package {package}@{version} not found in deps.dev"),
                )

        self.stats["api_calls"] += 1
        return results

    def _process_version_data(
        self,
        package: str,
        version: str,
        ecosystem: str,
        version_data: Dict,
        projects_data: Optional[Dict[str, Dict[str, Any]]] = None,
        packages_info_data: Optional[Dict[str, Dict[str, Any]]] = None,
    ) -> Dict[str, Any]:
        """Process version data from batch response."""
        if not version_data or "version" not in version_data:
            return self._get_fallback_data(
                package, version, ecosystem, Exception("Invalid version data")
            )

        version_info = version_data["version"]
        repository_url = self._extract_repository_url(version_info=version_info)

        # Get project data for description if related projects exist
        project_data = {}
        related_projects = version_info.get("relatedProjects", [])
        if related_projects:
            # Try to find SOURCE_REPO project first
            project_id = None
            for project in related_projects:
                if project.get("relationType") == "SOURCE_REPO":
                    project_id = project.get("projectKey", {}).get("id")
                    break

            # If no SOURCE_REPO, take first available project
            if not project_id and related_projects:
                project_id = related_projects[0].get("projectKey", {}).get("id")

            if project_id:
                # Use batch project data if available, otherwise fetch individually
                if projects_data and project_id in projects_data:
                    project_data = projects_data[project_id]
                else:
                    project_data = self._fetch_project_info(project_id)

        # Organize links from version data
        version_links = version_info.get("links", [])
        links = self._organize_links(version_links, project_data)

        # Get release data from batch package info
        releases_data = {"releases_count": 0, "latest_release_date": "", "has_releases": False, "recent_releases": []}
        if packages_info_data and package in packages_info_data:
            package_info = packages_info_data[package]
            if package_info:
                releases_data = self._get_release_activity_from_package_info(package_info)

        return {
            "enhanced": True,
            "source": "deps.dev",
            "package": package,
            "version": version,
            "ecosystem": ecosystem,
            "description": project_data.get("description", ""),
            "links": links,
            "licenses": self._extract_licenses({}, version_info),
            "repository": {
                "url": repository_url,
                "type": self._get_repository_type(repository_url),
                "normalized_url": self._normalize_repository_url(repository_url),
            },
            "scorecard": project_data.get("scorecard", {}),
            "releases": releases_data,
            "metadata": {
                "creation_date": version_info.get("publishedAt", ""),
                "open_issues_count": project_data.get("openIssuesCount"),
                "stars_count": project_data.get("starsCount"),
                "forks_count": project_data.get("forksCount"),
            },
        }

    @handle_external_api_errors(service="deps.dev", return_on_error={})
    def _fetch_package_info(self, ecosystem: str, package: str) -> Dict[str, Any]:
        """Fetch package info from deps.dev."""
        url = f"{self.base_url}/{self.api_version}/systems/{ecosystem}/packages/{quote(package, safe='')}"
        response = self._make_request("GET", url)
        return response.json()

    def _get_project_batch(self, project_ids: Set[str]) -> Dict[str, Dict[str, Any]]:
        """Get multiple projects using batch API."""
        if not project_ids:
            return {}

        # Filter out empty project IDs
        valid_project_ids = [pid for pid in project_ids if pid]
        if not valid_project_ids:
            return {}

        # Check cache for all projects first
        cached_projects = {}
        uncached_project_ids = []

        for project_id in valid_project_ids:
            cache_key = f"depsdev_project:{project_id}"
            cached_data = self._get_cached_data(cache_key, self.CACHE_TTL_STANDARD)
            if cached_data:
                cached_projects[project_id] = cached_data
            else:
                uncached_project_ids.append(project_id)

        # If all are cached, return cached data
        if not uncached_project_ids:
            return cached_projects

        # Build batch query for uncached projects
        project_queries = []
        for project_id in uncached_project_ids:
            project_queries.append({"projectKey": {"id": project_id}})

        # Make batch request with retry logic
        batch_url = f"{self.base_url}/{self.api_version}/projectbatch"
        try:
            response = self._make_request(
                "POST", batch_url, json={"requests": project_queries}
            )
            batch_results = response.json()

            # Process results using key-based matching
            batch_projects = {}
            response_map = {}

            # Build response map using projectKey for accurate matching
            for response in batch_results.get("responses", []):
                request_info = response.get("request", {}).get("projectKey", {})
                project_id = request_info.get("id")
                if project_id and "project" in response:
                    response_map[project_id] = response.get("project", {})

            # Match responses to requested project IDs
            for project_id in uncached_project_ids:
                if project_id in response_map:
                    project_data = response_map[project_id]
                    batch_projects[project_id] = project_data

                    # Cache the project data
                    cache_key = f"depsdev_project:{project_id}"
                    self._cache_data(cache_key, project_data)
                else:
                    self.logger.debug(f"No project data for: {project_id}")
                    batch_projects[project_id] = {}

            # Combine cached and batch results
            all_projects = {**cached_projects, **batch_projects}
            self.stats["api_calls"] += 1
            return all_projects

        except Exception as e:
            self.logger.warning(
                f"Batch project fetch failed for {len(uncached_project_ids)} projects: {e}"
            )
            # On failure, return cached data only
            return cached_projects

    def _get_package_info_batch(
        self, package_names: Set[str], ecosystem: str
    ) -> Dict[str, Dict[str, Any]]:
        """
        Get package info for multiple packages.
        Since there's no batch API for package info, we use concurrent requests
        with aggressive caching to minimize API calls.
        """
        if not package_names:
            return {}

        # Check cache for all packages first
        cached_packages = {}
        uncached_package_names = []

        for package_name in package_names:
            cache_key = f"depsdev_package:{ecosystem}:{package_name}"
            cached_data = self._get_cached_data(cache_key, self.CACHE_TTL_STANDARD)
            if cached_data:
                cached_packages[package_name] = cached_data
            else:
                uncached_package_names.append(package_name)

        # If all are cached, return cached data
        if not uncached_package_names:
            self.logger.debug(
                f"All {len(package_names)} packages found in cache"
            )
            return cached_packages

        # Fetch uncached packages individually (no batch API available)
        self.logger.info(
            f"Fetching package info for {len(uncached_package_names)} packages "
            f"(cached: {len(cached_packages)})"
        )

        batch_packages = {}
        for package_name in uncached_package_names:
            try:
                package_info = self._fetch_package_info(ecosystem, package_name)
                if package_info:
                    batch_packages[package_name] = package_info

                    # Cache the package data
                    cache_key = f"depsdev_package:{ecosystem}:{package_name}"
                    self._cache_data(cache_key, package_info)
                else:
                    batch_packages[package_name] = {}
            except Exception as e:
                self.logger.warning(
                    f"Failed to fetch package info for {package_name}: {e}"
                )
                batch_packages[package_name] = {}

        # Combine cached and fetched results
        all_packages = {**cached_packages, **batch_packages}
        return all_packages

    def _get_release_activity_from_package_info(self, package_info: Dict[str, Any]) -> Dict[str, Any]:
        """Extract release activity data from existing package info."""
        try:
            versions = package_info.get("versions", [])
            if not versions:
                return {"releases_count": 0, "latest_release_date": "", "has_releases": False, "recent_releases": []}

            # Sort versions by published date (most recent first)
            sorted_versions = sorted(
                [v for v in versions if v.get("publishedAt")],
                key=lambda x: x["publishedAt"],
                reverse=True
            )

            # Get recent releases (last 10)
            recent_releases = []
            for version in sorted_versions[:10]:
                recent_releases.append({
                    "version": version["versionKey"]["version"],
                    "published_at": version["publishedAt"],
                    "is_default": version.get("isDefault", False)
                })

            return {
                "releases_count": len(sorted_versions),
                "latest_release_date": sorted_versions[0]["publishedAt"] if sorted_versions else "",
                "has_releases": len(sorted_versions) > 0,
                "recent_releases": recent_releases
            }

        except Exception as e:
            self.logger.warning(f"Failed to extract release activity from package info: {e}")
            return {"releases_count": 0, "latest_release_date": "", "has_releases": False, "recent_releases": []}

    @handle_external_api_errors(service="deps.dev", return_on_error={})
    def _fetch_project_info(self, project_id: str) -> Dict[str, Any]:
        """Fetch project info from deps.dev."""
        if not project_id:
            return {}

        # Check cache first
        cache_key = f"depsdev_project:{project_id}"
        cached_data = self._get_cached_data(cache_key, self.CACHE_TTL_STANDARD)
        if cached_data:
            return cached_data

        url = (
            f"{self.base_url}/{self.api_version}/projects/{quote(project_id, safe='')}"
        )
        response = self._make_request("GET", url)
        project_data = response.json()

        # Cache the project data
        self._cache_data(cache_key, project_data)
        return project_data

    def _organize_links(
        self, version_links: List[Dict[str, Any]], project_data: Dict[str, Any]
    ) -> Dict[str, Optional[str]]:
        """Organize links from version and project data into structured format."""
        links: Dict[str, Optional[str]] = {
            "homepage": None,
            "documentation": None,
            "source_repository": None,
            "issue_tracker": None,
            "origin": None,
        }

        # Process version links
        for link in version_links:
            label = link.get("label", "").upper()
            url = link.get("url", "")
            if not url:
                continue

            if label == "HOMEPAGE":
                links["homepage"] = url
            elif label == "DOCUMENTATION":
                links["documentation"] = url
            elif label == "SOURCE_REPO":
                links["source_repository"] = url
            elif label == "ISSUE_TRACKER":
                links["issue_tracker"] = url
            elif label == "ORIGIN":
                links["origin"] = url

        # Fallback to project data if not found in version links
        if not links["homepage"] and project_data.get("homepage"):
            links["homepage"] = project_data["homepage"]

        return links

    def _extract_repository_url(
        self,
        package_info: Optional[Dict[str, Any]] = None,
        version_info: Optional[Dict[str, Any]] = None,
    ) -> Optional[str]:
        """
        Extract repository URL from package or version metadata.

        Args:
            package_info: Package metadata dictionary (optional)
            version_info: Version metadata dictionary (optional)

        Returns:
            Repository URL if found, None otherwise
        """
        package_info = package_info or {}
        version_info = version_info or {}

        # Check version_info links for SOURCE_REPO (highest priority)
        for link in version_info.get("links", []):
            if link.get("label") == "SOURCE_REPO":
                url = link.get("url", "")
                if self._is_repository_url(url):
                    return url.split("#")[0] if url else None

        # Check related projects from package_info
        for project in package_info.get("relatedProjects", []):
            project_key = project.get("projectKey", {})
            project_type = project_key.get("type", "").upper()
            if project_type in ["GITHUB", "GITLAB", "BITBUCKET"]:
                project_id = project_key.get("id", "")
                if project_id:
                    return self._build_repository_url(project_type, project_id)

        # Check links from package_info
        for link in package_info.get("links", []):
            url = link.get("url", "")
            if self._is_repository_url(url):
                return url

        return None

    def _build_repository_url(self, repo_type: str, project_id: str) -> str:
        """Build repository URL from type and ID."""
        if repo_type == "GITHUB":
            return f"https://github.com/{project_id}"
        elif repo_type == "GITLAB":
            return f"https://gitlab.com/{project_id}"
        elif repo_type == "BITBUCKET":
            return f"https://bitbucket.org/{project_id}"
        return project_id

    def _is_repository_url(self, url: str) -> bool:
        """Check if URL is a repository URL."""
        if not url:
            return False
        repo_hosts = [
            "github.com",
            "gitlab.com",
            "bitbucket.org",
            "git.sr.ht",
            "codeberg.org",
        ]
        try:
            parsed = urlparse(url)
            return any(host in parsed.netloc.lower() for host in repo_hosts)
        except Exception:
            return False

    def _get_repository_type(self, repository_url: Optional[str]) -> Optional[str]:
        """Determine repository type from URL."""
        if not repository_url:
            return None
        try:
            netloc = urlparse(repository_url).netloc.lower()
            if "github.com" in netloc:
                return "github"
            elif "gitlab.com" in netloc:
                return "gitlab"
            elif "bitbucket.org" in netloc:
                return "bitbucket"
            return "git"
        except Exception:
            return None

    def _normalize_repository_url(self, repository_url: Optional[str]) -> Optional[str]:
        """Normalize repository URL."""
        if not repository_url:
            return None
        try:
            normalized = repository_url.rstrip("/").replace(".git", "")
            if normalized.startswith("git@"):
                normalized = normalized.replace("git@", "https://").replace(":", "/", 1)
            if normalized.startswith("http://"):
                normalized = normalized.replace("http://", "https://")
            return normalized
        except Exception:
            return repository_url

    def _extract_licenses(
        self, package_info: Dict[str, Any], version_info: Dict[str, Any]
    ) -> List[str]:
        """Extract license information."""
        licenses = []
        licenses.extend(version_info.get("licenses", []))
        licenses.extend(package_info.get("licenses", []))
        return list(set(licenses))

    def _make_request(self, method: str, url: str, **kwargs) -> requests.Response:
        """Make HTTP request with rate limiting."""
        current_time = time.time()
        if current_time - self.last_request_time < self.RATE_LIMIT_DELAY:
            time.sleep(self.RATE_LIMIT_DELAY)
        self.last_request_time = current_time

        response = self.session.request(method, url, **kwargs)
        response.raise_for_status()
        return response

    def _get_fallback_data(
        self, package: str, version: str, ecosystem: str, error: Exception
    ) -> Dict[str, Any]:
        """Generate fallback data when fetch fails."""
        return {
            "enhanced": False,
            "source": "deps.dev",
            "error": str(error),
            "package": package,
            "version": version,
            "ecosystem": ecosystem,
            "description": "",
            "links": {
                "homepage": None,
                "documentation": None,
                "source_repository": None,
                "issue_tracker": None,
                "origin": None,
            },
            "licenses": [],
            "repository": {"url": None, "type": None, "normalized_url": None},
            "scorecard": {},
            "releases": {"releases_count": 0, "latest_release_date": "", "has_releases": False, "recent_releases": []},
            "metadata": {
                "creation_date": "",
                "open_issues_count": None,
                "stars_count": None,
                "forks_count": None,
            },
        }
