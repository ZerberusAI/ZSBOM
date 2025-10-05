"""
Simplified OSV.dev vulnerability provider.

Handles vulnerability scanning, CVSS scoring, and CWE weakness mapping
from the OSV.dev API for multiple ecosystems.
"""

import concurrent.futures
import logging
import time
from typing import Any, Dict, List, Optional, Tuple

import requests

from ..db.vulnerability import VulnerabilityCache
from ..cvss_utils import CVSSExtractor
from .formatters import PackageKeyFormatter
from .constants import OSV_ECOSYSTEM_MAPPING
from .mixins import CacheableMixin
from .utils import create_http_session


class OSVProvider(CacheableMixin):
    """
    Vulnerability provider for OSV.dev API supporting multiple ecosystems.

    Handles vulnerability scanning, CVSS scoring, and CWE weakness mapping.
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

        # API configuration
        self.osv_api_url = (
            config.get("sources", {})
            .get("cve", {})
            .get("osv_dev", {})
            .get("url", "https://api.osv.dev/v1")
        )
        self.batch_size = 1000

        # HTTP session
        self.session = self._create_session()

        # Ecosystem mapping (use shared constant)
        self.ecosystem_mapping = OSV_ECOSYSTEM_MAPPING

        self.last_request_time = 0
        self.stats = {"api_calls": 0, "cache_hits": 0, "errors": 0}

    def _create_session(self) -> requests.Session:
        timeout = self.config.get("enhancers", {}).get("timeout_seconds", 30)
        return create_http_session(
            user_agent="ZSBOM-OSVProvider/1.0",
            timeout=timeout,
            max_retries=3
        )

    def enhance(
        self, packages: List[Tuple[str, str]], ecosystem: str, context: Dict
    ) -> Dict[str, Any]:
        """Enhance packages with vulnerability data from OSV.dev."""
        if not packages:
            return {}

        ecosystem_lower = ecosystem.lower()
        if ecosystem_lower not in self.ecosystem_mapping:
            return {}

        # Use batch API for efficiency
        try:
            return self._get_vulnerabilities_batch(packages, ecosystem)
        except Exception as e:
            self.logger.error(f"Batch vulnerability query failed for {ecosystem}: {e}")
            return {}

    def _get_vulnerabilities_batch(
        self, packages: List[Tuple[str, str]], ecosystem: str
    ) -> Dict[str, Dict[str, Any]]:
        """Get vulnerabilities using batch API."""
        # Check cache
        batch_key = PackageKeyFormatter.create_batch_key(packages, ecosystem)
        cache_key = f"osv_batch:{batch_key}"
        cached_data = self._get_cached_data(cache_key, 24)  # 24 hours
        if cached_data:
            self.stats["cache_hits"] += len(packages)
            return cached_data

        osv_ecosystem = self.ecosystem_mapping[ecosystem.lower()]

        # Build batch queries
        queries = []
        for package, version in packages:
            queries.append(
                {
                    "package": {"name": package, "ecosystem": osv_ecosystem},
                    "version": version,
                }
            )

        # Split into batches if needed
        results = {}
        for i in range(0, len(packages), self.batch_size):
            batch_packages = packages[i : i + self.batch_size]
            batch_queries = queries[i : i + self.batch_size]
            batch_results = self._process_vulnerability_batch(
                batch_packages, batch_queries, ecosystem
            )
            results.update(batch_results)

        # Cache results
        self._cache_data(cache_key, results)
        self.stats["api_calls"] += 1
        return results

    def _fetch_all_vulns(self, vuln_ids):
        """Fetch all vuln details concurrently, return dict[id -> json]."""
        results = {}

        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            future_to_id = {
                executor.submit(self._fetch_single_vuln, vid): vid for vid in vuln_ids
            }
            for future in concurrent.futures.as_completed(future_to_id):
                vid = future_to_id[future]
                try:
                    vuln = future.result()
                    if vuln:
                        results[vid] = vuln
                except Exception as e:
                    self.logger.error(f"Failed to fetch vuln {vid}: {e}")
                    self.stats["errors"] += 1
        return results

    def _fetch_single_vuln(self, vuln_id):
        """Fetch a single vulnerability detail by ID."""
        url = f"{self.osv_api_url}/vulns/{vuln_id}"
        response = self._make_request("GET", url)
        return response.json()

    def _process_vulnerability_batch(
        self, packages: List[Tuple[str, str]], queries: List[Dict], ecosystem: str
    ) -> Dict[str, Dict[str, Any]]:
        """Process batch vulnerability query."""
        # Make batch request
        query_batch_url = self.osv_api_url + "/querybatch"
        response = self._make_request(
            "POST", query_batch_url, json={"queries": queries}
        )
        batch_results = response.json()

        # Step 1: collect all vuln IDs
        package_to_vuln_ids = {}
        all_vuln_ids = set()

        # Process results
        results = {}
        for i, (package, version) in enumerate(packages):
            if i < len(batch_results.get("results", [])):
                osv_result = batch_results["results"][i]
                # results[package] = self._process_vulnerabilities(package, version, ecosystem, osv_result)
                vuln_ids = [
                    v.get("id") for v in osv_result.get("vulns", []) if v.get("id")
                ]
                package_to_vuln_ids[(package, version)] = vuln_ids
                all_vuln_ids.update(vuln_ids)
            else:
                # results[package] = self._get_fallback_vuln_data(package, version, ecosystem)
                package_to_vuln_ids[(package, version)] = []

        # Step 2: fetch all vuln details concurrently
        vuln_details = self._fetch_all_vulns(all_vuln_ids)

        for (package, version), vuln_ids in package_to_vuln_ids.items():
            if vuln_ids:
                results[package] = self._process_vulnerabilities(
                    package, version, ecosystem, vuln_ids, vuln_details
                )
            else:
                results[package] = self._get_fallback_vuln_data(
                    package, version, ecosystem
                )

        return results

    def _process_vulnerabilities(
        self,
        package: str,
        version: str,
        ecosystem: str,
        vuln_ids: List[str],
        vuln_details: Dict[str, Dict],
    ) -> Dict[str, Any]:
        """Process vulnerability data for a package."""
        processed_vulns = []

        for vuln_id in vuln_ids:
            vuln = vuln_details[vuln_id]
            processed_vuln = self._process_single_vulnerability(vuln, version)
            processed_vulns.append(processed_vuln)

        return {
            "enhanced": True,
            "source": "osv.dev",
            "package": package,
            "version": version,
            "ecosystem": ecosystem,
            "vulnerabilities": processed_vulns,
            "vulnerability_count": len(processed_vulns),
            "high_severity_count": len(
                [
                    v
                    for v in processed_vulns
                    if v.get("severity", "").upper() in ["HIGH", "CRITICAL"]
                ]
            ),
        }

    def _process_single_vulnerability(self, vuln: Dict, version: str) -> Dict[str, Any]:
        """Process individual vulnerability."""
        cwe_mappings = []

        db_specific = vuln.get("database_specific", {})
        cwe_ids = db_specific.get("cwe_ids", [])
        cwe_mappings.extend(cwe_ids)

        # Extract CVSS score and severity using unified utilities
        severity_array = vuln.get("severity", [])
        cvss_score = CVSSExtractor.extract_best_cvss_score(severity_array)

        # Get severity from database_specific or calculate from CVSS score
        severity = db_specific.get("severity", "")
        if not severity and cvss_score is not None:
            severity = CVSSExtractor.score_to_severity(cvss_score)
        if not severity:
            severity = "MEDIUM"

        # Normalize severity (handles MODERATE → MEDIUM)
        severity = CVSSExtractor.normalize_severity(severity)

        return {
            "id": vuln.get("id", ""),
            "source": "osv.dev",
            "summary": vuln.get("summary", ""),
            "details": vuln.get("details", ""),
            "severity": severity,
            "cvss_score": cvss_score,
            "cvss_vector": severity_array,  # Store full array for SBOM generation
            "published": vuln.get("published", ""),
            "modified": vuln.get("modified", ""),
            "aliases": vuln.get("aliases", []),
            "references": vuln.get("references", []),
            "affected_versions": self._extract_affected_versions(vuln),
            "fixed": self._extract_fixed_versions(vuln, version),
            "cwe_ids": list(set(cwe_mappings)),
        }

    def _extract_affected_versions(self, vuln: Dict) -> List[str]:
        """Extract affected version ranges."""
        versions = set()
        for affected_item in vuln.get("affected", []):
            for v in affected_item.get("versions", []):
                versions.add(v)
        return list(versions)

    def _extract_fixed_versions(self, vuln: Dict, version: str) -> List[str]:
        """Extract ALL fixed versions from all affected ranges.

        Returns:
            List of fixed version strings, e.g. ["2.5.4", "3.0.4", "4.0.4"]
        """
        fixed_versions = []
        for affected_item in vuln.get("affected", []):
            # Check if current version is in the affected versions list
            affected_versions = affected_item.get("versions", [])
            if affected_versions and version not in affected_versions:
                continue

            for version_range in affected_item.get("ranges", []):
                # Only get fixes from ECOSYSTEM ranges, not GIT ranges
                if version_range.get("type") != "ECOSYSTEM":
                    continue
                events = version_range.get("events", [])
                for event in events:
                    if "fixed" in event:
                        fixed_versions.append(event['fixed'])
        return fixed_versions

    def _make_request(self, method: str, url: str, **kwargs) -> requests.Response:
        """Make HTTP request with rate limiting."""
        current_time = time.time()
        if current_time - self.last_request_time < 0.1:
            time.sleep(0.1)
        self.last_request_time = current_time

        response = self.session.request(method, url, **kwargs)
        response.raise_for_status()
        return response

    def _get_fallback_vuln_data(
        self, package: str, version: str, ecosystem: str
    ) -> Dict[str, Any]:
        """Generate fallback vulnerability data."""
        return {
            "enhanced": False,
            "source": "osv.dev",
            "package": package,
            "version": version,
            "ecosystem": ecosystem,
            "vulnerabilities": [],
            "vulnerability_count": 0,
            "high_severity_count": 0,
            "cwe_ids": [],
        }
