"""
Simplified MITRE weakness provider.

Handles CWE weakness definitions and mappings from the MITRE CWE database
based on vulnerability context from other providers.
"""

import io
import logging
import requests
import xml.etree.ElementTree as ET
import zipfile
from typing import Any, Dict, List, Optional, Tuple

from ..db.vulnerability import VulnerabilityCache
from .mixins import CacheableMixin
from .utils import create_http_session


class MITREProvider(CacheableMixin):
    """
    Weakness provider for MITRE CWE database integration.

    Handles CWE weakness definitions and mappings.
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

        # MITRE configuration
        self.mitre_config = config.get("sources", {}).get("cwe", {}).get("mitre_weaknesses", {})
        self.mitre_url = self.mitre_config.get("url", "https://cwe.mitre.org/data/xml/cwec_latest.xml.zip")

        # HTTP session
        self.session = self._create_session()

        # CWE data cache
        self._cwe_data = None
        self._cwe_loaded = False

        self.stats = {"api_calls": 0, "cache_hits": 0, "errors": 0}

    def _create_session(self) -> requests.Session:
        timeout = self.config.get("enhancers", {}).get("timeout_seconds", 30)
        return create_http_session(
            user_agent="ZSBOM-MITREProvider/1.0",
            timeout=timeout,
            max_retries=3,
            additional_headers={"Accept": "application/zip"}
        )

    def enhance(self, packages: List[Tuple[str, str]], ecosystem: str, context: Dict) -> Dict[str, Any]:
        """Enhance packages with CWE weakness data based on vulnerability context."""
        if not packages:
            return {}

        # Collect all CWE IDs from vulnerability context
        all_cwe_ids = set()
        for package, version in packages:
            vuln_data = context.get("vulnerability", {}).get(package, {})
            cwe_mappings = vuln_data.get("cwe_mappings", [])
            all_cwe_ids.update(cwe_mappings)

        if not all_cwe_ids:
            # Return empty results for packages without CWE data
            return {package: self._get_fallback_weakness_data(package, version, ecosystem)
                    for package, version in packages}

        # Get weakness mappings for all CWE IDs
        weakness_mappings = self._get_weakness_mappings(list(all_cwe_ids))

        # Map weakness data back to packages
        results = {}
        for package, version in packages:
            vuln_data = context.get("vulnerability", {}).get(package, {})
            package_cwe_ids = vuln_data.get("cwe_mappings", [])

            if package_cwe_ids:
                package_weaknesses = {cwe_id: weakness_mappings.get(cwe_id, {})
                                    for cwe_id in package_cwe_ids
                                    if cwe_id in weakness_mappings}

                results[package] = {
                    "enhanced": bool(package_weaknesses),
                    "source": "mitre",
                    "package": package,
                    "version": version,
                    "ecosystem": ecosystem,
                    "weakness_mappings": package_weaknesses,
                    "weakness_count": len(package_weaknesses)
                }
            else:
                results[package] = self._get_fallback_weakness_data(package, version, ecosystem)

        return results

    def _get_weakness_mappings(self, cwe_ids: List[str]) -> Dict[str, Dict[str, Any]]:
        """Get weakness mappings for CWE IDs."""
        # Ensure CWE data is loaded
        if not self._cwe_loaded:
            self._load_cwe_data()

        if not self._cwe_data:
            return {}

        mappings = {}
        for cwe_id in cwe_ids:
            # Normalize CWE ID
            normalized_id = self._normalize_cwe_id(cwe_id)
            cwe_data = self._cwe_data.get(normalized_id)

            if cwe_data:
                mappings[cwe_id] = {
                    "id": cwe_id,
                    "name": cwe_data.get("name", ""),
                    "description": cwe_data.get("description", ""),
                    "likelihood": cwe_data.get("likelihood", ""),
                    "impact": cwe_data.get("impact", ""),
                    "detection_methods": cwe_data.get("detection_methods", []),
                    "mitigation_techniques": cwe_data.get("mitigation_techniques", [])
                }

        return mappings

    def _load_cwe_data(self):
        """Load CWE data from MITRE database."""
        # Check cache first
        cache_key = "mitre_cwe_data"
        cached_data = self._get_cached_data(cache_key, 720)  # 30 days
        if cached_data:
            self._cwe_data = cached_data
            self._cwe_loaded = True
            self.stats["cache_hits"] += 1
            return

        try:
            # Download and parse CWE XML
            response = self._make_request("GET", self.mitre_url)

            # Extract XML from ZIP
            with zipfile.ZipFile(io.BytesIO(response.content)) as zip_file:
                xml_filename = next(name for name in zip_file.namelist() if name.endswith('.xml'))
                xml_content = zip_file.read(xml_filename)

            # Parse XML
            root = ET.fromstring(xml_content)
            cwe_data = {}

            # Extract weakness data
            for weakness in root.findall('.//{http://cwe.mitre.org/cwe-6}Weakness'):
                cwe_id = weakness.get('ID')
                if cwe_id:
                    normalized_id = int(cwe_id)
                    name = weakness.get('Name', '')

                    # Extract description
                    description_elem = weakness.find('.//{http://cwe.mitre.org/cwe-6}Description')
                    description = description_elem.text if description_elem is not None else ''

                    # Extract likelihood and impact
                    likelihood_elem = weakness.find('.//{http://cwe.mitre.org/cwe-6}Likelihood_Of_Exploit')
                    likelihood = likelihood_elem.text if likelihood_elem is not None else ''

                    # Store weakness data
                    cwe_data[normalized_id] = {
                        "id": cwe_id,
                        "name": name,
                        "description": description,
                        "likelihood": likelihood,
                        "impact": "",  # Could be extracted from XML if needed
                        "detection_methods": [],  # Could be extracted from XML if needed
                        "mitigation_techniques": []  # Could be extracted from XML if needed
                    }

            self._cwe_data = cwe_data
            self._cwe_loaded = True

            # Cache the data
            self._cache_data(cache_key, cwe_data)
            self.stats["api_calls"] += 1

            self.logger.info(f"Loaded {len(cwe_data)} CWE weaknesses from MITRE database")

        except Exception as e:
            self.logger.error(f"Failed to load CWE data from MITRE: {e}")
            self._cwe_data = {}
            self._cwe_loaded = True

    def _normalize_cwe_id(self, cwe_id: str) -> int:
        """Normalize CWE ID to integer."""
        try:
            # Remove CWE- prefix if present
            if cwe_id.startswith("CWE-"):
                return int(cwe_id[4:])
            else:
                return int(cwe_id)
        except (ValueError, TypeError):
            return 0

    def _make_request(self, method: str, url: str, **kwargs) -> requests.Response:
        """Make HTTP request."""
        response = self.session.request(method, url, **kwargs)
        response.raise_for_status()
        return response

    def _get_fallback_weakness_data(self, package: str, version: str, ecosystem: str) -> Dict[str, Any]:
        """Generate fallback weakness data."""
        return {
            "enhanced": False,
            "source": "mitre",
            "package": package,
            "version": version,
            "ecosystem": ecosystem,
            "weakness_mappings": {},
            "weakness_count": 0
        }