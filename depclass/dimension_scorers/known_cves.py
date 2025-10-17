"""Known CVEs dimension scorer."""

from typing import Any, Dict, List, Optional

from ..cvss_utils import CVSSExtractor
from .base import DimensionScorer


class KnownCVEsScorer(DimensionScorer):
    """Scores packages based on known CVE vulnerabilities.
    
    Scoring criteria:
    - No CVEs: 10.0
    - Low severity CVEs only: 7.0-9.0
    - Medium severity CVEs: 4.0-6.0
    - High severity CVEs: 1.0-3.0
    - Critical severity CVEs: 0.0-1.0
    
    Multiple CVEs compound the risk (lower score).
    """

    # CVSS severity mappings
    SEVERITY_WEIGHTS = {
        "CRITICAL": 0.0,
        "HIGH": 2.0,
        "MEDIUM": 5.0,
        "LOW": 8.0,
        "NONE": 10.0,
    }

    def score(
        self,
        package: str,
        installed_version: str,
        declared_version: Optional[str] = None,
        cve_list: Optional[List[Dict[str, Any]]] = None,
        **kwargs: Any
    ) -> float:
        """Calculate CVE risk score.
        
        Args:
            package: Package name
            installed_version: Currently installed version
            declared_version: Version declared in requirements
            cve_list: List of CVE dictionaries affecting this package
            **kwargs: Additional data (unused)
            
        Returns:
            Score between 0.0 (highest risk) and 10.0 (lowest risk)
        """
        if not cve_list:
            return 10.0  # No CVEs found
        
        # Filter CVEs for this specific package
        relevant_cves = [cve for cve in cve_list if cve.get("package_name") == package]
        
        if not relevant_cves:
            return 10.0  # No CVEs for this package
        
        # Calculate base score from most severe CVE
        worst_severity = self._get_worst_severity(relevant_cves)
        base_score = self.SEVERITY_WEIGHTS.get(worst_severity, 5.0)
        
        # Apply penalty for multiple CVEs
        cve_count = len(relevant_cves)
        if cve_count > 1:
            # Reduce score by 0.5 for each additional CVE, minimum 0.0
            count_penalty = min(2.0, (cve_count - 1) * 0.5)
            base_score = max(0.0, base_score - count_penalty)
        
        # Apply penalty for unfixed CVEs
        unfixed_count = sum(1 for cve in relevant_cves if not self._is_fixed(cve))
        if unfixed_count > 0:
            unfixed_penalty = min(1.0, unfixed_count * 0.3)
            base_score = max(0.0, base_score - unfixed_penalty)
        
        return self.validate_score(base_score)

    def get_details(
        self,
        package: str,
        installed_version: str,
        declared_version: Optional[str] = None,
        cve_list: Optional[List[Dict[str, Any]]] = None,
        **kwargs: Any
    ) -> Dict[str, Any]:
        """Get detailed CVE scoring information.
        
        Args:
            package: Package name
            installed_version: Currently installed version
            declared_version: Version declared in requirements
            cve_list: List of CVE dictionaries affecting this package
            **kwargs: Additional data (unused)
            
        Returns:
            Dictionary containing scoring details
        """
        score = self.score(package, installed_version, declared_version, cve_list, **kwargs)
        
        if not cve_list:
            return {
                "dimension": "known_cves",
                "score": score,
                "cve_count": 0,
                "cves": [],
                "worst_severity": None,
            }
        
        relevant_cves = [cve for cve in cve_list if cve.get("package_name") == package]
        
        cve_details = []
        for cve in relevant_cves:
            # Extract CVSS score from cvss_scores array
            cvss_score = cve.get("cvss_score", None)

            cve_details.append({
                "vuln_id": cve.get("vuln_id", cve.get("id")),
                "severity": self._get_severity(cve),
                "summary": cve.get("summary", ""),
                "fixed": self._is_fixed(cve),
                "cvss_score": cvss_score,
            })
        
        return {
            "dimension": "known_cves",
            "score": score,
            "cve_count": len(relevant_cves),
            "cves": cve_details,
            "worst_severity": self._get_worst_severity(relevant_cves),
            "unfixed_count": sum(1 for cve in relevant_cves if not self._is_fixed(cve)),
        }

    def _get_severity(self, cve: Dict[str, Any]) -> str:
        """Extract severity from enhanced CVE data and normalize to standard levels.

        Args:
            cve: Enhanced CVE dictionary with severity field

        Returns:
            Severity string (CRITICAL, HIGH, MEDIUM, LOW, NONE)
        """
        # Use unified CVSS extractor for severity extraction
        severity = CVSSExtractor.extract_severity_from_vuln(cve)

        # Ensure the severity is in our weight map
        if severity in self.SEVERITY_WEIGHTS:
            return severity

        return "MEDIUM"  # Default fallback

    def _get_worst_severity(self, cves: List[Dict[str, Any]]) -> str:
        """Find the worst severity among CVEs.
        
        Args:
            cves: List of CVE dictionaries
            
        Returns:
            Worst severity string
        """
        if not cves:
            return "NONE"
        
        severity_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE"]
        
        for severity in severity_order:
            if any(self._get_severity(cve) == severity for cve in cves):
                return severity
        
        return "NONE"

    def _is_fixed(self, cve: Dict[str, Any]) -> bool:
        """Check if CVE has been fixed based on OSV affected ranges.

        Args:
            cve: Enhanced CVE dictionary

        Returns:
            True if fixed version exists, False otherwise
        """
        # Check if there are any fixed ranges in the affected field
        affected = cve.get("affected", [])
        for affected_item in affected:
            ranges = affected_item.get("ranges", [])
            for range_item in ranges:
                events = range_item.get("events", [])
                # If there's a 'fixed' event, the CVE has a fix
                if any("fixed" in event for event in events):
                    return True

        return False