"""Known CVEs dimension scorer."""

from typing import Any, Dict, List, Optional

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
            cve_details.append({
                "vuln_id": cve.get("vuln_id"),
                "severity": self._get_severity(cve),
                "summary": cve.get("summary", ""),
                "fixed": self._is_fixed(cve),
                "cvss_score": cve.get("cvss_score"),
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
        """Extract severity from CVE data.
        
        Args:
            cve: CVE dictionary
            
        Returns:
            Severity string (CRITICAL, HIGH, MEDIUM, LOW, NONE)
        """
        # Try different severity fields
        severity = cve.get("severity", "").upper()
        if severity in self.SEVERITY_WEIGHTS:
            return severity
        
        # Try CVSS score mapping
        cvss_score = cve.get("cvss_score")
        if cvss_score is not None:
            try:
                score = float(cvss_score)
                if score >= 9.0:
                    return "CRITICAL"
                elif score >= 7.0:
                    return "HIGH"
                elif score >= 4.0:
                    return "MEDIUM"
                elif score > 0.0:
                    return "LOW"
                else:
                    return "NONE"
            except (ValueError, TypeError):
                pass
        
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
        """Check if CVE has been fixed.
        
        Args:
            cve: CVE dictionary
            
        Returns:
            True if fixed, False otherwise
        """
        # Check various fields that might indicate fix status
        fixed_in = cve.get("fixed_in")
        if fixed_in:
            return True
        
        patched = cve.get("patched", False)
        if patched:
            return True
        
        # Check if fix is available in newer versions
        fix_available = cve.get("fix_available", False)
        return fix_available