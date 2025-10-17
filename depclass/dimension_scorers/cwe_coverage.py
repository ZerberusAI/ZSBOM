"""CWE Coverage dimension scorer."""

from typing import Any, Dict, List, Optional

from .base import DimensionScorer


class CWECoverageScorer(DimensionScorer):
    """Scores packages based on CWE (Common Weakness Enumeration) coverage.
    
    Scoring criteria:
    - No CWEs: 10.0
    - Low severity CWEs: 7.0-9.0
    - Medium severity CWEs: 4.0-6.0
    - High severity CWEs: 1.0-3.0
    - Critical CWEs: 0.0-1.0
    
    Multiple CWEs compound the risk (lower score).
    """

    # CWE severity mappings based on common CWE classifications
    CWE_SEVERITY_MAP = {
        # High severity - security-critical weaknesses
        "CWE-78": "HIGH",   # OS Command Injection
        "CWE-79": "HIGH",   # XSS
        "CWE-89": "HIGH",   # SQL Injection
        "CWE-94": "HIGH",   # Code Injection
        "CWE-22": "HIGH",   # Path Traversal
        "CWE-611": "HIGH",  # XML External Entity
        "CWE-502": "HIGH",  # Deserialization
        
        # Medium severity - common security issues
        "CWE-79": "MEDIUM", # Cross-site Scripting
        "CWE-200": "MEDIUM", # Information Disclosure
        "CWE-287": "MEDIUM", # Authentication
        "CWE-352": "MEDIUM", # CSRF
        "CWE-434": "MEDIUM", # File Upload
        "CWE-798": "MEDIUM", # Hard-coded Credentials
        
        # Low severity - quality and minor security issues
        "CWE-404": "LOW",   # Resource Management
        "CWE-476": "LOW",   # Null Pointer
        "CWE-835": "LOW",   # Infinite Loop
        "CWE-190": "LOW",   # Integer Overflow
    }

    SEVERITY_WEIGHTS = {
        "HIGH": 1.0,
        "MEDIUM": 4.0,
        "LOW": 7.0,
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
        """Calculate CWE coverage risk score.
        
        Args:
            package: Package name
            installed_version: Currently installed version
            declared_version: Version declared in requirements
            cve_list: List of CVE dictionaries (may contain CWE mappings)
            **kwargs: Additional data (unused)
            
        Returns:
            Score between 0.0 (highest risk) and 10.0 (lowest risk)
        """
        if not cve_list:
            return 10.0  # No CVEs/CWEs found
        
        # Extract CWEs from enhanced CVEs for this package
        relevant_cves = [cve for cve in cve_list if cve.get("package_name") == package]

        if not relevant_cves:
            return 10.0  # No CVEs for this package

        # Collect all CWEs from the relevant CVEs (enhanced structure already promotes CWE IDs)
        all_cwes = []
        for cve in relevant_cves:
            cwe_ids = cve.get("cwe_ids", [])
            all_cwes.extend(cwe_ids)
        
        if not all_cwes:
            return 10.0  # No CWEs found
        
        # Calculate base score from most severe CWE
        worst_severity = self._get_worst_cwe_severity(all_cwes)
        base_score = self.SEVERITY_WEIGHTS.get(worst_severity, 7.0)
        
        # Apply penalty for multiple CWEs
        unique_cwes = set(all_cwes)
        cwe_count = len(unique_cwes)
        if cwe_count > 1:
            # Reduce score by 0.3 for each additional CWE, minimum 0.0
            count_penalty = min(2.0, (cwe_count - 1) * 0.3)
            base_score = max(0.0, base_score - count_penalty)
        
        # Apply penalty for high-severity CWE patterns
        high_severity_count = sum(1 for cwe in unique_cwes if self._get_cwe_severity(cwe) == "HIGH")
        if high_severity_count > 0:
            high_severity_penalty = min(1.5, high_severity_count * 0.5)
            base_score = max(0.0, base_score - high_severity_penalty)
        
        return self.validate_score(base_score)

    def get_details(
        self,
        package: str,
        installed_version: str,
        declared_version: Optional[str] = None,
        cve_list: Optional[List[Dict[str, Any]]] = None,
        **kwargs: Any
    ) -> Dict[str, Any]:
        """Get detailed CWE scoring information.
        
        Args:
            package: Package name
            installed_version: Currently installed version
            declared_version: Version declared in requirements
            cve_list: List of CVE dictionaries (may contain CWE mappings)
            **kwargs: Additional data (unused)
            
        Returns:
            Dictionary containing scoring details
        """
        score = self.score(package, installed_version, declared_version, cve_list, **kwargs)
        
        if not cve_list:
            return {
                "dimension": "cwe_coverage",
                "score": score,
                "cwe_count": 0,
                "cwes": [],
                "worst_severity": None,
            }
        
        relevant_cves = [cve for cve in cve_list if cve.get("package_name") == package]
        
        # Collect all CWEs with their sources (enhanced structure)
        all_cwes = []
        cwe_sources = {}
        for cve in relevant_cves:
            cwe_ids = cve.get("cwe_ids", [])
            vuln_id = cve.get("vuln_id", cve.get("id"))

            for cwe in cwe_ids:
                all_cwes.append(cwe)
                if cwe not in cwe_sources:
                    cwe_sources[cwe] = []
                cwe_sources[cwe].append(vuln_id)
        
        unique_cwes = set(all_cwes)
        cwe_details = []
        for cwe in unique_cwes:
            severity = self._get_cwe_severity(cwe)
            cwe_details.append({
                "cwe_id": cwe,
                "severity": severity,
                "description": self._get_cwe_description(cwe),
                "source_cves": cwe_sources.get(cwe, []),
            })
        
        return {
            "dimension": "cwe_coverage",
            "score": score,
            "cwe_count": len(unique_cwes),
            "cwes": cwe_details,
            "worst_severity": self._get_worst_cwe_severity(list(unique_cwes)),
            "high_severity_count": sum(1 for cwe in unique_cwes if self._get_cwe_severity(cwe) == "HIGH"),
        }

    def _get_cwe_severity(self, cwe: str) -> str:
        """Get severity classification for a CWE.
        
        Args:
            cwe: CWE identifier (e.g., "CWE-78")
            
        Returns:
            Severity string (HIGH, MEDIUM, LOW, NONE)
        """
        if not cwe:
            return "NONE"
        
        # Normalize CWE format
        cwe_normalized = cwe.upper()
        if not cwe_normalized.startswith("CWE-"):
            cwe_normalized = f"CWE-{cwe_normalized}"
        
        # Check predefined severity mappings
        severity = self.CWE_SEVERITY_MAP.get(cwe_normalized)
        if severity:
            return severity
        
        # Extract CWE number for heuristic classification
        try:
            cwe_num = int(cwe_normalized.replace("CWE-", ""))
            
            # Common high-severity ranges
            if cwe_num in [78, 79, 89, 94, 22, 611, 502]:
                return "HIGH"
            # Common medium-severity ranges
            elif cwe_num in [200, 287, 352, 434, 798]:
                return "MEDIUM"
            # Common low-severity ranges
            elif cwe_num in [404, 476, 835, 190]:
                return "LOW"
            else:
                return "MEDIUM"  # Default to medium
        except ValueError:
            return "MEDIUM"  # Default fallback

    def _get_worst_cwe_severity(self, cwes: List[str]) -> str:
        """Find the worst severity among CWEs.
        
        Args:
            cwes: List of CWE identifiers
            
        Returns:
            Worst severity string
        """
        if not cwes:
            return "NONE"
        
        severity_order = ["HIGH", "MEDIUM", "LOW", "NONE"]
        
        for severity in severity_order:
            if any(self._get_cwe_severity(cwe) == severity for cwe in cwes):
                return severity
        
        return "NONE"

    def _get_cwe_description(self, cwe: str) -> str:
        """Get human-readable description for a CWE.
        
        Args:
            cwe: CWE identifier
            
        Returns:
            Description string
        """
        descriptions = {
            "CWE-78": "OS Command Injection",
            "CWE-79": "Cross-site Scripting (XSS)",
            "CWE-89": "SQL Injection",
            "CWE-94": "Code Injection",
            "CWE-22": "Path Traversal",
            "CWE-611": "XML External Entity (XXE)",
            "CWE-502": "Deserialization Vulnerability",
            "CWE-200": "Information Disclosure",
            "CWE-287": "Authentication Bypass",
            "CWE-352": "Cross-Site Request Forgery (CSRF)",
            "CWE-434": "Unrestricted File Upload",
            "CWE-798": "Hard-coded Credentials",
            "CWE-404": "Resource Management Error",
            "CWE-476": "Null Pointer Dereference",
            "CWE-835": "Infinite Loop",
            "CWE-190": "Integer Overflow",
        }
        
        return descriptions.get(cwe, f"Common Weakness Enumeration {cwe}")