"""
Unified CVSS score extraction and severity mapping utilities.

This module provides a single source of truth for CVSS score parsing,
vector extraction, and severity level mapping across the entire ZSBOM codebase.

Eliminates duplication across:
- depclass/enhancers/osv_provider.py
- depclass/sbom.py
- depclass/dimension_scorers/known_cves.py
"""

from typing import Dict, List, Optional, Tuple
import logging

try:
    from cvss import CVSS2, CVSS3, CVSS4
    HAS_CVSS_LIBRARY = True
except ImportError:
    HAS_CVSS_LIBRARY = False


logger = logging.getLogger(__name__)


class CVSSExtractor:
    """
    Unified CVSS score and severity extraction.

    Handles multiple CVSS versions with priority-based selection:
    Priority: CVSS_V4 > CVSS_V3 > CVSS_V2

    Supports both OSV.dev API format and enhanced data format.
    """

    # CVSS version priority (lower number = higher priority)
    PRIORITY_MAP = {
        "CVSS_V4": 1,
        "CVSS_V3": 2,  # Handles both 3.0 and 3.1
        "CVSS_V2": 3,
    }

    # CVSS Parser classes by type
    PARSER_MAP = {
        "CVSS_V4": CVSS4 if HAS_CVSS_LIBRARY else None,
        "CVSS_V3": CVSS3 if HAS_CVSS_LIBRARY else None,
        "CVSS_V2": CVSS2 if HAS_CVSS_LIBRARY else None,
    }

    # Severity thresholds based on CVSS v3.x standard
    SEVERITY_THRESHOLDS = [
        (9.0, "CRITICAL"),
        (7.0, "HIGH"),
        (4.0, "MEDIUM"),
        (0.1, "LOW"),
        (0.0, "NONE"),
    ]

    @classmethod
    def extract_best_cvss_score(cls, severity_array: List[Dict]) -> Optional[float]:
        """
        Extract highest priority CVSS base score from severity array.

        Args:
            severity_array: List of severity objects from OSV.dev
                Example: [{"type": "CVSS_V3", "score": "CVSS:3.0/AV:N/AC:L/..."}]

        Returns:
            Float base score or None if extraction fails
        """
        if not severity_array or not isinstance(severity_array, list):
            return None

        if not HAS_CVSS_LIBRARY:
            logger.warning("cvss library not available, cannot parse CVSS vectors")
            return None

        best_score = None
        best_priority = float("inf")

        for item in severity_array:
            if not isinstance(item, dict):
                continue

            cvss_type = item.get("type")
            vector = item.get("score")

            if not cvss_type or not vector:
                continue

            # Get priority for this CVSS version
            priority = cls.PRIORITY_MAP.get(cvss_type, float("inf"))
            parser_class = cls.PARSER_MAP.get(cvss_type)

            if not parser_class or priority >= best_priority:
                continue

            # Try to parse the CVSS vector
            try:
                cvss_obj = parser_class(vector)
                score = cvss_obj.scores()[0]  # Get base score

                if score is not None:
                    best_score = float(score)
                    best_priority = priority
            except Exception as e:
                logger.debug(f"Failed to parse {cvss_type} vector: {e}")
                continue

        return best_score

    @classmethod
    def extract_best_cvss_vector(cls, severity_array: List[Dict]) -> Optional[Tuple[str, str]]:
        """
        Extract highest priority CVSS vector string and type.

        Useful for SBOM generation where we need the actual vector string.

        Args:
            severity_array: List of severity objects from OSV.dev

        Returns:
            Tuple of (vector_string, cvss_type) or None
            Example: ("CVSS:3.0/AV:N/AC:L/...", "CVSS_V3")
        """
        if not severity_array or not isinstance(severity_array, list):
            return None

        best_vector = None
        best_type = None
        best_priority = float("inf")

        for item in severity_array:
            if not isinstance(item, dict):
                continue

            cvss_type = item.get("type")
            vector = item.get("score")

            if not cvss_type or not vector:
                continue

            priority = cls.PRIORITY_MAP.get(cvss_type, float("inf"))

            if priority < best_priority:
                best_vector = vector
                best_type = cvss_type
                best_priority = priority

        return (best_vector, best_type) if best_vector else None

    @classmethod
    def score_to_severity(cls, score: float) -> str:
        """
        Map CVSS score to severity level using standard thresholds.

        Args:
            score: CVSS base score (0.0 - 10.0)

        Returns:
            Severity string: CRITICAL, HIGH, MEDIUM, LOW, or NONE
        """
        if score is None:
            return "UNKNOWN"

        try:
            score_float = float(score)
        except (ValueError, TypeError):
            return "UNKNOWN"

        for threshold, severity in cls.SEVERITY_THRESHOLDS:
            if score_float >= threshold:
                return severity

        return "NONE"

    @classmethod
    def normalize_severity(cls, severity_str: str) -> str:
        """
        Normalize severity strings to standard format.

        Handles OSV.dev "MODERATE" → "MEDIUM" mapping and case normalization.

        Args:
            severity_str: Raw severity string (any case)

        Returns:
            Normalized severity: CRITICAL, HIGH, MEDIUM, LOW, NONE, or UNKNOWN
        """
        if not severity_str:
            return "UNKNOWN"

        severity_upper = str(severity_str).upper()

        # OSV.dev uses "MODERATE" instead of "MEDIUM"
        if severity_upper == "MODERATE":
            return "MEDIUM"

        # Validate against known severity levels
        valid_severities = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE", "UNKNOWN"}
        if severity_upper in valid_severities:
            return severity_upper

        return "UNKNOWN"

    @classmethod
    def extract_severity_from_vuln(cls, vuln: Dict) -> str:
        """
        Extract and normalize severity from vulnerability data.

        Tries multiple sources in priority order:
        1. Explicit severity field
        2. CVSS score calculation
        3. Default to UNKNOWN

        Args:
            vuln: Vulnerability dictionary (OSV.dev or enhanced format)

        Returns:
            Normalized severity string
        """
        # Try explicit severity field first
        severity = vuln.get("severity")
        if severity:
            normalized = cls.normalize_severity(severity)
            if normalized != "UNKNOWN":
                return normalized

        # Try database_specific severity
        db_specific = vuln.get("database_specific", {})
        severity = db_specific.get("severity")
        if severity:
            normalized = cls.normalize_severity(severity)
            if normalized != "UNKNOWN":
                return normalized

        # Try to calculate from CVSS score
        cvss_score = vuln.get("cvss_score")
        if cvss_score is not None:
            return cls.score_to_severity(cvss_score)

        # Try to extract from cvss_vector array
        cvss_vector = vuln.get("cvss_vector", [])
        if cvss_vector:
            score = cls.extract_best_cvss_score(cvss_vector)
            if score is not None:
                return cls.score_to_severity(score)

        # Default fallback
        return "MEDIUM"


def extract_cvss_score(severity_array: List[Dict]) -> Optional[float]:
    """Convenience function for CVSS score extraction."""
    return CVSSExtractor.extract_best_cvss_score(severity_array)


def score_to_severity(score: float) -> str:
    """Convenience function for score to severity mapping."""
    return CVSSExtractor.score_to_severity(score)


def normalize_severity(severity_str: str) -> str:
    """Convenience function for severity normalization."""
    return CVSSExtractor.normalize_severity(severity_str)
