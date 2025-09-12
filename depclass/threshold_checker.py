"""
Vulnerability Threshold Checker for ZSBOM

This module provides threshold-based vulnerability scoring and decision making
for build failure scenarios in CI/CD pipelines.
"""
import logging
from typing import Dict, List, Any, Optional
from dataclasses import dataclass


@dataclass 
class ThresholdConfig:
    """Configuration for vulnerability threshold checking."""
    enabled: bool = False
    high_severity_weight: int = 5
    medium_severity_weight: int = 3
    low_severity_weight: int = 1
    max_score_threshold: int = 50
    fail_on_critical: bool = True


@dataclass
class VulnerabilityCounts:
    """Count of vulnerabilities by severity level."""
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0


@dataclass
class ThresholdResult:
    """Result of threshold checking."""
    threshold_exceeded: bool
    calculated_score: int
    max_threshold: int
    vulnerability_counts: VulnerabilityCounts
    critical_vulnerabilities_found: bool
    should_fail_build: bool
    failure_reason: Optional[str] = None


class ThresholdChecker:
    """
    Vulnerability threshold checker for build failure decisions.
    
    This class evaluates vulnerability scan results against configured thresholds
    and determines whether a build should fail based on:
    1. Critical vulnerabilities (always fail when threshold is enabled)
    2. Weighted score calculation: (High × Weight) + (Medium × Weight) + (Low × Weight)
    """
    
    def __init__(self, config: ThresholdConfig):
        """
        Initialize threshold checker with configuration.
        
        Args:
            config: Threshold configuration with weights and limits
        """
        self.config = config
        self.logger = logging.getLogger(__name__)
        
    def check_thresholds(self, validation_report: Dict[str, Any]) -> ThresholdResult:
        """
        Check vulnerability thresholds against validation report.
        
        Args:
            validation_report: ZSBOM validation report containing vulnerability data
            
        Returns:
            ThresholdResult with decision and score details
        """
        if not self.config.enabled:
            return ThresholdResult(
                threshold_exceeded=False,
                calculated_score=0,
                max_threshold=self.config.max_score_threshold,
                vulnerability_counts=VulnerabilityCounts(),
                critical_vulnerabilities_found=False,
                should_fail_build=False,
            )
        
        # Extract vulnerability counts from validation report
        vuln_counts = self._extract_vulnerability_counts(validation_report)
        
        # Check for critical vulnerabilities
        critical_found = vuln_counts.critical > 0
        
        # Calculate weighted score (excludes critical vulnerabilities)
        calculated_score = self._calculate_weighted_score(vuln_counts)
        
        # Determine if score exceeds threshold
        score_exceeded = calculated_score > self.config.max_score_threshold
        
        # Determine if build should fail
        should_fail = False
        failure_reason = None
        
        if critical_found and self.config.fail_on_critical:
            should_fail = True
            failure_reason = f"Critical vulnerabilities found: {vuln_counts.critical}"
        elif score_exceeded:
            should_fail = True
            failure_reason = f"Vulnerability score {calculated_score} exceeds threshold {self.config.max_score_threshold}"
            
        self.logger.info(
            f"Threshold check result: score={calculated_score}, threshold={self.config.max_score_threshold}, "
            f"critical={vuln_counts.critical}, should_fail={should_fail}"
        )
        
        return ThresholdResult(
            threshold_exceeded=score_exceeded,
            calculated_score=calculated_score,
            max_threshold=self.config.max_score_threshold,
            vulnerability_counts=vuln_counts,
            critical_vulnerabilities_found=critical_found,
            should_fail_build=should_fail,
            failure_reason=failure_reason,
        )
    
    def _extract_vulnerability_counts(self, validation_report: Dict[str, Any]) -> VulnerabilityCounts:
        """
        Extract vulnerability counts by severity from validation report.
        
        Args:
            validation_report: ZSBOM validation report
            
        Returns:
            VulnerabilityCounts with counts by severity
        """
        counts = VulnerabilityCounts()
        
        self.logger.debug(f"Extracting vulnerability counts from report structure: {list(validation_report.keys())}")
        
        # Handle the actual ZSBOM validation report structure
        # Actual structure: validation_report -> cve_issues -> [vuln] -> severity
        cve_issues = validation_report.get("cve_issues", [])
        
        self.logger.debug(f"Found {len(cve_issues)} CVE issues in validation report")
        
        for vuln in cve_issues:
            severity = vuln.get("severity", "").lower()
            package_name = vuln.get("package_name", "unknown")
            
            self.logger.debug(f"Processing vulnerability: {package_name} - {severity.upper()}")
            
            if severity == "critical":
                counts.critical += 1
            elif severity == "high":
                counts.high += 1
            elif severity == "medium":
                counts.medium += 1
            elif severity == "low":
                counts.low += 1
        
        self.logger.info(f"Vulnerability counts - Critical: {counts.critical}, High: {counts.high}, "
                        f"Medium: {counts.medium}, Low: {counts.low}")
        
        return counts
    
    def _calculate_weighted_score(self, vuln_counts: VulnerabilityCounts) -> int:
        """
        Calculate weighted vulnerability score.
        
        Score = (High × high_weight) + (Medium × medium_weight) + (Low × low_weight)
        Note: Critical vulnerabilities are not included in score calculation
        as they always fail when threshold is enabled.
        
        Args:
            vuln_counts: Vulnerability counts by severity
            
        Returns:
            Calculated weighted score
        """
        score = (
            (vuln_counts.high * self.config.high_severity_weight) +
            (vuln_counts.medium * self.config.medium_severity_weight) +
            (vuln_counts.low * self.config.low_severity_weight)
        )
        
        return score
    
    def get_threshold_summary(self, result: ThresholdResult) -> Dict[str, Any]:
        """
        Generate a summary of threshold checking results for reporting.
        
        Args:
            result: ThresholdResult from check_thresholds()
            
        Returns:
            Dictionary with threshold summary data
        """
        return {
            "threshold_config": {
                "enabled": self.config.enabled,
                "weights": {
                    "high": self.config.high_severity_weight,
                    "medium": self.config.medium_severity_weight,
                    "low": self.config.low_severity_weight,
                },
                "max_score_threshold": self.config.max_score_threshold,
                "fail_on_critical": self.config.fail_on_critical,
            },
            "vulnerability_counts": {
                "critical": result.vulnerability_counts.critical,
                "high": result.vulnerability_counts.high,
                "medium": result.vulnerability_counts.medium,
                "low": result.vulnerability_counts.low,
            },
            "scoring": {
                "calculated_score": result.calculated_score,
                "max_threshold": result.max_threshold,
                "threshold_exceeded": result.threshold_exceeded,
            },
            "decision": {
                "critical_vulnerabilities_found": result.critical_vulnerabilities_found,
                "should_fail_build": result.should_fail_build,
                "failure_reason": result.failure_reason,
            },
        }