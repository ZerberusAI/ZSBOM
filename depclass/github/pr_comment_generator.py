"""
PR Comment Generator for GitHub Actions workflows.

Generates rich, branded markdown comments with vulnerability data
for display in GitHub Pull Requests.
"""
import json
import os
from typing import Dict, List, Optional, Any
from datetime import datetime

from depclass.upload.models import ThresholdResult


class PRCommentGenerator:
    """Generates rich GitHub-flavored markdown PR comments with vulnerability data."""

    # GitHub raw URL for Zerberus logo (works on both light/dark themes)
    LOGO_URL = "https://raw.githubusercontent.com/ZerberusAI/ZSBOM/main/assets/ZEB_v1.png"
    LOGO_WIDTH = 300

    # Ecosystem emojis
    ECOSYSTEM_EMOJIS = {
        "python": ":snake:",
        "pypi": ":snake:",
        "npm": ":green_heart:",
        "javascript": ":green_heart:",
        "java": ":coffee:",
        "maven": ":coffee:",
        "go": ":large_blue_diamond:",
        "rust": ":crab:",
        "ruby": ":gem:",
        "php": ":elephant:",
        "csharp": ":large_blue_circle:",
        "dotnet": ":large_blue_circle:",
    }

    # Severity colors
    SEVERITY_COLORS = {
        "critical": ":red_circle:",
        "high": ":orange_circle:",
        "medium": ":yellow_circle:",
        "low": ":large_blue_circle:",
        "unknown": ":white_circle:",
    }

    def __init__(
        self,
        validation_report_path: str,
        risk_report_path: str,
        scan_metadata: dict,
        threshold_result: Optional[ThresholdResult],
        report_url: str,
    ):
        """
        Initialize PR comment generator.

        Args:
            validation_report_path: Path to validation_report.json
            risk_report_path: Path to risk_report.json
            scan_metadata: Scan metadata dictionary
            threshold_result: Threshold validation result (if available)
            report_url: URL to Zerberus dashboard report
        """
        self.validation_report_path = validation_report_path
        self.risk_report_path = risk_report_path
        self.scan_metadata = scan_metadata
        self.threshold_result = threshold_result
        self.report_url = report_url

        # Load reports
        self.validation_report = self._load_json(validation_report_path)
        self.risk_report = self._load_json(risk_report_path)

    def _load_json(self, file_path: str) -> Optional[Dict]:
        """Load JSON file safely."""
        try:
            if os.path.exists(file_path):
                with open(file_path, 'r') as f:
                    return json.load(f)
        except Exception:
            pass
        return None

    def generate(self) -> str:
        """Generate the complete PR comment markdown."""
        sections = []

        # Header with logo and branding
        sections.append(self._generate_header())

        # Status alert box
        sections.append(self._generate_status_alert())

        # Summary section
        sections.append(self._generate_summary())

        # Only add detailed sections if there are issues
        if self._has_vulnerabilities() or self._has_high_risk_packages():
            # High-risk packages
            if self._has_high_risk_packages():
                sections.append(self._generate_high_risk_packages())

            # Vulnerabilities
            if self._has_vulnerabilities():
                sections.append(self._generate_vulnerabilities())

            # Threshold details (if failed)
            if self.threshold_result and self.threshold_result.should_fail_build:
                sections.append(self._generate_threshold_details())

        # Footer with dashboard link
        sections.append(self._generate_footer())

        return "\n\n".join(sections)

    def _generate_header(self) -> str:
        """Generate header with logo and branding."""
        return f"""<div align="center">

<img src="{self.LOGO_URL}" alt="Zerberus" width="{self.LOGO_WIDTH}"/>

# :shield: ZSBOM Security Scan Results
**Powered by Trace-AI by Zerberus**

</div>

---"""

    def _generate_status_alert(self) -> str:
        """Generate status alert box based on scan results."""
        if self.threshold_result and self.threshold_result.should_fail_build:
            exceeded_by = self.threshold_result.calculated_score - self.threshold_result.max_threshold
            return f"""> [!WARNING]
> **Build Status: :x: BLOCKED** - Threshold exceeded by {exceeded_by:.1f} points"""
        elif self._has_critical_vulnerabilities():
            return f"""> [!CAUTION]
> **Build Status: :warning: WARNING** - Critical vulnerabilities detected"""
        else:
            return f"""> [!NOTE]
> **Build Status: :white_check_mark: PASSED** - No threshold violations detected"""

    def _generate_summary(self) -> str:
        """Generate summary section."""
        stats = self._calculate_statistics()

        ecosystems_str = ", ".join(stats["ecosystems"]) if stats["ecosystems"] else "None detected"
        status_emoji = ":white_check_mark:" if stats["status"] == "passed" else ":x:"

        summary = f"""## :package: Summary
- **Total Packages**: {stats['total_packages']} analyzed
- **Ecosystems**: {ecosystems_str}
- **Vulnerabilities**: {stats['total_vulnerabilities']} found"""

        if stats['total_vulnerabilities'] > 0:
            severity_parts = []
            if stats['critical'] > 0:
                severity_parts.append(f"{stats['critical']} Critical")
            if stats['high'] > 0:
                severity_parts.append(f"{stats['high']} High")
            if stats['medium'] > 0:
                severity_parts.append(f"{stats['medium']} Medium")
            if stats['low'] > 0:
                severity_parts.append(f"{stats['low']} Low")

            if severity_parts:
                summary += f" ({', '.join(severity_parts)})"

        summary += f"\n- **Scan Status**: {status_emoji} {stats['status'].title()}"

        return summary + "\n\n---"

    def _generate_high_risk_packages(self) -> str:
        """Generate top 5 high-risk packages table."""
        high_risk_packages = self._get_high_risk_packages(limit=5)

        if not high_risk_packages:
            return ""

        markdown = """## :warning: Top 5 High-Risk Packages

| Package | Ecosystem | Risk Score | Risk Level | Vulnerabilities |
|---------|-----------|------------|------------|-----------------|
"""

        for pkg in high_risk_packages:
            ecosystem_emoji = self._get_ecosystem_emoji(pkg.get("ecosystem", "unknown"))
            risk_level_emoji = self._get_risk_level_emoji(pkg.get("risk_level", "unknown"))

            # Count vulnerabilities by severity
            vuln_counts = pkg.get("vulnerability_counts", {})
            vuln_str = self._format_vulnerability_counts(vuln_counts)

            # Get package name (risk_report uses 'package' key, not 'name')
            pkg_name = pkg.get('package', pkg.get('name', 'unknown'))

            markdown += f"| {pkg_name} | {ecosystem_emoji} {pkg.get('ecosystem', 'unknown').title()} | {pkg.get('final_score', pkg.get('risk_score', 0)):.1f} | {risk_level_emoji} {pkg.get('risk_level', 'unknown').upper()} | {vuln_str} |\n"

        return markdown + "\n---"

    def _generate_vulnerabilities(self) -> str:
        """Generate vulnerabilities section with collapsible details by severity."""
        vulnerabilities = self._get_all_vulnerabilities()

        if not vulnerabilities:
            return ""

        # Group by severity
        by_severity = {
            "critical": [],
            "high": [],
            "medium": [],
            "low": [],
        }

        for vuln in vulnerabilities:
            severity = vuln.get("severity", "unknown").lower()
            if severity in by_severity:
                by_severity[severity].append(vuln)

        markdown = "## :rotating_light: Vulnerabilities Detected\n\n"

        # Critical vulnerabilities
        if by_severity["critical"]:
            markdown += self._generate_vulnerability_table("Critical", by_severity["critical"], ":red_circle:")

        # High vulnerabilities
        if by_severity["high"]:
            markdown += self._generate_vulnerability_table("High", by_severity["high"], ":orange_circle:")

        # Medium vulnerabilities
        if by_severity["medium"]:
            markdown += self._generate_vulnerability_table("Medium", by_severity["medium"], ":yellow_circle:")

        # Low vulnerabilities
        if by_severity["low"]:
            markdown += self._generate_vulnerability_table("Low", by_severity["low"], ":large_blue_circle:")

        return markdown + "---"

    def _generate_vulnerability_table(self, severity: str, vulnerabilities: List[Dict], emoji: str) -> str:
        """Generate a collapsible vulnerability table for a specific severity."""
        count = len(vulnerabilities)

        markdown = f"""<details>
<summary><b>{emoji} {severity} Severity ({count})</b></summary>

| Package | Ecosystem | CVE ID | CVSS Score | Summary |
|---------|-----------|--------|------------|---------|
"""

        for vuln in vulnerabilities:
            pkg_name = vuln.get("package", "unknown")
            ecosystem = vuln.get("ecosystem", "unknown")
            ecosystem_emoji = self._get_ecosystem_emoji(ecosystem)
            cve_id = vuln.get("id", "N/A")
            cvss_score = vuln.get("cvss_score", "N/A")
            if isinstance(cvss_score, (int, float)):
                cvss_score = f"{cvss_score:.1f}"
            summary = vuln.get("summary", "No description available")[:100]
            if len(vuln.get("summary", "")) > 100:
                summary += "..."

            markdown += f"| {pkg_name} | {ecosystem_emoji} {ecosystem.title()} | {cve_id} | {cvss_score} | {summary} |\n"

        markdown += "\n</details>\n\n"
        return markdown

    def _generate_threshold_details(self) -> str:
        """Generate threshold configuration and breach details."""
        if not self.threshold_result:
            return ""

        exceeded_by = self.threshold_result.calculated_score - self.threshold_result.max_threshold

        markdown = f"""## :gear: Threshold Configuration & Breach Details

> [!IMPORTANT]
> **Breach Analysis**
> - **Calculated Score**: {self.threshold_result.calculated_score:.1f} / {self.threshold_result.max_threshold:.1f}
> - **Exceeded By**: +{exceeded_by:.1f} points
> - **Failure Reason**: {self.threshold_result.failure_reason}

**Threshold Configuration:**
"""

        # Add threshold config table if available in metadata
        threshold_config = self.scan_metadata.get("threshold_config", {})
        if threshold_config:
            markdown += """
| Setting | Value |
|---------|-------|
"""
            markdown += f"| Max Score Threshold | {threshold_config.get('max_score_threshold', 'N/A')} |\n"
            markdown += f"| High Severity Weight | {threshold_config.get('high_severity_weight', 'N/A')} |\n"
            markdown += f"| Medium Severity Weight | {threshold_config.get('medium_severity_weight', 'N/A')} |\n"
            markdown += f"| Low Severity Weight | {threshold_config.get('low_severity_weight', 'N/A')} |\n"
            fail_on_critical = ":white_check_mark: Enabled" if threshold_config.get('fail_on_critical') else ":x: Disabled"
            markdown += f"| Fail on Critical | {fail_on_critical} |\n"

        return markdown + "\n---"

    def _generate_footer(self) -> str:
        """Generate footer with dashboard link and metadata."""
        # Get version and run info from metadata
        version = "0.10.0"  # Default version
        template_version = "2.0.0"  # Default template version

        # Get GitHub Actions context for workflow link
        ci_context = self.scan_metadata.get("ci_context", {})
        run_id = ci_context.get("run_id")
        repository = ci_context.get("repository")

        footer = f"""## :chart_with_upwards_trend: Full Details
:link: **[View Complete Analysis on Zerberus Dashboard]({self.report_url})**

---

<div align="center">

:robot: *Generated by ZSBOM v{version} | Template v{template_version}*"""

        # Add workflow run link only if we have valid GitHub Actions context
        if run_id and repository:
            workflow_url = f"https://github.com/{repository}/actions/runs/{run_id}"
            footer += f"  \n:link: *[Workflow Run #{run_id}]({workflow_url})*"

        footer += "\n\n</div>"

        return footer

    # Helper methods

    def _calculate_statistics(self) -> Dict[str, Any]:
        """Calculate summary statistics from reports."""
        stats = {
            "total_packages": 0,
            "ecosystems": set(),
            "total_vulnerabilities": 0,
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "status": "passed",
        }

        # Count packages and ecosystems
        if self.risk_report and isinstance(self.risk_report, list):
            stats["total_packages"] = len(self.risk_report)
            for pkg in self.risk_report:
                ecosystem = pkg.get("ecosystem", "unknown")
                if ecosystem != "unknown":
                    stats["ecosystems"].add(ecosystem)

        # Count vulnerabilities by severity
        if self.validation_report:
            for ecosystem, data in self.validation_report.get("ecosystems", {}).items():
                stats["ecosystems"].add(ecosystem)
                cve_issues = data.get("cve_issues", [])
                stats["total_vulnerabilities"] += len(cve_issues)

                for vuln in cve_issues:
                    severity = vuln.get("severity", "unknown").lower()
                    if severity == "critical":
                        stats["critical"] += 1
                    elif severity == "high":
                        stats["high"] += 1
                    elif severity == "medium":
                        stats["medium"] += 1
                    elif severity == "low":
                        stats["low"] += 1

        # Determine status
        if self.threshold_result and self.threshold_result.should_fail_build:
            stats["status"] = "failed"
        elif stats["critical"] > 0 or stats["total_vulnerabilities"] > 0:
            stats["status"] = "warning"

        stats["ecosystems"] = sorted(list(stats["ecosystems"]))

        return stats

    def _has_vulnerabilities(self) -> bool:
        """Check if there are any vulnerabilities."""
        if not self.validation_report:
            return False

        for ecosystem, data in self.validation_report.get("ecosystems", {}).items():
            if data.get("cve_issues", []):
                return True

        return False

    def _has_critical_vulnerabilities(self) -> bool:
        """Check if there are any critical vulnerabilities."""
        if not self.validation_report:
            return False

        for ecosystem, data in self.validation_report.get("ecosystems", {}).items():
            for vuln in data.get("cve_issues", []):
                if vuln.get("severity", "").lower() == "critical":
                    return True

        return False

    def _has_high_risk_packages(self) -> bool:
        """Check if there are any high-risk packages."""
        return bool(self._get_high_risk_packages(limit=1))

    def _get_high_risk_packages(self, limit: int = 5) -> List[Dict]:
        """Get high-risk packages sorted by risk score."""
        if not self.risk_report or not isinstance(self.risk_report, list):
            return []

        # Filter packages with risk level of medium or high
        high_risk = []
        for pkg in self.risk_report:
            risk_level = pkg.get("risk_level", "").lower()
            if risk_level in ["high", "medium"]:
                # Add vulnerability counts
                pkg_with_vulns = pkg.copy()
                pkg_with_vulns["vulnerability_counts"] = self._get_package_vulnerability_counts(pkg.get("package", ""))
                high_risk.append(pkg_with_vulns)

        # Sort by risk score (lower is riskier in ZSBOM)
        high_risk.sort(key=lambda x: x.get("final_score", 100))

        return high_risk[:limit]

    def _get_package_vulnerability_counts(self, package_name: str) -> Dict[str, int]:
        """Get vulnerability counts for a specific package."""
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}

        if not self.validation_report:
            return counts

        for ecosystem, data in self.validation_report.get("ecosystems", {}).items():
            for vuln in data.get("cve_issues", []):
                # Check if vulnerability affects this package
                affected_versions = vuln.get("affected_versions", [])
                # This is a simplified check - you may need to match against actual installed version
                if package_name.lower() in [pkg.lower() for pkg in affected_versions[:5]]:  # Check first 5 versions
                    severity = vuln.get("severity", "unknown").lower()
                    if severity in counts:
                        counts[severity] += 1

        return counts

    def _get_all_vulnerabilities(self) -> List[Dict]:
        """Get all vulnerabilities from validation report."""
        vulnerabilities = []

        if not self.validation_report:
            return vulnerabilities

        for ecosystem, data in self.validation_report.get("ecosystems", {}).items():
            for vuln in data.get("cve_issues", []):
                vuln_copy = vuln.copy()
                vuln_copy["ecosystem"] = ecosystem
                # Extract package name from affected versions or use first affected version
                if "package" not in vuln_copy:
                    affected = vuln.get("affected_versions", [])
                    vuln_copy["package"] = affected[0] if affected else "unknown"
                vulnerabilities.append(vuln_copy)

        return vulnerabilities

    def _get_ecosystem_emoji(self, ecosystem: str) -> str:
        """Get emoji for ecosystem."""
        ecosystem_lower = ecosystem.lower()
        return self.ECOSYSTEM_EMOJIS.get(ecosystem_lower, ":package:")

    def _get_risk_level_emoji(self, risk_level: str) -> str:
        """Get emoji for risk level."""
        risk_lower = risk_level.lower()
        if risk_lower == "high":
            return ":red_circle:"
        elif risk_lower == "medium":
            return ":orange_circle:"
        elif risk_lower == "low":
            return ":green_circle:"
        return ":white_circle:"

    def _format_vulnerability_counts(self, counts: Dict[str, int]) -> str:
        """Format vulnerability counts as a string."""
        parts = []
        if counts.get("critical", 0) > 0:
            parts.append(f"{counts['critical']} Critical")
        if counts.get("high", 0) > 0:
            parts.append(f"{counts['high']} High")
        if counts.get("medium", 0) > 0:
            parts.append(f"{counts['medium']} Medium")
        if counts.get("low", 0) > 0:
            parts.append(f"{counts['low']} Low")

        return ", ".join(parts) if parts else "None"
