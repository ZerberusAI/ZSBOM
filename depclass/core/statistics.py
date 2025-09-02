"""
Statistics calculation for ZSBOM.

Handles calculation of scan statistics following SOLID principles 
with single responsibility for statistics computation.
"""


class StatisticsCalculator:
    """Calculates comprehensive scan statistics."""
    
    def calculate_scan_statistics(
        self,
        dependencies_analysis: dict, 
        results: dict, 
        scores: list
    ) -> dict:
        """Calculate comprehensive scan statistics."""
        statistics = {}
        
        # Dependency statistics
        dependency_tree = dependencies_analysis.get("dependency_tree", {})
        statistics["total_dependencies"] = dependencies_analysis.get("total_packages", 0)
        statistics["direct_dependencies"] = len([
            pkg for pkg, info in dependency_tree.items() 
            if info.get("type") == "direct"
        ])
        statistics["transitive_dependencies"] = (
            statistics["total_dependencies"] - statistics["direct_dependencies"]
        )
        
        # Vulnerability statistics from validation results
        if results and "cve_issues" in results:
            vulnerabilities = results["cve_issues"]
            statistics["vulnerabilities_found"] = len(vulnerabilities)
            
            # Count by severity
            severity_counts = {}
            for vuln in vulnerabilities:
                severity = vuln.get("severity", "unknown").lower()
                severity_counts[severity] = severity_counts.get(severity, 0) + 1
            
            statistics["critical_vulnerabilities"] = severity_counts.get("critical", 0)
            statistics["high_vulnerabilities"] = severity_counts.get("high", 0)
            statistics["medium_vulnerabilities"] = severity_counts.get("medium", 0)
            statistics["low_vulnerabilities"] = severity_counts.get("low", 0)
        else:
            statistics["vulnerabilities_found"] = 0
            statistics["critical_vulnerabilities"] = 0
            statistics["high_vulnerabilities"] = 0
            statistics["medium_vulnerabilities"] = 0
            statistics["low_vulnerabilities"] = 0
        
        # Risk assessment statistics
        if scores:
            risk_counts = {}
            for score in scores:
                risk_level = score.get("risk_level", "unknown")
                risk_counts[risk_level] = risk_counts.get(risk_level, 0) + 1
            
            statistics["high_risk_packages"] = risk_counts.get("high", 0)
            statistics["medium_risk_packages"] = risk_counts.get("medium", 0)
            statistics["low_risk_packages"] = risk_counts.get("low", 0)
        else:
            statistics["high_risk_packages"] = 0
            statistics["medium_risk_packages"] = 0
            statistics["low_risk_packages"] = 0
        
        return statistics
    
    def calculate_dependency_statistics(self, dependencies_analysis: dict) -> dict:
        """Calculate dependency-specific statistics."""
        dependency_tree = dependencies_analysis.get("dependency_tree", {})
        return {
            "total_dependencies": dependencies_analysis.get("total_packages", 0),
            "direct_dependencies": len([
                pkg for pkg, info in dependency_tree.items() 
                if info.get("type") == "direct"
            ]),
            "transitive_dependencies": dependencies_analysis.get("total_packages", 0) - len([
                pkg for pkg, info in dependency_tree.items() 
                if info.get("type") == "direct"
            ])
        }
    
    def calculate_vulnerability_statistics(self, results: dict) -> dict:
        """Calculate vulnerability-specific statistics."""
        if not results or "cve_issues" not in results:
            return {
                "vulnerabilities_found": 0,
                "critical_vulnerabilities": 0,
                "high_vulnerabilities": 0,
                "medium_vulnerabilities": 0,
                "low_vulnerabilities": 0
            }
        
        vulnerabilities = results["cve_issues"]
        severity_counts = {}
        for vuln in vulnerabilities:
            severity = vuln.get("severity", "unknown").lower()
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
        
        return {
            "vulnerabilities_found": len(vulnerabilities),
            "critical_vulnerabilities": severity_counts.get("critical", 0),
            "high_vulnerabilities": severity_counts.get("high", 0),
            "medium_vulnerabilities": severity_counts.get("medium", 0),
            "low_vulnerabilities": severity_counts.get("low", 0)
        }
    
    def calculate_risk_statistics(self, scores: list) -> dict:
        """Calculate risk assessment statistics."""
        if not scores:
            return {
                "high_risk_packages": 0,
                "medium_risk_packages": 0,
                "low_risk_packages": 0
            }
        
        risk_counts = {}
        for score in scores:
            risk_level = score.get("risk_level", "unknown")
            risk_counts[risk_level] = risk_counts.get(risk_level, 0) + 1
        
        return {
            "high_risk_packages": risk_counts.get("high", 0),
            "medium_risk_packages": risk_counts.get("medium", 0),
            "low_risk_packages": risk_counts.get("low", 0)
        }