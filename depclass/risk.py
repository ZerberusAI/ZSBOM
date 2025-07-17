"""Risk scoring utilities for ZSBOM."""

from __future__ import annotations

import importlib.metadata
import os
import subprocess
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from .risk_model import RiskModel
from .risk_calculator import WeightedRiskCalculator


def parse_declared_versions(dependencies: Dict[str, Any]) -> Dict[str, str]:
    """Extract a mapping of package name to declared version (legacy format).
    
    This function maintains backward compatibility with the old format
    where dependencies was a nested structure with lists for requirements.txt.
    """
    versions: Dict[str, str] = {}

    reqs = dependencies.get("requirements.txt", [])
    for line in reqs:
        if "==" in line:
            name, version = line.split("==", 1)
            versions[name.lower()] = version.strip()

    pyproject = dependencies.get("pyproject.toml", {})
    if isinstance(pyproject, dict):
        for name, value in pyproject.items():
            if isinstance(value, str):
                versions[name.lower()] = value
            elif isinstance(value, dict) and "version" in value:
                versions[name.lower()] = value["version"]

    return versions


def parse_package_specifications(dependencies: Dict[str, Dict[str, str]]) -> Dict[str, Dict[str, str]]:
    """Parse package specifications from enhanced dependency extraction.
    
    Takes the new format from enhanced extract.py and creates a structure
    suitable for the new DeclaredVsInstalledScorer.
    
    Args:
        dependencies: Dictionary mapping file names to package specifications
        
    Returns:
        Dictionary mapping file names to package specifications
    """
    package_specs = {}
    
    for file_name, packages in dependencies.items():
        if file_name == "runtime":
            continue  # Skip runtime packages for specification parsing
        
        if packages:
            package_specs[file_name] = packages
    
    return package_specs


def get_primary_declared_version(package: str, package_specs: Dict[str, Dict[str, str]]) -> Optional[str]:
    """Get the primary declared version for a package based on file priority.
    
    Args:
        package: Package name
        package_specs: Package specifications from multiple files
        
    Returns:
        Primary declared version string or None if not found
    """
    file_priority = [
        "pyproject.toml",
        "requirements.txt",
        "setup.py",
        "setup.cfg",
        "Pipfile"
    ]
    
    for file_name in file_priority:
        if file_name in package_specs and package in package_specs[file_name]:
            return package_specs[file_name][package]
    
    return None


def _package_cve_issues(package: str, cve_list: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    return [cve for cve in cve_list if cve.get("package_name") == package]


def _get_distribution_path(package: str) -> Optional[str]:
    try:
        dist = importlib.metadata.distribution(package)
        path = str(dist.locate_file(""))
        if os.path.isdir(os.path.join(path, ".git")):
            return path
    except importlib.metadata.PackageNotFoundError:
        pass
    return None


def _last_commit_date(repo_path: str) -> Optional[datetime]:
    for branch in ("main", "master"):
        try:
            ts = (
                subprocess.check_output(
                    ["git", "-C", repo_path, "log", branch, "-1", "--format=%ct"],
                    text=True,
                )
                .strip()
            )
            if ts:
                return datetime.fromtimestamp(int(ts), timezone.utc)
        except subprocess.CalledProcessError:
            continue
    return None


def _abandonment_score(repo_path: Optional[str], model: RiskModel) -> tuple[int, Optional[int]]:
    if not repo_path:
        return 0, None
    last = _last_commit_date(repo_path)
    if not last:
        return 0, None
    days = (datetime.now(timezone.utc) - last).days
    if days > 730:
        return model.weight_abandonment * 2, days
    if days > 365:
        return model.weight_abandonment, days
    return 0, days


def compute_package_score(
    package: str,
    installed_version: str,
    declared_version: str | None,
    cve_list: List[Dict[str, Any]],
    typosquatting_whitelist: List[str],
    repo_path: Optional[str] = None,
    model: Optional[RiskModel] = None,
) -> Dict[str, Any]:
    """Compute a risk score for a package using the ZSBOM Risk Scoring Framework v1.0."""
    if model is None:
        model = RiskModel()

    # Initialize the weighted risk calculator
    calculator = WeightedRiskCalculator(model)
    
    # Calculate comprehensive score using the new framework
    result = calculator.calculate_score(
        package=package,
        installed_version=installed_version,
        declared_version=declared_version,
        cve_list=cve_list,
        typosquatting_whitelist=typosquatting_whitelist,
        repo_path=repo_path,
    )
    
    # Convert to legacy format for backward compatibility
    legacy_result = {
        "package": result["package"],
        "installed_version": result["installed_version"],
        "declared_version": result["declared_version"],
        "score": result["final_score"],
        "risk": result["risk_level"],
        "details": _convert_details_to_legacy_format(result),
    }
    
    return legacy_result


def _convert_details_to_legacy_format(framework_result: Dict[str, Any]) -> Dict[str, Any]:
    """Convert new framework result to legacy details format for backward compatibility."""
    details = {}
    
    # Version mismatch
    declared_details = framework_result["dimension_details"]["declared_vs_installed"]
    if not declared_details.get("exact_match") and declared_details.get("has_declared_version"):
        details["version_mismatch"] = {
            "declared": declared_details["declared_version"],
            "installed": declared_details["installed_version"],
        }
    
    # CVEs
    cve_details = framework_result["dimension_details"]["known_cves"]
    if cve_details["cve_count"] > 0:
        details["cves"] = [cve["vuln_id"] for cve in cve_details["cves"]]
    
    # CWEs (if any CVEs have CWEs)
    cwe_details = framework_result["dimension_details"]["cwe_coverage"]
    if cwe_details["cwe_count"] > 0:
        details["cwes"] = [cwe["cwe_id"] for cwe in cwe_details["cwes"]]
    
    # Abandonment
    abandonment_details = framework_result["dimension_details"]["package_abandonment"]
    if abandonment_details["score"] < 5.0:  # Arbitrary threshold for "abandoned"
        details["abandoned"] = True
        last_commit_info = abandonment_details["components"]["last_commit"]
        if last_commit_info.get("days_since_last_commit"):
            details["last_activity_days"] = last_commit_info["days_since_last_commit"]
    
    # Typosquatting
    typosquat_details = framework_result["dimension_details"]["typosquat_heuristics"]
    if typosquat_details["score"] < 5.0:  # Arbitrary threshold for "typosquatting"
        details["typosquatting"] = True
    
    return details




def score_packages(
    validation_results: Dict[str, Any],
    dependencies: Dict[str, Dict[str, str]],
    installed_packages: Dict[str, str],
    model: Optional[RiskModel] = None,
) -> List[Dict[str, Any]]:
    """Return detailed risk scores using enhanced dependency file parsing.
    
    This function provides comprehensive risk scoring with the full 3-factor 
    declared vs installed analysis:
    1. Version Match Precision Analysis (4 points)
    2. Specification Completeness Analysis (3 points)
    3. Cross-File Consistency Analysis (3 points)
    
    Args:
        validation_results: CVE and vulnerability data
        dependencies: Enhanced dependency data from extract.py
        installed_packages: Currently installed packages
        model: Risk model configuration
        
    Returns:
        List of detailed risk scores with enhanced declared vs installed analysis
    """
    if model is None:
        model = RiskModel()

    calculator = WeightedRiskCalculator(model)
    scores = []
    cve_data = validation_results.get("cve_issues", [])
    typosquatting_whitelist = validation_results.get("typosquatting_whitelist", [])
    
    # Parse package specifications from enhanced format
    package_specs = parse_package_specifications(dependencies)

    for pkg, inst_ver in installed_packages.items():
        # Get primary declared version for backward compatibility
        primary_declared_ver = get_primary_declared_version(pkg, package_specs)
        
        # Get CVEs and repo path
        cves = _package_cve_issues(pkg, cve_data)
        repo_path = _get_distribution_path(pkg)
        
        # Calculate score with enhanced package specification data
        detailed_score = calculator.calculate_score(
            package=pkg,
            installed_version=inst_ver,
            declared_version=primary_declared_ver,
            cve_list=cves,
            typosquatting_whitelist=typosquatting_whitelist,
            repo_path=repo_path,
            # Pass enhanced data for new declared vs installed analysis
            dependency_files=dependencies,
            package_specs=package_specs,
        )
        
        scores.append(detailed_score)

    return scores
