"""Risk scoring utilities for ZSBOM."""

from __future__ import annotations

import sys
from typing import Any, Dict, List, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed

from .risk_model import RiskModel
from .risk_calculator import WeightedRiskCalculator
from .models import PackageRef



def get_primary_declared_version(package: str, package_specs: Dict[str, Dict[str, str]]) -> Optional[str]:
    """Get the primary declared version for a package based on file priority.

    For direct dependencies, checks actual dependency files in priority order.
    For transitive dependencies, checks transitive declarations from parent packages.

    Args:
        package: Package name
        package_specs: Package specifications from multiple files

    Returns:
        Primary declared version string or None if not found
    """
    # File priority for direct dependencies
    file_priority = ["pyproject.toml", "requirements.txt", "setup.py", "setup.cfg", "Pipfile"]

    # Check direct dependency files first (highest priority)
    for file_name in file_priority:
        version = package_specs.get(file_name, {}).get(package)
        if version:
            return version

    # Check transitive dependency declarations from parent packages
    for file_name, packages in package_specs.items():
        if file_name.startswith("transitive_from_"):
            version = packages.get(package)
            if version:
                return version

    return None


def _package_cve_issues(package: str, cve_list: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    return [cve for cve in cve_list if cve.get("package_name") == package]


def score_packages(
    validation_results: Dict[str, Any],
    dependencies: Dict[str, Dict[str, str]],
    transitive_analysis: Dict[str, Any],
    model: Optional[RiskModel] = None,
    config: Optional[Dict[str, Any]] = None,
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
        transitive_analysis: Transitive analysis results with resolved versions
        model: Risk model configuration
        config: Configuration dictionary for transitive analysis settings
        
    Returns:
        List of detailed risk scores with enhanced declared vs installed analysis
    """
    if model is None:
        model = RiskModel()
    
    if config is None:
        config = {}

    calculator = WeightedRiskCalculator(model)
    scores = []

    # Extract CVE data from ecosystem-specific structure
    cve_data = []
    ecosystems_validation = validation_results.get("ecosystems", {})
    for ecosystem_name, ecosystem_data in ecosystems_validation.items():
        ecosystem_cves = ecosystem_data.get("cve_issues", [])
        cve_data.extend(ecosystem_cves)

    typosquatting_whitelist = validation_results.get("typosquatting_whitelist", [])
    
    # Get package specifications from extraction output
    package_specs = transitive_analysis.get("package_specs", {})
    
    # Process ecosystems separately for risk scoring
    ecosystems_data = transitive_analysis.get("resolution_details", {})
    
    if not ecosystems_data:
        print("⚠️ No resolved versions available from transitive analysis, cannot perform risk assessment")
        return []

    # Calculate total packages across all ecosystems
    total_packages = sum(len(packages) for packages in ecosystems_data.values() if isinstance(packages, dict))
    print(f"📦 Analyzing {total_packages} packages for risk assessment across {len(ecosystems_data)} ecosystems...")

    def score_single_package(pkg: str, ecosystem: str, packages: Dict[str, str],
                           classification: Dict[str, str],
                           dependency_tree: Dict[str, Any],
                           enhanced_data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Score a single package (for parallel execution)."""
        # Get resolved version for this package
        installed_version = packages.get(pkg)
        if installed_version is None:
            return None

        # Get primary declared version (None for transitive dependencies)
        primary_declared_ver = get_primary_declared_version(pkg, package_specs)

        # Get CVEs
        cves = _package_cve_issues(pkg, cve_data)

        pkg_ref = PackageRef(name=pkg, installed_version=installed_version, declared_version=primary_declared_ver)
        detailed_score = calculator.calculate_score(
            package=pkg_ref,
            cve_list=cves,
            typosquatting_whitelist=typosquatting_whitelist,
            # Pass enhanced data for new declared vs installed analysis
            dependency_files=dependencies,
            package_specs=package_specs,
            # Pass ecosystem-specific transitive analysis data
            dependency_tree=dependency_tree,
            classification=classification,
            ecosystem=ecosystem,
            # Pass enhanced data from enhancers to dimension scorers
            enhanced_data=enhanced_data,
        )

        # Add dependency classification and ecosystem information
        detailed_score["dependency_type"] = classification.get(pkg, "unknown")
        detailed_score["ecosystem"] = ecosystem

        return detailed_score

    # Process all ecosystems
    completed_count = 0
    for ecosystem, packages in ecosystems_data.items():
        if not isinstance(packages, dict) or not packages:
            continue

        # Get ecosystem-specific data
        dependency_tree = transitive_analysis.get("dependency_tree", {}).get(ecosystem, {})

        # Build classification from dependency_tree structure
        classification = {}
        for pkg_key, pkg_info in dependency_tree.items():
            # Extract package name from "package==version" format
            pkg_name = pkg_key.split("==")[0] if "==" in pkg_key else pkg_key
            classification[pkg_name] = pkg_info.get("type", "unknown")

        # Score ALL packages in this ecosystem (both direct and transitive)
        packages_to_score = set(packages.keys())

        # Extract enhanced data from transitive analysis (required for dimension scorers)
        enhanced_data = transitive_analysis.get("enhanced_data", {})
        if not enhanced_data:
            print(f"⚠️ No enhanced data available for ecosystem {ecosystem}, dimension scorers may not work properly")

        # Use parallel processing for scoring packages in this ecosystem
        max_workers = min(len(packages_to_score), 10)  # Limit to 10 concurrent workers

        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            # Submit all scoring tasks for this ecosystem
            future_to_pkg = {
                executor.submit(score_single_package, pkg, ecosystem, packages, classification, dependency_tree, enhanced_data): pkg
                for pkg in packages_to_score
            }

            # Collect results as they complete
            for future in as_completed(future_to_pkg):
                pkg = future_to_pkg[future]
                completed_count += 1

                # Progress reporting
                progress_msg = f"📊 Processed {completed_count}/{total_packages} packages ({ecosystem}:{pkg})"
                print(f"{progress_msg:<70}", end='\r')
                sys.stdout.flush()

                try:
                    result = future.result()
                    if result is not None:
                        scores.append(result)
                except Exception as exc:
                    print(f'\n⚠️ Package {ecosystem}:{pkg} generated an exception: {exc}')

    print(f"\n✅ Completed risk assessment for {len(scores)} packages across {len(ecosystems_data)} ecosystems")

    return scores
