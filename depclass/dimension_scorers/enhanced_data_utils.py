"""
Shared utilities for accessing enhanced dependency data across dimension scorers.

This module provides unified helper functions for extracting package data
from the enhanced_data structure populated by the EnhancerOrchestrator.

Eliminates duplicate _get_package_data() logic across:
- PackageAbandonmentScorer
- TyposquatHeuristicsScorer
"""

from typing import Any, Dict, Optional


def get_package_data(
    enhanced_data: Optional[Dict],
    package: str,
    ecosystem: str = "python",
    installed_version: Optional[str] = None
) -> Optional[Dict[str, Any]]:
    """
    Get package data from enhanced_data using direct dictionary access.

    Args:
        enhanced_data: Enhanced dependency data from enhancers
        package: Package name
        ecosystem: Package ecosystem (default: "python")
        installed_version: Package version for better key matching

    Returns:
        Package data dictionary or None
    """
    if not enhanced_data:
        return None

    # Get ecosystem data
    ecosystem_data = enhanced_data.get(ecosystem, {})
    if not ecosystem_data:
        return None

    # Try direct key access with version first (more specific)
    if installed_version:
        package_key = f"{package}=={installed_version}"
        if package_key in ecosystem_data:
            return ecosystem_data[package_key]

    # Try without version as fallback
    if package in ecosystem_data:
        return ecosystem_data[package]

    return None


def extract_repository_data(
    enhanced_data: Optional[Dict],
    package: str,
    ecosystem: str = "python",
    installed_version: Optional[str] = None
) -> Optional[Dict[str, Any]]:
    """
    Extract repository data from enhanced dependency data.

    Args:
        enhanced_data: Enhanced dependency data from enhancers
        package: Package name
        ecosystem: Package ecosystem
        installed_version: Package version for better key matching

    Returns:
        Repository data dictionary from GitHub enhancer or None
    """
    package_data = get_package_data(enhanced_data, package, ecosystem, installed_version)
    if not package_data:
        return None

    return package_data.get("repository")


def extract_metadata(
    enhanced_data: Optional[Dict],
    package: str,
    ecosystem: str = "python",
    installed_version: Optional[str] = None
) -> Optional[Dict[str, Any]]:
    """
    Extract metadata from enhanced dependency data.

    Args:
        enhanced_data: Enhanced dependency data from enhancers
        package: Package name
        ecosystem: Package ecosystem
        installed_version: Package version for better key matching

    Returns:
        Metadata dictionary from deps.dev enhancer (complete package data) or None
    """
    return get_package_data(enhanced_data, package, ecosystem, installed_version)


def extract_vulnerability_data(
    enhanced_data: Optional[Dict],
    package: str,
    ecosystem: str = "python",
    installed_version: Optional[str] = None
) -> Optional[Dict[str, Any]]:
    """
    Extract vulnerability data from enhanced dependency data.

    Args:
        enhanced_data: Enhanced dependency data from enhancers
        package: Package name
        ecosystem: Package ecosystem
        installed_version: Package version for better key matching

    Returns:
        Vulnerability data dictionary from OSV enhancer or None
    """
    package_data = get_package_data(enhanced_data, package, ecosystem, installed_version)
    if not package_data:
        return None

    return package_data.get("vulnerability")


def extract_package_metadata_field(
    enhanced_data: Optional[Dict],
    package: str,
    ecosystem: str = "python",
    installed_version: Optional[str] = None
) -> Optional[Dict[str, Any]]:
    """
    Extract only the metadata field from enhanced dependency data.

    This returns the actual package metadata (deps.dev info), not the entire
    enhanced package data structure.

    Args:
        enhanced_data: Enhanced dependency data from enhancers
        package: Package name
        ecosystem: Package ecosystem
        installed_version: Package version for better key matching

    Returns:
        Package metadata dictionary or None
    """
    package_data = get_package_data(enhanced_data, package, ecosystem, installed_version)
    if not package_data:
        return None

    # Return only the metadata field, not the full package data
    metadata = package_data.get("metadata", {})
    return metadata if metadata else None
