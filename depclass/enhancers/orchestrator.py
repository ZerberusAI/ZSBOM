"""
Simplified orchestrator for coordinated data enrichment.

This module provides a streamlined EnhancerOrchestrator that manages package-centric
enhancement using simple sequential processing with context passing between providers.
"""

import logging
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

from rich.progress import Progress, SpinnerColumn, TextColumn, TimeElapsedColumn
from rich.console import Console

from .deps_dev_provider import DepsDevProvider
from .osv_provider import OSVProvider
from .github_provider import GitHubProvider
from .mitre_provider import MITREProvider
from .formatters import PackageKeyFormatter
from ..db.vulnerability import VulnerabilityCache


class EnhancerOrchestrator:
    """
    Simplified package-centric enhancer orchestration.

    Features:
    - Sequential processing: metadata → vulnerability → repository → weakness
    - Context-based communication between providers
    - No complex inheritance or registry patterns
    - Each provider optimizes internally (batch vs individual)
    """

    def __init__(self, config: Dict, cache: Optional[VulnerabilityCache] = None):
        """
        Initialize the enhancer orchestrator.

        Args:
            config: Configuration dictionary
            cache: Optional VulnerabilityCache instance
        """
        self.config = config
        self.logger = logging.getLogger(__name__)
        self.cache = cache

        # Initialize providers directly
        self.metadata_provider = DepsDevProvider(config, cache)
        self.vulnerability_provider = OSVProvider(config, cache)
        self.repository_provider = GitHubProvider(config, cache)
        self.weakness_provider = MITREProvider(config, cache)

        # Progress display
        self.console = Console()
        self.show_progress = not config.get("ci_mode", False)

        # Execution tracking
        self.stats = {
            "total_packages": 0,
            "enhanced_packages": 0,
            "failed_packages": 0,
            "api_calls": 0,
            "cache_hits": 0,
            "errors": [],
            "enhanced_package_names": set(),
            "provider_stats": {}
        }

    def enhance_dependencies(self, dependencies_analysis: Dict) -> Dict[str, Any]:
        """
        Enhance dependencies across all detected ecosystems.

        Args:
            dependencies_analysis: Dependencies analysis result from extract.py

        Returns:
            Enhanced dependencies data with unified package keys
        """
        start_time = datetime.now()
        self.logger.info("Starting simplified dependency enhancement orchestration")

        enhanced_data = {}
        resolution_details = dependencies_analysis.get("resolution_details", {})

        # Process each ecosystem
        for ecosystem, packages in resolution_details.items():
            if not packages:
                continue

            self.logger.info(f"Enhancing {len(packages)} packages for ecosystem: {ecosystem}")

            # Convert packages to list of (name, version) tuples
            package_list = self._parse_package_list(packages, ecosystem)

            if not package_list:
                self.logger.warning(f"No valid packages found for ecosystem: {ecosystem}")
                continue

            # Enhance packages using sequential processing
            ecosystem_enhanced = self._enhance_ecosystem_packages(ecosystem, package_list)

            enhanced_data[ecosystem] = ecosystem_enhanced

        # Calculate execution time and update stats
        duration = (datetime.now() - start_time).total_seconds()
        self.logger.info(f"Enhancement completed in {duration:.2f} seconds")

        # Convert sets to lists for JSON serialization
        serializable_stats = self._get_serializable_stats()


        return {
            "enhanced_data": enhanced_data,
            "enhancement_metadata": {
                "timestamp": start_time.isoformat(),
                "duration_seconds": duration,
                "stats": serializable_stats
            }
        }

    def _parse_package_list(self, packages: Any, ecosystem: str) -> List[Tuple[str, str]]:
        """
        Parse packages into list of (name, version) tuples.

        Args:
            packages: Package data (dict or list)
            ecosystem: Package ecosystem

        Returns:
            List of (package_name, version) tuples
        """
        package_list = []

        if isinstance(packages, dict):
            # Format: {"package": "version", ...}
            package_list = [(name, version) for name, version in packages.items()]
        elif isinstance(packages, list):
            # Format: ["package==version", ...]
            for pkg_spec in packages:
                try:
                    name, version = PackageKeyFormatter.from_ecosystem_format(pkg_spec, ecosystem)
                    package_list.append((name, version))
                except Exception as e:
                    self.logger.warning(f"Failed to parse package spec {pkg_spec}: {e}")
                    continue

        return package_list

    def _enhance_ecosystem_packages(self, ecosystem: str, packages: List[Tuple[str, str]]) -> Dict[str, Any]:
        """
        Enhance packages for a specific ecosystem using sequential processing.

        Args:
            ecosystem: Package ecosystem
            packages: List of (package_name, version) tuples

        Returns:
            Enhanced data for all packages in unified format
        """
        self.stats["total_packages"] += len(packages)
        ecosystem_data = {}

        # Context for passing data between providers
        context = {
            "metadata": {},
            "vulnerability": {},
            "repository": {},
            "weakness": {}
        }

        # Sequential processing with progress display
        providers = [
            ("metadata", self.metadata_provider, "Fetching package metadata"),
            ("vulnerability", self.vulnerability_provider, "Scanning for vulnerabilities"),
            ("repository", self.repository_provider, "Analyzing repository activity"),
            ("weakness", self.weakness_provider, "Mapping weakness data")
        ]

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            TimeElapsedColumn(),
            console=self.console
        ) as progress:
            main_task = progress.add_task(f"Enhancing {ecosystem} packages", total=len(providers))

            for phase_name, provider, description in providers:
                progress.update(main_task, description=description)

                try:
                    # Each provider processes all packages and returns results
                    phase_results = provider.enhance(packages, ecosystem, context)

                    # Store results in context for next provider
                    context[phase_name] = phase_results

                    # Update stats
                    self._update_provider_stats(provider.__class__.__name__, phase_results)

                except Exception as e:
                    self.logger.error(f"Provider {provider.__class__.__name__} failed: {e}")
                    self.stats["errors"].append({
                        "provider": provider.__class__.__name__,
                        "phase": phase_name,
                        "ecosystem": ecosystem,
                        "error": str(e)
                    })

                progress.advance(main_task)

        # Combine all enhancement data for final output
        for package, version in packages:
            unified_key = PackageKeyFormatter.to_unified(package, version, ecosystem)
            original_format = PackageKeyFormatter.get_original_format(package, version, ecosystem)


            # Combine data from all providers
            combined_data = {
                "original_format": original_format,
                "package": package,
                "version": version,
                "ecosystem": ecosystem,
                "enhancement_timestamp": datetime.now().isoformat()
            }

            # Add data from each provider
            has_enhancement = False
            for phase_name in ["metadata", "vulnerability", "repository", "weakness"]:
                phase_data = context[phase_name].get(package, {})
                if phase_data.get("enhanced", False):
                    has_enhancement = True

                # Add phase data to combined result
                combined_data[phase_name] = phase_data

            combined_data["enhanced"] = has_enhancement

            # Track enhanced packages
            if has_enhancement:
                self.stats["enhanced_package_names"].add(package)

            ecosystem_data[unified_key] = combined_data

        return ecosystem_data

    def _update_provider_stats(self, provider_name: str, results: Dict[str, Any]) -> None:
        """Update provider statistics."""
        if provider_name not in self.stats["provider_stats"]:
            self.stats["provider_stats"][provider_name] = {
                "success": 0, "error": 0, "total": 0
            }

        for package, data in results.items():
            if data.get("enhanced", False):
                self.stats["provider_stats"][provider_name]["success"] += 1
            else:
                self.stats["provider_stats"][provider_name]["error"] += 1
            self.stats["provider_stats"][provider_name]["total"] += 1

    def _get_serializable_stats(self) -> Dict[str, Any]:
        """Get serializable statistics."""
        serializable_stats = self.stats.copy()
        serializable_stats["enhanced_package_names"] = list(self.stats["enhanced_package_names"])
        return serializable_stats

    def get_enhancement_statistics(self) -> Dict[str, Any]:
        """
        Get statistics about the enhancement process.

        Returns:
            Dictionary containing enhancement statistics
        """
        actual_enhanced_packages = len(self.stats["enhanced_package_names"])

        return {
            "total_packages": self.stats["total_packages"],
            "enhanced_packages": actual_enhanced_packages,
            "failed_packages": self.stats["failed_packages"],
            "success_rate": (
                actual_enhanced_packages / max(self.stats["total_packages"], 1)
            ) * 100,
            "cache_hits": self._get_total_cache_hits(),
            "cache_hit_rate": (self._get_total_cache_hits() / max(self.stats["total_packages"], 1)) * 100,
            "provider_stats": self.stats["provider_stats"],
            "errors": self.stats["errors"]
        }

    def _get_total_cache_hits(self) -> int:
        """Calculate total cache hits across all providers."""
        return (
            self.metadata_provider.stats.get("cache_hits", 0) +
            self.vulnerability_provider.stats.get("cache_hits", 0) +
            self.repository_provider.stats.get("cache_hits", 0) +
            self.weakness_provider.stats.get("cache_hits", 0)
        )