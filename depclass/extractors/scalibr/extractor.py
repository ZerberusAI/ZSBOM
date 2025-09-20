"""
Generic Scalibr extractor for all non-Python ecosystems.

Uses OSV Scalibr to detect and extract dependencies from all supported
package ecosystems except Python (which uses dedicated pip-tools logic).
"""

import json
from typing import Dict, List, Optional, Any
from pathlib import Path

from rich.console import Console

from ..base import BaseExtractor
from .wrapper import ScalibrWrapper
from .classifiers import get_classifier


class ScalibrExtractor(BaseExtractor):
    """Generic extractor using Scalibr for all non-Python ecosystems."""

    def __init__(self, project_path: str = "."):
        super().__init__(project_path)

    def can_extract(self) -> bool:
        """
        Check if this extractor can extract from the project.

        For ScalibrExtractor, we check if JavaScript/NPM environment is detected and
        if appropriate lock files exist for transitive dependency analysis.
        """
        console = Console()

        try:
            # First, check if this is a JavaScript/NPM project
            if not self._is_javascript_project():
                return False

            # Check if JavaScript lock files exist for transitive analysis
            lock_files_exist = self._check_javascript_lock_files()

            if not lock_files_exist:
                # JavaScript project detected but no lock files - show warning
                console.print("⚠️  JavaScript/NPM project detected but no lock files found.", style="yellow")
                console.print("   For transitive dependency analysis, please ensure one of these files exists:", style="dim")
                console.print("   • package-lock.json (npm)", style="dim")
                console.print("   • yarn.lock (Yarn)", style="dim")
                console.print("   • pnpm-lock.yaml (pnpm)", style="dim")
                console.print("   • npm-shrinkwrap.json (npm shrinkwrap)", style="dim")
                console.print("   Skipping JavaScript dependency extraction.", style="yellow")
                return False

            return True

        except Exception as e:
            console.print(f"⚠️ Error checking JavaScript environment: {e}", style="red")
            return False

    def extract_dependencies(
        self,
        config: Optional[Dict] = None,
        cache=None
    ) -> Dict[str, Any]:
        """Extract dependencies using Scalibr for all detected ecosystems."""
        config = self.validate_config(config)

        try:
            # Use Scalibr to scan with JavaScript/NPM plugin only
            # No enrichers - they don't provide useful data for our use case
            scalibr = ScalibrWrapper()
            plugins = ["javascript"]

            # Run Scalibr scan
            scalibr_result = scalibr.scan(str(self.project_path), plugins=plugins)

            if not scalibr_result:
                return self._create_empty_result()

            # Convert Scalibr results to ecosystem-separated format
            return self._parse_scalibr_results(scalibr_result, config)

        except Exception as e:
            print(f"⚠️ Scalibr extraction failed: {e}")
            return self._create_empty_result()

    def extract_all_ecosystems(
        self,
        config: Optional[Dict] = None,
        cache=None
    ) -> Dict[str, Any]:
        """
        Extract dependencies for all ecosystems detected by Scalibr.

        Returns results in the format expected for multi-ecosystem merging.
        """
        result = self.extract_dependencies(config, cache)

        # Return the ecosystems found by Scalibr
        ecosystems_data = result.get("ecosystems", {})
        if not ecosystems_data:
            return {}

        return ecosystems_data

    def _create_empty_result(self) -> Dict[str, Any]:
        """Create empty result structure."""
        return {
            "ecosystems": {},
            "ecosystems_detected": [],
            "total_packages": 0
        }

    def _parse_scalibr_results(self, scalibr_result: Dict[str, Any], config: Dict) -> Dict[str, Any]:
        """Parse Scalibr output and organize by ecosystem."""
        inventory = scalibr_result.get("Inventory", {})
        packages = inventory.get("Packages", [])

        if not packages:
            return self._create_empty_result()

        # Group packages by ecosystem
        ecosystems = {}
        ecosystems_detected = set()
        total_packages = 0

        # Get classifiers for each ecosystem to determine direct vs transitive
        ecosystem_classifiers = {}

        for package in packages:
            ecosystem = self._determine_ecosystem(package)
            if ecosystem and ecosystem != "python":  # Exclude Python - handled separately
                if ecosystem not in ecosystems:
                    ecosystems[ecosystem] = {
                        "dependencies": {},
                        "dependencies_analysis": {
                            "total_packages": 0,
                            "dependency_tree": {},
                            "package_files": [],
                            "resolution_details": {}
                        }
                    }

                # Initialize classifier for this ecosystem if not already done
                if ecosystem not in ecosystem_classifiers:
                    classifier = get_classifier(ecosystem)
                    if classifier:
                        direct_deps = classifier.get_direct_dependencies(Path(self.project_path))
                        ecosystem_classifiers[ecosystem] = (classifier, direct_deps)
                    else:
                        ecosystem_classifiers[ecosystem] = (None, set())

                # Get classifier data for this ecosystem
                classifier, direct_deps = ecosystem_classifiers[ecosystem]

                self._add_package_to_ecosystem(package, ecosystems[ecosystem], ecosystem, direct_deps)
                ecosystems_detected.add(ecosystem)
                total_packages += 1

        # Post-process each ecosystem to build proper structures
        for ecosystem_name, ecosystem_data in ecosystems.items():
            # Organize packages by their location files (using Scalibr's data)
            dependencies = self._organize_packages_by_location(packages, ecosystem_name)
            ecosystem_data["dependencies"] = dependencies

            # Use classifier to build enhanced dependency tree if available
            classifier_info = ecosystem_classifiers.get(ecosystem_name)
            if classifier_info:
                classifier, _ = classifier_info
                enhanced_tree = classifier.build_dependency_tree(
                    ecosystem_data["dependencies_analysis"]["dependency_tree"],
                    ecosystem_data["dependencies_analysis"]["resolution_details"]
                )
                ecosystem_data["dependencies_analysis"]["dependency_tree"] = enhanced_tree

            self._finalize_ecosystem_data(ecosystem_data, ecosystem_name)

        return {
            "ecosystems": ecosystems,
            "ecosystems_detected": list(ecosystems_detected),
            "total_packages": total_packages
        }

    def _determine_ecosystem(self, package: Dict[str, Any]) -> Optional[str]:
        """
        Determine the ecosystem using Scalibr's PURLType.

        Scalibr already determines and provides the ecosystem type,
        so we should rely on that instead of manual classification.
        """
        # Use Scalibr's authoritative ecosystem classification
        purl_type = package.get("PURLType", "")
        if purl_type:
            return purl_type.lower()

        # Only fallback if Scalibr doesn't provide PURLType (rare)
        name = package.get("Name", "")
        if not name:
            return None

        return "unknown"

    def _add_package_to_ecosystem(self, package: Dict[str, Any], ecosystem_data: Dict[str, Any], ecosystem: str, direct_deps: set) -> None:
        """Add a package to the appropriate ecosystem data structure with classification."""
        name = package.get("Name", "")
        version = package.get("Version", "")
        locations = package.get("Locations", [])

        # Clean the package name (remove ecosystem prefixes)
        clean_name = self._clean_package_name(name, ecosystem)

        if not clean_name:
            return

        # Add to resolution details
        ecosystem_data["dependencies_analysis"]["resolution_details"][clean_name] = version

        # Build dependency tree entry
        package_key = f"{clean_name}=={version}" if version else clean_name

        # Classify as direct or transitive using our classifier
        dependency_type = "direct" if clean_name in direct_deps else "transitive"

        ecosystem_data["dependencies_analysis"]["dependency_tree"][package_key] = {
            "type": dependency_type,
            "version": version,
            "locations": locations
        }

        # Dependencies will be organized by location/file in _parse_scalibr_results

    def _clean_package_name(self, name: str, ecosystem: str) -> str:
        """Clean package name by removing ecosystem prefixes."""
        prefixes = {
            "npm": ["npm:"],
            "go": ["go:"],
            "java": ["maven:"],
            "rust": ["cargo:"],
            "ruby": ["gem:"],
            "php": ["composer:"],
            "dart": ["pub:"],
            "swift": ["swift:"]
        }

        ecosystem_prefixes = prefixes.get(ecosystem, [])
        for prefix in ecosystem_prefixes:
            if name.startswith(prefix):
                return name[len(prefix):]

        return name

    def _organize_packages_by_location(self, packages: list, ecosystem: str) -> Dict[str, Dict[str, str]]:
        """
        Organize packages by their location (file) using Scalibr's data.

        Returns a dict where keys are filenames and values are {package: version} dicts.
        """
        dependencies = {}

        for package in packages:
            # Filter packages for this ecosystem
            if self._determine_ecosystem(package) != ecosystem:
                continue

            name = package.get("Name", "")
            version = package.get("Version", "")
            locations = package.get("Locations", [])

            # Clean package name
            clean_name = self._clean_package_name(name, ecosystem)
            if not clean_name:
                continue

            # Group by location file
            for location in locations:
                if location not in dependencies:
                    dependencies[location] = {}

                dependencies[location][clean_name] = version

        return dependencies


    def _finalize_ecosystem_data(self, ecosystem_data: Dict[str, Any], ecosystem_name: str) -> None:
        """Finalize ecosystem data by building package_files structure."""
        package_files = []
        dependencies = ecosystem_data.get("dependencies", {})

        for file_name, file_deps in dependencies.items():
            if file_deps:
                package_list = []
                for dep_name, version_spec in file_deps.items():
                    if version_spec:
                        package_list.append(f"{dep_name}@{version_spec}" if ecosystem_name == "npm" else f"{dep_name}=={version_spec}")
                    else:
                        package_list.append(dep_name)

                if package_list:
                    package_files.append({
                        "path": file_name,
                        "ecosystem": ecosystem_name,
                        "packages": package_list
                    })

        ecosystem_data["dependencies_analysis"]["package_files"] = package_files
        ecosystem_data["dependencies_analysis"]["total_packages"] = len(ecosystem_data["dependencies_analysis"]["resolution_details"])

    def validate_config(self, config: Optional[Dict]) -> Dict:
        """Validate and provide defaults for Scalibr-specific configuration."""
        base_config = super().validate_config(config)

        # Scalibr-specific defaults
        scalibr_defaults = {
            "scalibr_mode": "auto",  # auto, online, offline
            "include_dev_dependencies": True,
            "max_scan_timeout": 300  # 5 minutes
        }

        # Merge Scalibr defaults with base config
        for key, value in scalibr_defaults.items():
            if key not in base_config:
                base_config[key] = value

        return base_config

    def _is_javascript_project(self) -> bool:
        """Check if the current project is a JavaScript/NPM project."""
        js_files = [
            "package.json",
            "package-lock.json",
            "yarn.lock",
            "pnpm-lock.yaml",
            "npm-shrinkwrap.json"
        ]

        project_path = Path(self.project_path)
        for js_file in js_files:
            if (project_path / js_file).exists():
                return True

        return False

    def _check_javascript_lock_files(self) -> bool:
        """
        Check if any of the supported JavaScript lock files exist.

        Returns True if at least one lock file is found, False otherwise.
        """
        # All lock file types supported by Scalibr
        lock_files = [
            "package-lock.json",    # npm
            "yarn.lock",           # Yarn
            "pnpm-lock.yaml",      # pnpm
            "npm-shrinkwrap.json"  # npm shrinkwrap
        ]

        project_path = Path(self.project_path)
        for lock_file in lock_files:
            if (project_path / lock_file).exists():
                return True

        return False