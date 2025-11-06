"""
Generic Scalibr extractor for all non-Python ecosystems.

Uses OSV Scalibr to detect and extract dependencies from all supported
package ecosystems except Python (which uses dedicated pip-tools logic).
"""

from typing import Dict, List, Optional, Any
from pathlib import Path

from rich.console import Console

from ..base import BaseExtractor
from .wrapper import ScalibrWrapper
from .classifiers import get_classifier
from ...enhancers.deps_dev_provider import DepsDevProvider


class ScalibrExtractor(BaseExtractor):
    """Generic extractor using Scalibr for all non-Python ecosystems."""

    def __init__(self, project_path: str = "."):
        super().__init__(project_path)

    def can_extract(self) -> bool:
        """
        Check if this extractor can extract from the project.

        Returns True if JavaScript (with lock files) or Java project is detected.
        """
        console = Console()

        try:
            # Check for Java project - no lock file required
            if self._is_java_project():
                return True

            # Check for JavaScript/NPM project - lock files required
            if not self._is_javascript_project():
                return False

            # JavaScript found - verify lock files exist
            if not self._check_javascript_lock_files():
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
            console.print(f"⚠️ Error checking ecosystem support: {e}", style="red")
            return False

    def extract_dependencies(
        self,
        config: Optional[Dict] = None,
        cache=None
    ) -> Dict[str, Any]:
        """Extract dependencies using Scalibr for all detected ecosystems."""
        config = self.validate_config(config)

        try:
            # Determine which plugins to use based on detected ecosystems
            plugins = []
            if self._is_javascript_project():
                plugins.append("javascript")
            if self._is_java_project():
                # Use online Java plugin to resolve transitive dependencies
                plugins.extend([
                    "java/pomxmlnet",                        # Maven pom.xml (online - resolves transitive deps)
                    "java/gradlelockfile",                   # Gradle lock file
                    "java/gradleverificationmetadataxml"     # Gradle verification
                ])

            if not plugins:
                return self._create_empty_result()

            # Use Scalibr to scan with detected plugins
            scalibr = ScalibrWrapper()

            # Run Scalibr scan in online mode to resolve transitive dependencies for Java
            # JavaScript works fine in online mode too (lock files contain all needed data)
            scalibr_result = scalibr.scan(str(self.project_path), plugins=plugins, mode="online")

            if not scalibr_result:
                return self._create_empty_result()

            # Convert Scalibr results to ecosystem-separated format
            return self._parse_scalibr_results(scalibr_result, config, cache)

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

    def _parse_scalibr_results(self, scalibr_result: Dict[str, Any], config: Dict, cache=None) -> Dict[str, Any]:
        """Parse Scalibr output and organize by ecosystem."""
        inventory = scalibr_result.get("Inventory", {})
        packages = inventory.get("Packages", [])

        if not packages:
            return self._create_empty_result()

        # Create DepsDevProvider for API-based tree building
        depsdev_provider = DepsDevProvider(config, cache)

        # Group packages by ecosystem
        ecosystems = {}
        ecosystems_detected = set()
        total_packages = 0

        # Get classifiers for each ecosystem to determine direct vs transitive
        # Store: (classifier, direct_deps_set, processed_manifest_dirs)
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
                            "resolution_details": {},
                            "package_specs": {}
                        }
                    }

                # Initialize classifier for this ecosystem if not already done
                if ecosystem not in ecosystem_classifiers:
                    classifier = get_classifier(ecosystem)

                    # Inject DepsDevProvider for API-based tree building
                    if classifier and depsdev_provider and hasattr(classifier, 'set_depsdev_provider'):
                        classifier.set_depsdev_provider(depsdev_provider)

                    ecosystem_classifiers[ecosystem] = (classifier, set(), set())

                # Get current classifier data
                classifier, direct_deps, processed_dirs = ecosystem_classifiers[ecosystem]

                # Process any new manifest directories from this package's locations
                if classifier:
                    locations = package.get("Locations", [])
                    for location in locations:
                        manifest_path = Path(self.project_path) / location
                        if manifest_path.exists() and manifest_path.is_file():
                            manifest_dir = manifest_path.parent
                            # Only process each manifest directory once
                            if manifest_dir not in processed_dirs:
                                dir_direct_deps = classifier.get_direct_dependencies(manifest_dir)
                                direct_deps.update(dir_direct_deps)
                                processed_dirs.add(manifest_dir)

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
            classifier = None
            if classifier_info:
                classifier, _, _ = classifier_info
                enhanced_tree = classifier.build_dependency_tree(
                    ecosystem_data["dependencies_analysis"]["dependency_tree"],
                    ecosystem_data["dependencies_analysis"]["resolution_details"]
                )
                ecosystem_data["dependencies_analysis"]["dependency_tree"] = enhanced_tree

            # Build package_specs for declared vs installed analysis
            package_specs = self._build_package_specs(
                ecosystem_name,
                dependencies,
                ecosystem_data["dependencies_analysis"]["dependency_tree"],
                ecosystem_data["dependencies_analysis"]["resolution_details"],
                classifier
            )
            ecosystem_data["dependencies_analysis"]["package_specs"] = package_specs

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

    def _get_default_exclusions(self) -> set:
        """
        Get standard directories to exclude during manifest file discovery.

        Returns:
            Set of directory names to skip during recursive file search.
        """
        return {
            'node_modules', 'vendor', '.git', '__pycache__',
            'venv', '.venv', 'dist', 'build', '.pytest_cache', 'target'
        }

    def _discover_manifest_files(
        self,
        patterns: List[str],
        exclude_dirs: Optional[set] = None
    ) -> Dict[str, Path]:
        """
        Discover manifest files recursively with exclusion filtering.

        Args:
            patterns: List of file patterns to search for (e.g., ["package.json"])
            exclude_dirs: Optional set of directories to exclude (uses defaults if None)

        Returns:
            Dict mapping relative file paths (as strings) to absolute Path objects
        """
        if exclude_dirs is None:
            exclude_dirs = self._get_default_exclusions()

        discovered = {}
        project_path = Path(self.project_path)

        for pattern in patterns:
            for file_path in project_path.rglob(pattern):
                # Skip excluded directories
                if any(excluded in file_path.parts for excluded in exclude_dirs):
                    continue

                # Get relative path for the key
                try:
                    relative_path = file_path.relative_to(project_path)
                    file_key = str(relative_path)
                except ValueError:
                    file_key = file_path.name

                discovered[file_key] = file_path

        return discovered

    def _get_manifest_patterns(self, ecosystem_name: str) -> List[str]:
        """
        Get manifest file patterns for a given ecosystem.

        Args:
            ecosystem_name: Name of the ecosystem (e.g., "npm", "maven")

        Returns:
            List of file patterns to search for this ecosystem
        """
        ecosystem_patterns = {
            "npm": ["package.json"],
            "maven": ["pom.xml", "build.gradle", "build.gradle.kts"]
        }

        return ecosystem_patterns.get(ecosystem_name, [])

    def _build_package_specs(
        self,
        ecosystem_name: str,
        dependencies: Dict[str, Dict[str, str]],
        dependency_tree: Dict[str, Any],
        resolution_details: Dict[str, str],
        classifier
    ) -> Dict[str, Dict[str, str]]:
        """Build package_specs dictionary for declared vs installed scoring.

        Args:
            ecosystem_name: Name of the ecosystem (e.g., "npm")
            dependencies: Dict mapping file names to package specifications
            dependency_tree: Dict containing dependency tree structure
            resolution_details: Dict mapping packages to their resolved versions
            classifier: Ecosystem-specific classifier instance

        Returns:
            Dict with format {file_name: {package_name: version_spec}} for direct deps
            and {transitive_from_parent: {package_name: version_spec}} for transitive deps
        """
        package_specs = {}

        # Extract declared versions from manifest files using classifier
        if classifier:
            # Get manifest patterns for this ecosystem
            patterns = self._get_manifest_patterns(ecosystem_name)

            if patterns:
                # Discover all manifest files recursively
                manifests = self._discover_manifest_files(patterns)

                # Extract dependency specs from each manifest
                for file_key, manifest_path in manifests.items():
                    dependency_specs = classifier.get_direct_dependency_specs(manifest_path.parent)
                    if dependency_specs:
                        package_specs[file_key] = dependency_specs
            else:
                # Ecosystem not in patterns map - use dependencies dict as-is
                for file_name, packages in dependencies.items():
                    if packages:
                        package_specs[file_name] = packages.copy()
        else:
            # No classifier available - use dependencies dict as-is
            for file_name, packages in dependencies.items():
                if packages:
                    package_specs[file_name] = packages.copy()

        # Add transitive dependencies with their parent's declared versions
        self._add_transitive_package_specs(
            package_specs, dependency_tree, resolution_details
        )

        return package_specs

    def _add_transitive_package_specs(
        self,
        package_specs: Dict[str, Dict[str, str]],
        dependency_tree: Dict[str, Any],
        resolution_details: Dict[str, str]
    ) -> None:
        """Add transitive dependencies to package_specs with their parent's declared versions.

        This follows the same pattern as the Python extractor to ensure consistency
        in the declared vs installed scoring. Recursively traverses the entire dependency
        tree to capture all transitive relationships at all depth levels.

        Args:
            package_specs: Dictionary to modify (adds transitive specs)
            dependency_tree: Dict containing dependency tree structure with children
            resolution_details: Dict mapping packages to their resolved versions
        """
        # Build a reverse mapping: package -> list of parents by recursively traversing tree
        reverse_tree = {}

        def traverse_children(parent_name: str, children: Dict[str, Any]) -> None:
            """Recursively traverse children to build reverse tree."""
            for child_key, child_info in children.items():
                # Extract package name from "package==version" format
                child_name = child_key.split("==")[0] if "==" in child_key else child_key

                # Add parent-child relationship
                if child_name not in reverse_tree:
                    reverse_tree[child_name] = []
                reverse_tree[child_name].append(parent_name)

                # Recursively process this child's children
                grandchildren = child_info.get("children", {})
                if grandchildren:
                    traverse_children(child_name, grandchildren)

        # Start traversal from direct dependencies only
        for package_key, package_info in dependency_tree.items():
            # Extract package name from "package==version" format
            package_name = package_key.split("==")[0] if "==" in package_key else package_key

            # Only start traversal from direct dependencies
            if package_info.get("type") == "direct":
                children = package_info.get("children", {})
                if children:
                    traverse_children(package_name, children)

        # Now add transitive specs
        for package, parents in reverse_tree.items():
            if not parents:  # Skip packages with no parents (shouldn't happen here)
                continue

            for parent in parents:
                parent_lower = parent.lower()
                package_lower = package.lower()

                # Get the resolved version for this package
                package_resolved_version = resolution_details.get(package_lower, "")

                if package_resolved_version:
                    # Create a "transitive from parent" file entry
                    transitive_file = f"transitive_from_{parent_lower}"
                    if transitive_file not in package_specs:
                        package_specs[transitive_file] = {}

                    # Store the declared version (pinned to what parent resolves to)
                    package_specs[transitive_file][package_lower] = f"=={package_resolved_version}"

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
        """Check if the current project is a JavaScript/NPM project (recursively)."""
        js_files = [
            "package.json",
            "package-lock.json",
            "yarn.lock",
            "pnpm-lock.yaml",
            "npm-shrinkwrap.json"
        ]

        project_path = Path(self.project_path)
        exclude_dirs = {'node_modules', 'vendor', '.git', '__pycache__', 'venv', '.venv', 'dist', 'build', '.pytest_cache', 'target'}

        # Check recursively for any JS files
        for js_file in js_files:
            for file_path in project_path.rglob(js_file):
                # Skip excluded directories
                if not any(excluded in file_path.parts for excluded in exclude_dirs):
                    return True

        return False

    def _is_java_project(self) -> bool:
        """Check if the current project is a Java project (Maven or Gradle) recursively."""
        java_files = [
            "pom.xml",              # Maven
            "build.gradle",         # Gradle (Groovy)
            "build.gradle.kts",     # Gradle (Kotlin)
            "gradle.lockfile"       # Gradle lock file
        ]

        project_path = Path(self.project_path)
        exclude_dirs = {'node_modules', 'vendor', '.git', '__pycache__', 'venv', '.venv', 'dist', 'build', '.pytest_cache', 'target'}

        # Check recursively for any Java files
        for java_file in java_files:
            for file_path in project_path.rglob(java_file):
                # Skip excluded directories
                if not any(excluded in file_path.parts for excluded in exclude_dirs):
                    return True

        return False

    def _check_javascript_lock_files(self) -> bool:
        """
        Check if any of the supported JavaScript lock files exist recursively.

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
        exclude_dirs = {'node_modules', 'vendor', '.git', '__pycache__', 'venv', '.venv', 'dist', 'build', '.pytest_cache', 'target'}

        # Check recursively for any lock files
        for lock_file in lock_files:
            for file_path in project_path.rglob(lock_file):
                # Skip excluded directories
                if not any(excluded in file_path.parts for excluded in exclude_dirs):
                    return True

        return False