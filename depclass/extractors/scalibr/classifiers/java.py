"""
Java dependency classifier.

Determines direct vs transitive dependencies by reading pom.xml (Maven)
or build.gradle/build.gradle.kts (Gradle) to identify which packages
are directly declared.

Note: This classifier handles Java packages from both Maven and Gradle.
The ecosystem identifier uses 'maven' for PURL compatibility since Maven
Central is the primary package registry for both build systems.
"""

import re
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Set, Dict, List, Any, Optional

from rich.console import Console

from .base import BaseDependencyClassifier


class JavaDependencyClassifier(BaseDependencyClassifier):
    """
    Classifier for Java dependencies (Maven and Gradle).

    Reads pom.xml or build.gradle to determine which packages are direct
    dependencies vs transitive dependencies (only found in lock files).
    """

    # Maven namespace
    MAVEN_NS = {'mvn': 'http://maven.apache.org/POM/4.0.0'}

    def __init__(self):
        """Initialize Java dependency classifier."""
        super().__init__()

    # Framework-specific parent-child patterns for relationship inference
    # Maps parent artifact patterns to transitive groupId/artifact patterns
    FRAMEWORK_PATTERNS = {
        'spring-boot-starter': {
            'group_prefixes': ['org.springframework'],
            'artifacts': []
        },
        'jackson': {
            'group_prefixes': ['com.fasterxml.jackson'],
            'artifacts': ['jackson']
        },
        'tomcat': {
            'group_prefixes': ['org.apache.tomcat'],
            'artifacts': ['tomcat']
        },
        'logback': {
            'group_prefixes': ['ch.qos.logback', 'org.slf4j'],
            'artifacts': ['slf4j', 'logback']
        },
        'slf4j': {
            'group_prefixes': ['org.slf4j', 'ch.qos.logback'],
            'artifacts': ['slf4j', 'logback']
        }
    }

    def _extract_package_name(self, package_key: str) -> str:
        """Extract package name from 'package==version' format."""
        return package_key.split('==')[0] if '==' in package_key else package_key

    def _has_gradle_lockfile(self, flat_tree: Dict[str, Any]) -> bool:
        """Check if dependencies were resolved from gradle.lockfile (skips deps.dev API)."""
        return any(
            location.endswith("gradle.lockfile")
            for pkg_info in flat_tree.values()
            for location in pkg_info.get("locations", [])
        )

    def _collect_direct_dependencies_from_manifests(
        self, flat_tree: Dict[str, Any]
    ) -> Set[str]:
        """
        Parse and aggregate direct dependencies from all manifest directories.

        Discovers all unique directories containing manifest files (pom.xml,
        build.gradle) by examining package locations, then parses each directory
        to extract direct dependencies. Always includes root directory to catch
        parent/shared dependencies in multi-module projects.

        Args:
            flat_tree: Flat dependency tree with location metadata

        Returns:
            Unified set of direct dependency names (groupId:artifactId)
        """
        direct_deps = set()
        parsed_dirs = set()  # Track already-parsed directories

        # Discover and parse manifest directories from package locations
        for dep_data in flat_tree.values():
            for location in dep_data.get("locations", []):
                dir_path = Path(location).parent
                manifest_dir = dir_path if str(dir_path) != "." else Path(".")

                # Only parse each directory once
                if manifest_dir not in parsed_dirs:
                    parsed_dirs.add(manifest_dir)
                    self.logger.debug(f"Parsing direct dependencies from: {manifest_dir}")
                    deps_from_dir = self.get_direct_dependencies(manifest_dir)

                    if deps_from_dir:
                        self.logger.info(f"Found {len(deps_from_dir)} direct deps in {manifest_dir}")
                        direct_deps.update(deps_from_dir)
                    else:
                        self.logger.warning(f"No direct deps found in {manifest_dir}")

        # Always check root directory for parent/shared dependencies
        if Path(".") not in parsed_dirs:
            self.logger.debug("Parsing direct dependencies from root directory: .")
            root_deps = self.get_direct_dependencies(Path("."))
            if root_deps:
                self.logger.info(f"Found {len(root_deps)} direct deps in root directory")
                direct_deps.update(root_deps)
            else:
                self.logger.debug("No direct deps found in root directory")

        return direct_deps

    def _enhance_tree_with_children(
        self,
        flat_tree: Dict[str, Any],
        direct_deps: Set[str],
        relationships: Dict[str, List[str]],
        resolution_details: Dict[str, str]
    ) -> Dict[str, Any]:
        """Build enhanced tree with children for direct dependencies only."""
        enhanced_tree = {}
        for package_key, package_info in flat_tree.items():
            enhanced_info = package_info.copy()
            package_name = self._extract_package_name(package_key)

            # Only build children for direct dependencies
            if package_name in direct_deps:
                enhanced_info["children"] = self._build_children_recursive(
                    package_name, relationships, resolution_details,
                    current_depth=0, max_depth=3, visited=set()
                )
            else:
                enhanced_info["children"] = {}

            enhanced_tree[package_key] = enhanced_info

        return enhanced_tree

    def get_direct_dependencies(self, project_path: Path) -> Set[str]:
        """
        Get direct dependency names from pom.xml or build.gradle.

        Args:
            project_path: Path to the project directory

        Returns:
            Set of package names in format groupId:artifactId
        """
        console = Console()

        # Try Maven first
        pom_path = project_path / "pom.xml"
        if pom_path.exists():
            return self._parse_maven_dependencies(pom_path)

        # Try Gradle
        gradle_path = project_path / "build.gradle"
        gradle_kts_path = project_path / "build.gradle.kts"

        if gradle_path.exists():
            return self._parse_gradle_dependencies(gradle_path)
        elif gradle_kts_path.exists():
            return self._parse_gradle_dependencies(gradle_kts_path)

        console.print(
            "⚠️ No pom.xml or build.gradle found in project",
            style="yellow"
        )
        return set()

    def _parse_maven_dependencies(self, pom_path: Path) -> Set[str]:
        """
        Parse pom.xml to extract direct dependencies.

        Args:
            pom_path: Path to pom.xml file

        Returns:
            Set of dependency names in format groupId:artifactId
        """
        console = Console()
        direct_deps = set()

        try:
            tree = ET.parse(pom_path)
            root = tree.getroot()

            # Handle both with and without namespace
            namespace = self.MAVEN_NS if '{' in root.tag else {'mvn': ''}
            ns_prefix = 'mvn:' if '{' in root.tag else ''

            # Extract from <dependencies> section
            for dep in root.findall(f'.//{ns_prefix}dependencies/{ns_prefix}dependency', namespace):
                group_id_elem = dep.find(f'{ns_prefix}groupId', namespace)
                artifact_id_elem = dep.find(f'{ns_prefix}artifactId', namespace)

                if group_id_elem is not None and artifact_id_elem is not None:
                    group_id = group_id_elem.text
                    artifact_id = artifact_id_elem.text

                    if group_id and artifact_id:
                        # Maven format: groupId:artifactId
                        dep_name = f"{group_id}:{artifact_id}"
                        direct_deps.add(dep_name)

            # Also check <dependencyManagement> section (BOM imports)
            for dep in root.findall(f'.//{ns_prefix}dependencyManagement/{ns_prefix}dependencies/{ns_prefix}dependency', namespace):
                group_id_elem = dep.find(f'{ns_prefix}groupId', namespace)
                artifact_id_elem = dep.find(f'{ns_prefix}artifactId', namespace)

                if group_id_elem is not None and artifact_id_elem is not None:
                    group_id = group_id_elem.text
                    artifact_id = artifact_id_elem.text

                    if group_id and artifact_id:
                        dep_name = f"{group_id}:{artifact_id}"
                        direct_deps.add(dep_name)

            console.print(
                f"✓ Found {len(direct_deps)} direct dependencies in pom.xml",
                style="green"
            )

        except ET.ParseError as e:
            console.print(f"⚠️ Error parsing pom.xml: {e}", style="yellow")
        except Exception as e:
            console.print(
                f"⚠️ Unexpected error reading pom.xml: {e}",
                style="yellow"
            )

        return direct_deps

    def get_direct_dependency_specs(self, project_path: Path) -> Dict[str, str]:
        """
        Get direct dependencies with their declared versions from pom.xml or build.gradle.

        Args:
            project_path: Path to the project directory

        Returns:
            Dict mapping package names (groupId:artifactId) to version specifications
        """
        # Try Maven first
        pom_path = project_path / "pom.xml"
        if pom_path.exists():
            return self._parse_maven_dependency_versions(pom_path)

        # Try Gradle
        gradle_path = project_path / "build.gradle"
        gradle_kts_path = project_path / "build.gradle.kts"

        if gradle_path.exists():
            return self._parse_gradle_dependency_versions(gradle_path)
        elif gradle_kts_path.exists():
            return self._parse_gradle_dependency_versions(gradle_kts_path)

        return {}

    def _parse_maven_dependency_versions(self, pom_path: Path) -> Dict[str, str]:
        """
        Parse pom.xml to extract direct dependencies with their declared versions.

        Args:
            pom_path: Path to pom.xml file

        Returns:
            Dict mapping dependency names (groupId:artifactId) to version specifications
        """
        dependency_versions = {}

        try:
            tree = ET.parse(pom_path)
            root = tree.getroot()

            # Handle both with and without namespace
            namespace = self.MAVEN_NS if '{' in root.tag else {'mvn': ''}
            ns_prefix = 'mvn:' if '{' in root.tag else ''

            # Extract from <dependencies> section
            for dep in root.findall(f'.//{ns_prefix}dependencies/{ns_prefix}dependency', namespace):
                group_id_elem = dep.find(f'{ns_prefix}groupId', namespace)
                artifact_id_elem = dep.find(f'{ns_prefix}artifactId', namespace)
                version_elem = dep.find(f'{ns_prefix}version', namespace)

                if group_id_elem is not None and artifact_id_elem is not None:
                    group_id = group_id_elem.text
                    artifact_id = artifact_id_elem.text
                    version = version_elem.text if version_elem is not None else None

                    if group_id and artifact_id:
                        # Maven format: groupId:artifactId
                        dep_name = f"{group_id}:{artifact_id}"
                        # Store version if present (may be None if managed by parent POM)
                        if version:
                            dependency_versions[dep_name] = version

        except ET.ParseError:
            pass
        except Exception:
            pass

        return dependency_versions

    def _parse_gradle_dependency_versions(self, gradle_path: Path) -> Dict[str, str]:
        """
        Parse build.gradle to extract direct dependencies with versions.

        Args:
            gradle_path: Path to build.gradle or build.gradle.kts file

        Returns:
            Dict mapping dependency names (groupId:artifactId) to version specifications
        """
        dependency_versions = {}

        try:
            content = gradle_path.read_text()

            # Regex patterns for Gradle dependencies with versions
            # Matches: implementation 'group:artifact:version'
            # Also matches: compile, testImplementation, etc.
            patterns = [
                # Standard format: 'group:artifact:version'
                r"(?:implementation|compile|api|testImplementation|testCompile|runtimeOnly|compileOnly)\s*[(\s]*['\"]([^:'\"]+):([^:'\"]+):([^'\"]+)['\"]",
                # Separate group/artifact/version
                r"(?:implementation|compile|api|testImplementation|testCompile|runtimeOnly|compileOnly)\s*group:\s*['\"]([^'\"]+)['\"]\s*,\s*name:\s*['\"]([^'\"]+)['\"]\s*,\s*version:\s*['\"]([^'\"]+)['\"]",
            ]

            for pattern in patterns:
                for match in re.finditer(pattern, content):
                    group_id = match.group(1)
                    artifact_id = match.group(2)
                    version = match.group(3)

                    if group_id and artifact_id and version:
                        dep_name = f"{group_id}:{artifact_id}"
                        dependency_versions[dep_name] = version

        except Exception:
            pass

        return dependency_versions

    def _parse_gradle_dependencies(self, gradle_path: Path) -> Set[str]:
        """
        Parse build.gradle or build.gradle.kts to extract direct dependencies.

        Uses regex to extract dependency declarations in various formats:
        - implementation 'group:artifact:version'
        - implementation "group:artifact:version"
        - implementation group: 'group', name: 'artifact', version: 'version'

        Args:
            gradle_path: Path to build.gradle or build.gradle.kts file

        Returns:
            Set of dependency names in format groupId:artifactId
        """
        console = Console()
        direct_deps = set()

        try:
            with open(gradle_path, 'r', encoding='utf-8') as f:
                content = f.read()

            # Pattern 1: String notation "group:artifact:version"
            # Matches: implementation 'org.springframework:spring-core:5.3.0'
            # Matches: implementation "org.springframework:spring-core:5.3.0"
            pattern1 = r'(?:implementation|api|compile|runtimeOnly|compileOnly)\s+["\']([^:]+):([^:]+):[^"\']+["\']'

            # Pattern 2: Map notation with group and name
            # Matches: implementation group: 'org.springframework', name: 'spring-core', version: '5.3.0'
            pattern2 = r'(?:implementation|api|compile|runtimeOnly|compileOnly)\s+group:\s*["\']([^"\']+)["\']\s*,\s*name:\s*["\']([^"\']+)["\']'

            # Find all matches with pattern 1
            for match in re.finditer(pattern1, content):
                group_id = match.group(1)
                artifact_id = match.group(2)
                dep_name = f"{group_id}:{artifact_id}"
                direct_deps.add(dep_name)

            # Find all matches with pattern 2
            for match in re.finditer(pattern2, content):
                group_id = match.group(1)
                artifact_id = match.group(2)
                dep_name = f"{group_id}:{artifact_id}"
                direct_deps.add(dep_name)

            console.print(
                f"✓ Found {len(direct_deps)} direct dependencies in {gradle_path.name}",
                style="green"
            )

        except IOError as e:
            console.print(
                f"⚠️ Error reading {gradle_path.name}: {e}",
                style="yellow"
            )
        except Exception as e:
            console.print(
                f"⚠️ Unexpected error parsing {gradle_path.name}: {e}",
                style="yellow"
            )

        return direct_deps

    def build_dependency_tree(self, flat_tree: Dict[str, Any],
                             resolution_details: Dict[str, str]) -> Dict[str, Any]:
        """
        Build dependency tree for Java packages.

        - Maven (pom.xml): Uses deps.dev API for relationship accuracy
        - Gradle with lockfile: Skips deps.dev (Scalibr provides complete data)
        - Fallback: Heuristic inference if API unavailable

        Args:
            flat_tree: Flat dependency tree from Scalibr
            resolution_details: Package version mapping

        Returns:
            Enhanced dependency tree with children for direct dependencies only
        """
        # Only use deps.dev for Maven (pom.xml) - Gradle lockfiles have complete data
        if self.depsdev_provider and not self._has_gradle_lockfile(flat_tree):
            return self.build_tree_from_depsdev(
                flat_tree,
                resolution_details,
                ecosystem="maven"
            )

        # Fallback: Use heuristic inference if deps.dev unavailable
        direct_deps = self._collect_direct_dependencies_from_manifests(flat_tree)

        # Build simplified relationships for Maven/Gradle
        # Since lock files don't provide explicit parent-child relationships,
        # we infer them based on dependency patterns
        relationships = self._infer_java_relationships(flat_tree, direct_deps, resolution_details)

        # Build enhanced tree with children for direct dependencies
        return self._enhance_tree_with_children(flat_tree, direct_deps, relationships, resolution_details)

    def _infer_java_relationships(
        self,
        flat_tree: Dict[str, Any],
        direct_deps: Set[str],
        resolution_details: Dict[str, str]
    ) -> Dict[str, List[str]]:
        """
        Infer parent-child relationships for Java dependencies.

        Optimized algorithm with O(n+m) complexity:
        - n = direct dependencies, m = transitive dependencies
        - Pre-groups transitive deps by groupId for fast lookup
        - Uses framework pattern constants for relationship matching

        Since Maven/Gradle lock files don't explicitly store parent-child relationships
        like npm's package-lock.json, we infer them based on:
        1. Common group IDs (e.g., org.springframework.* packages likely belong together)
        2. Framework patterns from FRAMEWORK_PATTERNS constant
        3. Transitivity rules (any non-direct dep is a child of at least one direct dep)

        Args:
            flat_tree: Flat dependency tree from Scalibr
            direct_deps: Set of direct dependency names
            resolution_details: Package version mapping

        Returns:
            Dictionary mapping parent packages to lists of their children
        """
        # Extract all package names from flat_tree - O(p) where p = total packages
        all_packages = set()
        for package_key in flat_tree.keys():
            package_name = self._extract_package_name(package_key)
            all_packages.add(package_name)

        # Identify transitive dependencies - O(p)
        transitive_deps = all_packages - direct_deps

        # Pre-group transitive dependencies by groupId for O(1) lookup - O(m)
        transitive_by_group: Dict[str, List[str]] = {}
        transitive_metadata: Dict[str, Dict[str, str]] = {}

        for trans_dep in transitive_deps:
            parts = trans_dep.split(':')
            if len(parts) >= 2:
                group_id = parts[0]
                artifact_id = parts[1]

                # Group by groupId
                if group_id not in transitive_by_group:
                    transitive_by_group[group_id] = []
                transitive_by_group[group_id].append(trans_dep)

                # Store metadata for pattern matching
                transitive_metadata[trans_dep] = {
                    'group': group_id,
                    'artifact': artifact_id.lower()
                }

        relationships = {}

        # For each direct dependency, find children - O(n)
        for direct_dep in direct_deps:
            direct_parts = direct_dep.split(':')
            if len(direct_parts) < 2:
                continue

            direct_group = direct_parts[0]
            direct_artifact = direct_parts[1]
            direct_artifact_lower = direct_artifact.lower()

            children = set()

            # Strategy 1: Same groupId match - O(1) lookup
            if direct_group in transitive_by_group:
                children.update(transitive_by_group[direct_group])

            # Strategy 2: Framework pattern matching using constants
            for pattern_key, pattern_config in self.FRAMEWORK_PATTERNS.items():
                if pattern_key in direct_artifact_lower:
                    # Check group prefixes
                    for group_prefix in pattern_config['group_prefixes']:
                        # Add all transitive deps with matching group prefix
                        for trans_dep, metadata in transitive_metadata.items():
                            if metadata['group'].startswith(group_prefix):
                                children.add(trans_dep)

                    # Check artifact patterns
                    for artifact_pattern in pattern_config['artifacts']:
                        for trans_dep, metadata in transitive_metadata.items():
                            if artifact_pattern in metadata['artifact']:
                                children.add(trans_dep)

            # Store relationships (convert set to list)
            if children:
                relationships[direct_dep] = list(children)

        # Fallback: Assign unassigned transitive deps - O(m)
        assigned_transitive = set()
        for children_list in relationships.values():
            assigned_transitive.update(children_list)

        unassigned = transitive_deps - assigned_transitive

        if unassigned and direct_deps:
            first_direct = list(direct_deps)[0]
            if first_direct not in relationships:
                relationships[first_direct] = []
            relationships[first_direct].extend(list(unassigned))

        return relationships

    def _build_children_recursive(self, parent: str, relationships: Dict[str, List[str]],
                                 resolution_details: Dict[str, str], current_depth: int = 0,
                                 max_depth: int = 3, visited: Optional[Set[str]] = None) -> Dict[str, Any]:
        """
        Build children structure recursively for Java dependencies.

        Following established approach with proper safeguards to prevent massive files.

        Args:
            parent: Parent package name (groupId:artifactId format)
            relationships: Package dependency relationships
            resolution_details: Package version mapping
            current_depth: Current recursion depth
            max_depth: Maximum recursion depth (default 3)
            visited: Set of already visited packages to prevent cycles

        Returns:
            Dictionary with children structure matching established format
        """
        if visited is None:
            visited = set()

        # Prevent infinite recursion
        if current_depth >= max_depth:
            return {}

        # Prevent circular dependencies
        if parent in visited:
            return {}

        # Add to visited set for this branch
        visited = visited.copy()  # Create new copy for this branch
        visited.add(parent)

        children = {}

        for child in relationships.get(parent, []):
            version = resolution_details.get(child, "")
            child_key = f"{child}=={version}" if version else child

            child_info = {
                "type": "transitive",
                "depth": current_depth + 1,
            }

            # Recursively build children of this child
            sub_children = self._build_children_recursive(
                child, relationships, resolution_details,
                current_depth + 1, max_depth, visited
            )

            # Only add children key if there are actual children
            if sub_children:
                child_info["children"] = sub_children
            else:
                child_info["children"] = {}

            children[child_key] = child_info

        return children
