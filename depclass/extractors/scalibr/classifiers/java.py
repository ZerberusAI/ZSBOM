"""
Java dependency classifier.

Determines direct vs transitive dependencies by reading pom.xml (Maven)
or build.gradle/build.gradle.kts (Gradle) to identify which packages
are directly declared.

Note: This classifier handles Java packages from both Maven and Gradle.
The ecosystem identifier uses 'maven' for PURL compatibility since Maven
Central is the primary package registry for both build systems.
"""

import json
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

    def get_dependency_versions(self, project_path: Path) -> Dict[str, str]:
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

    def parse_lock_file(self, project_path: Path) -> Dict[str, List[str]]:
        """
        Parse gradle.lockfile for dependency relationships.

        Args:
            project_path: Path to the project directory

        Returns:
            Dictionary mapping package names to their direct dependencies
        """
        console = Console()
        lock_file = project_path / "gradle.lockfile"

        if not lock_file.exists():
            return {}

        relationships = {}

        try:
            with open(lock_file, 'r', encoding='utf-8') as f:
                content = f.read()

            # Gradle lockfile format:
            # group:artifact:version=config1,config2
            # We extract the package and note it exists
            # Note: gradle.lockfile doesn't explicitly show parent-child relationships
            # We'll use the flat structure and infer relationships from pom files if available

            for line in content.splitlines():
                line = line.strip()
                if not line or line.startswith('#'):
                    continue

                if '=' in line:
                    package_part = line.split('=')[0].strip()
                    # Format: group:artifact:version
                    parts = package_part.split(':')
                    if len(parts) >= 3:
                        group_id = parts[0]
                        artifact_id = parts[1]
                        # version = parts[2]
                        package_name = f"{group_id}:{artifact_id}"
                        # Initialize with empty list (we'll populate from Maven POM if needed)
                        if package_name not in relationships:
                            relationships[package_name] = []

        except IOError as e:
            console.print(f"⚠️ Error reading gradle.lockfile: {e}", style="yellow")

        return relationships

    def build_dependency_tree(self, flat_tree: Dict[str, Any],
                             resolution_details: Dict[str, str]) -> Dict[str, Any]:
        """
        Build dependency tree for Java packages following Python/JavaScript approach.

        This implementation follows the established pattern:
        - Only DIRECT dependencies get children populated
        - Allows multiple depth levels (max 3)
        - Uses visited tracking to prevent infinite loops
        - Keeps file size reasonable while showing meaningful relationships

        Args:
            flat_tree: Flat dependency tree from Scalibr
            resolution_details: Package version mapping

        Returns:
            Enhanced dependency tree with children for direct dependencies only
        """
        console = Console()

        # Get direct dependencies
        direct_deps = self.get_direct_dependencies(Path("."))

        # Parse lock file for relationships (Gradle)
        lock_relationships = self.parse_lock_file(Path("."))

        # For Maven, we can try to parse POM dependencies structure
        # For simplicity, we'll use a basic approach here
        maven_relationships = self._parse_maven_relationships(Path("."))

        # Merge relationships from both sources
        relationships = {**lock_relationships, **maven_relationships}

        # Enhanced tree - only direct dependencies get children
        enhanced_tree = {}
        for package_key, package_info in flat_tree.items():
            # Copy existing package info
            enhanced_info = package_info.copy()

            # Extract package name from 'package==version' format
            package_name = package_key.split('==')[0] if '==' in package_key else package_key

            # Only build children for DIRECT dependencies (following established approach)
            if package_name in direct_deps:
                children = self._build_children_recursive(
                    package_name, relationships, resolution_details,
                    current_depth=0, max_depth=3, visited=set()
                )
                enhanced_info["children"] = children
            else:
                # Transitive dependencies get empty children (like JavaScript/Python)
                enhanced_info["children"] = {}

            enhanced_tree[package_key] = enhanced_info

        return enhanced_tree

    def _parse_maven_relationships(self, project_path: Path) -> Dict[str, List[str]]:
        """
        Parse pom.xml to extract dependency relationships.

        Args:
            project_path: Path to the project directory

        Returns:
            Dictionary mapping package names to their direct dependencies
        """
        pom_path = project_path / "pom.xml"
        if not pom_path.exists():
            return {}

        relationships = {}

        try:
            tree = ET.parse(pom_path)
            root = tree.getroot()

            namespace = self.MAVEN_NS if '{' in root.tag else {'mvn': ''}
            ns_prefix = 'mvn:' if '{' in root.tag else ''

            # Extract dependencies and their transitive deps if specified
            # Note: POM files don't explicitly list transitive deps
            # This would require resolving the POM of each dependency
            # For now, we'll just note the direct dependencies

            for dep in root.findall(f'.//{ns_prefix}dependencies/{ns_prefix}dependency', namespace):
                group_id_elem = dep.find(f'{ns_prefix}groupId', namespace)
                artifact_id_elem = dep.find(f'{ns_prefix}artifactId', namespace)

                if group_id_elem is not None and artifact_id_elem is not None:
                    group_id = group_id_elem.text
                    artifact_id = artifact_id_elem.text

                    if group_id and artifact_id:
                        package_name = f"{group_id}:{artifact_id}"
                        # Initialize empty list (we don't know transitive deps without resolving)
                        if package_name not in relationships:
                            relationships[package_name] = []

        except ET.ParseError:
            pass
        except Exception:
            pass

        return relationships

    def _build_children_recursive(self, parent: str, relationships: Dict[str, List[str]],
                                 resolution_details: Dict[str, str], current_depth: int = 0,
                                 max_depth: int = 3, visited: set = None) -> Dict[str, Any]:
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
