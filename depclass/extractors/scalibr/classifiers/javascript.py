"""
JavaScript dependency classifier.

Determines direct vs transitive dependencies by reading package.json
to identify which packages are directly declared.

Note: While this classifier handles JavaScript packages, the ecosystem
identifier remains 'npm' for PURL compatibility since npm is the primary
package registry. However, this supports all JavaScript package managers
(npm, yarn, pnpm, bun) that use package.json and lock files.
"""

import json
from pathlib import Path
from typing import Set, Dict, List, Any

from rich.console import Console

from .base import BaseDependencyClassifier


class JavaScriptDependencyClassifier(BaseDependencyClassifier):
    """
    Classifier for JavaScript dependencies.

    Reads package.json to determine which packages are direct dependencies
    (declared in dependencies, devDependencies, etc.) vs transitive
    dependencies (only found in lock files such as package-lock.json,
    yarn.lock, pnpm-lock.yaml, etc.).
    """

    def get_direct_dependencies(self, project_path: Path) -> Set[str]:
        """
        Get direct dependency names from package.json.

        Args:
            project_path: Path to the project directory

        Returns:
            Set of package names declared in package.json
        """
        console = Console()
        package_json_path = project_path / "package.json"

        if not package_json_path.exists():
            return set()

        try:
            with open(package_json_path, 'r', encoding='utf-8') as f:
                data = json.load(f)

            direct_deps = set()

            # Include all dependency types from package.json
            dependency_types = [
                "dependencies",
                "devDependencies",
                "peerDependencies",
                "optionalDependencies"
            ]

            for dep_type in dependency_types:
                if dep_type in data:
                    direct_deps.update(data[dep_type].keys())

            return direct_deps

        except (json.JSONDecodeError, IOError) as e:
            console.print(f"⚠️ Error reading package.json: {e}", style="yellow")
            return set()

    def parse_lock_file(self, project_path: Path) -> Dict[str, Any]:
        """
        Parse package-lock.json for all package data.

        Args:
            project_path: Path to the project directory

        Returns:
            Dictionary with package data including relationships
        """
        console = Console()
        lock_file = project_path / "package-lock.json"

        if not lock_file.exists():
            return {}

        try:
            with open(lock_file, 'r', encoding='utf-8') as f:
                data = json.load(f)

            return data

        except (json.JSONDecodeError, IOError) as e:
            console.print(f"⚠️ Error parsing package-lock.json: {e}", style="yellow")
            return {}

    def build_dependency_tree(self, flat_tree: Dict[str, Any],
                             resolution_details: Dict[str, str]) -> Dict[str, Any]:
        """
        Build dependency tree for JavaScript packages following Python's approach.

        This implementation follows the Python extractor pattern:
        - Only DIRECT dependencies get children populated
        - Allows multiple depth levels (max 3) like Python
        - Uses visited tracking to prevent infinite loops
        - Keeps file size reasonable while showing meaningful relationships

        Args:
            flat_tree: Flat dependency tree from Scalibr
            resolution_details: Package version mapping

        Returns:
            Enhanced dependency tree with children for direct dependencies only
        """
        console = Console()

        # Parse package-lock.json for relationships
        lock_data = self.parse_lock_file(Path("."))
        if not lock_data:
            # Fallback to empty children for all packages
            enhanced_tree = {}
            for package_key, package_info in flat_tree.items():
                enhanced_info = package_info.copy()
                enhanced_info["children"] = {}
                enhanced_tree[package_key] = enhanced_info
            return enhanced_tree

        # Build dependency relationships from lock file
        relationships = {}
        packages = lock_data.get("packages", {})

        for pkg_path, pkg_info in packages.items():
            if pkg_path.startswith("node_modules/"):
                pkg_name = pkg_path.replace("node_modules/", "")
                # Handle nested node_modules (e.g., buffer/node_modules/isarray -> buffer)
                if "/node_modules/" in pkg_name:
                    pkg_name = pkg_name.split("/node_modules/")[0]

                deps = pkg_info.get("dependencies", {})
                if deps:
                    relationships[pkg_name] = list(deps.keys())

        # Get direct dependencies
        direct_deps = self.get_direct_dependencies(Path("."))

        # Enhanced tree - only direct dependencies get children
        enhanced_tree = {}
        for package_key, package_info in flat_tree.items():
            # Copy existing package info
            enhanced_info = package_info.copy()

            # Extract package name from 'package==version' format
            package_name = package_key.split('==')[0] if '==' in package_key else package_key

            # Only build children for DIRECT dependencies (following Python's approach)
            if package_name in direct_deps:
                children = self._build_children_recursive(
                    package_name, relationships, resolution_details,
                    current_depth=0, max_depth=3, visited=set()
                )
                enhanced_info["children"] = children
            else:
                # Transitive dependencies get empty children (like Python)
                enhanced_info["children"] = {}

            enhanced_tree[package_key] = enhanced_info

        return enhanced_tree

    def _build_children_recursive(self, parent: str, relationships: Dict[str, List[str]],
                                 resolution_details: Dict[str, str], current_depth: int = 0,
                                 max_depth: int = 3, visited: set = None) -> Dict[str, Any]:
        """
        Build children structure recursively for JavaScript dependencies.

        Following Python's approach with proper safeguards to prevent massive files.

        Args:
            parent: Parent package name
            relationships: Package dependency relationships
            resolution_details: Package version mapping
            current_depth: Current recursion depth
            max_depth: Maximum recursion depth (like Python's depth=3)
            visited: Set of already visited packages to prevent cycles

        Returns:
            Dictionary with children structure matching Python extractor format
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

