"""
Base dependency classifier for ecosystem-specific dependency classification.

Following SOLID principles:
- Single Responsibility: Each classifier handles one ecosystem
- Open/Closed: Easy to extend with new ecosystem classifiers
"""

from abc import ABC, abstractmethod
from pathlib import Path
from typing import Set, Dict, Any


class BaseDependencyClassifier(ABC):
    """
    Abstract base class for ecosystem-specific dependency classification.

    Subclasses implement ecosystem-specific logic to determine which packages
    are direct dependencies (declared in manifest files) vs transitive
    dependencies (dependencies of other packages).
    """

    @abstractmethod
    def get_direct_dependencies(self, project_path: Path) -> Set[str]:
        """
        Get the set of direct dependency names from manifest files.

        Args:
            project_path: Path to the project directory

        Returns:
            Set of package names that are direct dependencies
        """
        pass

    def classify(self, package_name: str, direct_deps: Set[str]) -> str:
        """
        Classify a package as direct or transitive.

        Args:
            package_name: Name of the package to classify
            direct_deps: Set of direct dependency names

        Returns:
            "direct" if package is in direct_deps, "transitive" otherwise
        """
        return "direct" if package_name in direct_deps else "transitive"

    def build_dependency_tree(self, flat_tree: Dict[str, Any],
                             resolution_details: Dict[str, str]) -> Dict[str, Any]:
        """
        Build enhanced dependency tree with children relationships.

        This is an optional method that ecosystems can override to provide
        parent-child dependency relationships. The default implementation
        returns the flat tree unchanged.

        Args:
            flat_tree: Flat dependency tree from extractor
            resolution_details: Package version mapping

        Returns:
            Enhanced dependency tree (default: unchanged flat tree)
        """
        # Default implementation: no children structure
        # Ecosystems like NPM can override this to add children
        for package_key, package_info in flat_tree.items():
            if "children" not in package_info:
                package_info["children"] = {}

        return flat_tree