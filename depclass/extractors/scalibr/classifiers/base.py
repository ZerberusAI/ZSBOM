"""
Base dependency classifier for ecosystem-specific dependency classification.

Following SOLID principles:
- Single Responsibility: Each classifier handles one ecosystem
- Open/Closed: Easy to extend with new ecosystem classifiers
"""

from abc import ABC, abstractmethod
from pathlib import Path
from typing import Set, Dict, Any, Optional
import logging
import concurrent.futures


class BaseDependencyClassifier(ABC):
    """
    Abstract base class for ecosystem-specific dependency classification.

    Subclasses implement ecosystem-specific logic to determine which packages
    are direct dependencies (declared in manifest files) vs transitive
    dependencies (dependencies of other packages).
    """

    def __init__(self):
        """Initialize base classifier."""
        self.logger = logging.getLogger(self.__class__.__name__)
        self.depsdev_provider = None

    @abstractmethod
    def get_direct_dependencies(self, project_path: Path) -> Set[str]:
        """Get direct dependency names from manifest files."""
        pass

    def classify(self, package_name: str, direct_deps: Set[str]) -> str:
        """Classify a package as direct or transitive."""
        return "direct" if package_name in direct_deps else "transitive"

    def build_dependency_tree(self, flat_tree: Dict[str, Any],
                             resolution_details: Dict[str, str]) -> Dict[str, Any]:
        """Build enhanced dependency tree with children relationships (default: flat tree with empty children)."""
        for package_key, package_info in flat_tree.items():
            if "children" not in package_info:
                package_info["children"] = {}

        return flat_tree

    def set_depsdev_provider(self, provider):
        """Inject deps.dev provider for API-based dependency resolution."""
        self.depsdev_provider = provider

    def build_tree_from_depsdev(
        self,
        flat_tree: Dict[str, Any],
        resolution_details: Dict[str, str],
        ecosystem: str
    ) -> Dict[str, Any]:
        """Build dependency tree using deps.dev API with parallel calls (1-level children only)."""
        if not self.depsdev_provider:
            return flat_tree

        # Initialize empty children
        for package_info in flat_tree.values():
            package_info.setdefault("children", {})

        # Get direct dependencies only
        direct_deps = [
            (pkg_key, info["version"])
            for pkg_key, info in flat_tree.items()
            if info.get("type") == "direct"
        ]

        if not direct_deps:
            return flat_tree

        # Fetch graphs in parallel
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            future_to_dep = {
                executor.submit(
                    self.depsdev_provider.get_dependency_graph,
                    pkg_key.split("==")[0],
                    version,
                    ecosystem
                ): pkg_key
                for pkg_key, version in direct_deps
            }

            # Process results
            for future in concurrent.futures.as_completed(future_to_dep):
                dep_key = future_to_dep[future]
                try:
                    graph = future.result()
                    if graph and "nodes" in graph and "edges" in graph:
                        # Add immediate children only (simple!)
                        children = self._extract_immediate_children(graph, flat_tree)
                        if dep_key in flat_tree:
                            flat_tree[dep_key]["children"] = children
                except Exception as e:
                    self.logger.debug(f"Graph fetch failed for {dep_key}: {e}")

        return flat_tree

    def _extract_immediate_children(
        self, graph: Dict[str, Any], flat_tree: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Extract immediate children from deps.dev graph (1-level only)."""
        nodes = graph.get("nodes", [])
        edges = graph.get("edges", [])

        if not nodes or not edges:
            return {}

        # Find children of node 0 (the package itself)
        children = {}
        for edge in edges:
            if edge.get("fromNode") == 0:  # Direct children only
                child_idx = edge.get("toNode")
                if child_idx and child_idx < len(nodes):
                    node = nodes[child_idx]
                    vk = node.get("versionKey", {})
                    name = vk.get("name")
                    version = vk.get("version")

                    if name and version:
                        child_key = f"{name}=={version}"
                        # Use existing info from flat_tree if available
                        if child_key in flat_tree:
                            children[child_key] = flat_tree[child_key].copy()
                        else:
                            children[child_key] = {
                                "type": "transitive",
                                "version": version,
                                "children": {}
                            }

        return children