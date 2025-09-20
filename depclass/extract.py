"""
Multi-ecosystem dependency extraction with auto-detection.

Automatically detects and extracts dependencies from all ecosystems present
in a project, using specialized logic for Python and Scalibr for everything else.
"""

from typing import Dict, Optional, Any, List
from pathlib import Path

from .extractors.python.extractor import PythonExtractor
from .extractors.scalibr.extractor import ScalibrExtractor


def extract(
    project_path: str = ".",
    config: Optional[Dict] = None,
    cache=None,
) -> Dict[str, Any]:
    """
    Auto-detect and extract dependencies from all ecosystems in a project.

    Args:
        project_path: Path to the project directory
        config: Configuration dictionary
        cache: Cache instance for external API calls

    Returns:
        Unified multi-ecosystem dependency extraction results:
        {
            "dependencies": {
                "python": {...},
                "npm": {...},
                # ... other ecosystems
            },
            "dependencies_analysis": {
                "total_packages": 150,
                "ecosystems_detected": ["python", "npm"],
                "dependency_tree": {
                    "python": {...},
                    "npm": {...}
                },
                "package_files": [
                    {"path": "requirements.txt", "ecosystem": "python", "packages": [...]},
                    {"path": "package.json", "ecosystem": "npm", "packages": [...]}
                ],
                "resolution_details": {
                    "python": {...},
                    "npm": {...}
                }
            }
        }
    """
    config = config or {}

    # Step 1: Extract from Python if present (using pip-tools)
    python_result = _extract_python_if_present(project_path, config, cache)

    # Step 2: Extract from all other ecosystems using Scalibr
    scalibr_result = _extract_via_scalibr(project_path, config, cache)

    # Step 3: Merge results
    return _merge_ecosystem_results(python_result, scalibr_result)


def _extract_python_if_present(project_path: str, config: Dict, cache) -> Dict[str, Any]:
    """Extract Python dependencies if Python files are detected."""
    try:
        python_extractor = PythonExtractor(project_path)

        if python_extractor.can_extract():
            print("🐍 Detected Python ecosystem")
            return python_extractor.extract_dependencies(config, cache)

        return _create_empty_ecosystem_result()

    except Exception as e:
        print(f"⚠️ Python extraction failed: {e}")
        return _create_empty_ecosystem_result()


def _extract_via_scalibr(project_path: str, config: Dict, cache) -> Dict[str, Any]:
    """Extract dependencies from all non-Python ecosystems using Scalibr."""
    try:
        scalibr_extractor = ScalibrExtractor(project_path)

        if scalibr_extractor.can_extract():
            ecosystems_found = scalibr_extractor.extract_all_ecosystems(config, cache)

            if ecosystems_found:
                detected = list(ecosystems_found.keys())
                print(f"🔍 Detected ecosystems via Scalibr: {', '.join(detected)}")

                return {
                    "ecosystems": ecosystems_found,
                    "ecosystems_detected": detected,
                    "total_packages": sum(
                        eco_data.get("dependencies_analysis", {}).get("total_packages", 0)
                        for eco_data in ecosystems_found.values()
                    )
                }

        return _create_empty_ecosystem_result()

    except Exception as e:
        print(f"⚠️ Scalibr extraction failed: {e}")
        return _create_empty_ecosystem_result()


def _create_empty_ecosystem_result() -> Dict[str, Any]:
    """Create empty ecosystem result structure."""
    return {
        "ecosystems": {},
        "ecosystems_detected": [],
        "total_packages": 0
    }


def _merge_ecosystem_results(
    python_result: Dict[str, Any],
    scalibr_result: Dict[str, Any]
) -> Dict[str, Any]:
    """Merge results from Python and Scalibr extractors into unified format."""

    # Combine all ecosystems
    all_ecosystems = {}
    all_ecosystems.update(python_result.get("ecosystems", {}))
    all_ecosystems.update(scalibr_result.get("ecosystems", {}))

    # Combine detected ecosystems lists
    detected_ecosystems = []
    detected_ecosystems.extend(python_result.get("ecosystems_detected", []))
    detected_ecosystems.extend(scalibr_result.get("ecosystems_detected", []))

    # Calculate total packages
    total_packages = python_result.get("total_packages", 0) + scalibr_result.get("total_packages", 0)

    if not all_ecosystems:
        print("❌ No package ecosystems detected in this project")
        return _create_empty_unified_result()

    # Build unified result structure
    dependencies = {}
    dependency_trees = {}
    all_package_files = []
    resolution_details = {}

    for ecosystem_name, ecosystem_data in all_ecosystems.items():
        # Extract dependencies for each ecosystem
        eco_dependencies = ecosystem_data.get("dependencies", {})
        dependencies[ecosystem_name] = eco_dependencies

        # Extract dependency analysis
        eco_analysis = ecosystem_data.get("dependencies_analysis", {})
        dependency_trees[ecosystem_name] = eco_analysis.get("dependency_tree", {})
        resolution_details[ecosystem_name] = eco_analysis.get("resolution_details", {})

        # Collect package files (already have ecosystem tags)
        eco_package_files = eco_analysis.get("package_files", [])
        all_package_files.extend(eco_package_files)

    print(f"✅ Successfully extracted dependencies from {len(detected_ecosystems)} ecosystems: {', '.join(detected_ecosystems)}")

    return {
        "dependencies": dependencies,
        "dependencies_analysis": {
            "total_packages": total_packages,
            "ecosystems_detected": detected_ecosystems,
            "dependency_tree": dependency_trees,
            "package_files": all_package_files,
            "resolution_details": resolution_details
        }
    }


def _create_empty_unified_result() -> Dict[str, Any]:
    """Create empty unified result structure."""
    return {
        "dependencies": {},
        "dependencies_analysis": {
            "total_packages": 0,
            "ecosystems_detected": [],
            "dependency_tree": {},
            "package_files": [],
            "resolution_details": {}
        }
    }


# Legacy compatibility functions
def extract_dependencies(project_path: str = ".", config: Optional[Dict] = None, cache=None) -> Dict[str, Any]:
    """
    Legacy compatibility function.

    This maintains backward compatibility with the old API while using the new
    multi-ecosystem extraction system under the hood.
    """
    result = extract(project_path, config, cache)

    # For backward compatibility, if only Python was found, return the old format
    ecosystems = result.get("dependencies", {})
    if len(ecosystems) == 1 and "python" in ecosystems:
        python_data = result["dependencies_analysis"]["dependency_tree"]["python"]
        python_deps = result["dependencies"]["python"]

        # Convert back to old format for backward compatibility
        return {
            "dependencies": python_deps,
            "dependencies_analysis": {
                "total_packages": result["dependencies_analysis"]["total_packages"],
                "dependency_tree": python_data,
                "package_files": [pf for pf in result["dependencies_analysis"]["package_files"] if pf.get("ecosystem") == "python"],
                "resolution_details": result["dependencies_analysis"]["resolution_details"].get("python", {})
            }
        }

    # For multi-ecosystem results, return the new format
    return result



if __name__ == "__main__":
    deps = extract()
    ecosystems = deps.get("dependencies", {})

    for ecosystem_name, ecosystem_deps in ecosystems.items():
        print(f"\n{ecosystem_name.upper()} dependencies:")
        for file_name, packages in ecosystem_deps.items():
            print(f"  {file_name}:")
            for package, version in packages.items():
                print(f"    {package}: {version}")