"""
Base extractor interface for multi-ecosystem dependency extraction.

Defines the contract that all ecosystem-specific extractors must implement.
"""

from abc import ABC, abstractmethod
from typing import Dict, List, Optional, Any
from pathlib import Path


class BaseExtractor(ABC):
    """
    Abstract base class for ecosystem-specific dependency extractors.

    Each extractor is responsible for:
    1. Detecting if the project uses its ecosystem
    2. Extracting dependencies from ecosystem-specific files
    3. Performing transitive dependency analysis if supported
    4. Returning results in a standardized format
    """

    def __init__(self, project_path: str = "."):
        """
        Initialize the extractor.

        Args:
            project_path: Path to the project directory to scan
        """
        self.project_path = Path(project_path)

    @property
    def ecosystem_name(self) -> Optional[str]:
        """
        Return the name of the ecosystem this extractor handles.

        For single-ecosystem extractors, this should return the ecosystem name.
        For meta-extractors (like ScalibrExtractor), this can return None.
        """
        return None

    @property
    def supported_files(self) -> List[str]:
        """
        Return list of file patterns this extractor can handle.

        For single-ecosystem extractors, this should return specific file patterns.
        For meta-extractors that delegate to external tools, this can return an empty list.
        """
        return []

    @abstractmethod
    def can_extract(self) -> bool:
        """
        Check if this extractor can handle the current project.

        Returns:
            True if the extractor can handle the project, False otherwise
        """
        pass

    @abstractmethod
    def extract_dependencies(
        self,
        config: Optional[Dict] = None,
        cache=None
    ) -> Dict[str, Any]:
        """
        Extract dependencies from the project.

        Args:
            config: Configuration dictionary
            cache: Cache instance for external API calls

        Returns:
            Dictionary with standardized dependency extraction results:
            {
                "dependencies": {...},  # Direct dependencies found in files
                "dependencies_analysis": {  # Enhanced analysis results
                    "total_packages": int,
                    "dependency_tree": {...},
                    "package_files": [...],
                    "resolution_details": {...}
                }
            }
        """
        pass

    def get_dependency_files(self) -> List[Path]:
        """
        Get list of dependency files found in the project.

        Returns:
            List of Path objects for found dependency files
        """
        found_files = []
        for pattern in self.supported_files:
            # Handle both exact filenames and glob patterns
            if "*" in pattern:
                found_files.extend(self.project_path.glob(pattern))
            else:
                file_path = self.project_path / pattern
                if file_path.exists():
                    found_files.append(file_path)
        return found_files

    def validate_config(self, config: Optional[Dict]) -> Dict:
        """
        Validate and provide defaults for configuration.

        Args:
            config: Configuration dictionary to validate

        Returns:
            Validated configuration with defaults applied
        """
        if config is None:
            config = {}

        # Apply common defaults
        validated_config = {
            "transitive_analysis": {
                "enabled": True,
                "timeout": 120,
                "cache_ttl_hours": 24
            },
            "caching": {
                "enabled": True,
                "path": "cache.db"
            },
            **config
        }

        return validated_config