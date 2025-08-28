"""
Scanner service interface for ZSBOM.

Defines the abstract interface that scanner implementations must follow,
supporting the Dependency Inversion Principle by allowing high-level 
modules to depend on abstractions rather than concrete implementations.
"""
from abc import ABC, abstractmethod
from typing import Dict, List, Optional, Tuple
from depclass.metadata import MetadataCollector


class IScannerService(ABC):
    """Abstract interface for scanner service implementations."""
    
    @abstractmethod
    def initialize_scan(
        self, 
        config_path: Optional[str],
        output: Optional[str],
        skip_sbom: bool,
        ignore_conflicts: bool,
        ecosystem: str
    ) -> Tuple[dict, str]:
        """
        Initialize scan with configuration and parameters.
        
        Returns:
            Tuple[dict, str]: Configuration and scan ID
        """
        pass
    
    @abstractmethod
    def extract_dependencies(
        self, 
        config: dict, 
        cache: Optional[object], 
        ecosystem: str
    ) -> Tuple[dict, dict]:
        """
        Extract dependencies from the project.
        
        Returns:
            Tuple[dict, dict]: Dependencies data and analysis
        """
        pass
    
    @abstractmethod
    def validate_security(
        self, 
        config: dict, 
        cache: Optional[object], 
        dependencies_analysis: dict
    ) -> dict:
        """
        Validate dependencies for security issues.
        
        Returns:
            dict: Validation results with vulnerabilities
        """
        pass
    
    @abstractmethod
    def assess_risk(
        self, 
        config: dict,
        results: dict, 
        dependency_data: dict, 
        dependencies_analysis: dict
    ) -> list:
        """
        Assess risk for dependencies.
        
        Returns:
            list: Risk scores for each package
        """
        pass
    
    @abstractmethod
    def generate_sbom(
        self, 
        config: dict,
        dependencies_analysis: dict, 
        dependency_data: dict
    ) -> bool:
        """
        Generate Software Bill of Materials.
        
        Returns:
            bool: Success status
        """
        pass
    
    @abstractmethod
    def save_results(
        self, 
        config: dict,
        results: dict,
        scores: list, 
        dependencies_analysis: dict,
        metadata_collector: MetadataCollector
    ) -> List[str]:
        """
        Save scan results to files.
        
        Returns:
            List[str]: List of generated file paths
        """
        pass
    
    @abstractmethod
    def execute_scan(
        self, 
        config_path: Optional[str] = None,
        output: Optional[str] = None,
        skip_sbom: bool = False,
        ignore_conflicts: bool = False,
        ecosystem: str = "python"
    ) -> Tuple[int, dict]:
        """
        Execute complete scan workflow.
        
        Returns:
            Tuple[int, dict]: Exit code and scan metadata
        """
        pass