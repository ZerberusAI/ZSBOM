"""
ZSBOM Metadata Collection Framework

This module provides comprehensive metadata collection capabilities for ZSBOM scans,
including execution context, environment details, performance metrics, and error tracking.

The framework follows SOLID principles with a modular architecture:
- MetadataCollector: Main orchestrator for metadata collection
- EnvironmentDetector: System and environment detection
- PerformanceTracker: Performance monitoring and timing
- ErrorTracker: Error capture and categorization  
- RepositoryDetector: Git/SCM information extraction

Usage:
    from depclass.metadata import MetadataCollector
    
    collector = MetadataCollector(config, console)
    scan_id = collector.start_collection()
    # ... perform ZSBOM operations ...
    metadata = collector.finalize_metadata(output_files)
    collector.save_metadata_file(metadata, "scan_metadata.json")
"""

from .collector import MetadataCollector
from .environment import EnvironmentDetector
from .performance import PerformanceTracker
from .error_tracker import ErrorTracker
from .repository import RepositoryDetector

__all__ = [
    "MetadataCollector",
    "EnvironmentDetector", 
    "PerformanceTracker",
    "ErrorTracker",
    "RepositoryDetector",
]

# Version information for metadata
__version__ = "1.0.0"
__author__ = "ZSBOM Team"
__description__ = "Metadata collection framework for ZSBOM security analysis"