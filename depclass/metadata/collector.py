"""
Metadata Collector Module for ZSBOM

This module provides the main orchestrator for comprehensive metadata collection
during ZSBOM execution, following SOLID principles with dependency injection
and extensible architecture.

Classes:
    MetadataCollector: Main metadata collection orchestrator
    ScanMetadata: Structured scan metadata container
    MetadataConfig: Configuration for metadata collection
"""

import json
import os
import uuid
from datetime import datetime, timezone
from typing import Dict, List, Optional, Any, Union
from dataclasses import dataclass, field
from pathlib import Path

from .environment import EnvironmentDetector
from .performance import PerformanceTracker, StageStatus
from .error_tracker import ErrorTracker, ErrorSeverity, ErrorCategory
from .repository import RepositoryDetector


# Metadata collection configuration constants
METADATA_CONFIG = {
    "enabled": True,
    "capture_environment": True,
    "capture_performance": True,
    "capture_errors": True,
    "output_file": "scan_metadata.json",
    "include_git_info": True,
    "include_system_info": True,
    "include_file_sizes": True,
    "max_error_records": 100,
    "performance_monitoring": True
}


@dataclass
class ScanMetadata:
    """Structured container for scan metadata following the Phase 3 schema."""
    
    scan_id: str
    execution: Dict[str, Any] = field(default_factory=dict)
    environment: Dict[str, Any] = field(default_factory=dict)
    repository: Dict[str, Any] = field(default_factory=dict)
    performance: Dict[str, Any] = field(default_factory=dict)
    configuration: Dict[str, Any] = field(default_factory=dict)
    outputs: Dict[str, Any] = field(default_factory=dict)
    errors: List[Dict[str, Any]] = field(default_factory=list)
    statistics: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "scan_id": self.scan_id,
            "execution": self.execution,
            "environment": self.environment,
            "repository": self.repository,
            "performance": self.performance,
            "configuration": self.configuration,
            "outputs": self.outputs,
            "errors": self.errors,
            "statistics": self.statistics
        }


class MetadataCollector:
    """
    Main metadata collection orchestrator following SOLID principles.
    
    This class coordinates the collection of comprehensive scan metadata including:
    - Execution timing and status
    - Environment and system information
    - Repository and CI context
    - Performance metrics per pipeline stage
    - Error tracking and categorization
    - Configuration details
    - Output file information
    - Statistical summaries
    """
    
    def __init__(
        self, 
        config: Dict[str, Any], 
        console: Any = None,
        working_directory: Optional[str] = None
    ):
        """
        Initialize metadata collector.
        
        Args:
            config: ZSBOM configuration dictionary
            console: Rich console instance for output
            working_directory: Override working directory for detection
        """
        self.config = config
        self.console = console
        self.working_directory = working_directory or os.getcwd()
        
        # Generate unique scan ID
        self.scan_id = str(uuid.uuid4())
        
        # Initialize component detectors (dependency injection)
        self.environment_detector = EnvironmentDetector()
        self.performance_tracker = PerformanceTracker(
            enable_resource_monitoring=METADATA_CONFIG["performance_monitoring"]
        )
        self.error_tracker = ErrorTracker()
        self.repository_detector = RepositoryDetector(self.working_directory)
        
        # Execution tracking
        self.started_at: Optional[datetime] = None
        self.completed_at: Optional[datetime] = None
        self.exit_code: int = 0
        self.status: str = "in_progress"
        
        # Output tracking
        self.generated_files: List[str] = []
        self.file_sizes: Dict[str, int] = {}
        
        # Statistics tracking
        self.statistics: Dict[str, Any] = {}
        
        # Configuration tracking
        self.config_source: str = "unknown"
        self.config_path: Optional[str] = None
    
    def start_collection(self) -> str:
        """
        Start metadata collection process.
        
        Returns:
            str: Unique scan ID for this collection session
        """
        self.started_at = datetime.now(timezone.utc)
        self.status = "in_progress"
        
        # Start overall performance timing
        self.performance_tracker.start_overall_timing()
        
        # Detect configuration source
        self._detect_configuration_source()
        
        return self.scan_id
    
    def track_stage_start(self, stage: str, custom_metrics: Optional[Dict[str, Any]] = None):
        """
        Start tracking a pipeline stage.
        
        Args:
            stage: Name of the pipeline stage
            custom_metrics: Optional custom metrics for this stage
        """
        try:
            self.performance_tracker.start_stage(stage, custom_metrics)
        except Exception as e:
            self.error_tracker.capture_error(
                e, "metadata_collection", 
                ErrorCategory.SYSTEM, 
                ErrorSeverity.WARNING,
                {"operation": "track_stage_start", "stage": stage}
            )
    
    def track_stage_end(self, stage: str, success: bool = True, error_message: Optional[str] = None):
        """
        End tracking a pipeline stage.
        
        Args:
            stage: Name of the pipeline stage
            success: Whether the stage completed successfully
            error_message: Optional error message if stage failed
        """
        try:
            self.performance_tracker.end_stage(stage, success, error_message)
        except Exception as e:
            self.error_tracker.capture_error(
                e, "metadata_collection",
                ErrorCategory.SYSTEM,
                ErrorSeverity.WARNING,
                {"operation": "track_stage_end", "stage": stage}
            )
    
    def skip_stage(self, stage: str, reason: Optional[str] = None):
        """
        Mark a stage as skipped.
        
        Args:
            stage: Name of the pipeline stage
            reason: Reason for skipping the stage
        """
        try:
            self.performance_tracker.skip_stage(stage, reason)
        except Exception as e:
            self.error_tracker.capture_error(
                e, "metadata_collection",
                ErrorCategory.SYSTEM,
                ErrorSeverity.WARNING,
                {"operation": "skip_stage", "stage": stage}
            )
    
    def capture_error(
        self, 
        error: Exception, 
        stage: str,
        category: Optional[ErrorCategory] = None,
        severity: Optional[ErrorSeverity] = None,
        details: Optional[Dict[str, Any]] = None
    ):
        """
        Capture an error during pipeline execution.
        
        Args:
            error: The exception that occurred
            stage: Pipeline stage where error occurred
            category: Optional error category override
            severity: Optional severity level override
            details: Additional error context
        """
        try:
            self.error_tracker.capture_error(error, stage, category, severity, details)
        except Exception:
            # Fallback: ensure error tracking doesn't break the pipeline
            pass
    
    def capture_message(
        self,
        message: str,
        stage: str,
        severity: ErrorSeverity = ErrorSeverity.INFO,
        category: ErrorCategory = ErrorCategory.UNKNOWN,
        details: Optional[Dict[str, Any]] = None
    ):
        """
        Capture a message/warning/info during pipeline execution.
        
        Args:
            message: The message to capture
            stage: Pipeline stage where message occurred
            severity: Severity level of the message
            category: Category of the message
            details: Additional context
        """
        try:
            self.error_tracker.capture_message(message, stage, severity, category, details)
        except Exception:
            # Fallback: ensure message tracking doesn't break the pipeline
            pass
    
    def add_generated_file(self, file_path: str):
        """
        Track a generated output file.
        
        Args:
            file_path: Path to the generated file
        """
        try:
            if file_path not in self.generated_files:
                self.generated_files.append(file_path)
                
            # Calculate file size if file exists
            if METADATA_CONFIG["include_file_sizes"] and os.path.exists(file_path):
                self.file_sizes[file_path] = os.path.getsize(file_path)
        except Exception as e:
            self.error_tracker.capture_error(
                e, "metadata_collection",
                ErrorCategory.SYSTEM,
                ErrorSeverity.WARNING,
                {"operation": "add_generated_file", "file_path": file_path}
            )
    
    def update_statistics(self, stats: Dict[str, Any]):
        """
        Update scan statistics.
        
        Args:
            stats: Dictionary of statistics to update
        """
        try:
            self.statistics.update(stats)
        except Exception as e:
            self.error_tracker.capture_error(
                e, "metadata_collection",
                ErrorCategory.SYSTEM,
                ErrorSeverity.WARNING,
                {"operation": "update_statistics"}
            )
    
    def finalize_metadata(
        self, 
        output_files: Optional[List[str]] = None,
        final_statistics: Optional[Dict[str, Any]] = None,
        exit_code: int = 0
    ) -> Dict[str, Any]:
        """
        Finalize and compile comprehensive metadata.
        
        Args:
            output_files: List of output files generated
            final_statistics: Final scan statistics
            exit_code: Process exit code
            
        Returns:
            Dict containing complete scan metadata
        """
        try:
            # Update completion time and status
            self.completed_at = datetime.now(timezone.utc)
            self.exit_code = exit_code
            self.status = "completed" if exit_code == 0 else "failed"
            
            # End overall timing
            self.performance_tracker.end_overall_timing()
            
            # Update file tracking
            if output_files:
                for file_path in output_files:
                    self.add_generated_file(file_path)
            
            # Update final statistics
            if final_statistics:
                self.update_statistics(final_statistics)
            
            # Compile comprehensive metadata
            metadata = ScanMetadata(
                scan_id=self.scan_id,
                execution=self._compile_execution_metadata(),
                environment=self._compile_environment_metadata(),
                repository=self._compile_repository_metadata(),
                performance=self._compile_performance_metadata(),
                configuration=self._compile_configuration_metadata(),
                outputs=self._compile_outputs_metadata(),
                errors=self._compile_errors_metadata(),
                statistics=self._compile_statistics_metadata()
            )
            
            return metadata.to_dict()
            
        except Exception as e:
            # Ensure we always return something, even if metadata compilation fails
            self.error_tracker.capture_error(
                e, "metadata_collection",
                ErrorCategory.SYSTEM,
                ErrorSeverity.CRITICAL,
                {"operation": "finalize_metadata"}
            )
            
            return self._create_fallback_metadata(exit_code)
    
    def save_metadata_file(
        self, 
        metadata: Dict[str, Any], 
        file_path: str = "scan_metadata.json"
    ):
        """
        Save metadata to JSON file.
        
        Args:
            metadata: Metadata dictionary to save
            file_path: Output file path
        """
        try:
            with open(file_path, 'w', encoding='utf-8') as f:
                json.dump(metadata, f, indent=2, ensure_ascii=False)
            
            # Track the metadata file itself
            self.add_generated_file(file_path)
            
        except Exception as e:
            # Try to save to a fallback location
            try:
                fallback_path = f"scan_metadata_fallback_{self.scan_id[:8]}.json"
                with open(fallback_path, 'w', encoding='utf-8') as f:
                    json.dump(metadata, f, indent=2, ensure_ascii=False)
            except Exception:
                # If all saving fails, log to console if available
                if self.console:
                    self.console.print(f"❌ Failed to save metadata: {str(e)}", style="bold red")
    
    def _detect_configuration_source(self):
        """Detect how configuration was loaded."""
        try:
            if os.path.exists("zsbom.config.yaml"):
                self.config_source = "auto_discovered"
                self.config_path = "./zsbom.config.yaml"
            elif "config_path" in self.config:
                self.config_source = "user_provided"
                self.config_path = self.config["config_path"]
            else:
                self.config_source = "default"
                self.config_path = None
        except Exception:
            self.config_source = "unknown"
    
    def _compile_execution_metadata(self) -> Dict[str, Any]:
        """Compile execution-related metadata."""
        duration = None
        if self.started_at and self.completed_at:
            duration = (self.completed_at - self.started_at).total_seconds()
        
        return {
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "duration_seconds": duration,
            "status": self.status,
            "exit_code": self.exit_code
        }
    
    def _compile_environment_metadata(self) -> Dict[str, Any]:
        """Compile environment-related metadata."""
        try:
            if METADATA_CONFIG["capture_environment"]:
                return self.environment_detector.detect_all()
            return {"capture_disabled": True}
        except Exception as e:
            return {"detection_failed": True, "error": str(e)}
    
    def _compile_repository_metadata(self) -> Dict[str, Any]:
        """Compile repository-related metadata."""
        try:
            if METADATA_CONFIG["include_git_info"]:
                return self.repository_detector.detect_all()
            return {"capture_disabled": True}
        except Exception as e:
            return {"detection_failed": True, "error": str(e)}
    
    def _compile_performance_metadata(self) -> Dict[str, Any]:
        """Compile performance-related metadata."""
        try:
            if METADATA_CONFIG["capture_performance"]:
                performance_summary = self.performance_tracker.get_performance_summary()
                
                # Extract stage-specific timings for easy access
                stage_timings = {}
                for stage_name, stage_data in performance_summary.get("stages", {}).items():
                    if stage_data.get("duration_seconds") is not None:
                        stage_timings[f"{stage_name}_seconds"] = stage_data["duration_seconds"]
                
                # Add file analysis information
                stage_timings["files_analyzed"] = list(self.file_sizes.keys())
                stage_timings["total_packages_processed"] = self.statistics.get("total_dependencies", 0)
                
                return stage_timings
            return {"capture_disabled": True}
        except Exception as e:
            return {"detection_failed": True, "error": str(e)}
    
    def _compile_configuration_metadata(self) -> Dict[str, Any]:
        """Compile configuration-related metadata."""
        try:
            config_metadata = {
                "config_source": self.config_source,
                "config_path": self.config_path,
                "ecosystem": self.config.get("ecosystem", "python"),
                "skip_sbom": False,  # Default from CLI
                "ignore_conflicts": self.config.get("ignore_conflicts", False)
            }
            
            # Add relevant configuration sections (without sensitive data)
            safe_config_keys = [
                "validation_rules", "transitive_analysis", "risk_model",
                "typosquat_detection", "version_consistency"
            ]
            
            for key in safe_config_keys:
                if key in self.config:
                    config_metadata[key] = self.config[key]
            
            return config_metadata
        except Exception as e:
            return {"compilation_failed": True, "error": str(e)}
    
    def _compile_outputs_metadata(self) -> Dict[str, Any]:
        """Compile output files metadata."""
        try:
            return {
                "generated_files": self.generated_files,
                "file_sizes": self.file_sizes
            }
        except Exception as e:
            return {"compilation_failed": True, "error": str(e)}
    
    def _compile_errors_metadata(self) -> List[Dict[str, Any]]:
        """Compile error records metadata."""
        try:
            if METADATA_CONFIG["capture_errors"]:
                errors = self.error_tracker.get_all_errors()
                # Limit number of error records to prevent huge metadata files
                max_errors = METADATA_CONFIG["max_error_records"]
                return errors[-max_errors:] if len(errors) > max_errors else errors
            return []
        except Exception as e:
            return [{"compilation_failed": True, "error": str(e)}]
    
    def _compile_statistics_metadata(self) -> Dict[str, Any]:
        """Compile scan statistics metadata."""
        try:
            stats = self.statistics.copy()
            
            # Add error statistics
            error_summary = self.error_tracker.get_error_summary()
            stats.update(error_summary)
            
            # Add performance statistics
            performance_summary = self.performance_tracker.get_performance_summary()
            stats["total_stages"] = performance_summary.get("total_stages", 0)
            stats["completed_stages"] = performance_summary.get("completed_stages", 0)
            stats["failed_stages"] = performance_summary.get("failed_stages", 0)
            
            return stats
        except Exception as e:
            return {"compilation_failed": True, "error": str(e)}
    
    def _create_fallback_metadata(self, exit_code: int) -> Dict[str, Any]:
        """Create minimal fallback metadata when compilation fails."""
        return {
            "scan_id": self.scan_id,
            "execution": {
                "started_at": self.started_at.isoformat() if self.started_at else None,
                "completed_at": datetime.now(timezone.utc).isoformat(),
                "status": "failed",
                "exit_code": exit_code,
                "metadata_compilation_failed": True
            },
            "environment": {"detection_failed": True},
            "repository": {"detection_failed": True},
            "performance": {"tracking_failed": True},
            "configuration": {"compilation_failed": True},
            "outputs": {"generated_files": [], "file_sizes": {}},
            "errors": [],
            "statistics": {"metadata_errors": True}
        }
    
    def cleanup(self):
        """Clean up resources and active timers."""
        try:
            self.performance_tracker.cleanup_active_timers()
        except Exception:
            pass