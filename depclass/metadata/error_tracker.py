"""
Error Tracking Module for ZSBOM Metadata Collection

This module provides comprehensive error capture, categorization, and tracking
for ZSBOM pipeline execution, following SOLID principles.

Classes:
    ErrorTracker: Main error tracking orchestrator
    ErrorRecord: Individual error record data structure
    ErrorCategory: Error categorization enumeration
    ErrorSeverity: Error severity levels
    ErrorAnalyzer: Error analysis and categorization logic
"""

import traceback
import sys
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from typing import Dict, List, Optional, Any, Type, Union
from dataclasses import dataclass, field
from enum import Enum


class ErrorSeverity(Enum):
    """Error severity levels for categorization."""
    CRITICAL = "critical"  # Scan cannot continue
    ERROR = "error"        # Feature degraded but scan continues
    WARNING = "warning"    # Minor issues, informational
    INFO = "info"          # General information


class ErrorCategory(Enum):
    """Error categories for systematic classification."""
    DEPENDENCY_EXTRACTION = "dependency_extraction"  # Package resolution, file parsing
    VALIDATION = "validation"                         # CVE/CWE lookup failures, API timeouts
    RISK_ASSESSMENT = "risk_assessment"              # Scoring calculation errors
    SBOM_GENERATION = "sbom_generation"              # Output format errors
    SYSTEM = "system"                                # File I/O, permissions, environment
    CONFIGURATION = "configuration"                  # Config validation, missing settings
    NETWORK = "network"                             # API calls, connectivity issues
    UNKNOWN = "unknown"                             # Uncategorized errors


@dataclass
class ErrorRecord:
    """Individual error record with comprehensive context."""
    timestamp: datetime
    level: ErrorSeverity
    stage: str
    category: ErrorCategory
    message: str
    exception_type: Optional[str] = None
    traceback_info: Optional[str] = None
    details: Dict[str, Any] = field(default_factory=dict)
    resolution_hint: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert error record to dictionary for JSON serialization."""
        return {
            "timestamp": self.timestamp.isoformat(),
            "level": self.level.value,
            "stage": self.stage,
            "category": self.category.value,
            "message": self.message,
            "exception_type": self.exception_type,
            "traceback_info": self.traceback_info,
            "details": self.details,
            "resolution_hint": self.resolution_hint
        }
    
    @classmethod
    def from_exception(
        cls,
        exception: Exception,
        stage: str,
        category: Optional[ErrorCategory] = None,
        severity: Optional[ErrorSeverity] = None,
        details: Optional[Dict[str, Any]] = None
    ) -> "ErrorRecord":
        """Create error record from exception."""
        return cls(
            timestamp=datetime.now(timezone.utc),
            level=severity or ErrorSeverity.ERROR,
            stage=stage,
            category=category or ErrorCategory.UNKNOWN,
            message=str(exception),
            exception_type=type(exception).__name__,
            traceback_info=traceback.format_exc(),
            details=details or {}
        )


class BaseErrorAnalyzer(ABC):
    """Abstract base class for error analysis and categorization."""
    
    @abstractmethod
    def can_analyze(self, exception: Exception) -> bool:
        """Check if this analyzer can handle the exception type."""
        pass
    
    @abstractmethod
    def analyze(self, exception: Exception, stage: str) -> ErrorRecord:
        """Analyze exception and return categorized error record."""
        pass
    
    @abstractmethod
    def get_analyzer_name(self) -> str:
        """Return name of this analyzer."""
        pass


class NetworkErrorAnalyzer(BaseErrorAnalyzer):
    """Analyzer for network-related errors."""
    
    NETWORK_EXCEPTIONS = (
        "ConnectionError", "TimeoutError", "HTTPError", "URLError",
        "DNSError", "SSLError", "RequestException"
    )
    
    def can_analyze(self, exception: Exception) -> bool:
        """Check if this is a network-related exception."""
        exception_name = type(exception).__name__
        return (
            exception_name in self.NETWORK_EXCEPTIONS or
            "connection" in str(exception).lower() or
            "timeout" in str(exception).lower() or
            "network" in str(exception).lower()
        )
    
    def analyze(self, exception: Exception, stage: str) -> ErrorRecord:
        """Analyze network exception."""
        severity = ErrorSeverity.WARNING
        details = {"exception_name": type(exception).__name__}
        resolution_hint = "Check network connectivity and API availability"
        
        # Determine severity based on exception type
        if "timeout" in str(exception).lower():
            severity = ErrorSeverity.WARNING
            resolution_hint = "Consider increasing timeout values or retry logic"
        elif "connection" in str(exception).lower():
            severity = ErrorSeverity.ERROR
            resolution_hint = "Verify network connectivity and service availability"
        
        return ErrorRecord(
            timestamp=datetime.now(timezone.utc),
            level=severity,
            stage=stage,
            category=ErrorCategory.NETWORK,
            message=str(exception),
            exception_type=type(exception).__name__,
            traceback_info=traceback.format_exc(),
            details=details,
            resolution_hint=resolution_hint
        )
    
    def get_analyzer_name(self) -> str:
        return "network_error_analyzer"


class FileSystemErrorAnalyzer(BaseErrorAnalyzer):
    """Analyzer for file system and I/O related errors."""
    
    FILESYSTEM_EXCEPTIONS = (
        "FileNotFoundError", "PermissionError", "IOError", "OSError",
        "IsADirectoryError", "NotADirectoryError", "FileExistsError"
    )
    
    def can_analyze(self, exception: Exception) -> bool:
        """Check if this is a file system exception."""
        return type(exception).__name__ in self.FILESYSTEM_EXCEPTIONS
    
    def analyze(self, exception: Exception, stage: str) -> ErrorRecord:
        """Analyze file system exception."""
        exception_name = type(exception).__name__
        severity = ErrorSeverity.ERROR
        resolution_hint = "Check file paths and permissions"
        
        if exception_name == "FileNotFoundError":
            resolution_hint = "Ensure required files exist and paths are correct"
        elif exception_name == "PermissionError":
            resolution_hint = "Check file/directory permissions and user access rights"
            severity = ErrorSeverity.CRITICAL
        elif exception_name == "IsADirectoryError":
            resolution_hint = "Expected file but found directory - check path specification"
        
        return ErrorRecord(
            timestamp=datetime.now(timezone.utc),
            level=severity,
            stage=stage,
            category=ErrorCategory.SYSTEM,
            message=str(exception),
            exception_type=exception_name,
            traceback_info=traceback.format_exc(),
            details={"exception_name": exception_name},
            resolution_hint=resolution_hint
        )
    
    def get_analyzer_name(self) -> str:
        return "filesystem_error_analyzer"


class DependencyErrorAnalyzer(BaseErrorAnalyzer):
    """Analyzer for dependency-related errors."""
    
    DEPENDENCY_KEYWORDS = [
        "requirement", "dependency", "package", "pip", "install",
        "resolve", "version", "conflict", "incompatible"
    ]
    
    def can_analyze(self, exception: Exception) -> bool:
        """Check if this is a dependency-related exception."""
        message = str(exception).lower()
        return any(keyword in message for keyword in self.DEPENDENCY_KEYWORDS)
    
    def analyze(self, exception: Exception, stage: str) -> ErrorRecord:
        """Analyze dependency exception."""
        message = str(exception).lower()
        severity = ErrorSeverity.WARNING
        resolution_hint = "Check dependency specifications and requirements"
        
        if "conflict" in message or "incompatible" in message:
            severity = ErrorSeverity.ERROR
            resolution_hint = "Resolve version conflicts in dependency specifications"
        elif "not found" in message:
            severity = ErrorSeverity.ERROR
            resolution_hint = "Ensure package names are correct and available in configured indexes"
        
        return ErrorRecord(
            timestamp=datetime.now(timezone.utc),
            level=severity,
            stage=stage,
            category=ErrorCategory.DEPENDENCY_EXTRACTION,
            message=str(exception),
            exception_type=type(exception).__name__,
            traceback_info=traceback.format_exc(),
            details={"raw_message": str(exception)},
            resolution_hint=resolution_hint
        )
    
    def get_analyzer_name(self) -> str:
        return "dependency_error_analyzer"


class ConfigurationErrorAnalyzer(BaseErrorAnalyzer):
    """Analyzer for configuration-related errors."""
    
    CONFIGURATION_KEYWORDS = [
        "config", "configuration", "yaml", "setting", "parameter",
        "invalid", "missing", "required"
    ]
    
    def can_analyze(self, exception: Exception) -> bool:
        """Check if this is a configuration-related exception."""
        message = str(exception).lower()
        return any(keyword in message for keyword in self.CONFIGURATION_KEYWORDS)
    
    def analyze(self, exception: Exception, stage: str) -> ErrorRecord:
        """Analyze configuration exception."""
        message = str(exception).lower()
        severity = ErrorSeverity.ERROR
        resolution_hint = "Check configuration file syntax and required parameters"
        
        if "missing" in message or "required" in message:
            severity = ErrorSeverity.CRITICAL
            resolution_hint = "Provide missing required configuration parameters"
        elif "invalid" in message:
            severity = ErrorSeverity.ERROR
            resolution_hint = "Fix invalid configuration values and syntax"
        
        return ErrorRecord(
            timestamp=datetime.now(timezone.utc),
            level=severity,
            stage=stage,
            category=ErrorCategory.CONFIGURATION,
            message=str(exception),
            exception_type=type(exception).__name__,
            traceback_info=traceback.format_exc(),
            details={"raw_message": str(exception)},
            resolution_hint=resolution_hint
        )
    
    def get_analyzer_name(self) -> str:
        return "configuration_error_analyzer"


class GenericErrorAnalyzer(BaseErrorAnalyzer):
    """Fallback analyzer for uncategorized errors."""
    
    def can_analyze(self, exception: Exception) -> bool:
        """This analyzer can handle any exception as fallback."""
        return True
    
    def analyze(self, exception: Exception, stage: str) -> ErrorRecord:
        """Generic error analysis."""
        return ErrorRecord(
            timestamp=datetime.now(timezone.utc),
            level=ErrorSeverity.ERROR,
            stage=stage,
            category=ErrorCategory.UNKNOWN,
            message=str(exception),
            exception_type=type(exception).__name__,
            traceback_info=traceback.format_exc(),
            details={"analyzer": "generic_fallback"},
            resolution_hint="Review error details and consult documentation"
        )
    
    def get_analyzer_name(self) -> str:
        return "generic_error_analyzer"


class ErrorTracker:
    """Main error tracking orchestrator following SOLID principles."""
    
    def __init__(self):
        self.errors: List[ErrorRecord] = []
        self.analyzers: List[BaseErrorAnalyzer] = [
            NetworkErrorAnalyzer(),
            FileSystemErrorAnalyzer(),
            DependencyErrorAnalyzer(), 
            ConfigurationErrorAnalyzer(),
            GenericErrorAnalyzer()  # Keep as last (fallback)
        ]
        self.error_counts: Dict[ErrorSeverity, int] = {
            severity: 0 for severity in ErrorSeverity
        }
    
    def capture_error(
        self,
        exception: Exception,
        stage: str,
        category: Optional[ErrorCategory] = None,
        severity: Optional[ErrorSeverity] = None,
        details: Optional[Dict[str, Any]] = None
    ):
        """Capture and categorize an error."""
        # Try to find appropriate analyzer
        error_record = None
        
        if category and severity:
            # Manual categorization provided
            error_record = ErrorRecord(
                timestamp=datetime.now(timezone.utc),
                level=severity,
                stage=stage,
                category=category,
                message=str(exception),
                exception_type=type(exception).__name__,
                traceback_info=traceback.format_exc(),
                details=details or {}
            )
        else:
            # Use analyzers to categorize
            for analyzer in self.analyzers:
                if analyzer.can_analyze(exception):
                    error_record = analyzer.analyze(exception, stage)
                    if details:
                        error_record.details.update(details)
                    break
        
        if error_record:
            self.errors.append(error_record)
            self.error_counts[error_record.level] += 1
    
    def capture_message(
        self,
        message: str,
        stage: str,
        severity: ErrorSeverity = ErrorSeverity.INFO,
        category: ErrorCategory = ErrorCategory.UNKNOWN,
        details: Optional[Dict[str, Any]] = None
    ):
        """Capture a message-based error/warning/info."""
        error_record = ErrorRecord(
            timestamp=datetime.now(timezone.utc),
            level=severity,
            stage=stage,
            category=category,
            message=message,
            details=details or {}
        )
        
        self.errors.append(error_record)
        self.error_counts[severity] += 1
    
    def get_errors_by_severity(self, severity: ErrorSeverity) -> List[ErrorRecord]:
        """Get all errors of a specific severity level."""
        return [error for error in self.errors if error.level == severity]
    
    def get_errors_by_category(self, category: ErrorCategory) -> List[ErrorRecord]:
        """Get all errors of a specific category."""
        return [error for error in self.errors if error.category == category]
    
    def get_errors_by_stage(self, stage: str) -> List[ErrorRecord]:
        """Get all errors from a specific stage."""
        return [error for error in self.errors if error.stage == stage]
    
    def has_critical_errors(self) -> bool:
        """Check if any critical errors were captured."""
        return self.error_counts[ErrorSeverity.CRITICAL] > 0
    
    def has_errors(self) -> bool:
        """Check if any errors (non-info) were captured."""
        return (
            self.error_counts[ErrorSeverity.CRITICAL] > 0 or
            self.error_counts[ErrorSeverity.ERROR] > 0 or
            self.error_counts[ErrorSeverity.WARNING] > 0
        )
    
    def get_error_summary(self) -> Dict[str, Any]:
        """Get comprehensive error summary."""
        return {
            "total_errors": len(self.errors),
            "error_counts": {severity.value: count for severity, count in self.error_counts.items()},
            "errors_by_category": {
                category.value: len(self.get_errors_by_category(category))
                for category in ErrorCategory
            },
            "has_critical_errors": self.has_critical_errors(),
            "has_errors": self.has_errors()
        }
    
    def get_all_errors(self) -> List[Dict[str, Any]]:
        """Get all error records as dictionaries."""
        return [error.to_dict() for error in self.errors]
    
    def add_analyzer(self, analyzer: BaseErrorAnalyzer):
        """Add custom error analyzer."""
        # Insert before generic analyzer (keep generic as fallback)
        self.analyzers.insert(-1, analyzer)
    
    def clear_errors(self):
        """Clear all captured errors."""
        self.errors.clear()
        self.error_counts = {severity: 0 for severity in ErrorSeverity}
    
    def get_recent_errors(self, limit: int = 10) -> List[ErrorRecord]:
        """Get most recent errors."""
        return self.errors[-limit:] if len(self.errors) > limit else self.errors