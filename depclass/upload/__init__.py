"""
ZSBOM Trace-AI Upload Module

This module provides upload functionality to securely transmit ZSBOM artifacts
to the Zerberus compliance platform via a 3-phase API workflow.

Phase 1: Scan Initiation - Create scan record with metadata
Phase 2: Upload URLs - Get S3 presigned URLs for file uploads  
Phase 3: Completion - Acknowledge upload completion and get dashboard URL
"""

from .environment_detector import TraceAIEnvironmentDetector
from .upload_orchestrator import UploadOrchestrator
from .exceptions import (
    TraceAIUploadError,
    EnvironmentValidationError,
    FileValidationError,
    APIConnectionError,
    AuthenticationError,
    UploadError,
    ScanStateError
)

# Main class for external use
class TraceAIUploadManager:
    """Main interface for Trace-AI upload functionality"""
    
    def __init__(self):
        self.detector = TraceAIEnvironmentDetector()
        self.orchestrator = None
    
    def is_upload_enabled(self) -> bool:
        """Check if upload is enabled via environment variables"""
        return self.detector.is_upload_enabled()
    
    def execute_upload_workflow(self, scan_files: dict, scan_metadata: dict):
        """Execute the complete upload workflow"""
        if not self.is_upload_enabled():
            raise EnvironmentValidationError("Upload not enabled - missing environment variables")
        
        if not self.orchestrator:
            config = self.detector.get_upload_config()
            self.orchestrator = UploadOrchestrator(config)
        
        return self.orchestrator.execute_upload_workflow(scan_files, scan_metadata)

__all__ = [
    'TraceAIUploadManager',
    'TraceAIEnvironmentDetector', 
    'UploadOrchestrator',
    'TraceAIUploadError',
    'EnvironmentValidationError',
    'FileValidationError',
    'APIConnectionError',
    'AuthenticationError',
    'UploadError',
    'ScanStateError'
]