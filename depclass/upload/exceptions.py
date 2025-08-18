"""
Trace-AI Upload Exception Hierarchy

Comprehensive exception handling for upload operations following
the SOLID principles with clear separation of concerns.
"""

from typing import Dict, Any, Optional


class TraceAIUploadError(Exception):
    """Base exception for all Trace-AI upload errors"""
    
    def __init__(self, message: str, error_code: Optional[str] = None, details: Optional[Dict[str, Any]] = None):
        self.message = message
        self.error_code = error_code
        self.details = details or {}
        super().__init__(self.message)
    
    def __str__(self) -> str:
        if self.error_code:
            return f"[{self.error_code}] {self.message}"
        return self.message


class EnvironmentValidationError(TraceAIUploadError):
    """Raised when environment variables are missing or invalid"""
    
    def __init__(self, message: str, missing_vars: Optional[list] = None):
        super().__init__(message, "ENV_VALIDATION_ERROR")
        self.missing_vars = missing_vars or []


class FileValidationError(TraceAIUploadError):  
    """Raised when file validation fails (size, format, structure)"""
    
    def __init__(self, message: str, file_path: Optional[str] = None, validation_type: Optional[str] = None):
        super().__init__(message, "FILE_VALIDATION_ERROR")
        self.file_path = file_path
        self.validation_type = validation_type


class APIConnectionError(TraceAIUploadError):
    """Raised for network or API communication failures"""
    
    def __init__(self, message: str, status_code: Optional[int] = None, endpoint: Optional[str] = None):
        super().__init__(message, "API_CONNECTION_ERROR")
        self.status_code = status_code
        self.endpoint = endpoint


class AuthenticationError(TraceAIUploadError):
    """Raised when Zerberus API key validation fails"""
    
    def __init__(self, message: str, key_type: Optional[str] = None):
        super().__init__(message, "AUTHENTICATION_ERROR")
        self.key_type = key_type


class UploadError(TraceAIUploadError):
    """Raised when S3 upload operations fail"""
    
    def __init__(self, message: str, file_path: Optional[str] = None, attempt_count: Optional[int] = None):
        super().__init__(message, "UPLOAD_ERROR")
        self.file_path = file_path
        self.attempt_count = attempt_count


class ScanStateError(TraceAIUploadError):
    """Raised when scan is in invalid state for requested operation"""
    
    def __init__(self, message: str, scan_id: Optional[str] = None, current_state: Optional[str] = None):
        super().__init__(message, "SCAN_STATE_ERROR")
        self.scan_id = scan_id
        self.current_state = current_state