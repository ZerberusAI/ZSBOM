"""
Simple exceptions for upload functionality.
"""


class UploadError(Exception):
    """Base upload error."""
    pass


class APIConnectionError(UploadError):
    """API connection failed."""
    
    def __init__(self, message, **kwargs):
        super().__init__(message)
        self.endpoint = kwargs.get('endpoint')
        self.status_code = kwargs.get('status_code')


class AuthenticationError(UploadError):
    """Authentication failed."""
    
    def __init__(self, message, **kwargs):
        super().__init__(message)
        self.endpoint = kwargs.get('endpoint')
        self.status_code = kwargs.get('status_code')


class ScanStateError(UploadError):
    """Scan state error."""
    pass