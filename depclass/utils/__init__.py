"""
Utility modules for ZSBOM.

This package contains shared utility functions and classes used throughout
the ZSBOM codebase, including exception handling for external API calls.
"""

from depclass.utils.api_error_handler import handle_external_api_errors
from depclass.utils.exceptions import (
    APIAuthenticationError,
    APIConnectionError,
    APINotFoundError,
    APIRateLimitError,
    APIServerError,
    APITimeoutError,
    ExternalAPIError,
    RestrictedEnvironmentError,
)

__all__ = [
    "handle_external_api_errors",
    "ExternalAPIError",
    "APITimeoutError",
    "APIConnectionError",
    "RestrictedEnvironmentError",
    "APIAuthenticationError",
    "APIRateLimitError",
    "APINotFoundError",
    "APIServerError",
]
