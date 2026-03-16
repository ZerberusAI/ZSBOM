"""
Enhanced exception handling for external API calls.

This module provides specialized exception classes for handling failures
when communicating with external services (deps.dev, OSV.dev, GitHub, etc.).

Each exception includes:
- Clear error message
- Service/endpoint context
- Suggested user action
- Original exception preserved for debugging
"""

from typing import Optional


class ExternalAPIError(Exception):
    """
    Base exception for all external API-related errors.

    This is the parent class for all external API exceptions and should
    be used for generic API errors that don't fit other specific categories.

    Args:
        message: Human-readable error message
        service: Name of the external service (e.g., "deps.dev", "OSV.dev")
        endpoint: API endpoint that failed (e.g., "/v3alpha/querybatch")
        original_exception: The original exception that was caught
        suggested_action: Suggested action for the user to resolve the issue
    """

    def __init__(
        self,
        message: str,
        service: Optional[str] = None,
        endpoint: Optional[str] = None,
        original_exception: Optional[Exception] = None,
        suggested_action: Optional[str] = None,
    ):
        self.message = message
        self.service = service
        self.endpoint = endpoint
        self.original_exception = original_exception
        self.suggested_action = suggested_action

        # Build comprehensive error message
        error_parts = [message]

        if service:
            error_parts.append(f"Service: {service}")

        if endpoint:
            error_parts.append(f"Endpoint: {endpoint}")

        if suggested_action:
            error_parts.append(f"Action: {suggested_action}")

        if original_exception:
            error_parts.append(f"Original error: {str(original_exception)}")

        super().__init__(" | ".join(error_parts))


class APITimeoutError(ExternalAPIError):
    """Raised when an API request times out."""

    def __init__(self, message: str, timeout_duration: Optional[int] = None, **kwargs):
        self.timeout_duration = timeout_duration
        action = "Check network connectivity and retry"
        if timeout_duration:
            action += f" (timeout after {timeout_duration}s)"
        super().__init__(message, suggested_action=action, **kwargs)


class APIConnectionError(ExternalAPIError):
    """Raised when unable to establish connection to API."""

    def __init__(self, message: str, **kwargs):
        # Only set default suggested_action if not already provided
        if 'suggested_action' not in kwargs:
            kwargs['suggested_action'] = "Check network connectivity and verify the service is accessible"
        super().__init__(message, **kwargs)


class RestrictedEnvironmentError(APIConnectionError):
    """
    Raised when connection failure appears to be due to network restrictions.

    Common in regulated industries (healthcare, finance) where:
    - External domains must be whitelisted
    - Corporate proxies block certain traffic
    - Strict firewall rules prevent outbound connections

    Args:
        message: Human-readable error message
        service: Name of the external service
        endpoint: API endpoint that failed
        original_exception: The original connection exception
        restriction_type: Type of restriction detected (dns, proxy, firewall, unknown)
    """

    def __init__(
        self,
        message: str,
        restriction_type: Optional[str] = None,
        **kwargs
    ):
        self.restriction_type = restriction_type

        # Map restriction types to suggested actions
        actions = {
            "dns": "DNS resolution failed. In corporate environments, contact IT to whitelist this domain",
            "proxy": "Proxy connection failed. Check corporate proxy settings or contact IT to allow this service",
            "firewall": "Connection refused. In regulated environments, contact IT to update firewall rules",
        }
        action = actions.get(
            restriction_type,
            "Network connection failed. This may be a firewall or proxy restriction "
            "in corporate/regulated environments. Contact IT to verify access to this service"
        )

        super().__init__(message, suggested_action=action, **kwargs)

    @classmethod
    def detect_and_raise(
        cls,
        connection_error: Exception,
        service: Optional[str] = None,
        endpoint: Optional[str] = None,
    ):
        """
        Intelligently detect if a connection error is due to restrictions.

        Analyzes the exception message to determine the likely cause and
        raises RestrictedEnvironmentError with appropriate guidance.

        Args:
            connection_error: The original connection exception
            service: Name of the external service
            endpoint: API endpoint that failed

        Raises:
            RestrictedEnvironmentError: If restriction patterns are detected
            APIConnectionError: If no specific restriction pattern found
        """
        error_msg = str(connection_error).lower()

        # Pattern definitions: (patterns, message, restriction_type)
        restriction_patterns = [
            (
                ["name resolution", "dns", "nodename nor servname provided",
                 "getaddrinfo failed", "name or service not known"],
                "DNS resolution failed",
                "dns"
            ),
            (
                ["proxy", "407 proxy authentication", "tunnel connection failed"],
                "Proxy connection failed",
                "proxy"
            ),
            (
                ["connection refused", "errno 111"],
                "Connection refused",
                "firewall"
            ),
        ]

        # Check for known restriction patterns
        for patterns, msg, rtype in restriction_patterns:
            if any(p in error_msg for p in patterns):
                raise cls(
                    message=msg,
                    service=service,
                    endpoint=endpoint,
                    original_exception=connection_error,
                    restriction_type=rtype
                )

        # Default case - generic restriction
        raise cls(
            message="Network connection failed",
            service=service,
            endpoint=endpoint,
            original_exception=connection_error,
            restriction_type="unknown"
        )


class APIAuthenticationError(ExternalAPIError):
    """Raised when API request fails due to authentication issues (401, 403)."""

    def __init__(self, message: str, status_code: Optional[int] = None, **kwargs):
        self.status_code = status_code
        actions = {
            401: "Verify API credentials are valid and not expired",
            403: "Verify you have permission to access this resource"
        }
        super().__init__(
            message,
            suggested_action=actions.get(status_code, "Check authentication credentials and permissions"),
            **kwargs
        )


class APIRateLimitError(ExternalAPIError):
    """Raised when API rate limit is exceeded."""

    def __init__(self, message: str, retry_after: Optional[int] = None, **kwargs):
        self.retry_after = retry_after
        action = f"Wait before retrying (retry after {retry_after}s)" if retry_after \
                 else "Wait before retrying or implement exponential backoff"
        super().__init__(message, suggested_action=action, **kwargs)


class APINotFoundError(ExternalAPIError):
    """Raised when API resource is not found (404)."""

    def __init__(self, message: str, resource: Optional[str] = None, **kwargs):
        self.resource = resource
        super().__init__(
            message,
            suggested_action="Verify the resource exists in the service or try an alternative data source",
            **kwargs
        )


class APIServerError(ExternalAPIError):
    """Raised when API returns a server error (5xx)."""

    def __init__(self, message: str, status_code: Optional[int] = None, **kwargs):
        self.status_code = status_code
        super().__init__(
            message,
            suggested_action="Service is experiencing issues. Wait and retry, or check service status page",
            **kwargs
        )


# Export all exception classes
__all__ = [
    "ExternalAPIError",
    "APITimeoutError",
    "APIConnectionError",
    "RestrictedEnvironmentError",
    "APIAuthenticationError",
    "APIRateLimitError",
    "APINotFoundError",
    "APIServerError",
]
