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
    """

    def __init__(
        self,
        message: str,
        service: Optional[str] = None,
        endpoint: Optional[str] = None,
        original_exception: Optional[Exception] = None,
        suggested_action: Optional[str] = None,
    ):
        """
        Initialize ExternalAPIError.

        Args:
            message: Human-readable error message
            service: Name of the external service (e.g., "deps.dev", "OSV.dev")
            endpoint: API endpoint that failed (e.g., "/v3alpha/querybatch")
            original_exception: The original exception that was caught
            suggested_action: Suggested action for the user to resolve the issue
        """
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
    """
    Raised when an API request times out.

    This typically indicates:
    - Slow network connection
    - Service is experiencing high load
    - Firewall introducing delays
    """

    def __init__(
        self,
        message: str,
        service: Optional[str] = None,
        endpoint: Optional[str] = None,
        timeout_duration: Optional[int] = None,
        original_exception: Optional[Exception] = None,
    ):
        """
        Initialize APITimeoutError.

        Args:
            message: Human-readable error message
            service: Name of the external service
            endpoint: API endpoint that timed out
            timeout_duration: Timeout duration in seconds
            original_exception: The original timeout exception
        """
        self.timeout_duration = timeout_duration

        suggested_action = "Check network connectivity and retry"
        if timeout_duration:
            suggested_action += f" (timeout after {timeout_duration}s)"

        super().__init__(
            message=message,
            service=service,
            endpoint=endpoint,
            original_exception=original_exception,
            suggested_action=suggested_action,
        )


class APIConnectionError(ExternalAPIError):
    """
    Raised when unable to establish connection to API.

    This typically indicates:
    - Network connectivity issues
    - DNS resolution failures
    - Service is down or unreachable
    """

    def __init__(
        self,
        message: str,
        service: Optional[str] = None,
        endpoint: Optional[str] = None,
        original_exception: Optional[Exception] = None,
    ):
        """
        Initialize APIConnectionError.

        Args:
            message: Human-readable error message
            service: Name of the external service
            endpoint: API endpoint that failed
            original_exception: The original connection exception
        """
        suggested_action = (
            "Check network connectivity and verify the service is accessible"
        )

        super().__init__(
            message=message,
            service=service,
            endpoint=endpoint,
            original_exception=original_exception,
            suggested_action=suggested_action,
        )


class RestrictedEnvironmentError(APIConnectionError):
    """
    Raised when connection failure appears to be due to network restrictions.

    This exception is raised when intelligent detection suggests the failure
    is due to corporate firewalls, proxy restrictions, or domain whitelisting.

    Common in regulated industries (healthcare, finance) where:
    - External domains must be whitelisted
    - Corporate proxies block certain traffic
    - Strict firewall rules prevent outbound connections
    """

    def __init__(
        self,
        message: str,
        service: Optional[str] = None,
        endpoint: Optional[str] = None,
        original_exception: Optional[Exception] = None,
        restriction_type: Optional[str] = None,
    ):
        """
        Initialize RestrictedEnvironmentError.

        Args:
            message: Human-readable error message
            service: Name of the external service
            endpoint: API endpoint that failed
            original_exception: The original connection exception
            restriction_type: Type of restriction detected
                (dns, proxy, firewall, unknown)
        """
        self.restriction_type = restriction_type

        # Build suggested action based on restriction type
        if restriction_type == "dns":
            suggested_action = (
                "DNS resolution failed. In corporate environments, "
                "contact IT to whitelist this domain"
            )
        elif restriction_type == "proxy":
            suggested_action = (
                "Proxy connection failed. Check corporate proxy settings "
                "or contact IT to allow this service"
            )
        elif restriction_type == "firewall":
            suggested_action = (
                "Connection refused. In regulated environments, "
                "contact IT to update firewall rules"
            )
        else:
            suggested_action = (
                "Network connection failed. This may be a firewall or proxy "
                "restriction in corporate/regulated environments. "
                "Contact IT to verify access to this service"
            )

        # Store original suggested action before calling super().__init__
        self._restriction_action = suggested_action

        # Initialize parent with temporary message
        super().__init__(
            message=message,
            service=service,
            endpoint=endpoint,
            original_exception=original_exception,
        )

        # Override suggested_action after parent initialization
        self.suggested_action = self._restriction_action

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

        # DNS resolution failures
        if any(
            pattern in error_msg
            for pattern in [
                "name resolution",
                "dns",
                "nodename nor servname provided",
                "getaddrinfo failed",
                "name or service not known",
            ]
        ):
            raise cls(
                message="DNS resolution failed",
                service=service,
                endpoint=endpoint,
                original_exception=connection_error,
                restriction_type="dns",
            )

        # Proxy-related errors
        if any(
            pattern in error_msg
            for pattern in [
                "proxy",
                "407 proxy authentication",
                "tunnel connection failed",
            ]
        ):
            raise cls(
                message="Proxy connection failed",
                service=service,
                endpoint=endpoint,
                original_exception=connection_error,
                restriction_type="proxy",
            )

        # Connection refused (firewall blocking)
        if "connection refused" in error_msg or "errno 111" in error_msg:
            raise cls(
                message="Connection refused",
                service=service,
                endpoint=endpoint,
                original_exception=connection_error,
                restriction_type="firewall",
            )

        # Generic restriction (can't determine specific type)
        raise cls(
            message="Network connection failed",
            service=service,
            endpoint=endpoint,
            original_exception=connection_error,
            restriction_type="unknown",
        )


class APIAuthenticationError(ExternalAPIError):
    """
    Raised when API request fails due to authentication issues.

    This typically indicates:
    - Invalid API key or token
    - Expired credentials
    - Insufficient permissions (403)
    """

    def __init__(
        self,
        message: str,
        service: Optional[str] = None,
        endpoint: Optional[str] = None,
        status_code: Optional[int] = None,
        original_exception: Optional[Exception] = None,
    ):
        """
        Initialize APIAuthenticationError.

        Args:
            message: Human-readable error message
            service: Name of the external service
            endpoint: API endpoint that failed
            status_code: HTTP status code (401, 403)
            original_exception: The original HTTP exception
        """
        self.status_code = status_code

        if status_code == 401:
            suggested_action = "Verify API credentials are valid and not expired"
        elif status_code == 403:
            suggested_action = (
                "Verify you have permission to access this resource"
            )
        else:
            suggested_action = "Check authentication credentials and permissions"

        super().__init__(
            message=message,
            service=service,
            endpoint=endpoint,
            original_exception=original_exception,
            suggested_action=suggested_action,
        )


class APIRateLimitError(ExternalAPIError):
    """
    Raised when API rate limit is exceeded.

    This typically indicates:
    - Too many requests in a short time period
    - Need to implement rate limiting or backoff
    """

    def __init__(
        self,
        message: str,
        service: Optional[str] = None,
        endpoint: Optional[str] = None,
        retry_after: Optional[int] = None,
        original_exception: Optional[Exception] = None,
    ):
        """
        Initialize APIRateLimitError.

        Args:
            message: Human-readable error message
            service: Name of the external service
            endpoint: API endpoint that was rate limited
            retry_after: Seconds to wait before retrying (from Retry-After header)
            original_exception: The original HTTP exception
        """
        self.retry_after = retry_after

        suggested_action = "Wait before retrying"
        if retry_after:
            suggested_action += f" (retry after {retry_after}s)"
        else:
            suggested_action += " or implement exponential backoff"

        super().__init__(
            message=message,
            service=service,
            endpoint=endpoint,
            original_exception=original_exception,
            suggested_action=suggested_action,
        )


class APINotFoundError(ExternalAPIError):
    """
    Raised when API resource is not found (404).

    This typically indicates:
    - Package/version doesn't exist in the service
    - Incorrect endpoint or resource identifier
    - Service doesn't have data for this resource
    """

    def __init__(
        self,
        message: str,
        service: Optional[str] = None,
        endpoint: Optional[str] = None,
        resource: Optional[str] = None,
        original_exception: Optional[Exception] = None,
    ):
        """
        Initialize APINotFoundError.

        Args:
            message: Human-readable error message
            service: Name of the external service
            endpoint: API endpoint that returned 404
            resource: Resource identifier that wasn't found
            original_exception: The original HTTP exception
        """
        self.resource = resource

        suggested_action = (
            "Verify the resource exists in the service "
            "or try an alternative data source"
        )

        super().__init__(
            message=message,
            service=service,
            endpoint=endpoint,
            original_exception=original_exception,
            suggested_action=suggested_action,
        )


class APIServerError(ExternalAPIError):
    """
    Raised when API returns a server error (5xx).

    This typically indicates:
    - Service is experiencing issues
    - Temporary outage or degraded performance
    - Internal server error
    """

    def __init__(
        self,
        message: str,
        service: Optional[str] = None,
        endpoint: Optional[str] = None,
        status_code: Optional[int] = None,
        original_exception: Optional[Exception] = None,
    ):
        """
        Initialize APIServerError.

        Args:
            message: Human-readable error message
            service: Name of the external service
            endpoint: API endpoint that returned server error
            status_code: HTTP status code (500, 502, 503, 504)
            original_exception: The original HTTP exception
        """
        self.status_code = status_code

        suggested_action = (
            "Service is experiencing issues. "
            "Wait and retry, or check service status page"
        )

        super().__init__(
            message=message,
            service=service,
            endpoint=endpoint,
            original_exception=original_exception,
            suggested_action=suggested_action,
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
