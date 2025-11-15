"""
Reusable decorator for handling external API exceptions.

This module provides a decorator that automatically handles all external API
exceptions, reducing boilerplate code from ~80 lines to ~1 line per method.
"""

import functools
import logging
from typing import Any, Callable, Optional

import requests

from .exceptions import (
    APIConnectionError,
    APINotFoundError,
    APIRateLimitError,
    APIServerError,
    APITimeoutError,
    ExternalAPIError,
    RestrictedEnvironmentError,
)


def handle_external_api_errors(
    service: str,
    return_on_error: Any = None,
    log_stats: bool = True,
    suppress_errors: bool = True,
):
    """
    Decorator that automatically handles all external API exceptions.

    This decorator wraps API methods and provides comprehensive exception
    handling, including:
    - Timeout detection and logging
    - Intelligent restricted environment detection
    - HTTP error mapping (404, 429, 5xx, etc.)
    - Automatic stats tracking
    - Clear, actionable error messages

    Usage:
        @handle_external_api_errors(service="deps.dev", return_on_error={})
        def get_data(self, package, version):
            response = self.session.get(url)
            return response.json()

    Args:
        service: Name of the external service (e.g., "deps.dev", "OSV.dev")
        return_on_error: Value to return when an error occurs (default: None)
        log_stats: Whether to increment self.stats["errors"] on failure
        suppress_errors: If True, return fallback value; if False, raise custom exception

    Returns:
        Decorated function that handles all exceptions automatically
    """

    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        def wrapper(self, *args, **kwargs):
            # Get logger from self if available
            logger = getattr(self, "logger", logging.getLogger(func.__name__))

            # Extract context for error messages (try to get package/version from args)
            context = _extract_context(args, kwargs)

            # Build endpoint context if URL is accessible
            # Note: URL is typically not in positional args, mainly in kwargs
            endpoint = kwargs.get("url", None)

            try:
                # Execute the wrapped function
                return func(self, *args, **kwargs)

            except requests.exceptions.Timeout as e:
                # Timeout error - use APITimeoutError for clear context
                error = APITimeoutError(
                    message=f"Timeout while calling {service}",
                    service=service,
                    endpoint=endpoint,
                    timeout_duration=getattr(
                        getattr(self, "session", None), "timeout", None
                    ),
                    original_exception=e,
                )
                return _handle_error(
                    error=error,
                    logger=logger,
                    log_level="warning",
                    stats=getattr(self, "stats", None) if log_stats else None,
                    context=context,
                    suppress=suppress_errors,
                    return_value=return_on_error,
                )

            except requests.exceptions.ConnectionError as e:
                # Connection error - use intelligent detection for restrictions
                try:
                    RestrictedEnvironmentError.detect_and_raise(
                        connection_error=e,
                        service=service,
                        endpoint=endpoint,
                    )
                except RestrictedEnvironmentError as restricted_error:
                    # Log the detailed restriction information
                    return _handle_error(
                        error=restricted_error,
                        logger=logger,
                        log_level="warning",
                        stats=getattr(self, "stats", None) if log_stats else None,
                        context=context,
                        suppress=suppress_errors,
                        return_value=return_on_error,
                    )
                except Exception:
                    # If detect_and_raise doesn't raise RestrictedEnvironmentError,
                    # it re-raises the original ConnectionError, which we should
                    # handle as a generic connection error
                    error = APIConnectionError(
                        message=f"Connection failed for {service}",
                        service=service,
                        endpoint=endpoint,
                        original_exception=e,
                    )
                    return _handle_error(
                        error=error,
                        logger=logger,
                        log_level="warning",
                        stats=getattr(self, "stats", None) if log_stats else None,
                        context=context,
                        suppress=suppress_errors,
                        return_value=return_on_error,
                    )

            except requests.exceptions.HTTPError as e:
                # HTTP errors - map to specific exception types
                error, log_level = _create_http_exception(e, service, endpoint, context)
                return _handle_error(
                    error=error,
                    logger=logger,
                    log_level=log_level,
                    stats=getattr(self, "stats", None) if log_stats else None,
                    context=context,
                    suppress=suppress_errors,
                    return_value=return_on_error,
                )

            except requests.exceptions.RequestException as e:
                # Generic request exception - wrap in ExternalAPIError
                error = ExternalAPIError(
                    message=f"Request failed for {service}",
                    service=service,
                    endpoint=endpoint,
                    original_exception=e,
                    suggested_action="Check network connectivity and retry",
                )
                return _handle_error(
                    error=error,
                    logger=logger,
                    log_level="error",
                    stats=getattr(self, "stats", None) if log_stats else None,
                    context=context,
                    suppress=suppress_errors,
                    return_value=return_on_error,
                )

            except Exception as e:
                # Unexpected errors - keep generic handling but provide context
                error = ExternalAPIError(
                    message=f"Unexpected error calling {service}",
                    service=service,
                    endpoint=endpoint,
                    original_exception=e,
                    suggested_action="This is an unexpected error. Please report this issue.",
                )
                return _handle_error(
                    error=error,
                    logger=logger,
                    log_level="error",
                    stats=getattr(self, "stats", None) if log_stats else None,
                    context=context,
                    suppress=suppress_errors,
                    return_value=return_on_error,
                )

        return wrapper

    return decorator


def _create_http_exception(
    http_error: requests.exceptions.HTTPError,
    service: str,
    endpoint: Optional[str],
    context: str,
) -> tuple[ExternalAPIError, str]:
    """
    Map HTTP error to specific exception and log level.

    Args:
        http_error: The HTTP error exception
        service: Name of the external service
        endpoint: API endpoint that failed
        context: Additional context (e.g., package@version)

    Returns:
        Tuple of (exception, log_level)
    """
    status_code = http_error.response.status_code if http_error.response else None

    # 404 Not Found
    if status_code == 404:
        return (
            APINotFoundError(
                message=f"Resource not found in {service}",
                service=service,
                endpoint=endpoint,
                resource=context,
                original_exception=http_error,
            ),
            "debug",
        )

    # 429 Rate Limit
    if status_code == 429:
        retry_after = (
            http_error.response.headers.get("Retry-After")
            if http_error.response
            else None
        )
        return (
            APIRateLimitError(
                message=f"Rate limit exceeded for {service}",
                service=service,
                endpoint=endpoint,
                retry_after=int(retry_after) if retry_after else None,
                original_exception=http_error,
            ),
            "warning",
        )

    # 5xx Server Errors
    if status_code and 500 <= status_code < 600:
        return (
            APIServerError(
                message=f"{service} server error",
                service=service,
                endpoint=endpoint,
                status_code=status_code,
                original_exception=http_error,
            ),
            "error",
        )

    # Generic HTTP Error
    return (
        ExternalAPIError(
            message=f"HTTP error calling {service}",
            service=service,
            endpoint=endpoint,
            original_exception=http_error,
            suggested_action=(
                f"HTTP {status_code} - Check API status or try again later"
                if status_code
                else "Check API status or try again later"
            ),
        ),
        "error",
    )


def _extract_context(args: tuple, kwargs: dict) -> str:
    """
    Extract contextual information from function arguments.

    Attempts to extract package name, version, or other identifying
    information to provide better error messages.

    Args:
        args: Positional arguments passed to the function
        kwargs: Keyword arguments passed to the function

    Returns:
        Context string (e.g., "package@version" or empty string)
    """
    # Skip 'self' if present (instance methods have self as args[0])
    start_idx = 1 if args and hasattr(args[0], '__dict__') else 0

    # Try to extract package and version from common argument patterns
    package = kwargs.get("package") or (args[start_idx] if len(args) > start_idx else None)
    version = kwargs.get("version") or (args[start_idx + 1] if len(args) > start_idx + 1 else None)

    if package and version:
        return f"{package}@{version}"
    elif package:
        return str(package)
    return ""


def _handle_error(
    error: Exception,
    logger: logging.Logger,
    log_level: str,
    stats: Optional[dict],
    context: str,
    suppress: bool,
    return_value: Any,
):
    """
    Handle an error by logging, updating stats, and returning/raising.

    Args:
        error: The exception to handle
        logger: Logger instance for logging
        log_level: Logging level (debug/warning/error)
        stats: Stats dictionary to update (if provided)
        context: Additional context for logging
        suppress: Whether to suppress (return) or raise the error
        return_value: Value to return if suppressing

    Raises:
        The original error if suppress=False
    """
    # Build log message with context
    log_message = str(error)
    if context:
        log_message = f"[{context}] {log_message}"

    # Log based on level
    if log_level == "debug":
        logger.debug(log_message)
    elif log_level == "warning":
        logger.warning(log_message)
    else:  # error
        logger.error(log_message)

    # Update stats if provided
    if stats is not None and "errors" in stats:
        stats["errors"] += 1

    # Return or raise based on suppress flag
    if suppress:
        return return_value
    else:
        raise error


# Export decorator
__all__ = ["handle_external_api_errors"]
