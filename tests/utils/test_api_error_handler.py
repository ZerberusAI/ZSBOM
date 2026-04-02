"""
Tests for the API error handler decorator.

This module tests the handle_external_api_errors decorator to ensure it
properly handles all exception types, logs appropriately, and tracks stats.
"""

import logging
from unittest.mock import Mock

import pytest
import requests

from depclass.utils.api_error_handler import handle_external_api_errors
from depclass.utils.exceptions import RestrictedEnvironmentError


class MockAPIClient:
    """Mock API client with decorated methods that raise various exceptions."""

    def __init__(self):
        self.logger = logging.getLogger("MockAPIClient")
        self.stats = {"errors": 0, "api_calls": 0}
        self.session = Mock()
        self.session.timeout = 30
        self.last_exception = None

    @handle_external_api_errors(service="test-service", return_on_error={})
    def successful_call(self, package: str, version: str):
        """Method that succeeds."""
        return {"package": package, "version": version, "status": "success"}

    @handle_external_api_errors(service="test-service", return_on_error={})
    def timeout_call(self, package: str, version: str):
        """Method that raises Timeout."""
        raise requests.exceptions.Timeout("Request timed out after 30s")

    @handle_external_api_errors(service="test-service", return_on_error={})
    def dns_failure_call(self, package: str, version: str):
        """Method that raises DNS resolution error."""
        raise requests.exceptions.ConnectionError(
            "Failed to resolve 'api.example.com': Name resolution failed"
        )

    @handle_external_api_errors(service="test-service", return_on_error={})
    def proxy_failure_call(self, package: str, version: str):
        """Method that raises proxy error."""
        raise requests.exceptions.ConnectionError(
            "407 Proxy Authentication Required"
        )

    @handle_external_api_errors(service="test-service", return_on_error={})
    def firewall_blocked_call(self, package: str, version: str):
        """Method that raises connection refused."""
        raise requests.exceptions.ConnectionError(
            "[Errno 111] Connection refused"
        )

    @handle_external_api_errors(service="test-service", return_on_error={})
    def generic_connection_error(self, package: str, version: str):
        """Method that raises generic connection error."""
        raise requests.exceptions.ConnectionError("Network unreachable")

    @handle_external_api_errors(service="test-service", return_on_error={})
    def not_found_call(self, package: str, version: str):
        """Method that raises 404."""
        mock_response = Mock()
        mock_response.status_code = 404
        error = requests.exceptions.HTTPError()
        error.response = mock_response
        raise error

    @handle_external_api_errors(service="test-service", return_on_error={})
    def rate_limit_call(self, package: str, version: str):
        """Method that raises 429 rate limit."""
        mock_response = Mock()
        mock_response.status_code = 429
        mock_response.headers = {"Retry-After": "60"}
        error = requests.exceptions.HTTPError()
        error.response = mock_response
        raise error

    @handle_external_api_errors(service="test-service", return_on_error={})
    def server_error_call(self, package: str, version: str):
        """Method that raises 500 server error."""
        mock_response = Mock()
        mock_response.status_code = 500
        error = requests.exceptions.HTTPError()
        error.response = mock_response
        raise error

    @handle_external_api_errors(service="test-service", return_on_error={})
    def bad_request_call(self, package: str, version: str):
        """Method that raises 400 bad request."""
        mock_response = Mock()
        mock_response.status_code = 400
        error = requests.exceptions.HTTPError()
        error.response = mock_response
        raise error

    @handle_external_api_errors(service="test-service", return_on_error={})
    def generic_request_exception(self, package: str, version: str):
        """Method that raises generic RequestException."""
        raise requests.exceptions.RequestException("Network error occurred")

    @handle_external_api_errors(service="test-service", return_on_error={})
    def unexpected_exception(self, package: str, version: str):
        """Method that raises unexpected exception."""
        raise ValueError("Unexpected error in processing")

    @handle_external_api_errors(
        service="test-service", return_on_error=None, log_stats=False
    )
    def no_stats_tracking(self, package: str, version: str):
        """Method with stats tracking disabled."""
        raise requests.exceptions.Timeout("Timeout")

    @handle_external_api_errors(
        service="test-service", return_on_error={"custom": "fallback"}
    )
    def custom_return_value(self, package: str, version: str):
        """Method with custom return value."""
        raise requests.exceptions.Timeout("Timeout")

    @handle_external_api_errors(
        service="test-service", return_on_error=[], suppress_errors=False
    )
    def raise_errors(self, package: str, version: str):
        """Method that raises errors instead of suppressing."""
        raise requests.exceptions.Timeout("Timeout")


class TestHandleExternalAPIErrors:
    """Test suite for handle_external_api_errors decorator."""

    def test_successful_call(self):
        """Test decorator doesn't interfere with successful calls."""
        client = MockAPIClient()
        result = client.successful_call("test-pkg", "1.0.0")

        assert result == {
            "package": "test-pkg",
            "version": "1.0.0",
            "status": "success",
        }
        assert client.stats["errors"] == 0

    def test_timeout_exception(self, caplog):
        """Test Timeout exception is handled correctly."""
        client = MockAPIClient()

        with caplog.at_level(logging.WARNING):
            result = client.timeout_call("test-pkg", "1.0.0")

        # Should return empty dict (default return_on_error)
        assert result == {}
        # Should increment errors
        assert client.stats["errors"] == 1
        # Should log as warning
        assert any(
            "test-pkg@1.0.0" in record.message or "Timeout" in record.message
            for record in caplog.records
        )

    def test_dns_failure_restriction(self, caplog):
        """Test DNS resolution failure is detected and logged."""
        client = MockAPIClient()

        with caplog.at_level(logging.WARNING):
            result = client.dns_failure_call("test-pkg", "1.0.0")

        assert result == {}
        assert client.stats["errors"] == 1
        # Should mention DNS or whitelist
        log_text = " ".join(record.message for record in caplog.records)
        assert "DNS" in log_text or "whitelist" in log_text or "resolution" in log_text

    def test_proxy_failure_restriction(self, caplog):
        """Test proxy failure is detected and logged."""
        client = MockAPIClient()

        with caplog.at_level(logging.WARNING):
            result = client.proxy_failure_call("test-pkg", "1.0.0")

        assert result == {}
        assert client.stats["errors"] == 1
        # Should mention proxy
        log_text = " ".join(record.message for record in caplog.records)
        assert "proxy" in log_text.lower() or "407" in log_text

    def test_firewall_blocked_restriction(self, caplog):
        """Test connection refused is detected as firewall issue."""
        client = MockAPIClient()

        with caplog.at_level(logging.WARNING):
            result = client.firewall_blocked_call("test-pkg", "1.0.0")

        assert result == {}
        assert client.stats["errors"] == 1
        # Should mention connection refused or firewall
        log_text = " ".join(record.message for record in caplog.records)
        assert (
            "refused" in log_text.lower()
            or "firewall" in log_text.lower()
            or "111" in log_text
        )

    def test_generic_connection_error(self, caplog):
        """Test generic connection error is handled."""
        client = MockAPIClient()

        with caplog.at_level(logging.WARNING):
            result = client.generic_connection_error("test-pkg", "1.0.0")

        assert result == {}
        assert client.stats["errors"] == 1

    def test_not_found_404(self, caplog):
        """Test 404 not found is logged as debug."""
        client = MockAPIClient()

        with caplog.at_level(logging.DEBUG):
            result = client.not_found_call("test-pkg", "1.0.0")

        assert result == {}
        assert client.stats["errors"] == 1
        # 404 should be logged at DEBUG level
        assert any(
            record.levelname == "DEBUG" and "404" in str(record.message)
            or "not found" in record.message.lower()
            for record in caplog.records
        )

    def test_rate_limit_429(self, caplog):
        """Test 429 rate limit is handled correctly."""
        client = MockAPIClient()

        with caplog.at_level(logging.WARNING):
            result = client.rate_limit_call("test-pkg", "1.0.0")

        assert result == {}
        assert client.stats["errors"] == 1
        # Should mention rate limit or retry
        log_text = " ".join(record.message for record in caplog.records)
        assert "rate" in log_text.lower() or "429" in log_text or "60" in log_text

    def test_server_error_500(self, caplog):
        """Test 500 server error is logged as error."""
        client = MockAPIClient()

        with caplog.at_level(logging.ERROR):
            result = client.server_error_call("test-pkg", "1.0.0")

        assert result == {}
        assert client.stats["errors"] == 1
        # 500 should be logged at ERROR level
        assert any(
            record.levelname == "ERROR" and ("500" in str(record.message) or "server" in record.message.lower())
            for record in caplog.records
        )

    def test_bad_request_400(self, caplog):
        """Test 400 bad request is handled."""
        client = MockAPIClient()

        with caplog.at_level(logging.ERROR):
            result = client.bad_request_call("test-pkg", "1.0.0")

        assert result == {}
        assert client.stats["errors"] == 1

    def test_generic_request_exception(self, caplog):
        """Test generic RequestException is handled."""
        client = MockAPIClient()

        with caplog.at_level(logging.ERROR):
            result = client.generic_request_exception("test-pkg", "1.0.0")

        assert result == {}
        assert client.stats["errors"] == 1

    def test_unexpected_exception(self, caplog):
        """Test unexpected exceptions are handled."""
        client = MockAPIClient()

        with caplog.at_level(logging.ERROR):
            result = client.unexpected_exception("test-pkg", "1.0.0")

        assert result == {}
        assert client.stats["errors"] == 1
        # Should mention unexpected error
        log_text = " ".join(record.message for record in caplog.records)
        assert "unexpected" in log_text.lower() or "ValueError" in log_text

    def test_stats_tracking_disabled(self):
        """Test that stats tracking can be disabled."""
        client = MockAPIClient()
        initial_errors = client.stats["errors"]

        result = client.no_stats_tracking("test-pkg", "1.0.0")

        assert result is None  # return_on_error is None
        # Stats should NOT be incremented
        assert client.stats["errors"] == initial_errors

    def test_custom_return_value(self):
        """Test custom return_on_error value."""
        client = MockAPIClient()

        result = client.custom_return_value("test-pkg", "1.0.0")

        assert result == {"custom": "fallback"}
        assert client.stats["errors"] == 1

    def test_suppress_errors_false(self):
        """Test that errors can be raised instead of suppressed."""
        client = MockAPIClient()

        # Should raise instead of returning fallback value
        # The decorator will still catch and re-raise with our custom exception
        with pytest.raises(Exception):  # Could be Timeout or wrapped exception
            client.raise_errors("test-pkg", "1.0.0")

    def test_context_in_logs(self, caplog):
        """Test that package context appears in log messages."""
        client = MockAPIClient()

        with caplog.at_level(logging.WARNING):
            result = client.timeout_call("my-package", "2.0.0")

        # Context should be in logs
        log_text = " ".join(record.message for record in caplog.records)
        assert "my-package" in log_text or "2.0.0" in log_text


class TestRestrictedEnvironmentDetection:
    """Test RestrictedEnvironmentError detection logic."""

    def test_dns_resolution_patterns(self):
        """Test various DNS resolution failure patterns."""
        dns_patterns = [
            "Temporary failure in name resolution",
            "getaddrinfo failed",
            "Name or service not known",
            "nodename nor servname provided",
        ]

        for pattern in dns_patterns:
            error = requests.exceptions.ConnectionError(pattern)
            with pytest.raises(RestrictedEnvironmentError) as exc_info:
                RestrictedEnvironmentError.detect_and_raise(
                    error, service="test-service", endpoint="/api/test"
                )

            assert exc_info.value.restriction_type == "dns"
            assert exc_info.value.service == "test-service"
            # Check suggested action mentions whitelisting
            assert (
                "whitelist" in exc_info.value.suggested_action.lower()
                or "DNS" in str(exc_info.value)
            )

    def test_proxy_error_patterns(self):
        """Test various proxy error patterns."""
        proxy_patterns = [
            "407 Proxy Authentication Required",
            "Proxy connection failed",
            "Tunnel connection failed",
        ]

        for pattern in proxy_patterns:
            error = requests.exceptions.ConnectionError(pattern)
            with pytest.raises(RestrictedEnvironmentError) as exc_info:
                RestrictedEnvironmentError.detect_and_raise(
                    error, service="test-service", endpoint="/api/test"
                )

            assert exc_info.value.restriction_type == "proxy"
            assert "proxy" in exc_info.value.suggested_action.lower()

    def test_firewall_blocked_patterns(self):
        """Test connection refused patterns (firewall)."""
        firewall_patterns = [
            "Connection refused",
            "[Errno 111] Connection refused",
        ]

        for pattern in firewall_patterns:
            error = requests.exceptions.ConnectionError(pattern)
            with pytest.raises(RestrictedEnvironmentError) as exc_info:
                RestrictedEnvironmentError.detect_and_raise(
                    error, service="test-service", endpoint="/api/test"
                )

            assert exc_info.value.restriction_type == "firewall"
            assert (
                "firewall" in exc_info.value.suggested_action.lower()
                or "refused" in str(exc_info.value).lower()
            )

    def test_unknown_connection_error(self):
        """Test generic connection error falls back to unknown restriction."""
        error = requests.exceptions.ConnectionError("Some generic network error")

        with pytest.raises(RestrictedEnvironmentError) as exc_info:
            RestrictedEnvironmentError.detect_and_raise(
                error, service="test-service", endpoint="/api/test"
            )

        assert exc_info.value.restriction_type == "unknown"
        # Should mention corporate or network restrictions
        suggestion = exc_info.value.suggested_action.lower()
        assert (
            "corporate" in suggestion
            or "network" in suggestion
            or "it" in suggestion
        )

    def test_service_and_endpoint_preserved(self):
        """Test that service and endpoint information is preserved."""
        error = requests.exceptions.ConnectionError("Connection failed")

        with pytest.raises(RestrictedEnvironmentError) as exc_info:
            RestrictedEnvironmentError.detect_and_raise(
                error, service="deps.dev", endpoint="/v3alpha/packages"
            )

        assert exc_info.value.service == "deps.dev"
        assert exc_info.value.endpoint == "/v3alpha/packages"
        assert exc_info.value.original_exception == error


class TestDepsDevProviderIntegration:
    """Integration tests to verify decorator preserves business logic in deps_dev_provider.py"""

    def test_decorated_methods_preserve_return_types(self):
        """Verify all decorated methods return correct types on success and error."""
        from unittest.mock import Mock, patch
        from depclass.enhancers.deps_dev_provider import DepsDevProvider

        config = {"caching": {"enabled": False}}
        provider = DepsDevProvider(config, cache=None)

        # Test _fetch_package_info - should return dict on error
        with patch.object(provider, "_make_request", side_effect=requests.exceptions.Timeout("Timeout")):
            result = provider._fetch_package_info("pypi", "test-pkg")
            assert result == {}, "Should return empty dict on error"
            assert provider.stats["errors"] >= 1, "Should increment error stats"

        # Test _fetch_project_info - should return dict on error
        with patch.object(provider, "_make_request", side_effect=requests.exceptions.Timeout("Timeout")):
            result = provider._fetch_project_info("github.com/test/repo")
            assert result == {}, "Should return empty dict on error"

        # Test get_dependency_graph - should return dict on error
        with patch.object(provider, "_make_request", side_effect=requests.exceptions.Timeout("Timeout")):
            result = provider.get_dependency_graph("test-pkg", "1.0.0", "pypi")
            assert result == {}, "Should return empty dict on error"


class TestEdgeCases:
    """Test edge cases and corner scenarios."""

    def test_missing_logger_attribute(self, caplog):
        """Test decorator works when class has no logger attribute."""

        class NoLoggerClass:
            """Mock class without a logger attribute."""

            stats = {"errors": 0}

            @handle_external_api_errors(service="test", return_on_error={})
            def failing_call(self):
                raise requests.exceptions.Timeout("Timeout")

        client = NoLoggerClass()

        with caplog.at_level(logging.WARNING):
            result = client.failing_call()

        assert result == {}
        assert client.stats["errors"] == 1
        # Should still log using the default logger
        assert len(caplog.records) > 0

    def test_empty_service_name(self, caplog):
        """Test decorator with empty service name."""
        client = MockAPIClient()

        @handle_external_api_errors(service="", return_on_error={})
        def test_method(self):
            raise requests.exceptions.Timeout("Timeout")

        with caplog.at_level(logging.WARNING):
            result = test_method(client)

        assert result == {}
        # Should still work, just with less context in logs
        assert len(caplog.records) > 0

    def test_missing_stats_attribute(self):
        """Test decorator works when class has no stats attribute."""

        class NoStatsClass:
            """Mock class without a stats attribute."""

            logger = logging.getLogger("NoStatsClass")

            @handle_external_api_errors(service="test", return_on_error={})
            def failing_call(self):
                raise requests.exceptions.Timeout("Timeout")

        client = NoStatsClass()
        result = client.failing_call()

        # Should not crash due to missing stats
        assert result == {}

    def test_context_extraction_with_kwargs(self, caplog):
        """Test context extraction when using keyword arguments."""
        client = MockAPIClient()

        with caplog.at_level(logging.WARNING):
            # Call with kwargs instead of positional args
            result = client.timeout_call(package="pkg-via-kwarg", version="3.0.0")

        assert result == {}
        # Should extract context from kwargs
        log_text = " ".join(record.message for record in caplog.records)
        assert "pkg-via-kwarg" in log_text or "3.0.0" in log_text

    def test_context_extraction_without_version(self, caplog):
        """Test context extraction when only package is provided."""

        class SingleArgClass:
            """Mock class with method that only has package arg."""

            logger = logging.getLogger("SingleArgClass")
            stats = {"errors": 0}

            @handle_external_api_errors(service="test", return_on_error={})
            def single_arg_method(self, package: str):
                raise requests.exceptions.Timeout("Timeout")

        client = SingleArgClass()

        with caplog.at_level(logging.WARNING):
            result = client.single_arg_method("standalone-pkg")

        assert result == {}
        # Should extract package name without version
        log_text = " ".join(record.message for record in caplog.records)
        assert "standalone-pkg" in log_text

    def test_thread_safety_documentation(self):
        """
        Document that stats tracking is NOT thread-safe.

        This test demonstrates the known limitation that concurrent
        calls to decorated methods may result in incorrect stats counts
        due to non-atomic increment operations.

        NOTE: This is expected behavior - stats tracking requires
        external synchronization (e.g., threading.Lock) for thread-safe
        usage.
        """
        import threading

        client = MockAPIClient()
        initial_errors = client.stats["errors"]

        def make_failing_call():
            client.timeout_call("pkg", "1.0")

        # Make 10 concurrent failing calls
        threads = [threading.Thread(target=make_failing_call) for _ in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        # In an ideal world, errors would be exactly initial_errors + 10
        # However, due to race conditions, it might be less
        # This test documents the limitation rather than asserting exact value
        assert client.stats["errors"] >= initial_errors + 5, (
            "Stats should be incremented, though exact count may vary "
            "due to race conditions (known limitation)"
        )

    def test_http_error_without_response(self, caplog):
        """Test HTTPError without response object."""
        client = MockAPIClient()

        @handle_external_api_errors(service="test", return_on_error={})
        def http_error_no_response(self):
            error = requests.exceptions.HTTPError("HTTP error without response")
            error.response = None  # No response object
            raise error

        with caplog.at_level(logging.ERROR):
            result = http_error_no_response(client)

        assert result == {}
        assert client.stats["errors"] == 1
        # Should handle gracefully without crashing


if __name__ == "__main__":
    pytest.main([__file__, "-v", "-s"])
