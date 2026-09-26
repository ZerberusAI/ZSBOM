"""Error messages and retries in the Zerberus API client.

The server says why it refused (a 403 "Tool integration is not active", a 422
"Upload incomplete: missing ..."). ZSBOM must pass that reason on, and must not
retry a request the server has already refused.
"""

import json
from datetime import datetime
from unittest.mock import Mock

import pytest
import requests

from depclass.upload.api_client import ZerberusAPIClient
from depclass.upload.exceptions import APIConnectionError, AuthenticationError
from depclass.upload.models import (
    CompletionRequest,
    TraceAIConfig,
    UploadStatus,
    UploadSummary,
)


def _response(status_code, body, content_type="application/json"):
    response = requests.Response()
    response.status_code = status_code
    response._content = (body if isinstance(body, str) else json.dumps(body)).encode()
    response.headers["Content-Type"] = content_type
    return response


def _completion():
    return CompletionRequest(
        upload_status=UploadStatus.FAILED,
        uploaded_files=[],
        failed_files=["dependencies.json"],
        completed_at=datetime(2026, 9, 25, 12, 0, 0),
        upload_summary=UploadSummary(
            total_files=1, successful_uploads=0, failed_uploads=1, total_size_bytes=0
        ),
    )


@pytest.fixture
def client():
    return ZerberusAPIClient(TraceAIConfig(api_url="https://api.test/", license_key="ZRB-test"))


@pytest.fixture(autouse=True)
def no_backoff_sleep(monkeypatch):
    monkeypatch.setattr("time.sleep", lambda seconds: None)


def test_403_carries_the_server_reason(client):
    with pytest.raises(AuthenticationError, match="403 Forbidden: Tool integration is not active"):
        client._handle_response_errors(
            _response(403, {"detail": "Tool integration is not active"}), "ep"
        )


def test_401_keeps_the_license_key_hint(client):
    with pytest.raises(
        AuthenticationError, match="Invalid or expired Zerberus license key.*ZERBERUS_LICENSE_KEY"
    ):
        client._handle_response_errors(
            _response(401, {"detail": "Invalid or expired Zerberus license key"}), "ep"
        )


def test_404_uses_the_server_message(client):
    with pytest.raises(APIConnectionError, match="Scan not found: abc") as error:
        client._handle_response_errors(
            _response(404, {"success": False, "message": "Scan not found: abc"}), "ep"
        )
    assert error.value.status_code == 404


def test_fastapi_validation_detail_list_is_readable(client):
    detail = [{"loc": ["body", "upload_status"], "msg": "string does not match regex"}]
    with pytest.raises(APIConnectionError, match="string does not match regex"):
        client._handle_response_errors(_response(422, {"detail": detail}), "ep")


def test_gateway_html_error_shows_the_body(client):
    with pytest.raises(APIConnectionError, match="502 Bad Gateway"):
        client._handle_response_errors(
            _response(502, "<html><h1>502 Bad Gateway</h1></html>", "text/html"), "ep"
        )


def test_rejected_acknowledge_is_not_retried(client):
    client.session.post = Mock(
        return_value=_response(
            422,
            {
                "success": False,
                "message": "Upload incomplete: missing required file(s): dependencies.json. Re-run the ZSBOM workflow.",
            },
        )
    )
    with pytest.raises(APIConnectionError, match=r"missing required file\(s\): dependencies.json"):
        client.acknowledge_completion("scan-1", _completion())
    assert client.session.post.call_count == 1


def test_server_errors_are_still_retried(client):
    client.session.post = Mock(return_value=_response(503, {"message": "Service Unavailable"}))
    with pytest.raises(APIConnectionError):
        client.acknowledge_completion("scan-1", _completion())
    assert client.session.post.call_count == 3
