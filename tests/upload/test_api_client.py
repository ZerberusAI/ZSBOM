"""Error messages and retries in the Zerberus API client.

The server says why it refused (a 403 "Tool integration is not active", a 422
"Upload incomplete: missing ..."). ZSBOM must pass that reason on, and must not
retry a request the server has already refused.
"""

import json
import types
from datetime import datetime, timedelta
from unittest.mock import Mock

import backoff._sync
import pytest
import requests

from depclass.upload.api_client import (
    RETRY_BUDGET_SECONDS,
    RETRY_MAX_WAIT_SECONDS,
    ZerberusAPIClient,
)
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


class _Clock:
    """Fake time for the retries: sleeping moves the clock on."""

    def __init__(self):
        self.now = datetime(2026, 10, 8, 10, 42, 0)
        self.sleeps = []

    def sleep(self, seconds):
        self.sleeps.append(seconds)
        self.now += timedelta(seconds=seconds)


@pytest.fixture
def clock(monkeypatch):
    clock = _Clock()
    monkeypatch.setattr("time.sleep", clock.sleep)
    # backoff measures its time budget with datetime.datetime.now().
    fake_datetime = types.SimpleNamespace(
        datetime=types.SimpleNamespace(now=lambda: clock.now)
    )
    monkeypatch.setattr(backoff._sync, "datetime", fake_datetime)
    return clock


UNAVAILABLE = {"message": "Service Unavailable"}
ACKNOWLEDGED = {
    "scan_id": "scan-1",
    "status": "completed",
    "report_url": "https://app.test/r",
    "message": "ok",
    "processing_status": "queued",
    "estimated_processing_time": "1m",
}


def test_a_short_outage_is_ridden_out(client, clock):
    # 2026-10-08: meta-guard returned 503 for a while and the old retries
    # gave up after about a second, failing the customer's build.
    client.session.post = Mock(
        side_effect=[
            _response(503, UNAVAILABLE),
            _response(503, UNAVAILABLE),
            _response(200, ACKNOWLEDGED),
        ]
    )
    result = client.acknowledge_completion("scan-1", _completion())
    assert result.status == "completed"
    assert client.session.post.call_count == 3
    assert 2 <= clock.sleeps[0] < 3
    assert 4 <= clock.sleeps[1] < 5


def test_waits_grow_and_never_exceed_30_seconds(client, clock):
    client.session.post = Mock(return_value=_response(503, UNAVAILABLE))
    with pytest.raises(APIConnectionError):
        client.acknowledge_completion("scan-1", _completion())
    for wait, low in zip(clock.sleeps, (2, 4, 8, 16, 30)):
        assert low <= wait < low + 1
    assert all(wait <= RETRY_MAX_WAIT_SECONDS + 1 for wait in clock.sleeps)


def test_retrying_stops_at_the_90_second_budget(client, clock):
    client.session.post = Mock(return_value=_response(503, UNAVAILABLE))
    with pytest.raises(APIConnectionError):
        client.acknowledge_completion("scan-1", _completion())
    assert sum(clock.sleeps) == pytest.approx(RETRY_BUDGET_SECONDS)
    assert client.session.post.call_count == len(clock.sleeps) + 1


@pytest.mark.parametrize(
    "call",
    [
        lambda c: c.initiate_scan(Mock()),
        lambda c: c.get_upload_urls("scan-1", ["dependencies.json"]),
        lambda c: c.acknowledge_completion("scan-1", _completion()),
    ],
    ids=["initiate_scan", "get_upload_urls", "acknowledge_completion"],
)
def test_every_api_call_uses_the_same_retries(client, clock, call):
    client.session.post = Mock(return_value=_response(503, UNAVAILABLE))
    with pytest.raises(APIConnectionError):
        call(client)
    assert 2 <= clock.sleeps[0] < 3
    assert sum(clock.sleeps) == pytest.approx(RETRY_BUDGET_SECONDS)
