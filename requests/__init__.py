"""Minimal stub of the requests package for offline tests."""

class Response:
    """Very small HTTP response stub."""
    status_code = 200
    text = ""

    def json(self):  # pragma: no cover - simple stub
        return {}


class RequestException(Exception):
    """Generic request exception used by stubs."""


class Session:
    def __init__(self):  # pragma: no cover - simple stub
        self.headers = {}

    def get(self, *args, **kwargs):  # pragma: no cover - simple stub
        return Response()

    def post(self, *args, **kwargs):  # pragma: no cover - simple stub
        return Response()

    def mount(self, *args, **kwargs):  # pragma: no cover - simple stub
        pass


def get(*args, **kwargs):  # pragma: no cover - simple stub
    return Response()


def post(*args, **kwargs):  # pragma: no cover - simple stub
    return Response()


from . import adapters  # noqa: F401 - ensure submodule exists

__all__ = [
    "Session",
    "Response",
    "RequestException",
    "get",
    "post",
    "adapters",
]
