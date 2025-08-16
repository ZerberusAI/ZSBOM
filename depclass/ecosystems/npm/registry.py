"""Mocked NPM registry queries."""

from typing import Any, Dict


def query_registry(package: str) -> Dict[str, Any]:
    """Return mock metadata for a package.

    The real project would query the NPM registry for package information.  For
    the purposes of the unit tests we simply return a minimal dictionary which
    proves that a lookup occurred.
    """

    return {"name": package, "mock": True}
