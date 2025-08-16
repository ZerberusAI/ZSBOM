"""NPM ecosystem helpers."""

from .reader import read_manifest
from .normalise import normalise_name
from .registry import query_registry

__all__ = ["read_manifest", "normalise_name", "query_registry"]
