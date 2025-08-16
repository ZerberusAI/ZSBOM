"""Utilities for reading NPM dependency manifests."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, Tuple

from .normalise import normalise_name


def read_manifest(path: str = ".") -> Tuple[Dict[str, str], Dict[str, Any]]:
    """Read a ``package.json`` manifest and return its dependencies.

    Parameters
    ----------
    path:
        Directory containing the ``package.json`` file.

    Returns
    -------
    tuple
        A two item tuple ``(packages, graph_partial)`` where ``packages`` is a
        mapping of normalised package names to their version specifiers and
        ``graph_partial`` is the raw dependency section which can later be used
        to build a full dependency graph.
    """

    manifest_path = Path(path) / "package.json"
    if not manifest_path.exists():
        return {}, {}

    data = json.loads(manifest_path.read_text(encoding="utf-8"))
    deps = data.get("dependencies", {}) or {}
    packages = {normalise_name(name): spec for name, spec in deps.items()}
    return packages, deps
