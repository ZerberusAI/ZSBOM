"""
Dependency classifiers for determining direct vs transitive dependencies.

Provides ecosystem-specific classifiers that can determine whether a package
is a direct dependency (declared in manifest files) or a transitive dependency
(dependency of another package).
"""

from .registry import get_classifier

__all__ = ["get_classifier"]