"""
Simplified enhancer layer for ZSBOM - streamlined external data enrichment.

This module provides a simplified infrastructure for enhancing dependency data with external sources.
The new architecture emphasizes simplicity and pragmatic design:

- Direct provider instantiation (no complex registry)
- Sequential processing with context passing
- Each provider handles its own optimization (batch vs individual)
- Simple enhance() interface across all providers

The enhancer system uses four main provider types:
1. DepsDevProvider: Package metadata from deps.dev API
2. OSVProvider: Vulnerability data from OSV.dev API
3. GitHubProvider: Repository analysis from GitHub API
4. MITREProvider: CWE weakness data from MITRE database
"""

from .orchestrator import EnhancerOrchestrator
from .formatters import PackageKeyFormatter
from .deps_dev_provider import DepsDevProvider
from .osv_provider import OSVProvider
from .github_provider import GitHubProvider
from .mitre_provider import MITREProvider
from .constants import OSV_ECOSYSTEM_MAPPING, DEPSDEV_ECOSYSTEM_MAPPING
from .mixins import CacheableMixin
from .utils import create_http_session

__all__ = [
    "EnhancerOrchestrator",
    "PackageKeyFormatter",
    "DepsDevProvider",
    "OSVProvider",
    "GitHubProvider",
    "MITREProvider",
    "OSV_ECOSYSTEM_MAPPING",
    "DEPSDEV_ECOSYSTEM_MAPPING",
    "CacheableMixin",
    "create_http_session"
]