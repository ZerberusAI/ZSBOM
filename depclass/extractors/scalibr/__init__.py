"""
Scalibr wrapper for multi-language dependency extraction.

Provides a Python interface to the OSV Scalibr shared library for
extracting dependencies from various package ecosystems.
"""

from .wrapper import ScalibrWrapper

__all__ = ["ScalibrWrapper"]