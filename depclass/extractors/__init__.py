"""
Extractors package for multi-ecosystem dependency extraction.

This package provides extractors for different package ecosystems.
The main extraction logic uses auto-detection instead of manual registration.
"""

from .base import BaseExtractor

__all__ = ["BaseExtractor"]