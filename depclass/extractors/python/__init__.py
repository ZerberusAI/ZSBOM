"""
Python ecosystem dependency extractor.

Handles Python dependency files like pyproject.toml, requirements.txt, setup.py, etc.
"""

from .extractor import PythonExtractor

__all__ = ["PythonExtractor"]