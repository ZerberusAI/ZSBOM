"""
CLI module for ZSBOM.

Provides command-line interface components following clean architecture principles.
"""
from depclass.cli.app import app as _app

# Export app function for pyproject.toml entry point
def app():
    """Entry point function for pyproject.toml scripts."""
    _app()

__all__ = ['app']