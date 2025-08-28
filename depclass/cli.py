"""
CLI entry point for ZSBOM.


Original implementation has been refactored into:
- ConfigManager: Configuration loading and merging
- FileManager: File collection and management  
- StatisticsCalculator: Statistics computation
- ScannerService: Scan workflow orchestration
- UploadService: Upload workflow management
- Thin CLI command wrappers

"""
from depclass.cli.app import app as _app

# Make app callable at module level for pyproject.toml entry point
def app():
    """Entry point function for pyproject.toml scripts."""
    _app()

# For backward compatibility
__all__ = ['app']

if __name__ == "__main__":
    app()