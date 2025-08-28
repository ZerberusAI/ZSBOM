"""
Upload command implementation.

Thin wrapper around UploadService that handles CLI argument parsing
and delegates business logic to the service layer.
"""
import sys
from typing import Optional

import typer

from depclass.core.uploader import UploadService


def upload_command(
    api_url: Optional[str] = typer.Option(None, "--api-url", help="Zerberus API URL (overrides ZERBERUS_API_URL)"),
    license_key: Optional[str] = typer.Option(None, "--license-key", help="License key (overrides ZERBERUS_LICENSE_KEY)"),
    config_path: Optional[str] = typer.Option(None, "-c", "--config", help="Path to config YAML")
):
    """Upload scan results to Zerberus platform."""
    
    # Delegate to service layer
    upload_service = UploadService()
    exit_code = upload_service.execute_upload(
        api_url=api_url,
        license_key=license_key,
        config_path=config_path
    )
    
    # Exit with appropriate code
    if exit_code != 0:
        sys.exit(exit_code)