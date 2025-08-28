"""
Scan command implementation.

Thin wrapper around ScannerService that handles CLI argument parsing
and delegates business logic to the service layer.
"""
import sys
from typing import Optional

import typer

from depclass.core.scanner import ScannerService


def scan_command(
    config_path: Optional[str] = typer.Option(None, "-c", "--config", help="Path to config YAML"),
    output: Optional[str] = typer.Option(None, "-o", "--output", help="Output file override"),
    skip_sbom: bool = typer.Option(False, "-sb", "--skip-sbom", help="Skip the SBOM report generation"),
    ignore_conflicts: bool = typer.Option(False, "--ignore-conflicts", help="Continue analysis even when dependency conflicts are detected"),
    ecosystem: str = typer.Option("python", "--ecosystem", help="Target dependency ecosystem")
):
    """Run ZSBOM security analysis and generate Software Bill of Materials."""
    
    # Delegate to service layer
    scanner_service = ScannerService()
    exit_code, metadata = scanner_service.execute_scan(
        config_path=config_path,
        output=output,
        skip_sbom=skip_sbom,
        ignore_conflicts=ignore_conflicts,
        ecosystem=ecosystem
    )
    
    # Exit with appropriate code
    if exit_code != 0:
        sys.exit(exit_code)