"""
Simplified CLI for ZSBOM - replaces the complex multi-module CLI structure.
"""
import sys
from typing import Optional
import typer
from depclass.scanner import ScannerService


# Initialize Typer app
app = typer.Typer(help="ZSBOM - Zerberus SBOM Automation Framework")


def scan_command(
    config_path: Optional[str] = typer.Option(None, "-c", "--config", help="Path to config YAML"),
    output: Optional[str] = typer.Option(None, "-o", "--output", help="Output file override"),
    skip_sbom: bool = typer.Option(False, "-sb", "--skip-sbom", help="Skip the SBOM report generation"),
    ignore_conflicts: bool = typer.Option(False, "--ignore-conflicts", help="Continue analysis even when dependency conflicts are detected")
):
    """Run ZSBOM security analysis and generate Software Bill of Materials."""
    
    scanner_service = ScannerService()
    exit_code, metadata = scanner_service.execute_scan(
        config_path=config_path,
        output=output,
        skip_sbom=skip_sbom,
        ignore_conflicts=ignore_conflicts
    )
    
    if exit_code != 0:
        sys.exit(exit_code)


def upload_command(
    license_key: Optional[str] = typer.Option(None, "--license-key", help="Zerberus license key"),
    api_url: Optional[str] = typer.Option(None, "--api-url", help="Zerberus API URL"),
    timeout: int = typer.Option(300, "--timeout", help="Upload timeout in seconds")
):
    """Upload scan results to Zerberus platform."""
    
    try:
        # Import upload modules only when needed (lazy loading)
        from depclass.upload_orchestrator import UploadOrchestrator
        from depclass.upload.models import TraceAIConfig
        from depclass.environment_detector import EnvironmentDetector
        
        # Get license key from environment if not provided
        if not license_key:
            import os
            license_key = os.getenv("ZERBERUS_LICENSE_KEY")
            if not license_key:
                typer.echo("❌ License key is required. Use --license-key or set ZERBERUS_LICENSE_KEY environment variable.")
                sys.exit(1)
        
        # Get API URL from environment if not provided
        if not api_url:
            import os
            api_url = os.getenv("ZERBERUS_API_URL")
            if not api_url:
                typer.echo("❌ API URL is required. Use --api-url or set ZERBERUS_API_URL environment variable.")
                sys.exit(1)
        
        # Create configuration
        config = TraceAIConfig(
            api_url=api_url,
            license_key=license_key,
            upload_timeout=timeout
        )
        
        # Detect scan files
        env_detector = EnvironmentDetector()
        scan_files = env_detector.detect_scan_files()
        
        if not scan_files:
            typer.echo("❌ No scan files found. Run 'zsbom scan' first.")
            sys.exit(1)
        
        # Load scan metadata
        scan_metadata = {}
        try:
            import json
            with open("scan_metadata.json", "r") as f:
                scan_metadata = json.load(f)
        except FileNotFoundError:
            typer.echo("⚠️ No scan metadata found. Proceeding with minimal metadata.")
        
        # Execute upload (metadata file will be updated automatically with API scan_id)
        orchestrator = UploadOrchestrator(config)
        result = orchestrator.execute_upload_workflow(scan_files, scan_metadata)
        
        if result.success:
            typer.echo(f"✅ Upload successful! Report available at: {result.report_url}")
            
            # Check threshold validation results
            if result.threshold_result and result.threshold_result.should_fail_build:
                typer.echo(f"❌ Build failed: {result.threshold_result.failure_reason}")
                sys.exit(1)
        else:
            typer.echo(f"❌ Upload failed: {result.error}")
            sys.exit(1)
            
    except KeyboardInterrupt:
        typer.echo("\n⚠️ Upload interrupted by user")
        sys.exit(130)
    except Exception as e:
        typer.echo(f"❌ Upload failed: {str(e)}")
        sys.exit(1)


# Register commands
app.command("scan", help="Run ZSBOM security analysis and generate Software Bill of Materials.")(scan_command)
app.command("upload", help="Upload scan results to Zerberus platform.")(upload_command)


# Add callback to make scan the default command when no subcommand is specified
@app.callback(invoke_without_command=True)
def main(ctx: typer.Context):
    """ZSBOM - Zerberus SBOM Automation Framework.
    
    Run 'zsbom scan' to analyze dependencies and generate security reports.
    Run 'zsbom upload' to upload scan results to Zerberus platform.
    """
    if ctx.invoked_subcommand is None:
        # Default to scan command when no subcommand is specified
        ctx.invoke(scan_command, config_path=None, output=None, skip_sbom=False, ignore_conflicts=False)