"""
Simplified CLI for ZSBOM - replaces the complex multi-module CLI structure.
"""
import os
import json
import sys
from typing import Optional
import typer
from depclass.scanner import ScannerService
from depclass.upload_orchestrator import UploadOrchestrator
from depclass.upload.models import TraceAIConfig
from depclass.environment_detector import EnvironmentDetector
from depclass.rich_utils.ui_helpers import get_console


# Initialize Typer app
app = typer.Typer(help="ZSBOM - Zerberus SBOM Automation Framework")

# Exit codes for `zsbom upload`. The generated GitHub workflow keys its
# messages on these, so keep them in step with the template.
EXIT_OK = 0
EXIT_THRESHOLD_VIOLATED = 1
EXIT_UPLOAD_FAILED = 2


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

    console = get_console()

    try:
        # Get license key from environment if not provided
        if not license_key:
            license_key = os.getenv("ZERBERUS_LICENSE_KEY")
            if not license_key:
                console.print("❌ License key is required. Use --license-key or set ZERBERUS_LICENSE_KEY environment variable.", style="bold red")
                sys.exit(EXIT_UPLOAD_FAILED)

        # Get API URL from environment if not provided
        if not api_url:
            api_url = os.getenv("ZERBERUS_API_URL")
            if not api_url:
                console.print("❌ API URL is required. Use --api-url or set ZERBERUS_API_URL environment variable.", style="bold red")
                sys.exit(EXIT_UPLOAD_FAILED)

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
            console.print("❌ No scan files found. Run 'zsbom scan' first.", style="bold red")
            sys.exit(EXIT_UPLOAD_FAILED)

        # Load scan metadata
        scan_metadata = {}
        try:
            with open("scan_metadata.json", "r") as f:
                scan_metadata = json.load(f)

            # Check if repository uses unsupported ecosystems
            statistics = scan_metadata.get("statistics", {})
            if statistics.get("unsupported_repo", False):
                console.print("ℹ️  This repository uses unsupported ecosystems - skipping upload", style="bold blue")
                console.print(f"📦 Currently supported: {', '.join(statistics.get('supported_ecosystems', []))}", style="dim")
                console.print("✅ No action required", style="bold green")
                sys.exit(0)

        except FileNotFoundError:
            console.print("⚠️ No scan metadata found. Proceeding with minimal metadata.", style="bold yellow")

        # Execute upload (metadata file will be updated automatically with API scan_id)
        orchestrator = UploadOrchestrator(config)
        result = orchestrator.execute_upload_workflow(scan_files, scan_metadata)

        threshold = result.threshold_result
        threshold_failed = bool(threshold and threshold.should_fail_build)

        if not result.success:
            console.print(f"❌ Upload failed: {result.error}", style="bold red")
            if threshold_failed:
                console.print(f"❌ CVE threshold also violated: {threshold.failure_reason}", style="bold red")
            sys.exit(EXIT_UPLOAD_FAILED)

        console.print(f"✅ Upload successful! Report available at: {result.report_url}", style="bold green")
        if threshold_failed:
            console.print(f"❌ Build failed: {threshold.failure_reason}", style="bold red")
            sys.exit(EXIT_THRESHOLD_VIOLATED)

    except KeyboardInterrupt:
        console.print("\n⚠️ Upload interrupted by user", style="bold yellow")
        sys.exit(130)
    except Exception as e:
        console.print(f"❌ Upload failed: {str(e)}", style="bold red")
        sys.exit(EXIT_UPLOAD_FAILED)


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