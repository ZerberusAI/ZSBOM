"""
Main CLI application for ZSBOM.

Defines the Typer application structure and command routing,
following clean architecture principles with thin CLI layer.
"""
import typer

from depclass.cli.commands.scan import scan_command
from depclass.cli.commands.upload import upload_command


# Initialize Typer app
app = typer.Typer(help="ZSBOM - Zerberus SBOM Automation Framework")

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
        ctx.invoke(scan_command, config_path=None, output=None, skip_sbom=False, ignore_conflicts=False, ecosystem="python")