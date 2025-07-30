import os
import sys

from rich.console import Console

def is_ci_environment():
    return (
        os.getenv('CI') is not None or
        os.getenv('GITHUB_ACTIONS') is not None or
        not sys.stdout.isatty()
    )

def get_console() -> Console:
    """Detect environment and create console."""
    is_interactive = is_ci_environment()
    
    if not is_interactive:
        # CI/automated environment - no colors, no interactive elements
        console = Console(force_terminal=False, no_color=True)
        return console
    else:
        # Interactive terminal - full Rich capabilities
        console = Console()
        return console
