"""
Version command - Display version information.
"""

import click
from rich.console import Console
from device_detect import __version__

console = Console()


@click.command()
def version():
    """Display version information."""
    console.print(f"[cyan]device-detect version {__version__}")
