"""
Info command - Display module information.
"""

import click
from rich.console import Console
from rich.table import Table
from device_detect import __version__
from device_detect.constants import PRIORITY_VENDORS

console = Console()


@click.command()
def info():
    """Display module information and supported vendors."""
    console.print(f"\n[bold cyan]Device Detection Module v{__version__}[/bold cyan]\n")
    console.print("Automatic network device type detection using SNMP and SSH.\n")
    
    # Supported vendors table
    table = Table(title="Supported Vendors")
    table.add_column("Vendor", style="cyan")
    table.add_column("Priority", style="green")
    
    for vendor in PRIORITY_VENDORS:
        table.add_row(vendor.capitalize(), "✓")
    
    console.print(table)
    console.print("\n[yellow]Use 'device-detect list-patterns' to see all supported device types.[/yellow]\n")
