"""
List patterns command - Display supported device patterns.
"""

import click
from rich.console import Console
from rich.table import Table
from device_detect.patterns import SNMP_MAPPER_DICT, SSH_MAPPER_DICT

console = Console()


@click.command()
@click.option('--vendor', help='Filter by vendor (cisco, aruba, hp, oneaccess)')
def list_patterns(vendor):
    """List all supported device type patterns."""
    
    # Collect all device types
    all_devices = set()
    all_devices.update(SNMP_MAPPER_DICT.keys())
    all_devices.update(SSH_MAPPER_DICT.keys())
    
    # Filter by vendor if specified
    if vendor:
        all_devices = {d for d in all_devices if d.startswith(vendor.lower())}
    
    # Create table
    table = Table(title="Supported Device Types")
    table.add_column("Device Type", style="cyan")
    table.add_column("SNMP", style="green")
    table.add_column("SSH", style="blue")
    
    for device_type in sorted(all_devices):
        has_snmp = "✓" if device_type in SNMP_MAPPER_DICT else "✗"
        has_ssh = "✓" if device_type in SSH_MAPPER_DICT else "✗"
        table.add_row(device_type, has_snmp, has_ssh)
    
    console.print(f"\n")
    console.print(table)
    console.print(f"\n[yellow]Total: {len(all_devices)} device types[/yellow]\n")
