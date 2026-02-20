"""
Main CLI entry point for device-detect.
"""

import click
from device_detect import __version__
from device_detect.utils import setup_logging
from device_detect.cli.config_loader import load_config, get_config_setting


@click.group()
@click.option(
    '--log-level',
    type=click.Choice(['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'], case_sensitive=False),
    help='Set logging level'
)
@click.option(
    '--config',
    type=click.Path(exists=True),
    help='YAML config file (can also be passed to individual commands)'
)
@click.version_option(version=__version__, prog_name="device-detect")
@click.pass_context
def cli(ctx, log_level, config):
    """
    Device Detection CLI - Automatic network device type detection.
    
    Supports detection via SNMP and SSH for Cisco, OneAccess, Aruba, and HP devices.
    """
    # Load config if provided at global level
    cfg = None
    if config:
        try:
            cfg = load_config(config)
        except Exception:
            pass  # Config errors will be caught by individual commands
    
    # Determine log_level: CLI arg > config value > default
    final_log_level = 'INFO'
    if log_level:
        final_log_level = log_level.upper()
    elif cfg:
        final_log_level = get_config_setting(cfg, 'log_level', 'INFO').upper()
    
    # Setup logging with the specified level
    setup_logging(final_log_level)
    
    # Store log_level in context for commands to access
    ctx.ensure_object(dict)
    ctx.obj['log_level'] = final_log_level


# Import and register commands
from device_detect.cli.commands import detect, collect, version, info, list_patterns, test_connection

cli.add_command(detect.detect)
cli.add_command(collect.collect)
cli.add_command(version.version)
cli.add_command(info.info)
cli.add_command(list_patterns.list_patterns)
cli.add_command(test_connection.test_connection)


if __name__ == "__main__":
    cli()
