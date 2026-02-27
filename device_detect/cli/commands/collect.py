"""
Collect command - Raw data collection without device detection.
"""

import click
import os
from datetime import datetime
from rich.console import Console
from device_detect import DeviceDetect
from device_detect.cli.config_loader import (
    load_config, get_snmp_credentials, get_ssh_credentials,
    get_output_settings, get_parallel_settings, get_collection_settings, get_config_setting
)
from device_detect.cli.formatters import save_output
from device_detect.cli.parallel import process_devices_parallel

console = Console()


@click.command()
@click.option('--host', help='Single host to collect data from')
@click.option('--config', type=click.Path(exists=True), help='YAML config file with hosts and credentials')
@click.option('--snmp-community', help='SNMP community string (v2c)')
@click.option('--snmp-version', type=int, help='SNMP version (1, 2, or 3)')
@click.option('--snmp-user', help='SNMPv3 username')
@click.option('--snmp-auth-proto', help='SNMPv3 auth protocol (sha, md5)')
@click.option('--snmp-auth-password', help='SNMPv3 auth password')
@click.option('--snmp-priv-proto', help='SNMPv3 priv protocol (aes, des)')
@click.option('--snmp-priv-password', help='SNMPv3 priv password')
@click.option('--ssh-username', help='SSH username')
@click.option('--ssh-password', help='SSH password')
@click.option('--ssh-enable-password', help='SSH enable password (optional)')
@click.option('--ssh-port', type=int, help='SSH port')
@click.option('--ssh-timing-profile', type=click.Choice(['fast', 'normal', 'slow']), help='SSH timing profile')
@click.option('--snmp-only', is_flag=True, help='Collect only SNMP data')
@click.option('--ssh-only', is_flag=True, help='Collect only SSH data')
@click.option('--output', type=click.Choice(['json', 'csv', 'excel']), help='Output format')
@click.option('--output-file', type=click.Path(), help='Output file path')
@click.option('--output-dir', type=click.Path(), help='Output directory (auto-generates filename)')
@click.option('--csv-delimiter', help='CSV delimiter character')
@click.option('--max-workers', type=int, help='Maximum concurrent workers for parallel collection')
@click.option('--sequential', is_flag=True, help='Process devices sequentially instead of in parallel')
@click.option('--collect-ssh-commands', is_flag=True, help='Collect all SSH detection commands outputs')
@click.option('--additional-commands', help='Comma-separated list of additional commands to collect (deduplicated against detection commands)')
@click.option('--sanitize', is_flag=True, help='Remove escape characters and control codes from command outputs')
@click.option('--no-banners', is_flag=True, help='Exclude SSH banners from collection result (default: False, banners included)')
@click.pass_context
def collect(ctx, host, config, snmp_community, snmp_version, snmp_user, snmp_auth_proto, snmp_auth_password,
           snmp_priv_proto, snmp_priv_password, ssh_username, ssh_password, ssh_enable_password,
           ssh_port, ssh_timing_profile, snmp_only, ssh_only, output, output_file, output_dir, csv_delimiter, 
           max_workers, sequential, collect_ssh_commands, additional_commands, sanitize, no_banners):
    """Collect raw device data (SNMP/SSH) without device type detection. Multi-device collection runs in parallel by default."""
    
    # Get log_level from context
    log_level = ctx.obj.get('log_level', 'INFO') if ctx.obj else 'INFO'
    
    # Load config and apply CLI override logic
    cfg = None
    if config:
        cfg = load_config(config)
    
    # Helper function to get value: CLI arg > config value > default
    def get_value(cli_val, cli_param_name, config_key, default_val):
        # Check if CLI value was explicitly provided
        param_source = ctx.get_parameter_source(cli_param_name)
        if param_source == click.core.ParameterSource.COMMANDLINE:
            return cli_val
        # Otherwise use config if available
        if cfg:
            return get_config_setting(cfg, config_key, default_val)
        return default_val
    
    # Apply override logic for all settings (Click stores params with underscores)
    snmp_version = get_value(snmp_version, 'snmp_version', 'snmp_version', 2)
    ssh_port = get_value(ssh_port, 'ssh_port', 'ssh_port', 22)
    ssh_timing_profile = get_value(ssh_timing_profile, 'ssh_timing_profile', 'ssh_timing_profile', 'fast')
    output = get_value(output, 'output', 'output_format', 'json')
    output_file = get_value(output_file, 'output_file', 'output_file', None)
    output_dir = get_value(output_dir, 'output_dir', 'output_dir', None)
    csv_delimiter = get_value(csv_delimiter, 'csv_delimiter', 'csv_delimiter', ';')
    max_workers = get_value(max_workers, 'max_workers', 'max_workers', 10)
    
    # Flag handling (is_flag doesn't use defaults the same way)
    if not sequential and cfg:
        sequential = get_config_setting(cfg, 'sequential', False)
    if not snmp_only and cfg:
        snmp_only = get_config_setting(cfg, 'snmp_only', False)
    if not ssh_only and cfg:
        ssh_only = get_config_setting(cfg, 'ssh_only', False)
    if not collect_ssh_commands and cfg:
        collect_ssh_commands = get_config_setting(cfg, 'collect_ssh_commands', False)
    if not sanitize and cfg:
        sanitize = get_config_setting(cfg, 'sanitize', False)
    
    # Validate mutually exclusive flags
    if snmp_only and ssh_only:
        console.print("[red]Error: --snmp-only and --ssh-only are mutually exclusive")
        return
    
    # Parse additional commands from CLI (comma-separated)
    additional_commands_list = None
    if additional_commands:
        additional_commands_list = [cmd.strip() for cmd in additional_commands.split(',') if cmd.strip()]
    
    results = []
    
    # Config file mode
    if cfg:
        try:
            hosts = cfg['hosts']
            snmp_creds = get_snmp_credentials(cfg)
            ssh_creds = get_ssh_credentials(cfg)
            
            # Merge CLI credentials with config credentials (CLI takes precedence)
            # Check if CLI credentials were provided
            if snmp_community:
                snmp_creds['snmp_community'] = snmp_community
            if snmp_user:
                snmp_creds['snmp_user'] = snmp_user
            if snmp_auth_proto:
                snmp_creds['snmp_auth_proto'] = snmp_auth_proto
            if snmp_auth_password:
                snmp_creds['snmp_auth_password'] = snmp_auth_password
            if snmp_priv_proto:
                snmp_creds['snmp_priv_proto'] = snmp_priv_proto
            if snmp_priv_password:
                snmp_creds['snmp_priv_password'] = snmp_priv_password
            if ssh_username:
                ssh_creds['ssh_username'] = ssh_username
            if ssh_password:
                ssh_creds['ssh_password'] = ssh_password
            if ssh_enable_password:
                ssh_creds['ssh_enable_password'] = ssh_enable_password
            
            # Validate that we have credentials for at least one protocol
            has_snmp = 'snmp_community' in snmp_creds or 'snmp_user' in snmp_creds
            has_ssh = 'ssh_username' in ssh_creds and 'ssh_password' in ssh_creds
            
            if not has_snmp and not has_ssh:
                console.print("[red]Error: No credentials provided. Please provide SNMP or SSH credentials via config file or CLI parameters.")
                console.print("[yellow]Examples:")
                console.print("  SNMP: --snmp-community YOUR_COMMUNITY")
                console.print("  SSH: --ssh-username USER --ssh-password PASS")
                return
            
            # Validate credentials match collection mode
            if snmp_only and not has_snmp:
                console.print("[red]Error: --snmp-only specified but no SNMP credentials provided")
                return
            if ssh_only and not has_ssh:
                console.print("[red]Error: --ssh-only specified but no SSH credentials provided")
                return
            
            # Get additional commands from config file (if not provided via CLI)
            config_additional_commands = cfg.get('additional_commands', [])
            if not additional_commands_list and config_additional_commands:
                additional_commands_list = config_additional_commands
            
            # Define collection function for parallel processing
            def collect_device(hostname):
                detector = DeviceDetect(
                    hostname=hostname, 
                    log_level=log_level,
                    include_banners=False if no_banners else None,
                    **snmp_creds, 
                    **ssh_creds
                )
                return detector.collect(
                    snmp_only=snmp_only, 
                    ssh_only=ssh_only,
                    collect_ssh_commands=collect_ssh_commands,
                    additional_commands=additional_commands_list,
                    sanitize_output=sanitize
                )
            
            # Process devices in parallel (or sequential if flag set)
            results = process_devices_parallel(
                hosts=hosts,
                process_func=collect_device,
                max_workers=max_workers,
                sequential=sequential,
                operation_name="Collecting"
            )
                    
        except Exception as e:
            console.print(f"[red]Error loading config: {e}")
            return
    
    # Single host mode
    elif host:
        try:
            detector = DeviceDetect(
                hostname=host,
                snmp_community=snmp_community,
                snmp_version=snmp_version,
                snmp_user=snmp_user,
                snmp_auth_proto=snmp_auth_proto,
                snmp_auth_password=snmp_auth_password,
                snmp_priv_proto=snmp_priv_proto,
                snmp_priv_password=snmp_priv_password,
                ssh_username=ssh_username,
                ssh_password=ssh_password,
                ssh_enable_password=ssh_enable_password,
                ssh_port=ssh_port,
                ssh_timing_profile=ssh_timing_profile,
                include_banners=False if no_banners else None,
                log_level=log_level
            )
            result = detector.collect(
                snmp_only=snmp_only, 
                ssh_only=ssh_only,
                collect_ssh_commands=collect_ssh_commands,
                additional_commands=additional_commands_list,
                sanitize_output=sanitize
            )
            results.append(result)
        except Exception as e:
            console.print(f"[red]Error: {e}")
            return
    else:
        console.print("[yellow]Error: Either --host or --config must be specified")
        return
    
    # Determine output file path
    final_output_file = None
    if output_file:
        final_output_file = output_file
    elif output_dir:
        # Create directory if it doesn't exist
        os.makedirs(output_dir, exist_ok=True)
        
        # Generate filename
        # Map output format to file extension
        ext_map = {'json': 'json', 'csv': 'csv', 'excel': 'xlsx', 'yaml': 'yaml', 'table': 'txt'}
        ext = ext_map.get(output, output)
        
        if host:
            # Single host: use hostname
            filename = f"{host.replace('.', '_')}_collection.{ext}"
        else:
            # Multiple hosts: use timestamp
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"collection_{timestamp}.{ext}"
        
        final_output_file = os.path.join(output_dir, filename)
    
    # Excel format requires output file
    if output == 'excel' and not final_output_file:
        console.print("[red]Error: Excel format requires --output-file or --output-dir")
        return
    
    # Output results
    if results:
        output_str = save_output(results, output, final_output_file, csv_delimiter=csv_delimiter)
        if final_output_file:
            console.print(f"[green]{output_str}")
        else:
            console.print(output_str)
    else:
        console.print("[yellow]No results collected")
