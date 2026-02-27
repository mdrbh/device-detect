"""
Detect command - Main device detection CLI command.
"""

import click
from rich.console import Console
from device_detect import DeviceDetect
from device_detect.cli.config_loader import (
    load_config, get_snmp_credentials, get_ssh_credentials,
    get_output_settings, get_parallel_settings, get_config_setting
)
from device_detect.cli.formatters import save_output
from device_detect.cli.parallel import process_devices_parallel

console = Console()


@click.command()
@click.option('--host', help='Single host to detect')
@click.option('--config', type=click.Path(exists=True), help='YAML config file with hosts and credentials')
@click.option('--offline', is_flag=True, help='Offline mode: detect from collected JSON file(s)')
@click.option('--input-file', type=click.Path(exists=True), help='Input JSON file (offline mode)')
@click.option('--input-dir', type=click.Path(exists=True), help='Input directory with JSON files (offline mode)')
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
@click.option('--ssh-verification', is_flag=True, help='Verify SNMP detection via SSH')
@click.option('--include-banners', is_flag=True, help='Include SSH banners in detection result (default: False)')
@click.option('--output', type=click.Choice(['json', 'yaml', 'table', 'csv', 'excel']), help='Output format')
@click.option('--output-file', type=click.Path(), help='Output file path')
@click.option('--csv-delimiter', help='CSV delimiter character')
@click.option('--max-workers', type=int, help='Maximum concurrent workers for parallel detection')
@click.option('--sequential', is_flag=True, help='Process devices sequentially instead of in parallel')
@click.pass_context
def detect(ctx, host, config, offline, input_file, input_dir, snmp_community, snmp_version, snmp_user, snmp_auth_proto, snmp_auth_password,
           snmp_priv_proto, snmp_priv_password, ssh_username, ssh_password, ssh_enable_password,
           ssh_port, ssh_timing_profile, ssh_verification, include_banners, output, output_file, csv_delimiter, max_workers, sequential):
    """Detect device type(s) using SNMP and/or SSH, or from collected JSON data (offline mode). Multi-device detection runs in parallel by default."""
    
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
    output = get_value(output, 'output', 'output_format', 'table')
    output_file = get_value(output_file, 'output_file', 'output_file', None)
    csv_delimiter = get_value(csv_delimiter, 'csv_delimiter', 'csv_delimiter', ';')
    max_workers = get_value(max_workers, 'max_workers', 'max_workers', 10)
    
    # Flag handling (is_flag doesn't use defaults the same way)
    if not sequential and cfg:
        sequential = get_config_setting(cfg, 'sequential', False)
    if not ssh_verification and cfg:
        ssh_verification = get_config_setting(cfg, 'ssh_verification', False)
    
    results = []
    
    # Offline mode
    if offline:
        import os
        from pathlib import Path
        
        # Validate offline mode inputs
        if not input_file and not input_dir:
            console.print("[red]Error: --input-file or --input-dir required for offline mode")
            return
        
        if input_file and input_dir:
            console.print("[red]Error: --input-file and --input-dir are mutually exclusive")
            return
        
        # Single file offline detection
        if input_file:
            try:
                # Check if file contains array or single object
                import json
                from pathlib import Path
                
                file_path = Path(input_file)
                with open(file_path, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                
                # Handle array of collected results
                if isinstance(data, list):
                    console.print(f"[cyan]Processing {len(data)} device(s) from {input_file}")
                    for item in data:
                        # Save each item to temp and process
                        result = DeviceDetect.detect_offline_from_dict(item)
                        results.append(result)
                else:
                    # Single object
                    result = DeviceDetect.detect_offline(input_file)
                    results.append(result)
            except Exception as e:
                console.print(f"[red]Error: {e}")
                return
        
        # Directory batch offline detection
        elif input_dir:
            try:
                dir_path = Path(input_dir)
                json_files = list(dir_path.glob('*.json'))
                
                if not json_files:
                    console.print(f"[yellow]No JSON files found in {input_dir}")
                    return
                
                file_paths = [str(f) for f in json_files]
                
                # Use existing parallel infrastructure
                results = process_devices_parallel(
                    hosts=file_paths,
                    process_func=DeviceDetect.detect_offline,
                    max_workers=max_workers,
                    sequential=sequential,
                    operation_name="Offline detecting"
                )
            except Exception as e:
                console.print(f"[red]Error: {e}")
                return
    
    # Config file mode
    elif cfg:
        try:
            hosts = cfg['hosts']
            snmp_creds = get_snmp_credentials(cfg)
            ssh_creds = get_ssh_credentials(cfg)
            
            # Merge CLI credentials with config credentials (CLI takes precedence)
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
            
            # Define detection function for parallel processing
            def detect_device(hostname):
                detector = DeviceDetect(
                    hostname=hostname, 
                    log_level=log_level, 
                    ssh_verification=ssh_verification,
                    include_banners=include_banners if include_banners else None,
                    **snmp_creds, 
                    **ssh_creds
                )
                return detector.detect()
            
            # Process devices in parallel (or sequential if flag set)
            results = process_devices_parallel(
                hosts=hosts,
                process_func=detect_device,
                max_workers=max_workers,
                sequential=sequential,
                operation_name="Detecting"
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
                ssh_verification=ssh_verification,
                include_banners=include_banners if include_banners else None,
                log_level=log_level
            )
            result = detector.detect()
            results.append(result)
        except Exception as e:
            console.print(f"[red]Error: {e}")
            return
    else:
        console.print("[yellow]Error: Either --host or --config must be specified")
        return
    
    # Output results
    if results:
        output_str = save_output(results, output, output_file, csv_delimiter=csv_delimiter)
        if output_file:
            console.print(f"[green]{output_str}")
        else:
            console.print(output_str)
