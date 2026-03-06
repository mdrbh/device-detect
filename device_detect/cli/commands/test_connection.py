"""
Test connection command - Test SNMP or SSH connectivity.
"""

import click
from rich.console import Console
from device_detect.snmp.detector import SNMPDetector
from device_detect.ssh.detector import SSHDetector
from device_detect.cli.config_loader import (
    load_config, get_snmp_credentials, get_ssh_credentials,
    get_parallel_settings, get_config_setting
)
from device_detect.cli.parallel import process_devices_parallel

console = Console()


@click.command()
@click.option('--host', help='Single host to test')
@click.option('--config', type=click.Path(exists=True), help='YAML config file with hosts and credentials')
@click.option('--protocol', type=click.Choice(['snmp', 'ssh']), required=True, help='Protocol to test')
@click.option('--snmp-community', help='SNMP community string')
@click.option('--snmp-version', type=int, help='SNMP version')
@click.option('--snmp-user', help='SNMPv3 username')
@click.option('--snmp-auth-proto', help='SNMPv3 auth protocol')
@click.option('--snmp-auth-password', help='SNMPv3 auth password')
@click.option('--snmp-priv-proto', help='SNMPv3 priv protocol')
@click.option('--snmp-priv-password', help='SNMPv3 priv password')
@click.option('--ssh-username', help='SSH username')
@click.option('--ssh-password', help='SSH password')
@click.option('--ssh-port', type=int, help='SSH port')
@click.option('--max-workers', type=int, help='Maximum concurrent workers for parallel testing')
@click.option('--sequential', is_flag=True, help='Process devices sequentially instead of in parallel')
@click.pass_context
def test_connection(ctx, host, config, protocol, snmp_community, snmp_version, snmp_user, snmp_auth_proto, 
                   snmp_auth_password, snmp_priv_proto, snmp_priv_password,
                   ssh_username, ssh_password, ssh_port, max_workers, sequential):
    """Test SNMP or SSH connection to device(s). Multi-device testing runs in parallel by default."""
    
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
    max_workers = get_value(max_workers, 'max_workers', 'max_workers', 10)
    
    # Sequential flag handling
    if not sequential and cfg:
        sequential = get_config_setting(cfg, 'sequential', False)
    
    # Validate protocol-specific requirements for single host mode
    if host and not cfg:
        if protocol == 'snmp':
            if not snmp_community and snmp_version in [1, 2]:
                console.print("[red]Error: --snmp-community required for SNMPv1/v2c[/red]")
                return
            if snmp_version == 3 and not snmp_user:
                console.print("[red]Error: --snmp-user required for SNMPv3[/red]")
                return
        elif protocol == 'ssh':
            if not ssh_username or not ssh_password:
                console.print("[red]Error: --ssh-username and --ssh-password required[/red]")
                return
    
    # Config file mode (multiple hosts)
    if cfg:
        try:
            hosts = cfg['hosts']
            snmp_creds = get_snmp_credentials(cfg)
            ssh_creds = get_ssh_credentials(cfg)
            
            # Define test function based on protocol
            if protocol == 'snmp':
                def test_device(hostname):
                    return _test_snmp_connection(hostname, **snmp_creds)
            else:  # ssh
                def test_device(hostname):
                    return _test_ssh_connection(hostname, **ssh_creds)
            
            # Process devices in parallel (or sequential if flag set)
            process_devices_parallel(
                hosts=hosts,
                process_func=test_device,
                max_workers=max_workers,
                sequential=sequential,
                operation_name=f"Testing {protocol.upper()}"
            )
                    
        except Exception as e:
            console.print(f"[red]Error loading config: {e}")
            return
    
    # Single host mode
    elif host:
        if protocol == 'snmp':
            _test_snmp_connection(
                host, snmp_version, snmp_community, snmp_user, 
                snmp_auth_proto, snmp_auth_password, snmp_priv_proto, snmp_priv_password
            )
        else:  # ssh
            _test_ssh_connection(host, ssh_username, ssh_password, ssh_port)
    else:
        console.print("[yellow]Error: Either --host or --config must be specified[/yellow]")
        return


def _test_snmp_connection(hostname, snmp_version=2, snmp_community=None, snmp_user=None,
                         snmp_auth_proto=None, snmp_auth_password=None, 
                         snmp_priv_proto=None, snmp_priv_password=None):
    """Test SNMP connection to a single device. Returns result dict for parallel processing."""
    try:
        detector = SNMPDetector(
            hostname=hostname,
            version=snmp_version,
            community=snmp_community,
            user=snmp_user,
            auth_proto=snmp_auth_proto,
            auth_password=snmp_auth_password,
            priv_proto=snmp_priv_proto,
            priv_password=snmp_priv_password
        )
        data = detector.get_snmp_data()
        
        if data and data.sys_descr:
            return {"success": True, "data": data}
        else:
            raise Exception("No data received")
            
    except Exception as e:
        raise Exception(f"SNMP connection failed: {e}")


def _test_ssh_connection(hostname, ssh_username=None, ssh_password=None, ssh_port=22, ssh_enable_password=None, ssh_timing_profile=None, **kwargs):
    """Test SSH connection to a single device. Returns result dict for parallel processing."""
    try:
        detector = SSHDetector(
            device_type="autodetect",
            host=hostname,
            username=ssh_username,
            password=ssh_password,
            port=ssh_port
        )
        
        ssh_data = detector.get_ssh_data()
        detector.disconnect()
        
        return {"success": True, "data": ssh_data}
        
    except Exception as e:
        raise Exception(f"SSH connection failed: {e}")
