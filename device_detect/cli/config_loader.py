"""
YAML configuration file loader for CLI.
"""

import yaml
from typing import Dict, List, Any, Optional
from pathlib import Path


def load_config(config_path: str) -> Dict[str, Any]:
    """
    Load configuration from YAML file.
    
    Expected format (flat structure):
        credentials:
          snmp:
            version: 2
            community: public
            # OR for SNMPv3:
            user: username
            auth_proto: sha
            auth_password: authpass
            priv_proto: aes
            priv_password: privpass
          ssh:
            username: admin
            password: secret
            enable_password: enable_secret  # optional
        hosts:
          - 192.168.1.1
          - 192.168.1.2
        
        # All CLI settings (optional, flat structure)
        log_level: INFO
        output_format: table
        output_file: /path/to/output.json
        output_dir: /path/to/dir
        csv_delimiter: ";"
        max_workers: 10
        sequential: false
        ssh_timing_profile: normal
        ssh_port: 22
        snmp_only: false
        ssh_only: false
        collect_ssh_commands: false
        sanitize: false
        additional_commands:
          - "show interfaces"
          - "show ip route"
    
    Args:
        config_path: Path to YAML configuration file
        
    Returns:
        Dictionary with config values
        
    Raises:
        FileNotFoundError: If config file doesn't exist
        yaml.YAMLError: If config file is invalid YAML
    """
    path = Path(config_path)
    
    if not path.exists():
        raise FileNotFoundError(f"Configuration file not found: {config_path}")
    
    with open(path, 'r') as f:
        config = yaml.safe_load(f)
    
    # Validate config structure
    if not isinstance(config, dict):
        raise ValueError("Invalid config: must be a dictionary")
    
    if 'hosts' not in config:
        raise ValueError("Invalid config: missing 'hosts' section")
    
    if not isinstance(config['hosts'], list):
        raise ValueError("Invalid config: 'hosts' must be a list")
    
    # Note: 'credentials' section is optional - credentials can be provided via CLI parameters
    
    return config


def get_config_setting(config: Dict[str, Any], key: str, default: Any = None) -> Any:
    """
    Get a setting from config with a default fallback.
    
    Args:
        config: Configuration dictionary
        key: Setting key
        default: Default value if key not found
        
    Returns:
        Config value or default
    """
    return config.get(key, default)


def get_snmp_credentials(config: Dict[str, Any]) -> Dict[str, Any]:
    """
    Extract SNMP credentials from config.
    
    Args:
        config: Configuration dictionary
        
    Returns:
        Dictionary with SNMP credential parameters
    """
    snmp = config.get('credentials', {}).get('snmp', {})
    
    if not snmp:
        return {}
    
    creds = {}
    
    # Version
    creds['snmp_version'] = snmp.get('version', 2)
    
    # SNMPv1/v2c
    if 'community' in snmp:
        creds['snmp_community'] = snmp['community']
    
    # SNMPv3
    if 'user' in snmp:
        creds['snmp_user'] = snmp['user']
    if 'auth_proto' in snmp:
        creds['snmp_auth_proto'] = snmp['auth_proto']
    if 'auth_password' in snmp:
        creds['snmp_auth_password'] = snmp['auth_password']
    if 'priv_proto' in snmp:
        creds['snmp_priv_proto'] = snmp['priv_proto']
    if 'priv_password' in snmp:
        creds['snmp_priv_password'] = snmp['priv_password']
    
    return creds


def get_ssh_credentials(config: Dict[str, Any]) -> Dict[str, Any]:
    """
    Extract SSH credentials from config.
    
    Args:
        config: Configuration dictionary
        
    Returns:
        Dictionary with SSH credential parameters
    """
    ssh = config.get('credentials', {}).get('ssh', {})
    
    if not ssh:
        return {}
    
    creds = {}
    
    if 'username' in ssh:
        creds['ssh_username'] = ssh['username']
    if 'password' in ssh:
        creds['ssh_password'] = ssh['password']
    if 'enable_password' in ssh:
        creds['ssh_enable_password'] = ssh['enable_password']
    if 'port' in ssh:
        creds['ssh_port'] = ssh['port']
    
    # Also check for ssh_port at top level (flat config)
    if 'ssh_port' in config and 'ssh_port' not in creds:
        creds['ssh_port'] = config['ssh_port']
    
    # Also check for ssh_timing_profile at top level
    if 'ssh_timing_profile' in config:
        creds['ssh_timing_profile'] = config['ssh_timing_profile']
    
    return creds


def get_output_settings(config: Dict[str, Any]) -> Dict[str, Any]:
    """
    Extract output settings from config.
    
    Args:
        config: Configuration dictionary
        
    Returns:
        Dictionary with output settings
    """
    settings = {}
    
    if 'output_format' in config:
        settings['output_format'] = config['output_format']
    if 'output_file' in config:
        settings['output_file'] = config['output_file']
    if 'output_dir' in config:
        settings['output_dir'] = config['output_dir']
    if 'csv_delimiter' in config:
        settings['csv_delimiter'] = config['csv_delimiter']
    
    return settings


def get_parallel_settings(config: Dict[str, Any]) -> Dict[str, Any]:
    """
    Extract parallel execution settings from config.
    
    Args:
        config: Configuration dictionary
        
    Returns:
        Dictionary with parallel settings
    """
    settings = {}
    
    if 'max_workers' in config:
        settings['max_workers'] = config['max_workers']
    if 'sequential' in config:
        settings['sequential'] = config['sequential']
    
    return settings


def get_collection_settings(config: Dict[str, Any]) -> Dict[str, Any]:
    """
    Extract collection-specific settings from config.
    
    Args:
        config: Configuration dictionary
        
    Returns:
        Dictionary with collection settings
    """
    settings = {}
    
    if 'snmp_only' in config:
        settings['snmp_only'] = config['snmp_only']
    if 'ssh_only' in config:
        settings['ssh_only'] = config['ssh_only']
    if 'collect_ssh_commands' in config:
        settings['collect_ssh_commands'] = config['collect_ssh_commands']
    if 'sanitize' in config:
        settings['sanitize'] = config['sanitize']
    
    return settings
