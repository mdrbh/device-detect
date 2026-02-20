"""
Network automation framework driver mapper using netutils.lib_mapper.

This module provides utilities to map device_detect device types to
framework-specific driver names for Scrapli, NAPALM, Nornir, and Ansible.
"""

import logging
from typing import Optional, Dict

logger = logging.getLogger(__name__)

# Cache for lib_mapper availability check
_LIB_MAPPER_AVAILABLE = None


def _check_lib_mapper_available() -> bool:
    """Check if netutils.lib_mapper is available."""
    global _LIB_MAPPER_AVAILABLE
    
    if _LIB_MAPPER_AVAILABLE is not None:
        return _LIB_MAPPER_AVAILABLE
    
    try:
        from netutils.lib_mapper import ANSIBLE_LIB_MAPPER, NAPALM_LIB_MAPPER, NETMIKO_LIB_MAPPER
        _LIB_MAPPER_AVAILABLE = True
        logger.debug("netutils.lib_mapper is available")
    except ImportError:
        _LIB_MAPPER_AVAILABLE = False
        logger.warning("netutils.lib_mapper not available - framework mappings will return None")
    
    return _LIB_MAPPER_AVAILABLE


def get_scrapli_driver(device_type: str) -> Optional[str]:
    """
    Get Scrapli driver name for a device type.
    
    Args:
        device_type: Device type (e.g., 'cisco_ios', 'aruba_aoscx')
        
    Returns:
        Scrapli driver name or None if not mapped
        
    Examples:
        >>> get_scrapli_driver('cisco_ios')
        'cisco_iosxe'
        >>> get_scrapli_driver('aruba_aoscx')
        'aruba_aoscx'
    """
    if not device_type:
        return None
    
    if not _check_lib_mapper_available():
        return None
    
    try:
        from netutils.lib_mapper import NETMIKO_LIB_MAPPER
        
        # Get netmiko mapper entry
        mapper_entry = NETMIKO_LIB_MAPPER.get(device_type)
        if not mapper_entry:
            logger.debug(f"No mapping found for device_type: {device_type}")
            return None
        
        # Check if mapper_entry is a dict or string
        if isinstance(mapper_entry, dict):
            scrapli_driver = mapper_entry.get("scrapli")
        elif isinstance(mapper_entry, str):
            # In newer versions, NETMIKO_LIB_MAPPER may map directly to scrapli driver name
            scrapli_driver = mapper_entry
        else:
            scrapli_driver = None
        
        logger.debug(f"Mapped {device_type} -> scrapli: {scrapli_driver}")
        return scrapli_driver
        
    except Exception as e:
        logger.error(f"Error getting Scrapli driver for {device_type}: {e}")
        return None


def get_napalm_driver(device_type: str) -> Optional[str]:
    """
    Get NAPALM driver name for a device type.
    
    Args:
        device_type: Device type (e.g., 'cisco_ios', 'aruba_aoscx')
        
    Returns:
        NAPALM driver name or None if not mapped
        
    Examples:
        >>> get_napalm_driver('cisco_ios')
        'ios'
        >>> get_napalm_driver('cisco_nxos')
        'nxos'
    """
    if not device_type:
        return None
    
    if not _check_lib_mapper_available():
        return None
    
    try:
        from netutils.lib_mapper import NAPALM_LIB_MAPPER
        
        # NAPALM_LIB_MAPPER uses reversed mapping (napalm_driver -> netmiko_driver)
        # We need to find the key where the value matches our device_type
        for napalm_driver, netmiko_driver in NAPALM_LIB_MAPPER.items():
            if netmiko_driver == device_type:
                logger.debug(f"Mapped {device_type} -> napalm: {napalm_driver}")
                return napalm_driver
        
        logger.debug(f"No NAPALM mapping found for device_type: {device_type}")
        return None
        
    except Exception as e:
        logger.error(f"Error getting NAPALM driver for {device_type}: {e}")
        return None


def get_nornir_driver(device_type: str) -> Optional[str]:
    """
    Get Nornir driver name for a device type.
    
    Nornir typically uses the same driver names as Netmiko.
    
    Args:
        device_type: Device type (e.g., 'cisco_ios', 'aruba_aoscx')
        
    Returns:
        Nornir driver name (same as device_type) or None
        
    Examples:
        >>> get_nornir_driver('cisco_ios')
        'cisco_ios'
        >>> get_nornir_driver('aruba_aoscx')
        'aruba_aoscx'
    """
    if not device_type:
        return None
    
    # Nornir uses netmiko driver names directly
    # Just verify the device_type exists in the mapper
    if not _check_lib_mapper_available():
        return None
    
    try:
        from netutils.lib_mapper import NETMIKO_LIB_MAPPER
        
        if device_type in NETMIKO_LIB_MAPPER:
            logger.debug(f"Mapped {device_type} -> nornir: {device_type}")
            return device_type
        
        logger.debug(f"No Nornir mapping found for device_type: {device_type}")
        return None
        
    except Exception as e:
        logger.error(f"Error getting Nornir driver for {device_type}: {e}")
        return None


def get_ansible_driver(device_type: str) -> Optional[str]:
    """
    Get Ansible network_os for a device type.
    
    Args:
        device_type: Device type (e.g., 'cisco_ios', 'aruba_aoscx')
        
    Returns:
        Ansible network_os or None if not mapped
        
    Examples:
        >>> get_ansible_driver('cisco_ios')
        'cisco.ios.ios'
        >>> get_ansible_driver('cisco_nxos')
        'cisco.nxos.nxos'
    """
    if not device_type:
        return None
    
    if not _check_lib_mapper_available():
        return None
    
    try:
        from netutils.lib_mapper import ANSIBLE_LIB_MAPPER
        
        # ANSIBLE_LIB_MAPPER uses reversed mapping (ansible_network_os -> netmiko_driver)
        # We need to find the key where the value matches our device_type
        for ansible_os, netmiko_driver in ANSIBLE_LIB_MAPPER.items():
            if netmiko_driver == device_type:
                logger.debug(f"Mapped {device_type} -> ansible: {ansible_os}")
                return ansible_os
        
        logger.debug(f"No Ansible mapping found for device_type: {device_type}")
        return None
        
    except Exception as e:
        logger.error(f"Error getting Ansible driver for {device_type}: {e}")
        return None


def get_framework_drivers(device_type: str) -> Dict[str, Optional[str]]:
    """
    Get all framework driver mappings for a device type.
    
    Args:
        device_type: Device type (e.g., 'cisco_ios', 'aruba_aoscx')
        
    Returns:
        Dictionary with framework names as keys and driver names as values
        
    Examples:
        >>> get_framework_drivers('cisco_ios')
        {
            'scrapli': 'cisco_iosxe',
            'napalm': 'ios',
            'nornir': 'cisco_ios',
            'ansible': 'cisco.ios.ios'
        }
    """
    return {
        'scrapli': get_scrapli_driver(device_type),
        'napalm': get_napalm_driver(device_type),
        'nornir': get_nornir_driver(device_type),
        'ansible': get_ansible_driver(device_type),
    }
