"""
Input validation for DeviceDetect configuration.
Validates hostnames, credentials, and configuration parameters.
"""

import logging
from typing import Optional, Tuple

from device_detect.models import DetectionResult
from device_detect.utils import validate_hostname as utils_validate_hostname

logger = logging.getLogger(__name__)


def validate_hostname(hostname: str) -> bool:
    """
    Validate hostname format.
    
    Args:
        hostname: Target device IP or hostname
        
    Returns:
        True if valid, False otherwise
    """
    return utils_validate_hostname(hostname)


def validate_snmp_credentials(
    snmp_version: int,
    snmp_community: Optional[str],
    snmp_user: Optional[str]
) -> Tuple[bool, Optional[str]]:
    """
    Validate SNMP credentials based on version.
    
    Args:
        snmp_version: SNMP version (1, 2, or 3)
        snmp_community: SNMP community string (v1/v2c)
        snmp_user: SNMPv3 username
        
    Returns:
        Tuple of (is_valid, error_message)
    """
    if snmp_version in [1, 2]:
        if snmp_community:
            return True, None
        return False, f"SNMPv{snmp_version} requires community string"
    
    elif snmp_version == 3:
        if snmp_user:
            return True, None
        return False, "SNMPv3 requires username"
    
    return False, f"Invalid SNMP version: {snmp_version}"


def validate_ssh_credentials(
    ssh_username: Optional[str],
    ssh_password: Optional[str]
) -> Tuple[bool, Optional[str]]:
    """
    Validate SSH credentials.
    
    Args:
        ssh_username: SSH username
        ssh_password: SSH password
        
    Returns:
        Tuple of (is_valid, error_message)
    """
    if ssh_username and ssh_password:
        return True, None
    
    if not ssh_username:
        return False, "SSH username required"
    if not ssh_password:
        return False, "SSH password required"
    
    return False, "SSH credentials incomplete"


def validate_config(
    hostname: str,
    snmp_version: int,
    snmp_community: Optional[str],
    snmp_user: Optional[str],
    ssh_username: Optional[str],
    ssh_password: Optional[str]
) -> Tuple[bool, Optional[DetectionResult]]:
    """
    Complete configuration validation.
    
    Validates hostname and ensures at least one detection method
    (SNMP or SSH) has valid credentials.
    
    Args:
        hostname: Target device IP or hostname
        snmp_version: SNMP version
        snmp_community: SNMP community string
        snmp_user: SNMPv3 username
        ssh_username: SSH username
        ssh_password: SSH password
        
    Returns:
        Tuple of (is_valid, error_result)
        If valid: (True, None)
        If invalid: (False, DetectionResult with error details)
    """
    # Validate hostname
    if not validate_hostname(hostname):
        return False, DetectionResult(
            hostname=hostname,
            operation_mode="detect",
            method=None,
            success=False,
            device_type=None,
            score=0,
            error=f"Invalid hostname: {hostname}",
            error_type="ConfigurationError",
            error_details={"hostname": hostname, "reason": "Hostname validation failed"}
        )
    
    # Check SNMP credentials
    snmp_valid, snmp_error = validate_snmp_credentials(snmp_version, snmp_community, snmp_user)
    
    # Check SSH credentials
    ssh_valid, ssh_error = validate_ssh_credentials(ssh_username, ssh_password)
    
    # At least one method must be available
    if not snmp_valid and not ssh_valid:
        return False, DetectionResult(
            hostname=hostname,
            operation_mode="detect",
            method=None,
            success=False,
            device_type=None,
            score=0,
            error="No valid credentials provided - need either SNMP or SSH credentials",
            error_type="ConfigurationError",
            error_details={
                "snmp_available": snmp_valid,
                "ssh_available": ssh_valid,
                "snmp_error": snmp_error,
                "ssh_error": ssh_error,
                "reason": "At least one detection method (SNMP or SSH) must have valid credentials"
            }
        )
    
    # Validation passed
    return True, None