"""
Result building and error handling utilities.
Handles score calculation and DetectionResult construction.
"""

import logging
from typing import Optional, List
from datetime import datetime

from device_detect.models import DetectionResult, SNMPData, SSHData, TimingData, ErrorRecord
from device_detect.mapper import get_framework_drivers

logger = logging.getLogger(__name__)


def calculate_detection_score(
    final_result: Optional[str],
    snmp_result: Optional[str],
    ssh_result: Optional[str],
    ssh_verification_attempted: bool,
    ssh_verification_success: Optional[bool]
) -> int:
    """
    Calculate detection confidence score based on detection results.
    
    Args:
        final_result: Final detected device type
        snmp_result: SNMP detection result
        ssh_result: SSH detection result
        ssh_verification_attempted: Whether SSH verification was attempted
        ssh_verification_success: Whether SSH verification succeeded
        
    Returns:
        Confidence score (0-100)
    """
    if not final_result:
        return 0
    
    # SNMP + SSH verification succeeded (highest confidence)
    if ssh_verification_attempted and ssh_verification_success:
        return 99
    
    # Both SNMP and SSH detected same device (no verification mode)
    if snmp_result and ssh_result and snmp_result == ssh_result:
        return 99
    
    # Only SNMP detected
    if snmp_result and not ssh_result:
        return 75
    
    # Only SSH detected
    if ssh_result and not snmp_result:
        return 85
    
    # SNMP + SSH verification failed, then SSH autodetect (using SSH result)
    if ssh_verification_attempted and not ssh_verification_success:
        return 70
    
    # SNMP and SSH detected different devices (using SSH result)
    if snmp_result and ssh_result:
        return 70
    
    return 50




def determine_method(snmp_data: Optional[SNMPData], ssh_data: Optional[SSHData]) -> Optional[str]:
    """
    Determine the detection/collection method based on collected data.
    
    Args:
        snmp_data: SNMP data object (if collected)
        ssh_data: SSH data object (if collected)
        
    Returns:
        Method string: 'SNMP', 'SSH', 'SNMP+SSH', or None
    """
    has_snmp = snmp_data is not None
    has_ssh = ssh_data is not None
    
    if has_snmp and has_ssh:
        return "SNMP+SSH"
    elif has_snmp:
        return "SNMP"
    elif has_ssh:
        return "SSH"
    else:
        return None


def get_framework_mappings(device_type: Optional[str]) -> dict:
    """
    Get framework driver mappings for a device type.
    
    Args:
        device_type: Device type to map (e.g., 'cisco_ios')
        
    Returns:
        Dictionary with framework driver fields
    """
    if not device_type:
        return {
            'scrapli_driver': None,
            'napalm_driver': None,
            'nornir_driver': None,
            'ansible_driver': None
        }
    
    mappings = get_framework_drivers(device_type)
    return {
        'scrapli_driver': mappings.get('scrapli'),
        'napalm_driver': mappings.get('napalm'),
        'nornir_driver': mappings.get('nornir'),
        'ansible_driver': mappings.get('ansible')
    }


def build_detection_result(
    hostname: str,
    final_result: Optional[str],
    snmp_result: Optional[str],
    ssh_result: Optional[str],
    snmp_data: Optional[SNMPData],
    ssh_data: Optional[SSHData],
    ssh_verification_attempted: bool,
    ssh_verification_success: Optional[bool],
    verification_notes: Optional[str],
    error_records: List[ErrorRecord],
    start_time: datetime,
    phase_timings: dict
) -> DetectionResult:
    """
    Build complete DetectionResult for detect operation.
    
    Args:
        hostname: Target hostname
        final_result: Final detected device type
        snmp_result: SNMP detection result
        ssh_result: SSH detection result
        snmp_data: Collected SNMP data
        ssh_data: Collected SSH data
        ssh_verification_attempted: Whether SSH verification was attempted
        ssh_verification_success: Whether SSH verification succeeded
        verification_notes: Notes about verification
        error_records: List of ErrorRecord objects
        start_time: Operation start time
        phase_timings: Dictionary of phase timings
        
    Returns:
        Complete DetectionResult object
    """
    # Calculate timing
    end_time = datetime.now()
    total_seconds = (end_time - start_time).total_seconds()
    
    # Calculate score
    score = calculate_detection_score(
        final_result, snmp_result, ssh_result,
        ssh_verification_attempted, ssh_verification_success
    )
    
    # Determine method
    method = determine_method(snmp_data, ssh_data)
    
    # Determine success
    success = final_result is not None
    
    # Get framework mappings
    framework_mappings = get_framework_mappings(final_result)
    
    return DetectionResult(
        hostname=hostname,
        operation_mode="detect",
        method=method,
        success=success,
        device_type=final_result,
        score=score,
        snmp_data=snmp_data,
        ssh_data=ssh_data,
        timing=TimingData(
            total_seconds=total_seconds,
            phase_timings=phase_timings
        ),
        ssh_verification_attempted=ssh_verification_attempted,
        ssh_verification_success=ssh_verification_success,
        verification_notes=verification_notes,
        error_records=error_records,
        **framework_mappings
    )


def build_collection_result(
    hostname: str,
    snmp_data: Optional[SNMPData],
    ssh_data: Optional[SSHData],
    error_records: List[ErrorRecord],
    start_time: datetime,
    phase_timings: dict
) -> DetectionResult:
    """
    Build DetectionResult for collect operation.
    
    Args:
        hostname: Target hostname
        snmp_data: Collected SNMP data
        ssh_data: Collected SSH data
        error_records: List of ErrorRecord objects
        start_time: Operation start time
        phase_timings: Dictionary of phase timings
        
    Returns:
        DetectionResult object for collection mode
    """
    # Calculate timing
    end_time = datetime.now()
    total_seconds = (end_time - start_time).total_seconds()
    
    # Determine success (if we collected any data)
    success = snmp_data is not None or ssh_data is not None
    
    # Determine method
    method = determine_method(snmp_data, ssh_data)
    
    return DetectionResult(
        hostname=hostname,
        operation_mode="collect",
        method=method,
        success=success,
        device_type=None,  # No detection in collection mode
        score=0,  # No score in collection mode
        snmp_data=snmp_data,
        ssh_data=ssh_data,
        timing=TimingData(
            total_seconds=total_seconds,
            phase_timings=phase_timings
        ),
        error_records=error_records
    )
