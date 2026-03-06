"""
Offline device detection using pre-collected data.
Performs pattern matching on SNMP/SSH data from JSON files without network calls.
"""

import json
import logging
import re
from typing import Optional, Dict, Tuple
from pathlib import Path
from datetime import datetime

from device_detect.models import SNMPData, SSHData, DetectionResult, TimingData
from device_detect.patterns import SNMP_MAPPER_DICT, SSH_MAPPER_DICT, DEVICE_TYPE_ALIASES
from device_detect.mapper import get_framework_drivers

logger = logging.getLogger(__name__)


def detect_offline(json_file_path: str) -> DetectionResult:
    """
    Perform offline detection from a JSON file.
    
    Args:
        json_file_path: Path to JSON file with collected data
        
    Returns:
        DetectionResult with offline detection results
    """
    data = load_collected_data(json_file_path)
    return detect_offline_from_dict(data)


def detect_offline_from_dict(data: dict) -> DetectionResult:
    """
    Perform offline detection from a data dictionary.
    
    Args:
        data: Dictionary containing collected SNMP/SSH data
        
    Returns:
        DetectionResult with offline detection results
    """
    start_time = datetime.now()
    hostname = data.get('hostname', 'unknown')
    
    # Parse SNMP data if present
    snmp_data = None
    snmp_data_dict = data.get('snmp_data')
    if snmp_data_dict:
        snmp_data = SNMPData(**snmp_data_dict)
    
    # Parse SSH data if present
    ssh_data = None
    ssh_data_dict = data.get('ssh_data')
    if ssh_data_dict:
        ssh_data = SSHData(**ssh_data_dict)
    
    # Perform pattern matching
    snmp_result, snmp_matches = detect_from_snmp_data(snmp_data)
    ssh_result, ssh_matches = detect_from_ssh_data(ssh_data)
    
    # Determine final result
    final_result = None
    method = None
    
    if snmp_result and ssh_result:
        method = "SNMP+SSH"
        if snmp_result == ssh_result:
            final_result = snmp_result
        else:
            # Prefer SSH result when there's a mismatch
            final_result = ssh_result
    elif ssh_result:
        method = "SSH"
        final_result = ssh_result
    elif snmp_result:
        method = "SNMP"
        final_result = snmp_result
    
    # Calculate score
    score = calculate_offline_score(
        snmp_match=snmp_result is not None,
        ssh_match=ssh_result is not None,
        matches_agree=(snmp_result == ssh_result if snmp_result and ssh_result else False)
    )
    
    # Get framework mappings
    framework_mappings = {}
    if final_result:
        mappings = get_framework_drivers(final_result)
        framework_mappings = {
            'scrapli_driver': mappings.get('scrapli'),
            'napalm_driver': mappings.get('napalm'),
            'nornir_driver': mappings.get('nornir'),
            'ansible_driver': mappings.get('ansible')
        }
    
    # Calculate timing
    end_time = datetime.now()
    total_seconds = (end_time - start_time).total_seconds()
    
    return DetectionResult(
        hostname=hostname,
        operation_mode="offline",
        method=method,
        success=final_result is not None,
        device_type=final_result,
        score=score,
        snmp_data=snmp_data,
        ssh_data=ssh_data,
        timing=TimingData(
            total_seconds=total_seconds,
            phase_timings={}
        ),
        **framework_mappings
    )


def load_collected_data(json_file_path: str) -> dict:
    """
    Load and validate collected data from JSON file.
    
    Args:
        json_file_path: Path to JSON file containing DetectionResult data
        
    Returns:
        Parsed dictionary from JSON file
        
    Raises:
        FileNotFoundError: If file doesn't exist
        ValueError: If JSON is invalid or missing required fields
    """
    file_path = Path(json_file_path)
    
    if not file_path.exists():
        raise FileNotFoundError(f"JSON file not found: {json_file_path}")
    
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
    except json.JSONDecodeError as e:
        raise ValueError(f"Invalid JSON file: {e}")
    
    # Handle both single object and array formats
    if isinstance(data, list):
        if len(data) == 0:
            raise ValueError("JSON array is empty")
        if len(data) > 1:
            raise ValueError(f"JSON contains multiple results ({len(data)}). Use --input-dir for batch offline detection of multi-host collection files.")
        # Extract single object from array
        data = data[0]
    
    # Validate structure
    if not isinstance(data, dict):
        raise ValueError("JSON root must be an object/dictionary or array with single object")
    
    if 'hostname' not in data:
        raise ValueError("JSON missing required field: 'hostname'")
    
    logger.debug(f"Loaded collected data from {json_file_path}")
    return data


def detect_from_snmp_data(snmp_data: SNMPData) -> Tuple[Optional[str], Dict[str, int]]:
    """
    Perform SNMP pattern matching on collected data.
    
    Args:
        snmp_data: SNMPData object with sys_descr, sys_object_id, etc.
        
    Returns:
        Tuple of (best_match, potential_matches_dict)
        best_match is None if no patterns matched
    """
    if not snmp_data or not snmp_data.sys_descr:
        logger.debug("No SNMP sys_descr available for pattern matching")
        return None, {}
    
    sys_descr = snmp_data.sys_descr
    potential_matches: Dict[str, int] = {}
    
    logger.debug(f"Matching SNMP sys_descr: {sys_descr}")
    
    # Match against SNMP patterns
    for device_type, config in SNMP_MAPPER_DICT.items():
        expr = config["expr"]
        priority = config["priority"]
        
        if expr.search(sys_descr):
            potential_matches[device_type] = priority
            logger.debug(f"SNMP match: {device_type} (priority {priority})")
    
    if not potential_matches:
        logger.debug("No SNMP pattern matches found")
        return None, {}
    
    # Get best match
    best_match = max(potential_matches.items(), key=lambda t: t[1])[0]
    logger.debug(f"Best SNMP match: {best_match}")
    
    return best_match, potential_matches


def detect_from_ssh_data(ssh_data: SSHData) -> Tuple[Optional[str], Dict[str, int]]:
    """
    Perform SSH pattern matching on collected data.
    
    Args:
        ssh_data: SSHData object with banner, prompt, detection_commands, etc.
        
    Returns:
        Tuple of (best_match, potential_matches_dict)
        best_match is None if no patterns matched
    """
    if not ssh_data:
        logger.debug("No SSH data available for pattern matching")
        return None, {}
    
    potential_matches: Dict[str, int] = {}
    
    logger.debug("Starting SSH pattern matching on collected data")
    
    # Match against SSH patterns
    for device_type, config in SSH_MAPPER_DICT.items():
        dispatch_method = config.get("dispatch")
        priority = config.get("priority", 99)
        
        # Match based on dispatch method type
        if dispatch_method == "_autodetect_std":
            # Standard pattern matching on command outputs
            cmd = config.get("cmd", "")
            search_patterns = config.get("search_patterns", [])
            
            if cmd and search_patterns and ssh_data.detection_commands:
                output = ssh_data.detection_commands.get(cmd, "")
                if _match_patterns(output, search_patterns):
                    potential_matches[device_type] = priority
                    logger.debug(f"SSH match: {device_type} (priority {priority})")
        
        elif dispatch_method == "_autodetect_remote_version":
            # Match on SSH server version
            search_patterns = config.get("search_patterns", [])
            if search_patterns and ssh_data.ssh_version:
                if _match_patterns(ssh_data.ssh_version, search_patterns):
                    potential_matches[device_type] = priority
                    logger.debug(f"SSH version match: {device_type} (priority {priority})")
        
        elif dispatch_method == "_autodetect_multi":
            # Multi-command matching (all must match)
            commands = config.get("commands", [])
            if commands and ssh_data.detection_commands:
                all_matched = True
                for cmd_dict in commands:
                    cmd = cmd_dict.get("cmd", "")
                    search_patterns = cmd_dict.get("search_patterns", [])
                    output = ssh_data.detection_commands.get(cmd, "")
                    
                    if not _match_patterns(output, search_patterns):
                        all_matched = False
                        break
                
                if all_matched:
                    potential_matches[device_type] = priority
                    logger.debug(f"SSH multi-match: {device_type} (priority {priority})")
    
    if not potential_matches:
        logger.debug("No SSH pattern matches found")
        return None, {}
    
    # Get best match and apply aliases
    best_match = max(potential_matches.items(), key=lambda t: t[1])[0]
    
    # Apply device type aliases
    if best_match in DEVICE_TYPE_ALIASES:
        original = best_match
        best_match = DEVICE_TYPE_ALIASES[best_match]
        logger.debug(f"Applied alias: {original} -> {best_match}")
    
    logger.debug(f"Best SSH match: {best_match}")
    return best_match, potential_matches


def _match_patterns(text: str, patterns: list, flags: int = re.IGNORECASE) -> bool:
    """
    Check if text matches any of the provided regex patterns.
    
    Args:
        text: Text to search in
        patterns: List of regex pattern strings
        flags: Regex flags (default: case-insensitive)
        
    Returns:
        True if any pattern matches, False otherwise
    """
    if not text or not patterns:
        return False
    
    for pattern in patterns:
        try:
            if re.search(pattern, text, flags=flags):
                return True
        except re.error as e:
            logger.warning(f"Invalid regex pattern '{pattern}': {e}")
    
    return False


def calculate_offline_score(snmp_match: bool, ssh_match: bool, matches_agree: bool) -> int:
    """
    Calculate confidence score for offline detection.
    
    Args:
        snmp_match: Whether SNMP pattern matched
        ssh_match: Whether SSH pattern matched
        matches_agree: Whether both methods agree on device_type
        
    Returns:
        Confidence score (0-100)
    """
    if snmp_match and ssh_match:
        if matches_agree:
            return 99  # Both methods agree
        else:
            return 70  # Both matched but disagree
    elif ssh_match:
        return 85  # SSH only
    elif snmp_match:
        return 75  # SNMP only
    else:
        return 0  # No match