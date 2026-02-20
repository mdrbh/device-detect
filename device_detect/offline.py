"""
Offline device detection using pre-collected data.
Performs pattern matching on SNMP/SSH data from JSON files without network calls.
"""

import json
import logging
import re
from typing import Optional, Dict, Tuple
from pathlib import Path

from device_detect.models import SNMPData, SSHData, DetectionResult
from device_detect.patterns import SNMP_MAPPER_DICT, SSH_MAPPER_DICT, DEVICE_TYPE_ALIASES

logger = logging.getLogger(__name__)


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
