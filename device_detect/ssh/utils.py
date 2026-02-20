"""SSH-specific utility functions."""

import re
import logging
from typing import Dict, List, Optional

from device_detect.patterns import SSH_MAPPER_DICT

logger = logging.getLogger(__name__)


def get_ssh_mapper_base(device_types: Optional[List[str]] = None) -> List[tuple]:
    """
    Get SSH mapper sorted by command frequency for optimization.
    Devices that use the same command are grouped together to minimize
    the number of commands that need to be sent.
    
    Args:
        device_types: Optional list of device types to include. If None, includes all.
    
    Returns:
        List of tuples (device_type, config_dict) sorted by command frequency
    """
    # Filter SSH_MAPPER_DICT if device_types provided
    if device_types is not None:
        filtered_dict = {dt: cfg for dt, cfg in SSH_MAPPER_DICT.items() 
                        if dt in device_types}
    else:
        filtered_dict = SSH_MAPPER_DICT
    
    # Count command frequencies
    cmd_count: Dict[str, int] = {}
    for device_type, config in filtered_dict.items():
        # Handle both single command and multi-command patterns
        if "cmd" in config:
            # Single command pattern
            cmd = config["cmd"]
            cmd_count[cmd] = cmd_count.get(cmd, 0) + 1
        elif "commands" in config:
            # Multi-command pattern - use first command for sorting
            first_cmd = config["commands"][0]["cmd"]
            cmd_count[first_cmd] = cmd_count.get(first_cmd, 0) + 1
    
    # Sort by command frequency (most common first)
    def sort_key(item):
        config = item[1]
        if "cmd" in config:
            return cmd_count.get(config["cmd"], 0)
        elif "commands" in config:
            return cmd_count.get(config["commands"][0]["cmd"], 0)
        return 0
    
    sorted_items = sorted(
        filtered_dict.items(),
        key=sort_key,
        reverse=True
    )
    
    return sorted_items


def strip_ansi_codes(text: str) -> str:
    """
    Strip ANSI escape sequences from text.
    
    Args:
        text: Text potentially containing ANSI codes
        
    Returns:
        Clean text without ANSI codes
    """
    # Comprehensive ANSI escape sequence pattern
    # Matches CSI sequences like [232;21H, [?25h, etc.
    ansi_pattern = re.compile(
        r'\x1b\[[0-9;?]*[a-zA-Z]|'     # Standard CSI sequences (ESC[...)
        r'\x1b\][^\x07]*\x07|'         # OSC sequences (ESC]...BEL)
        r'\x1b[=>]|'                   # Other ESC sequences
        r'\[[0-9;?]*[a-zA-Z]|'         # CSI without ESC prefix (common in some devices)
        r'\[[0-9;?]*H|'                # Cursor position sequences
        r'\[[\d;]*[HfABCDEFGJKSTm]|'  # Various CSI sequences
        r'\[\?[\d;]*[hl]'              # DEC private mode
    )
    # Remove ANSI sequences
    cleaned = ansi_pattern.sub('', text)
    
    # Remove remaining control characters except newline (\n), carriage return (\r), and tab (\t)
    # Keep \n (0x0A), \r (0x0D), \t (0x09)
    cleaned = re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]', '', cleaned)
    
    # Additional cleanup for any remaining escape sequences
    cleaned = re.sub(r'\x1b.', '', cleaned)
    
    return cleaned
