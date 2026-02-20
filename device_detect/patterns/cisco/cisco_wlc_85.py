"""Cisco WLC 8.5+ device detection patterns."""

import re

PATTERNS = {
    "ssh": {
        "ssh_version": [r"SSH-2\.0-Cisco-.*"],
        "cmd": "show inventory",
        "dispatch": "_autodetect_std",
        "search_patterns": [r"Cisco.*Wireless.*Controller"],
        "priority": 96,
    },
    "snmp": None,  # No SNMP pattern defined for this device type
}
