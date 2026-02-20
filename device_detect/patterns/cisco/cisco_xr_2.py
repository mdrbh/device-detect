"""Cisco IOS XR (alternative detection) device detection patterns."""

import re

PATTERNS = {
    "ssh": {
        "ssh_version": [r"SSH-2\.0-Cisco-.*"],
        "cmd": "show version brief",
        "search_patterns": [r"Cisco IOS XR"],
        "priority": 92,
        "dispatch": "_autodetect_std",
    },
    "snmp": None,  # No SNMP pattern defined for this device type
}
