"""Cisco Viptela device detection patterns."""

import re

PATTERNS = {
    "ssh": {
        "ssh_version": [r"SSH-2\.0-Cisco-.*"],
        "cmd": "show system status",
        "search_patterns": [r"Viptela, Inc"],
        "priority": 91,
        "dispatch": "_autodetect_std",
    },
    "snmp": None,  # No SNMP pattern defined for this device type
}
