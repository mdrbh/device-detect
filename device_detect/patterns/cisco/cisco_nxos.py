"""Cisco NX-OS device detection patterns."""

import re

PATTERNS = {
    "ssh": {
        "ssh_version": [r"SSH-2\.0-Cisco-.*"],
        "cmd": "show version",
        "search_patterns": [r"Cisco Nexus Operating System", r"NX-OS"],
        "priority": 99,
        "dispatch": "_autodetect_std",
    },
    "snmp": {
        "oid": "1.3.6.1.2.1.1.1.0",
        "expr": re.compile(r".*Cisco NX-OS.*", re.IGNORECASE),
        "priority": 99,
    },
}
