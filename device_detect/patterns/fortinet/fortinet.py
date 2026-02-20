"""Fortinet device detection patterns."""

import re

PATTERNS = {
    "ssh": {
        "ssh_version": [r"SSH-2\.0-.*"],
        "cmd": "get system status",
        "search_patterns": [r"FortiGate", r"FortiOS"],
        "priority": 80,
        "dispatch": "_autodetect_std",
    },
    "snmp": {
        "oid": "1.3.6.1.2.1.1.1.0",
        "expr": re.compile(r"Forti.*", re.IGNORECASE),
        "priority": 80,
    },
}
