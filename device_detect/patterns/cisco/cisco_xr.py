"""Cisco IOS XR device detection patterns."""

import re

PATTERNS = {
    "ssh": {
        "ssh_version": [r"SSH-2\.0-Cisco-.*"],
        "cmd": "show version",
        "search_patterns": [r"Cisco IOS XR"],
        "priority": 95,
        "dispatch": "_autodetect_std",
    },
    "snmp": {
        "oid": "1.3.6.1.2.1.1.1.0",
        "expr": re.compile(r".*Cisco IOS XR Software.*", re.IGNORECASE),
        "priority": 99,
    },
}
