"""Aruba AOS-CX device detection patterns."""

import re

PATTERNS = {
    "ssh": {
        "ssh_version": [r"SSH-2\.0-OpenSSH.*"],
        "cmd": "show version",
        "search_patterns": [r"ArubaOS-CX"],
        "priority": 99,
        "dispatch": "_autodetect_std",
    },
    "snmp": {
        "oid": "1.3.6.1.2.1.1.1.0",
        "expr": re.compile(r"aruba.*cx|arubaos-cx", re.IGNORECASE),
        "priority": 99,
    },
}
