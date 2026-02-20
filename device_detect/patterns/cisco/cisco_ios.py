"""Cisco IOS device detection patterns."""

import re

PATTERNS = {
    "ssh": {
        "ssh_version": [r"SSH-2\.0-Cisco-.*"],
        "cmd": "show version",
        "search_patterns": [
            "Cisco IOS Software",
            "Cisco Internetwork Operating System Software",
        ],
        "priority": 98,
        "dispatch": "_autodetect_std",
    },
    "snmp": {
        "oid": "1.3.6.1.2.1.1.1.0",
        "expr": re.compile(r".*Cisco IOS Software.*,.*", re.IGNORECASE),
        "priority": 90,
    },
}
