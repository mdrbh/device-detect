"""Cisco WLC device detection patterns."""

import re

PATTERNS = {
    "ssh": {
        "ssh_version": [r"SSH-2\.0-.*CISCO_WLC.*"],
        "cmd": "",
        "dispatch": "_autodetect_remote_version",
        "search_patterns": [r"CISCO_WLC"],
        "priority": 97,
    },
    "snmp": {
        "oid": "1.3.6.1.2.1.1.1.0",
        "expr": re.compile(r".*Cisco Controller.*", re.IGNORECASE),
        "priority": 99,
    },
}
