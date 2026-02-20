"""Aruba ProCurve device detection patterns."""

import re

PATTERNS = {
    "ssh": {
        "ssh_version": [r"SSH-2\.0-Mocana SSH.*"],
        "commands": [
            {
                "cmd": "show version",
                "search_patterns": [r"Image stamp.*/code/build"],
            },
            {
                "cmd": "show dhcp client vendor-specific",
                "search_patterns": [r"Aruba"],
            }
        ],
        "priority": 99,
        "dispatch": "_autodetect_multi",
    },
    "snmp": {
        "oid": "1.3.6.1.2.1.1.1.0",
        "expr": re.compile(r"aruba.*revision.*rom.*/code/build", re.IGNORECASE | re.DOTALL),
        "priority": 99,
    },
}
