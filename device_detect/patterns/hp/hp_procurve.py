"""HP ProCurve device detection patterns."""

import re

PATTERNS = {
    "ssh": {
        "ssh_version": [r"SSH-2\.0-Mocana SSH.*"],
        "cmd": "show version",
        "search_patterns": [r"Image stamp.*/code/build"],
        "priority": 99,
        "dispatch": "_autodetect_std",
    },
    "snmp": {
        "oid": "1.3.6.1.2.1.1.1.0",
        "expr": re.compile(r".ProCurve", re.IGNORECASE),
        "priority": 99,
    },
}
