"""HP Comware device detection patterns."""

import re

PATTERNS = {
    "ssh": {
        "ssh_version": [r"SSH-2\.0-.*Comware.*", r"SSH-2\.0-HPVSS.*"],
        "cmd": "display version",
        "search_patterns": ["HPE Comware", "HP Comware"],
        "priority": 99,
        "dispatch": "_autodetect_std",
    },
    "snmp": {
        "oid": "1.3.6.1.2.1.1.1.0",
        "expr": re.compile(r".*HP(E)? Comware.*", re.IGNORECASE),
        "priority": 99,
    },
}
