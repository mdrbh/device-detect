"""
Constants and configuration defaults for device detection.
"""

# Timeout configurations (in seconds)
SNMP_TIMEOUT = 2
SSH_CONNECTION_TIMEOUT = 10
SSH_COMMAND_TIMEOUT = 5
OVERALL_TIMEOUT = 30

# SSH autodetect specific settings - NORMAL profile (default)
SSH_POST_CONNECTION_DELAY = 1.5  # Seconds to wait after SSH connection for login to complete
SSH_CHANNEL_READ_TIMING = 3.0  # Last read timing for channel read operations
SSH_COMMAND_DELAY = 0.5  # Delay after sending command before reading response

# SSH Timing Profiles - configurable via ssh_timing_profile parameter
SSH_TIMING_PROFILES = {
    "fast": {
        "post_connection_delay": 1.0,
        "channel_read_timing": 2.0,
        "command_delay": 0.3,
        "read_interval": 0.3,  # How often to check for new data
        "max_wait": 10,  # Maximum seconds to wait for command completion
    },
    "normal": {
        "post_connection_delay": 1.5,
        "channel_read_timing": 3.0,
        "command_delay": 0.5,
        "read_interval": 0.5,
        "max_wait": 15,
    },
    "slow": {
        "post_connection_delay": 3.0,
        "channel_read_timing": 6.0,
        "command_delay": 1.0,
        "read_interval": 1.0,
        "max_wait": 20,
    },
}

# Default timing profile
DEFAULT_SSH_TIMING_PROFILE = "fast"

# Adaptive retry settings
SSH_ADAPTIVE_RETRY_ENABLED = True
SSH_MAX_RETRIES = 2  # Maximum retries for incomplete responses

# Global settings
GLOBAL_CMD_VERIFY = False  # Disable command verification for autodetect

# Priority vendors to focus detection on
PRIORITY_VENDORS = ["cisco", "oneaccess", "aruba", "hp"]

# SNMP OIDs for device identification and information
SNMP_SYS_DESCR_OID = "1.3.6.1.2.1.1.1.0"
SNMP_SYS_OBJECT_ID_OID = "1.3.6.1.2.1.1.2.0"
SNMP_SYS_UPTIME_OID = "1.3.6.1.2.1.1.3.0"
SNMP_SYS_NAME_OID = "1.3.6.1.2.1.1.5.0"

# SNMP version defaults
SNMP_DEFAULT_VERSION = 2  # SNMPv2c

# Priority threshold for early exit (99 = highly confident match)
HIGH_CONFIDENCE_PRIORITY = 99

# Logging
DEFAULT_LOG_LEVEL = "INFO"
