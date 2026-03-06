"""
Device Detection Library

A streamlined library for automatic network device type detection using SNMP and SSH.
Focused on Cisco, OneAccess, Aruba, and HP devices.

Usage Modes:
    1. Python Module: Direct integration into Python scripts
    2. Nornir Compatible: Use with Nornir automation framework
    3. CLI: Command-line interface for standalone usage
"""

from device_detect.core import DeviceDetect
from device_detect.models import DetectionResult, SNMPData, SSHData, TimingData
from device_detect.exceptions import (
    DeviceDetectError,
    SNMPDetectionError,
    SSHDetectionError,
    TimeoutError,
    AuthenticationError,
    ConnectionError,
)
from device_detect.operations.offline import (
    detect_offline,
    detect_offline_from_dict,
    load_collected_data,
    detect_from_snmp_data,
    detect_from_ssh_data,
    calculate_offline_score
)

__version__ = "0.10.0"
__all__ = [
    "DeviceDetect",
    "DetectionResult",
    "SNMPData",
    "SSHData",
    "TimingData",
    "DeviceDetectError",
    "SNMPDetectionError",
    "SSHDetectionError",
    "TimeoutError",
    "AuthenticationError",
    "ConnectionError",
    "detect_offline",
    "detect_offline_from_dict",
    "load_collected_data",
    "detect_from_snmp_data",
    "detect_from_ssh_data",
    "calculate_offline_score",
]
