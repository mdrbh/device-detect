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

__version__ = "0.7.0"
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
]
