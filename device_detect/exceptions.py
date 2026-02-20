"""
Custom exception classes for device detection.
"""


class DeviceDetectError(Exception):
    """Base exception for all device detection errors."""
    pass


class SNMPDetectionError(DeviceDetectError):
    """Raised when SNMP detection fails."""
    pass


class SSHDetectionError(DeviceDetectError):
    """Raised when SSH detection fails."""
    pass


class TimeoutError(DeviceDetectError):
    """Raised when a detection operation times out."""
    pass


class AuthenticationError(DeviceDetectError):
    """Raised when authentication fails."""
    pass


class ConnectionError(DeviceDetectError):
    """Raised when connection to device fails."""
    pass
