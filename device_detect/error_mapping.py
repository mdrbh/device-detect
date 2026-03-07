"""
Map third-party library exceptions to standardized error types.

This module provides centralized exception handling for puresnmp, netmiko,
and paramiko libraries, converting library-specific exceptions into
user-friendly error messages with categorization.
"""

from typing import Tuple, Dict, Any, Optional
from datetime import datetime
import logging
import socket
import traceback

# Import third-party exceptions with graceful fallback
try:
    from puresnmp.exc import (
        Timeout as PureSNMPTimeout,
        NoSuchOID,
        ErrorResponse as SNMPErrorResponse,
        SnmpError,
        EmptyMessage,
    )
    PURESNMP_AVAILABLE = True
except ImportError:
    PURESNMP_AVAILABLE = False
    PureSNMPTimeout = None
    NoSuchOID = None
    SNMPErrorResponse = None
    SnmpError = None
    EmptyMessage = None

try:
    from netmiko.exceptions import (
        NetmikoTimeoutException,
        NetmikoAuthenticationException,
        ReadTimeout,
        ConfigInvalidException,
        ConnectionException as NetmikoConnectionException,
    )
    NETMIKO_AVAILABLE = True
except ImportError:
    NETMIKO_AVAILABLE = False
    NetmikoTimeoutException = None
    NetmikoAuthenticationException = None
    ReadTimeout = None
    ConfigInvalidException = None
    NetmikoConnectionException = None

try:
    from paramiko.ssh_exception import (
        SSHException,
        AuthenticationException as ParamikoAuthException,
        BadAuthenticationType,
        PartialAuthentication,
        ChannelException,
        BadHostKeyException,
        NoValidConnectionsError,
    )
    PARAMIKO_AVAILABLE = True
except ImportError:
    PARAMIKO_AVAILABLE = False
    SSHException = None
    ParamikoAuthException = None
    BadAuthenticationType = None
    PartialAuthentication = None
    ChannelException = None
    BadHostKeyException = None
    NoValidConnectionsError = None

logger = logging.getLogger(__name__)

# Error type constants
ERROR_TYPE_TIMEOUT = "TimeoutError"
ERROR_TYPE_AUTHENTICATION = "AuthenticationError"
ERROR_TYPE_CONNECTION = "ConnectionError"
ERROR_TYPE_INVALID_CREDENTIALS = "InvalidCredentialsError"
ERROR_TYPE_HOST_KEY = "HostKeyError"
ERROR_TYPE_SNMP_ERROR = "SNMPError"
ERROR_TYPE_NO_DATA = "NoDataError"
ERROR_TYPE_UNEXPECTED = "UnexpectedError"


def map_exception_to_error(exception: Exception) -> Tuple[str, str, Dict[str, Any]]:
    """
    Map a third-party library exception to standardized error format.
    
    Args:
        exception: The caught exception
        
    Returns:
        Tuple of (error_message, error_type, error_details)
        
    Example:
        >>> try:
        ...     # some netmiko operation
        ... except Exception as e:
        ...     msg, err_type, details = map_exception_to_error(e)
        ...     # Use in DetectionResult
    """
    error_details: Dict[str, Any] = {
        "original_exception": type(exception).__name__,
        "library": None,
    }
    
    # PureSNMP exceptions
    if PURESNMP_AVAILABLE:
        if isinstance(exception, PureSNMPTimeout):
            error_details["library"] = "puresnmp"
            return (
                f"SNMP request timed out: {exception}",
                ERROR_TYPE_TIMEOUT,
                error_details
            )
        
        if isinstance(exception, NoSuchOID):
            error_details["library"] = "puresnmp"
            error_details["oid"] = str(exception)
            return (
                f"SNMP OID not found on device: {exception}",
                ERROR_TYPE_NO_DATA,
                error_details
            )
        
        if isinstance(exception, SNMPErrorResponse):
            error_details["library"] = "puresnmp"
            return (
                f"SNMP error response from device: {exception}",
                ERROR_TYPE_SNMP_ERROR,
                error_details
            )
        
        if isinstance(exception, (SnmpError, EmptyMessage)):
            error_details["library"] = "puresnmp"
            return (
                f"SNMP protocol error: {exception}",
                ERROR_TYPE_SNMP_ERROR,
                error_details
            )
    
    # Netmiko exceptions
    if NETMIKO_AVAILABLE:
        if isinstance(exception, NetmikoAuthenticationException):
            error_details["library"] = "netmiko"
            return (
                f"SSH authentication failed: {exception}",
                ERROR_TYPE_AUTHENTICATION,
                error_details
            )
        
        if isinstance(exception, (NetmikoTimeoutException, ReadTimeout)):
            error_details["library"] = "netmiko"
            return (
                f"SSH operation timed out: {exception}",
                ERROR_TYPE_TIMEOUT,
                error_details
            )
        
        if isinstance(exception, NetmikoConnectionException):
            error_details["library"] = "netmiko"
            return (
                f"SSH connection failed: {exception}",
                ERROR_TYPE_CONNECTION,
                error_details
            )
    
    # Paramiko exceptions
    if PARAMIKO_AVAILABLE:
        if isinstance(exception, ParamikoAuthException):
            error_details["library"] = "paramiko"
            return (
                f"SSH authentication failed: {exception}",
                ERROR_TYPE_AUTHENTICATION,
                error_details
            )
        
        if isinstance(exception, (BadAuthenticationType, PartialAuthentication)):
            error_details["library"] = "paramiko"
            return (
                f"SSH authentication method not supported: {exception}",
                ERROR_TYPE_INVALID_CREDENTIALS,
                error_details
            )
        
        if isinstance(exception, BadHostKeyException):
            error_details["library"] = "paramiko"
            return (
                f"SSH host key verification failed: {exception}",
                ERROR_TYPE_HOST_KEY,
                error_details
            )
        
        if isinstance(exception, NoValidConnectionsError):
            error_details["library"] = "paramiko"
            return (
                f"SSH connection failed - no valid connections: {exception}",
                ERROR_TYPE_CONNECTION,
                error_details
            )
        
        if isinstance(exception, (SSHException, ChannelException)):
            error_details["library"] = "paramiko"
            return (
                f"SSH protocol error: {exception}",
                ERROR_TYPE_CONNECTION,
                error_details
            )
    
    # Socket exceptions (used by both paramiko and puresnmp)
    if isinstance(exception, socket.timeout):
        error_details["library"] = "socket"
        return (
            f"Network timeout: {exception}",
            ERROR_TYPE_TIMEOUT,
            error_details
        )
    
    if isinstance(exception, (socket.error, OSError)):
        error_details["library"] = "socket"
        return (
            f"Network error: {exception}",
            ERROR_TYPE_CONNECTION,
            error_details
        )
    
    # Unknown exception
    return (
        f"Unexpected error: {exception}",
        ERROR_TYPE_UNEXPECTED,
        error_details
    )


def is_fatal_exception(exception: Exception) -> bool:
    """
    Determine if an exception should stop all detection attempts.
    
    Args:
        exception: The caught exception
        
    Returns:
        True if exception is fatal (should stop detection),
        False if detection can continue with other methods
        
    Example:
        >>> if is_fatal_exception(e):
        ...     # Stop all detection attempts
        ... else:
        ...     # Try fallback method
    """
    # NoSuchOID is not fatal - just means device doesn't have that OID
    if PURESNMP_AVAILABLE and isinstance(exception, NoSuchOID):
        return False
    
    # Timeouts are not fatal - can try other methods
    if PURESNMP_AVAILABLE and isinstance(exception, PureSNMPTimeout):
        return False
    
    if NETMIKO_AVAILABLE and isinstance(exception, (NetmikoTimeoutException, ReadTimeout)):
        return False
    
    if isinstance(exception, socket.timeout):
        return False
    
    # Authentication failures are fatal for that protocol
    if NETMIKO_AVAILABLE and isinstance(exception, NetmikoAuthenticationException):
        return True
    
    if PARAMIKO_AVAILABLE and isinstance(exception, ParamikoAuthException):
        return True
    
    # Host key failures are fatal (security issue)
    if PARAMIKO_AVAILABLE and isinstance(exception, BadHostKeyException):
        return True
    
    # Default: treat as non-fatal (allow fallback)
    return False


def should_retry_on_exception(exception: Exception) -> bool:
    """
    Determine if an operation should be retried based on exception type.
    
    Args:
        exception: The caught exception
        
    Returns:
        True if operation should be retried, False otherwise
        
    Example:
        >>> if should_retry_on_exception(e):
        ...     # Retry the operation
        ... else:
        ...     # Don't retry, handle error
    """
    # Retry on timeouts and temporary network errors
    if PURESNMP_AVAILABLE and isinstance(exception, PureSNMPTimeout):
        return True
    
    if NETMIKO_AVAILABLE and isinstance(exception, (NetmikoTimeoutException, ReadTimeout)):
        return True
    
    if isinstance(exception, socket.timeout):
        return True
    
    # Don't retry on authentication failures
    if NETMIKO_AVAILABLE and isinstance(exception, NetmikoAuthenticationException):
        return False
    
    if PARAMIKO_AVAILABLE and isinstance(exception, (ParamikoAuthException, BadAuthenticationType)):
        return False
    
    # Don't retry on host key failures (security issue)
    if PARAMIKO_AVAILABLE and isinstance(exception, BadHostKeyException):
        return False
    
    # Default: don't retry
    return False


def create_error_record(
    exception: Exception,
    phase: str,
    method: str,
    severity: str = "error",
    context: Optional[Dict[str, Any]] = None,
    include_stack_trace: bool = False
) -> 'ErrorRecord':
    """
    Create ErrorRecord from exception with full context.
    
    This function converts exceptions into structured ErrorRecord objects,
    preserving all relevant information for troubleshooting and logging.
    
    Args:
        exception: Caught exception
        phase: Detection phase (e.g., "snmp_detect", "ssh_connect", "ssh_verify")
        method: Detection method ("snmp" or "ssh")
        severity: Error severity ("error" or "warning")
        context: Additional context dict (command, OID, timeout, etc.)
        include_stack_trace: Include stack trace (when DEBUG logging enabled)
        
    Returns:
        ErrorRecord with all details populated
        
    Example:
        >>> try:
        ...     # SNMP operation
        ... except Exception as e:
        ...     error_rec = create_error_record(
        ...         e, "snmp_detect", "snmp",
        ...         context={"oid": "1.3.6.1.2.1.1.1.0"},
        ...         include_stack_trace=log_level == "DEBUG"
        ...     )
    """
    from device_detect.models import ErrorRecord
    
    # Map exception to standardized format
    message, error_type, error_details = map_exception_to_error(exception)
    
    # Create timestamp
    timestamp = datetime.now().isoformat()
    
    # Extract exception class name
    exception_class = type(exception).__name__
    
    # Get library from error_details
    library = error_details.get("library")
    
    # Merge context with error_details
    full_context = context.copy() if context else {}
    # Add original exception details to context
    for key, value in error_details.items():
        if key not in full_context and key != "library":
            full_context[key] = value
    
    # Capture stack trace if requested
    stack_trace = None
    if include_stack_trace:
        stack_trace = traceback.format_exc()
    
    return ErrorRecord(
        timestamp=timestamp,
        phase=phase,
        method=method,
        severity=severity,
        error_type=error_type,
        message=message,
        library=library,
        exception_class=exception_class,
        context=full_context if full_context else None,
        stack_trace=stack_trace
    )
