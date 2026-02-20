"""
Helper functions and utilities for device detection.
"""

import functools
import logging
import signal
from typing import Any, Callable, Optional

from device_detect.exceptions import TimeoutError

logger = logging.getLogger(__name__)


def timeout_decorator(seconds: int):
    """
    Decorator to add timeout to a function.
    
    Args:
        seconds: Maximum time in seconds for function execution
        
    Raises:
        TimeoutError: If function execution exceeds timeout
    """
    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            def timeout_handler(signum, frame):
                raise TimeoutError(f"Function {func.__name__} timed out after {seconds} seconds")
            
            # Set the signal handler and alarm
            old_handler = signal.signal(signal.SIGALRM, timeout_handler)
            signal.alarm(seconds)
            
            try:
                result = func(*args, **kwargs)
            finally:
                # Disable the alarm and restore old handler
                signal.alarm(0)
                signal.signal(signal.SIGALRM, old_handler)
            
            return result
        return wrapper
    return decorator


def validate_hostname(hostname: str) -> bool:
    """
    Validate hostname or IP address format.
    
    Args:
        hostname: Hostname or IP address to validate
        
    Returns:
        True if valid, False otherwise
    """
    if not hostname or not isinstance(hostname, str):
        return False
    
    # Basic validation - not empty and reasonable length
    if len(hostname) < 1 or len(hostname) > 255:
        return False
    
    return True


def validate_snmp_version(version: int) -> bool:
    """
    Validate SNMP version.
    
    Args:
        version: SNMP version (1, 2, or 3)
        
    Returns:
        True if valid, False otherwise
    """
    return version in [1, 2, 3]


def setup_logging(log_level: str = "INFO") -> None:
    """
    Setup logging configuration.
    
    Args:
        log_level: Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
    """
    numeric_level = getattr(logging, log_level.upper(), None)
    if not isinstance(numeric_level, int):
        raise ValueError(f"Invalid log level: {log_level}")
    
    logging.basicConfig(
        level=numeric_level,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )


def sanitize_output(output: str) -> str:
    """
    Sanitize command output by removing backspaces and control characters.
    
    Args:
        output: Raw command output
        
    Returns:
        Sanitized output string
    """
    if not output:
        return output
    
    # Remove backspace characters and what they delete
    while '\x08' in output:
        # Find backspace
        pos = output.find('\x08')
        if pos > 0:
            # Remove the character before backspace and the backspace itself
            output = output[:pos-1] + output[pos+1:]
        else:
            # Just remove the backspace if at start
            output = output[1:]
    
    # Remove other common control characters
    control_chars = ['\x00', '\x01', '\x02', '\x03', '\x04', '\x05', '\x06', '\x07',
                     '\x0b', '\x0c', '\x0e', '\x0f', '\x10', '\x11', '\x12', '\x13',
                     '\x14', '\x15', '\x16', '\x17', '\x18', '\x19', '\x1a', '\x1b',
                     '\x1c', '\x1d', '\x1e', '\x1f', '\x7f']
    
    for char in control_chars:
        output = output.replace(char, '')
    
    return output
