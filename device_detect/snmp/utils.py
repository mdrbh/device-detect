"""SNMP-specific utility functions."""

from typing import Optional


def sanitize_snmp_value(value) -> Optional[str]:
    """
    Extract clean string from SNMP response value.
    
    Args:
        value: Raw SNMP response value (could be OctetString, Integer, etc.)
        
    Returns:
        Clean decoded string or None
    """
    if value is None:
        return None
    
    # Check for pythonized attribute (puresnmp's decoded value)
    if hasattr(value, 'pythonize'):
        pythonized = value.pythonize()
        # If it's bytes, decode it
        if isinstance(pythonized, bytes):
            return pythonized.decode('utf-8', errors='replace')
        # Otherwise return as string
        return str(pythonized)
    
    # Fallback: if it's an OctetString with __bytes__, get the bytes content
    if hasattr(value, '__bytes__'):
        raw_bytes = bytes(value)
        # Try to decode, handling potential BER/ASN.1 encoding
        try:
            return raw_bytes.decode('utf-8', errors='replace')
        except Exception:
            return str(value)
    
    # Otherwise convert to string
    return str(value)
