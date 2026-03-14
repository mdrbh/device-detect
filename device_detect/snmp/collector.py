"""SNMP data collection via async operations."""

import asyncio
import logging
import socket
from typing import Optional, Tuple

try:
    from puresnmp import ObjectIdentifier
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
    ObjectIdentifier = None
    PureSNMPTimeout = None
    NoSuchOID = None
    SNMPErrorResponse = None
    SnmpError = None
    EmptyMessage = None

from device_detect.constants import (
    SNMP_SYS_DESCR_OID,
    SNMP_SYS_OBJECT_ID_OID,
    SNMP_SYS_UPTIME_OID,
    SNMP_SYS_NAME_OID,
)
from device_detect.models import SNMPData, ErrorRecord
from device_detect.snmp.utils import sanitize_snmp_value
from device_detect.snmp.client import create_snmp_client
from device_detect.error_mapping import create_error_record

logger = logging.getLogger(__name__)


async def collect_snmp_data(
    hostname: str,
    version: int,
    community: Optional[str] = None,
    user: Optional[str] = None,
    auth_proto: Optional[str] = None,
    auth_password: Optional[str] = None,
    priv_proto: Optional[str] = None,
    priv_password: Optional[str] = None,
    timeout: int = 5,
    log_level: str = "INFO",
) -> Tuple[Optional[SNMPData], Optional[ErrorRecord]]:
    """
    Collect all SNMP data using multiget (sysDescr, sysObjectID, sysUpTime, sysName).
    
    Args:
        hostname: Target device IP or hostname
        version: SNMP version (1, 2, or 3)
        community: SNMP community string (v1/v2c)
        user: SNMPv3 username
        auth_proto: SNMPv3 auth protocol
        auth_password: SNMPv3 authentication password
        priv_proto: SNMPv3 privacy protocol
        priv_password: SNMPv3 privacy password
        timeout: SNMP timeout in seconds
        log_level: Logging level (for stack trace inclusion)
        
    Returns:
        Tuple of (SNMPData object or None, ErrorRecord or None)
    """
    try:
        # Convert OID strings to ObjectIdentifiers
        oids = [
            ObjectIdentifier(SNMP_SYS_DESCR_OID),
            ObjectIdentifier(SNMP_SYS_OBJECT_ID_OID),
            ObjectIdentifier(SNMP_SYS_UPTIME_OID),
            ObjectIdentifier(SNMP_SYS_NAME_OID),
        ]
        
        # Create SNMP client (without timeout parameter - not supported in puresnmp 2.0)
        client = create_snmp_client(
            hostname=hostname,
            version=version,
            community=community,
            user=user,
            auth_proto=auth_proto,
            auth_password=auth_password,
            priv_proto=priv_proto,
            priv_password=priv_password,
        )
        
        # Execute multiget with timeout wrapper
        results = await asyncio.wait_for(client.multiget(oids), timeout=timeout)
        
        # Build SNMPData object
        snmp_data = SNMPData(
            sys_descr=sanitize_snmp_value(results[0]),
            sys_object_id=sanitize_snmp_value(results[1]),
            sys_uptime=sanitize_snmp_value(results[2]),
            sys_name=sanitize_snmp_value(results[3]),
        )
        
        # Check for empty sysDescr (edge case)
        if not snmp_data.sys_descr or snmp_data.sys_descr.strip() == "":
            logger.debug(f"[{hostname}] Empty sysDescr received from device")
            # Return data anyway, but log warning
        
        logger.debug(f"[{hostname}] SNMP data collected successfully")
        return snmp_data, None
        
    except asyncio.TimeoutError as e:
        # asyncio.wait_for raises TimeoutError, not PureSNMPTimeout
        logger.error(f"[{hostname}] SNMP collection timed out after {timeout}s")
        error_record = create_error_record(
            e,
            phase="snmp_collect",
            method="snmp",
            severity="error",
            context={"timeout": timeout, "oids": [SNMP_SYS_DESCR_OID, SNMP_SYS_OBJECT_ID_OID, SNMP_SYS_UPTIME_OID, SNMP_SYS_NAME_OID]},
            include_stack_trace=(log_level == "DEBUG")
        )
        return None, error_record
        
    except (PureSNMPTimeout, NoSuchOID, SNMPErrorResponse, SnmpError, EmptyMessage) as e:
        # PureSNMP-specific exceptions
        if isinstance(e, NoSuchOID):
            logger.warning(f"[{hostname}] SNMP OID not found: {e}")
            severity = "warning"
        else:
            logger.error(f"[{hostname}] SNMP error during collection: {e}")
            severity = "error"
            
        error_record = create_error_record(
            e,
            phase="snmp_collect",
            method="snmp",
            severity=severity,
            context={"timeout": timeout, "version": version},
            include_stack_trace=(log_level == "DEBUG")
        )
        return None, error_record
        
    except (socket.timeout, socket.error, OSError) as e:
        # Network-level exceptions
        logger.error(f"[{hostname}] Network error during SNMP collection: {e}")
        error_record = create_error_record(
            e,
            phase="snmp_collect",
            method="snmp",
            severity="error",
            context={"timeout": timeout},
            include_stack_trace=(log_level == "DEBUG")
        )
        return None, error_record
        
    except Exception as e:
        # Catch-all for unexpected exceptions
        logger.error(f"[{hostname}] Unexpected error during SNMP collection: {e}")
        error_record = create_error_record(
            e,
            phase="snmp_collect",
            method="snmp",
            severity="error",
            context={"timeout": timeout},
            include_stack_trace=(log_level == "DEBUG")
        )
        return None, error_record


async def get_sysdescr(
    hostname: str,
    version: int,
    community: Optional[str] = None,
    user: Optional[str] = None,
    auth_proto: Optional[str] = None,
    auth_password: Optional[str] = None,
    priv_proto: Optional[str] = None,
    priv_password: Optional[str] = None,
    timeout: int = 5,
    log_level: str = "INFO",
) -> Tuple[Optional[str], Optional[ErrorRecord]]:
    """
    Query sysDescr OID via SNMP.
    
    Args:
        hostname: Target device IP or hostname
        version: SNMP version (1, 2, or 3)
        community: SNMP community string (v1/v2c)
        user: SNMPv3 username
        auth_proto: SNMPv3 auth protocol
        auth_password: SNMPv3 authentication password
        priv_proto: SNMPv3 privacy protocol
        priv_password: SNMPv3 privacy password
        timeout: SNMP timeout in seconds
        log_level: Logging level (for stack trace inclusion)
        
    Returns:
        Tuple of (Raw sysDescr value or None, ErrorRecord or None)
    """
    try:
        # Convert OID string to ObjectIdentifier
        oid = ObjectIdentifier(SNMP_SYS_DESCR_OID)
        
        # Create SNMP client (without timeout parameter - not supported in puresnmp 2.0)
        client = create_snmp_client(
            hostname=hostname,
            version=version,
            community=community,
            user=user,
            auth_proto=auth_proto,
            auth_password=auth_password,
            priv_proto=priv_proto,
            priv_password=priv_password,
        )
        
        # Execute get with timeout wrapper
        result = await asyncio.wait_for(client.get(oid), timeout=timeout)
        logger.debug(f"[{hostname}] sysDescr retrieved successfully")
        return result, None
        
    except asyncio.TimeoutError as e:
        logger.error(f"[{hostname}] sysDescr query timed out after {timeout}s")
        error_record = create_error_record(
            e,
            phase="snmp_sysdescr",
            method="snmp",
            severity="error",
            context={"timeout": timeout, "oid": SNMP_SYS_DESCR_OID},
            include_stack_trace=(log_level == "DEBUG")
        )
        return None, error_record
        
    except (PureSNMPTimeout, NoSuchOID, SNMPErrorResponse, SnmpError, EmptyMessage) as e:
        if isinstance(e, NoSuchOID):
            logger.warning(f"[{hostname}] sysDescr OID not found on device")
            severity = "warning"
        else:
            logger.error(f"[{hostname}] SNMP error querying sysDescr: {e}")
            severity = "error"
            
        error_record = create_error_record(
            e,
            phase="snmp_sysdescr",
            method="snmp",
            severity=severity,
            context={"timeout": timeout, "oid": SNMP_SYS_DESCR_OID, "version": version},
            include_stack_trace=(log_level == "DEBUG")
        )
        return None, error_record
        
    except (socket.timeout, socket.error, OSError) as e:
        logger.error(f"[{hostname}] Network error querying sysDescr: {e}")
        error_record = create_error_record(
            e,
            phase="snmp_sysdescr",
            method="snmp",
            severity="error",
            context={"timeout": timeout, "oid": SNMP_SYS_DESCR_OID},
            include_stack_trace=(log_level == "DEBUG")
        )
        return None, error_record
        
    except Exception as e:
        logger.error(f"[{hostname}] Unexpected error querying sysDescr: {e}")
        error_record = create_error_record(
            e,
            phase="snmp_sysdescr",
            method="snmp",
            severity="error",
            context={"timeout": timeout, "oid": SNMP_SYS_DESCR_OID},
            include_stack_trace=(log_level == "DEBUG")
        )
        return None, error_record
