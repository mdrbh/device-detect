"""SNMP data collection via async operations."""

import logging
from typing import Optional

try:
    from puresnmp import ObjectIdentifier
    from puresnmp.exc import Timeout as PureSNMPTimeout
    PURESNMP_AVAILABLE = True
except ImportError:
    PURESNMP_AVAILABLE = False
    ObjectIdentifier = None
    PureSNMPTimeout = None

from device_detect.constants import (
    SNMP_SYS_DESCR_OID,
    SNMP_SYS_OBJECT_ID_OID,
    SNMP_SYS_UPTIME_OID,
    SNMP_SYS_NAME_OID,
)
from device_detect.models import SNMPData
from device_detect.snmp.utils import sanitize_snmp_value
from device_detect.snmp.client import create_snmp_client

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
) -> Optional[SNMPData]:
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
        
    Returns:
        SNMPData object with collected data
    """
    # Convert OID strings to ObjectIdentifiers
    oids = [
        ObjectIdentifier(SNMP_SYS_DESCR_OID),
        ObjectIdentifier(SNMP_SYS_OBJECT_ID_OID),
        ObjectIdentifier(SNMP_SYS_UPTIME_OID),
        ObjectIdentifier(SNMP_SYS_NAME_OID),
    ]
    
    # Create SNMP client
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
    
    # Execute multiget
    results = await client.multiget(oids)
    
    # Build SNMPData object
    snmp_data = SNMPData(
        sys_descr=sanitize_snmp_value(results[0]),
        sys_object_id=sanitize_snmp_value(results[1]),
        sys_uptime=sanitize_snmp_value(results[2]),
        sys_name=sanitize_snmp_value(results[3]),
    )
    return snmp_data


async def get_sysdescr(
    hostname: str,
    version: int,
    community: Optional[str] = None,
    user: Optional[str] = None,
    auth_proto: Optional[str] = None,
    auth_password: Optional[str] = None,
    priv_proto: Optional[str] = None,
    priv_password: Optional[str] = None,
):
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
        
    Returns:
        Raw sysDescr value from SNMP
    """
    # Convert OID string to ObjectIdentifier
    oid = ObjectIdentifier(SNMP_SYS_DESCR_OID)
    
    # Create SNMP client
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
    
    # Execute get
    result = await client.get(oid)
    return result
