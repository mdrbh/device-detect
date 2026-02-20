"""SNMP client creation and credential handling."""

import logging
from typing import Optional

try:
    from puresnmp import Client, V2C
    from puresnmp.credentials import V3, Auth, Priv
    PURESNMP_AVAILABLE = True
    PURESNMP_V3_AVAILABLE = True
except ImportError:
    try:
        from puresnmp import Client, V2C
        PURESNMP_AVAILABLE = True
        V3 = None
        Auth = None
        Priv = None
        PURESNMP_V3_AVAILABLE = False
    except ImportError:
        PURESNMP_AVAILABLE = False
        PURESNMP_V3_AVAILABLE = False
        Client = None
        V2C = None
        V3 = None
        Auth = None
        Priv = None

from device_detect.exceptions import SNMPDetectionError

logger = logging.getLogger(__name__)


def validate_snmp_credentials(
    version: int,
    community: Optional[str] = None,
    user: Optional[str] = None,
    auth_proto: Optional[str] = None,
    auth_password: Optional[str] = None,
    priv_proto: Optional[str] = None,
    priv_password: Optional[str] = None,
) -> None:
    """
    Validate SNMP credentials based on version.
    
    Args:
        version: SNMP version (1, 2, or 3)
        community: SNMP community string (v1/v2c)
        user: SNMPv3 username
        auth_proto: SNMPv3 auth protocol
        auth_password: SNMPv3 authentication password
        priv_proto: SNMPv3 privacy protocol
        priv_password: SNMPv3 privacy password
        
    Raises:
        SNMPDetectionError: If credentials are invalid for the version
    """
    if version == 3:
        if not user:
            raise SNMPDetectionError("SNMPv3 requires a username")
        if auth_proto and not auth_password:
            raise SNMPDetectionError("auth_proto specified but auth_password missing")
        if priv_proto and not priv_password:
            raise SNMPDetectionError("priv_proto specified but priv_password missing")
        if priv_proto and not auth_proto:
            raise SNMPDetectionError("Privacy requires authentication (specify auth_proto)")


def map_auth_protocol(auth_proto: str) -> str:
    """
    Map authentication protocol name to puresnmp format.
    
    Args:
        auth_proto: Protocol name (md5, sha, sha1, sha224, sha256, sha384, sha512)
        
    Returns:
        Mapped protocol name for puresnmp
    """
    auth_method = auth_proto.lower()
    if auth_method in ['sha', 'sha-1']:
        auth_method = 'sha1'
    return auth_method


def map_priv_protocol(priv_proto: str) -> str:
    """
    Map privacy protocol name to puresnmp format.
    
    Args:
        priv_proto: Protocol name (des, 3des, aes, aes128, aes192, aes256)
        
    Returns:
        Mapped protocol name for puresnmp
    """
    priv_method = priv_proto.lower()
    # Map aes128/aes192/aes256 to just 'aes'
    if priv_method.startswith('aes'):
        priv_method = 'aes'
    elif priv_method in ['3des', 'des3']:
        priv_method = 'des'
    return priv_method


def build_v3_credentials(
    user: str,
    auth_proto: Optional[str] = None,
    auth_password: Optional[str] = None,
    priv_proto: Optional[str] = None,
    priv_password: Optional[str] = None,
) -> 'V3':
    """
    Build SNMPv3 credentials object.
    
    Args:
        user: SNMPv3 username
        auth_proto: Authentication protocol
        auth_password: Authentication password
        priv_proto: Privacy protocol
        priv_password: Privacy password
        
    Returns:
        V3 credentials object
        
    Raises:
        SNMPDetectionError: If puresnmp-crypto is not available
    """
    if not PURESNMP_V3_AVAILABLE:
        raise SNMPDetectionError(
            "SNMPv3 requires puresnmp-crypto. Install with: pip install puresnmp[crypto]"
        )
    
    auth = None
    priv = None
    
    # Create Auth object if auth protocol is specified
    if auth_proto and auth_password:
        auth_method = map_auth_protocol(auth_proto)
        auth = Auth(
            key=auth_password.encode('utf-8'),
            method=auth_method
        )
        logger.debug(f"SNMPv3 auth configured: {auth_method}")
    
    # Create Priv object if privacy protocol is specified
    if priv_proto and priv_password:
        priv_method = map_priv_protocol(priv_proto)
        priv = Priv(
            key=priv_password.encode('utf-8'),
            method=priv_method
        )
        logger.debug(f"SNMPv3 priv configured: {priv_method}")
    
    # Create V3 credentials
    credentials = V3(
        username=user,
        auth=auth,
        priv=priv
    )
    
    return credentials


def create_snmp_client(
    hostname: str,
    version: int,
    community: Optional[str] = None,
    user: Optional[str] = None,
    auth_proto: Optional[str] = None,
    auth_password: Optional[str] = None,
    priv_proto: Optional[str] = None,
    priv_password: Optional[str] = None,
) -> Client:
    """
    Create SNMP client instance.
    
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
        Configured SNMP Client instance
        
    Raises:
        SNMPDetectionError: If configuration is invalid or unsupported
    """
    if not PURESNMP_AVAILABLE:
        raise SNMPDetectionError(
            "puresnmp library not available. Install with: pip install puresnmp"
        )
    
    if version in [1, 2]:
        # SNMPv1/v2c using puresnmp 2.0 Client API
        client = Client(
            hostname,
            credentials=V2C(community)
        )
        return client
        
    elif version == 3:
        # SNMPv3 with authentication and/or privacy
        credentials = build_v3_credentials(
            user=user,
            auth_proto=auth_proto,
            auth_password=auth_password,
            priv_proto=priv_proto,
            priv_password=priv_password
        )
        
        client = Client(hostname, credentials=credentials)
        return client
    else:
        raise SNMPDetectionError(f"Unsupported SNMP version: {version}")
