"""
SNMP-based device type detection.
Supports SNMPv1, v2c, and v3 with full authentication options.
"""

import asyncio
import logging
from typing import Optional, Dict

try:
    from puresnmp.exc import Timeout as PureSNMPTimeout
    PURESNMP_AVAILABLE = True
except ImportError:
    PURESNMP_AVAILABLE = False
    PureSNMPTimeout = None

from device_detect.constants import (
    SNMP_TIMEOUT,
    SNMP_DEFAULT_VERSION,
)
from device_detect.patterns import SNMP_MAPPER_DICT
from device_detect.exceptions import SNMPDetectionError
from device_detect.models import SNMPData
from device_detect.snmp.client import validate_snmp_credentials
from device_detect.snmp.collector import collect_snmp_data, get_sysdescr
from device_detect.snmp.utils import sanitize_snmp_value

logger = logging.getLogger(__name__)


class SNMPDetector:
    """
    SNMP-based device type auto-detection.
    
    Supports SNMPv1, v2c, and v3 with various authentication and privacy options.
    
    Attributes:
        hostname: Target device hostname or IP
        potential_matches: Dictionary of {device_type: priority} for all matches found
    """
    
    def __init__(
        self,
        hostname: str,
        version: int = SNMP_DEFAULT_VERSION,
        community: Optional[str] = None,
        # SNMPv3 parameters
        user: Optional[str] = None,
        auth_proto: Optional[str] = None,
        auth_password: Optional[str] = None,
        priv_proto: Optional[str] = None,
        priv_password: Optional[str] = None,
        timeout: int = SNMP_TIMEOUT,
    ) -> None:
        """
        Initialize SNMP detector.
        
        Args:
            hostname: Target device IP or hostname
            version: SNMP version (1, 2, or 3)
            community: SNMP community string (v1/v2c)
            user: SNMPv3 username
            auth_proto: SNMPv3 auth protocol (md5, sha, sha224, sha256, sha384, sha512)
            auth_password: SNMPv3 authentication password
            priv_proto: SNMPv3 privacy protocol (des, 3des, aes128, aes192, aes256)
            priv_password: SNMPv3 privacy password
            timeout: SNMP timeout in seconds
        """
        if not PURESNMP_AVAILABLE:
            raise SNMPDetectionError(
                "puresnmp library not available. Install with: pip install puresnmp"
            )
        
        self.hostname = hostname
        self.version = version
        self.community = community
        self.timeout = timeout
        
        # SNMPv3 parameters
        self.user = user
        self.auth_proto = auth_proto
        self.auth_password = auth_password
        self.priv_proto = priv_proto
        self.priv_password = priv_password
        
        self.potential_matches: Dict[str, int] = {}
        
        # Validate credentials
        validate_snmp_credentials(
            version=version,
            community=community,
            user=user,
            auth_proto=auth_proto,
            auth_password=auth_password,
            priv_proto=priv_proto,
            priv_password=priv_password,
        )
        
        logger.info(f"SNMP detector initialized for {hostname} (v{version})")
    
    def autodetect(self) -> Optional[str]:
        """
        Attempt SNMP-based device type detection.
        
        Queries sysDescr OID and matches against vendor patterns.
        
        Returns:
            device_type string if detected, None if no match or SNMP fails
        """
        logger.info(f"Starting SNMP autodetection for {self.hostname}")
        
        try:
            # Get sysDescr via SNMP
            sys_descr = self._get_sysdescr()
            
            if not sys_descr:
                logger.warning("Empty or no sysDescr received")
                return None
            
            logger.debug(f"sysDescr: {sys_descr}")
            
            # Match against vendor patterns
            for device_type, config in SNMP_MAPPER_DICT.items():
                expr = config["expr"]
                priority = config["priority"]
                
                if expr.search(sys_descr):
                    self.potential_matches[device_type] = priority
                    logger.debug(f"SNMP match: {device_type} (priority {priority})")
            
            if not self.potential_matches:
                logger.warning("No SNMP pattern matches found")
                return None
            
            # Return best match
            best_match = sorted(
                self.potential_matches.items(),
                key=lambda t: t[1],
                reverse=True
            )
            
            device_type = best_match[0][0]
            logger.info(f"SNMP detection complete. Best match: {device_type}")
            return device_type
            
        except Exception as e:
            logger.warning(f"SNMP detection failed: {e}")
            return None
    
    def get_snmp_data(self) -> Optional[SNMPData]:
        """
        Collect all SNMP data (sysDescr, sysObjectID, sysUpTime, sysName).
        
        Returns:
            SNMPData object with collected data, or None on failure
        """
        try:
            # Run async SNMP multiget in sync context
            result = asyncio.run(
                collect_snmp_data(
                    hostname=self.hostname,
                    version=self.version,
                    community=self.community,
                    user=self.user,
                    auth_proto=self.auth_proto,
                    auth_password=self.auth_password,
                    priv_proto=self.priv_proto,
                    priv_password=self.priv_password,
                    timeout=self.timeout,
                )
            )
            return result
            
        except PureSNMPTimeout:
            logger.warning(f"SNMP timeout querying {self.hostname}")
            return None
        except Exception as e:
            logger.error(f"SNMP data collection failed: {e}")
            return None
    
    def _get_sysdescr(self) -> Optional[str]:
        """
        Query sysDescr OID via SNMP.
        
        Returns:
            sysDescr string or None on failure
        """
        try:
            # Run async SNMP query in sync context
            result = asyncio.run(
                get_sysdescr(
                    hostname=self.hostname,
                    version=self.version,
                    community=self.community,
                    user=self.user,
                    auth_proto=self.auth_proto,
                    auth_password=self.auth_password,
                    priv_proto=self.priv_proto,
                    priv_password=self.priv_password,
                    timeout=self.timeout,
                )
            )
            
            # Sanitize and convert result to string
            if result:
                return sanitize_snmp_value(result)
            return None
            
        except PureSNMPTimeout:
            logger.warning(f"SNMP timeout querying {self.hostname}")
            return None
        except Exception as e:
            logger.error(f"SNMP query failed: {e}")
            return None
