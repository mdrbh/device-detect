"""
Collection operation workflow.
Handles data collection without device type detection.
"""

import logging
import time
from typing import Optional, List, Dict, Any

logger = logging.getLogger(__name__)


class CollectionOperation:
    """
    Manages the data collection workflow.
    
    Collects SNMP and SSH data without performing pattern matching.
    """
    
    def __init__(self, device_detect_instance):
        """
        Initialize collection operation.
        
        Args:
            device_detect_instance: Reference to parent DeviceDetect instance
        """
        self.device = device_detect_instance
        self.all_errors: List[Dict[str, Any]] = []
        self.phase_timings: Dict[str, float] = {}
    
    def execute(
        self,
        snmp_only: bool = False,
        ssh_only: bool = False,
        collect_ssh_commands: bool = False,
        additional_commands: Optional[list] = None,
        sanitize_output: bool = False
    ) -> tuple:
        """
        Execute the complete collection workflow.
        
        Args:
            snmp_only: Only collect SNMP data
            ssh_only: Only collect SSH data
            collect_ssh_commands: Collect all SSH detection commands outputs
            additional_commands: List of additional commands to collect
            sanitize_output: Remove escape characters from command outputs
            
        Returns:
            Tuple of (all_errors, phase_timings)
        """
        logger.info(f"Starting data collection for {self.device.hostname}")
        
        # Collect SNMP data
        if not ssh_only and self.device._has_snmp_credentials():
            self._collect_snmp_data()
        
        # Collect SSH data
        if not snmp_only and self.device._has_ssh_credentials():
            self._collect_ssh_data(
                collect_ssh_commands,
                additional_commands,
                sanitize_output
            )
        
        return self.all_errors, self.phase_timings
    
    def _collect_snmp_data(self) -> None:
        """Collect SNMP data without detection."""
        logger.info("Collecting SNMP data")
        phase_start = time.time()
        snmp_result = self.device._try_snmp_detection(detect_device_type=False)
        self.phase_timings["snmp_collect"] = time.time() - phase_start
        
        if snmp_result.success:
            self.device.snmp_data = snmp_result.snmp_data
        else:
            self.all_errors.append({
                "method": "snmp",
                "error": snmp_result.error,
                "error_type": snmp_result.error_type,
                "error_details": snmp_result.error_details
            })
            logger.warning(f"SNMP collection failed: {snmp_result.error}")
            self.device.warnings.append(f"SNMP collection failed: {snmp_result.error}")
    
    def _collect_ssh_data(
        self,
        collect_ssh_commands: bool,
        additional_commands: Optional[list],
        sanitize_output: bool
    ) -> None:
        """
        Collect SSH data without detection.
        
        Args:
            collect_ssh_commands: Collect all SSH detection commands outputs
            additional_commands: List of additional commands to collect
            sanitize_output: Remove escape characters from command outputs
        """
        logger.info("Collecting SSH data")
        phase_start = time.time()
        ssh_result = self.device._try_ssh_detection(
            detect_device_type=False,
            collect_ssh_commands=collect_ssh_commands,
            additional_commands=additional_commands,
            sanitize_commands=sanitize_output
        )
        self.phase_timings["ssh_collect"] = time.time() - phase_start
        
        if ssh_result.success:
            self.device.ssh_data = ssh_result.ssh_data
        else:
            self.all_errors.append({
                "method": "ssh",
                "error": ssh_result.error,
                "error_type": ssh_result.error_type,
                "error_details": ssh_result.error_details
            })
            logger.warning(f"SSH collection failed: {ssh_result.error}")
            self.device.warnings.append(f"SSH collection failed: {ssh_result.error}")