"""
Detection operation workflow.
Handles the complete detection flow including SNMP, SSH verification, and SSH detection.
"""

import logging
import time
from typing import Optional, List
from datetime import datetime

from device_detect.models import MethodResult, ErrorRecord

logger = logging.getLogger(__name__)


class DetectionOperation:
    """
    Manages the complete device detection workflow.
    
    Coordinates SNMP detection, SSH verification, and SSH fallback detection.
    """
    
    def __init__(self, device_detect_instance):
        """
        Initialize detection operation.
        
        Args:
            device_detect_instance: Reference to parent DeviceDetect instance
        """
        self.device = device_detect_instance
        self.snmp_result: Optional[str] = None
        self.ssh_result: Optional[str] = None
        self.final_result: Optional[str] = None
        self.error_records: List[ErrorRecord] = []
        self.phase_timings: dict = {}
        
    def execute(self) -> tuple:
        """
        Execute the complete detection workflow.
        
        Returns:
            Tuple of (final_result, snmp_result, ssh_result, error_records, phase_timings)
        """
        logger.info(f"Starting device detection for {self.device.hostname}")
        
        # Phase 1: SNMP Detection
        if self.device.enable_snmp and self.device._has_snmp_credentials():
            self._run_snmp_phase()
        
        # Phase 2: SSH Verification or Detection
        if self.device._has_ssh_credentials():
            if self.snmp_result and self.device.ssh_verification:
                # Verification mode
                verified, ssh_detect_result = self._run_ssh_verification_phase(self.snmp_result)
                if not verified and ssh_detect_result:
                    # Use SSH detection result from fallback
                    self.ssh_result = ssh_detect_result
            else:
                # Normal SSH detection
                self._run_ssh_detection_phase()
        
        # Determine final result
        self.final_result = self._resolve_final_result()
        
        return (
            self.final_result,
            self.snmp_result,
            self.ssh_result,
            self.error_records,
            self.phase_timings
        )
    
    def _run_snmp_phase(self) -> None:
        """Execute SNMP detection phase."""
        logger.debug("Phase 1: SNMP detection")
        phase_start = time.time()
        snmp_result = self.device._try_snmp_detection()
        self.phase_timings["snmp_detect"] = time.time() - phase_start
        
        if snmp_result.success:
            self.snmp_result = snmp_result.device_type
            self.device.snmp_data = snmp_result.snmp_data
            logger.info(f"SNMP detected: {self.snmp_result}")
        else:
            # Add error record if present
            if snmp_result.error_record:
                self.error_records.append(snmp_result.error_record)
                logger.warning(f"SNMP detection failed: {snmp_result.error_record.message}")
            else:
                logger.warning("SNMP detection failed: Unknown error")
    
    def _run_ssh_verification_phase(self, device_type: str) -> tuple:
        """
        Execute SSH verification phase.
        
        Args:
            device_type: Device type to verify
            
        Returns:
            Tuple of (verified, fallback_ssh_result)
        """
        logger.debug(f"Phase 2: SSH verification of SNMP result ({device_type})")
        ssh_phase_start = time.time()
        self.device.ssh_verification_attempted = True
        
        verify_result = self.device._try_ssh_verification(device_type)
        ssh_elapsed = time.time() - ssh_phase_start
        self.phase_timings["ssh_verify"] = ssh_elapsed
        
        if verify_result.success and verify_result.device_type:
            logger.debug(f"SSH verification succeeded for {device_type}")
            self.device.ssh_verification_success = True
            self.ssh_result = device_type
            self.device.ssh_data = verify_result.ssh_data
            return True, None
        else:
            logger.warning(f"SSH verification failed for {device_type}, falling back to full SSH detection")
            self.device.ssh_verification_success = False
            self.device.verification_notes = f"SSH verification failed for SNMP-detected {device_type}, performed full SSH autodetection"
            error_msg = verify_result.error_record.message if verify_result.error_record else "Unknown error"
            self.device.warnings.append(f"SSH verification failed for {device_type}: {error_msg}")
            
            # Fall back to full SSH detection
            fallback_start = time.time()
            ssh_result = self.device._try_ssh_detection()
            self.phase_timings["ssh_detect"] = time.time() - fallback_start
            
            if ssh_result.success:
                self.device.ssh_data = ssh_result.ssh_data
                logger.info(f"SSH fallback detected: {ssh_result.device_type}")
                return False, ssh_result.device_type
            else:
                # Add error record if present
                if ssh_result.error_record:
                    self.error_records.append(ssh_result.error_record)
                    logger.warning(f"SSH fallback detection failed: {ssh_result.error_record.message}")
                else:
                    logger.warning("SSH fallback detection failed: Unknown error")
                return False, None
    
    def _run_ssh_detection_phase(self) -> None:
        """Execute normal SSH detection phase."""
        logger.debug("Phase 2: SSH detection")
        ssh_phase_start = time.time()
        ssh_result = self.device._try_ssh_detection()
        ssh_elapsed = time.time() - ssh_phase_start
        self.phase_timings["ssh_connect"] = ssh_elapsed * 0.3  # Estimate
        self.phase_timings["ssh_detect"] = ssh_elapsed * 0.7   # Estimate
        
        if ssh_result.success:
            self.ssh_result = ssh_result.device_type
            self.device.ssh_data = ssh_result.ssh_data
            logger.info(f"SSH detected: {self.ssh_result}")
        else:
            # Add error record if present
            if ssh_result.error_record:
                self.error_records.append(ssh_result.error_record)
                logger.warning(f"SSH detection failed: {ssh_result.error_record.message}")
            else:
                logger.warning("SSH detection failed: Unknown error")
    
    def _resolve_final_result(self) -> Optional[str]:
        """
        Resolve the final detection result from SNMP and SSH results.
        
        Returns:
            Final device type or None
        """
        if self.snmp_result and self.ssh_result:
            if self.snmp_result == self.ssh_result:
                logger.debug("SNMP and SSH agree on device type")
                return self.snmp_result
            else:
                logger.warning(f"Detection conflict: SNMP={self.snmp_result}, SSH={self.ssh_result}")
                self.device.warnings.append(
                    f"Detection conflict: SNMP detected '{self.snmp_result}' "
                    f"but SSH detected '{self.ssh_result}' - using SSH result"
                )
                # Prefer SSH result as it's more detailed
                return self.ssh_result
        elif self.snmp_result:
            return self.snmp_result
        elif self.ssh_result:
            return self.ssh_result
        
        logger.warning("Device detection failed - no match found")
        return None