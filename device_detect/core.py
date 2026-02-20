"""
Main DeviceDetect orchestrator class.
Coordinates SNMP and SSH detection with configurable options.
"""

import logging
import time
from datetime import datetime
from typing import Optional

from device_detect.snmp.detector import SNMPDetector
from device_detect.ssh.detector import SSHDetector
from device_detect.exceptions import DeviceDetectError
from device_detect.utils import validate_hostname, setup_logging
from device_detect.constants import DEFAULT_LOG_LEVEL
from device_detect.models import DetectionResult, SNMPData, SSHData, TimingData
from device_detect.offline import (
    load_collected_data,
    detect_from_snmp_data,
    detect_from_ssh_data,
    calculate_offline_score
)
from device_detect.mapper import get_framework_drivers

logger = logging.getLogger(__name__)


class DeviceDetect:
    """
    Main device detection orchestrator.
    
    Coordinates SNMP and SSH-based detection with configurable priorities
    and fallback behavior.
    
    Detection flow:
        1. Try SNMP detection (if enabled and credentials provided)
        2. Optionally verify SNMP result via SSH
        3. Fall back to SSH detection if SNMP fails
        4. Return best match device_type or None
    """
    
    def __init__(
        self,
        hostname: str,
        # SNMP parameters
        snmp_community: Optional[str] = None,
        snmp_version: int = 2,
        snmp_user: Optional[str] = None,
        snmp_auth_proto: Optional[str] = None,
        snmp_auth_password: Optional[str] = None,
        snmp_priv_proto: Optional[str] = None,
        snmp_priv_password: Optional[str] = None,
        # SSH parameters
        ssh_username: Optional[str] = None,
        ssh_password: Optional[str] = None,
        ssh_enable_password: Optional[str] = None,
        ssh_port: int = 22,
        # SSH version filtering options
        ssh_version_filter: bool = True,
        ssh_version_fallback: bool = True,
        # SSH timing options
        ssh_timing_profile: str = "normal",
        # Detection options
        enable_snmp: bool = True,
        ssh_verification: bool = False,
        # Logging
        log_level: str = DEFAULT_LOG_LEVEL,
    ) -> None:
        """
        Initialize DeviceDetect orchestrator.
        
        Args:
            hostname: Target device IP or hostname
            snmp_community: SNMP community string (v1/v2c)
            snmp_version: SNMP version (1, 2, or 3)
            snmp_user: SNMPv3 username
            snmp_auth_proto: SNMPv3 auth protocol
            snmp_auth_password: SNMPv3 auth password
            snmp_priv_proto: SNMPv3 privacy protocol
            snmp_priv_password: SNMPv3 privacy password
            ssh_username: SSH username
            ssh_password: SSH password
            ssh_enable_password: SSH enable password for privileged mode
            ssh_port: SSH port (default 22)
            ssh_version_filter: Enable SSH version filtering (default: True)
            ssh_version_fallback: Test non-matching device types if no match (default: True)
            enable_snmp: Enable SNMP detection phase
            ssh_verification: Verify SNMP results via SSH
            log_level: Logging level
        """
        # Setup logging
        setup_logging(log_level)
        
        # Validate hostname
        if not validate_hostname(hostname):
            raise DeviceDetectError(f"Invalid hostname: {hostname}")
        
        self.hostname = hostname
        
        # SNMP configuration
        self.snmp_community = snmp_community
        self.snmp_version = snmp_version
        self.snmp_user = snmp_user
        self.snmp_auth_proto = snmp_auth_proto
        self.snmp_auth_password = snmp_auth_password
        self.snmp_priv_proto = snmp_priv_proto
        self.snmp_priv_password = snmp_priv_password
        
        # SSH configuration
        self.ssh_username = ssh_username
        self.ssh_password = ssh_password
        self.ssh_enable_password = ssh_enable_password
        self.ssh_port = ssh_port
        self.ssh_version_filter = ssh_version_filter
        self.ssh_version_fallback = ssh_version_fallback
        self.ssh_timing_profile = ssh_timing_profile
        
        # Detection options
        self.enable_snmp = enable_snmp
        self.ssh_verification = ssh_verification
        
        # Results tracking
        self.snmp_result: Optional[str] = None
        self.ssh_result: Optional[str] = None
        self.final_result: Optional[str] = None
        self.snmp_data: Optional[SNMPData] = None
        self.ssh_data: Optional[SSHData] = None
        self.ssh_verification_attempted: bool = False
        self.ssh_verification_success: Optional[bool] = None
        self.verification_notes: Optional[str] = None
        
        logger.info(f"DeviceDetect initialized for {hostname}")
    
    def detect(self) -> DetectionResult:
        """
        Execute device type detection and return detailed results.
        
        Returns:
            DetectionResult object with all collected data and timing information
        """
        logger.info(f"Starting device detection for {self.hostname}")
        
        # Track timing
        start_time = datetime.now()
        phase_timings = {}
        
        # Phase 1: SNMP Detection
        if self.enable_snmp and self._has_snmp_credentials():
            logger.info("Phase 1: Attempting SNMP detection")
            phase_start = time.time()
            self.snmp_result, self.snmp_data = self._try_snmp_detection()
            phase_timings["snmp_detect"] = time.time() - phase_start
            
            if self.snmp_result:
                logger.info(f"SNMP detected: {self.snmp_result}")
        
        # Phase 2: SSH Verification or Detection
        if self._has_ssh_credentials():
            # If SNMP detected and ssh_verification enabled, verify SNMP result via SSH
            if self.snmp_result and self.ssh_verification:
                logger.info(f"Phase 2: Attempting SSH verification of SNMP result ({self.snmp_result})")
                ssh_phase_start = time.time()
                self.ssh_verification_attempted = True
                
                verified, ssh_data = self._try_ssh_verification(self.snmp_result)
                ssh_elapsed = time.time() - ssh_phase_start
                phase_timings["ssh_verify"] = ssh_elapsed
                
                if verified:
                    logger.info(f"SSH verification succeeded for {self.snmp_result}")
                    self.ssh_verification_success = True
                    self.ssh_result = self.snmp_result
                    self.ssh_data = ssh_data
                else:
                    logger.warning(f"SSH verification failed for {self.snmp_result}, falling back to full SSH detection")
                    self.ssh_verification_success = False
                    self.verification_notes = f"SSH verification failed for SNMP-detected {self.snmp_result}, performed full SSH autodetection"
                    
                    # Fall back to full SSH detection
                    fallback_start = time.time()
                    self.ssh_result, self.ssh_data = self._try_ssh_detection()
                    phase_timings["ssh_detect"] = time.time() - fallback_start
                    
                    if self.ssh_result:
                        logger.info(f"SSH fallback detected: {self.ssh_result}")
            else:
                # Normal SSH detection (no verification)
                logger.info("Phase 2: Attempting SSH detection")
                ssh_phase_start = time.time()
                self.ssh_result, self.ssh_data = self._try_ssh_detection()
                ssh_elapsed = time.time() - ssh_phase_start
                phase_timings["ssh_connect"] = ssh_elapsed * 0.3  # Estimate
                phase_timings["ssh_detect"] = ssh_elapsed * 0.7   # Estimate
                
                if self.ssh_result:
                    logger.info(f"SSH detected: {self.ssh_result}")
        
        # Determine final result
        if self.snmp_result and self.ssh_result:
            if self.snmp_result == self.ssh_result:
                logger.info("SNMP and SSH agree on device type")
                self.final_result = self.snmp_result
            else:
                logger.warning(f"Detection conflict: SNMP={self.snmp_result}, SSH={self.ssh_result}")
                # Prefer SSH result as it's more detailed
                self.final_result = self.ssh_result
        elif self.snmp_result:
            self.final_result = self.snmp_result
        elif self.ssh_result:
            self.final_result = self.ssh_result
        
        # Calculate timing
        end_time = datetime.now()
        total_seconds = (end_time - start_time).total_seconds()
        
        # Calculate score
        score = self._calculate_score()
        
        # Determine detection method
        method = self._determine_method()
        
        # Build result
        success = self.final_result is not None
        if not success:
            logger.warning("Device detection failed - no match found")
        
        # Get framework driver mappings if device_type was detected
        framework_mappings = self._get_framework_mappings(self.final_result)
        
        result = DetectionResult(
            hostname=self.hostname,
            operation_mode="detect",
            method=method,
            success=success,
            device_type=self.final_result,
            score=score,
            snmp_data=self.snmp_data,
            ssh_data=self.ssh_data,
            timing=TimingData(
                total_seconds=total_seconds,
                phase_timings=phase_timings
            ),
            ssh_verification_attempted=self.ssh_verification_attempted,
            ssh_verification_success=self.ssh_verification_success,
            verification_notes=self.verification_notes,
            **framework_mappings
        )
        
        return result
    
    @staticmethod
    def detect_offline_from_dict(data: dict) -> DetectionResult:
        """
        Perform offline device detection from pre-collected data dictionary.
        
        This method processes a single collected result dictionary and
        performs pattern matching without any network calls.
        
        Args:
            data: Dictionary containing collected data (from JSON array element)
            
        Returns:
            DetectionResult with detected device_type and confidence score
            
        Raises:
            ValueError: If data is invalid or missing required fields
        """
        if not isinstance(data, dict):
            raise ValueError("Data must be a dictionary")
        
        if 'hostname' not in data:
            raise ValueError("Data missing required field: 'hostname'")
        
        hostname = data['hostname']
        logger.info(f"Starting offline detection from dictionary for {hostname}")
        
        start_time = datetime.now()
        
        # Reconstruct data objects
        collected_result = DetectionResult.from_dict(data)
        snmp_data = collected_result.snmp_data
        ssh_data = collected_result.ssh_data
        
        # Run pattern matching on collected data
        snmp_result = None
        ssh_result = None
        
        if snmp_data:
            logger.info(f"Running SNMP pattern matching for {hostname}")
            snmp_result, _ = detect_from_snmp_data(snmp_data)
            if snmp_result:
                logger.info(f"SNMP pattern matched: {snmp_result}")
        
        if ssh_data:
            logger.info(f"Running SSH pattern matching for {hostname}")
            ssh_result, _ = detect_from_ssh_data(ssh_data)
            if ssh_result:
                logger.info(f"SSH pattern matched: {ssh_result}")
        
        # Determine final result
        final_result = None
        if snmp_result and ssh_result:
            if snmp_result == ssh_result:
                logger.info("SNMP and SSH patterns agree")
                final_result = snmp_result
            else:
                logger.warning(f"Pattern mismatch: SNMP={snmp_result}, SSH={ssh_result}")
                # Prefer SSH result as it's more detailed
                final_result = ssh_result
        elif ssh_result:
            final_result = ssh_result
        elif snmp_result:
            final_result = snmp_result
        
        # Calculate score
        matches_agree = snmp_result == ssh_result if (snmp_result and ssh_result) else False
        score = calculate_offline_score(
            snmp_match=snmp_result is not None,
            ssh_match=ssh_result is not None,
            matches_agree=matches_agree
        )
        
        # Determine method
        has_snmp = snmp_data is not None
        has_ssh = ssh_data is not None
        method = "SNMP+SSH" if (has_snmp and has_ssh) else ("SNMP" if has_snmp else ("SSH" if has_ssh else None))
        
        # Calculate timing
        end_time = datetime.now()
        total_seconds = (end_time - start_time).total_seconds()
        
        success = final_result is not None
        if not success:
            logger.warning(f"Offline detection failed for {hostname} - no pattern matches found")
        else:
            logger.info(f"Offline detection complete for {hostname}: {final_result} (score: {score})")
        
        # Get framework driver mappings
        framework_mappings = DeviceDetect._get_framework_mappings(final_result)
        
        # Build result
        result = DetectionResult(
            hostname=hostname,
            operation_mode="offline",
            method=method,
            success=success,
            device_type=final_result,
            score=score,
            snmp_data=snmp_data,
            ssh_data=ssh_data,
            timing=TimingData(
                total_seconds=total_seconds,
                phase_timings={"offline_detect": total_seconds}
            ),
            **framework_mappings
        )
        
        return result
    
    def collect(self, snmp_only: bool = False, ssh_only: bool = False,
                collect_ssh_commands: bool = False, 
                additional_commands: Optional[list] = None,
                sanitize_output: bool = False) -> DetectionResult:
        """
        Collect raw device data without detection/pattern matching.
        
        Args:
            snmp_only: Only collect SNMP data
            ssh_only: Only collect SSH data
            collect_ssh_commands: Collect all SSH detection commands outputs
            additional_commands: List of additional commands to collect (deduplicated)
            sanitize_output: Remove escape characters and control codes from command outputs
            
        Returns:
            DetectionResult object with collected data (no device_type or confidence)
        """
        logger.info(f"Starting data collection for {self.hostname}")
        
        # Track timing
        start_time = datetime.now()
        phase_timings = {}
        
        # Collect SNMP data (without device type detection)
        if not ssh_only and self._has_snmp_credentials():
            logger.info("Collecting SNMP data")
            phase_start = time.time()
            _, self.snmp_data = self._try_snmp_detection(detect_device_type=False)
            phase_timings["snmp_collect"] = time.time() - phase_start
        
        # Collect SSH data (without device type detection)
        if not snmp_only and self._has_ssh_credentials():
            logger.info("Collecting SSH data")
            phase_start = time.time()
            _, self.ssh_data = self._try_ssh_detection(
                detect_device_type=False,
                collect_ssh_commands=collect_ssh_commands,
                additional_commands=additional_commands,
                sanitize_commands=sanitize_output
            )
            phase_timings["ssh_collect"] = time.time() - phase_start
        
        # Calculate timing
        end_time = datetime.now()
        total_seconds = (end_time - start_time).total_seconds()
        
        # Determine success (if we collected any data)
        success = self.snmp_data is not None or self.ssh_data is not None
        
        # Determine collection method
        method = self._determine_method()
        
        # Build result
        result = DetectionResult(
            hostname=self.hostname,
            operation_mode="collect",
            method=method,
            success=success,
            device_type=None,  # No detection in collection mode
            score=0,  # No score in collection mode
            snmp_data=self.snmp_data,
            ssh_data=self.ssh_data,
            timing=TimingData(
                total_seconds=total_seconds,
                phase_timings=phase_timings
            )
        )
        
        logger.info(f"Data collection completed for {self.hostname}")
        return result
    
    def _has_snmp_credentials(self) -> bool:
        """Check if SNMP credentials are available."""
        if self.snmp_version in [1, 2]:
            return self.snmp_community is not None
        elif self.snmp_version == 3:
            return self.snmp_user is not None
        return False
    
    def _has_ssh_credentials(self) -> bool:
        """Check if SSH credentials are available."""
        return self.ssh_username is not None and self.ssh_password is not None
    
    def _try_snmp_detection(self, detect_device_type: bool = True) -> tuple[Optional[str], Optional[SNMPData]]:
        """
        Attempt SNMP detection and data collection.
        
        Args:
            detect_device_type: If True, run pattern matching. If False, only collect data.
        
        Returns:
            Tuple of (device_type, snmp_data)
        """
        try:
            detector = SNMPDetector(
                hostname=self.hostname,
                version=self.snmp_version,
                community=self.snmp_community,
                user=self.snmp_user,
                auth_proto=self.snmp_auth_proto,
                auth_password=self.snmp_auth_password,
                priv_proto=self.snmp_priv_proto,
                priv_password=self.snmp_priv_password,
            )
            
            # Get device type only if detection is enabled
            device_type = None
            if detect_device_type:
                device_type = detector.autodetect()
            
            # Collect SNMP data
            snmp_data = detector.get_snmp_data()
            
            return device_type, snmp_data
            
        except Exception as e:
            logger.error(f"SNMP detection error: {e}")
            return None, None
    
    def _try_ssh_verification(self, device_type: str) -> tuple[bool, Optional[SSHData]]:
        """
        Verify a specific device type via SSH.
        
        Args:
            device_type: The device type to verify
        
        Returns:
            Tuple of (verified, ssh_data)
        """
        try:
            ssh_params = {
                "device_type": "autodetect",
                "host": self.hostname,
                "username": self.ssh_username,
                "password": self.ssh_password,
                "port": self.ssh_port,
                "ssh_version_filter": self.ssh_version_filter,
                "fallback": self.ssh_version_fallback,
                "ssh_timing_profile": self.ssh_timing_profile,
            }
            
            if self.ssh_enable_password:
                ssh_params["secret"] = self.ssh_enable_password
            
            detector = SSHDetector(**ssh_params)
            verified, _ = detector.verify_device_type(device_type)
            
            # Collect SSH data
            ssh_data = detector.get_ssh_data()
            
            return verified, ssh_data
            
        except Exception as e:
            logger.error(f"SSH verification error: {e}")
            return False, None
    
    def _try_ssh_detection(self, detect_device_type: bool = True,
                          collect_ssh_commands: bool = False,
                          additional_commands: Optional[list] = None,
                          sanitize_commands: bool = False) -> tuple[Optional[str], Optional[SSHData]]:
        """
        Attempt SSH detection and data collection.
        
        Args:
            detect_device_type: If True, run pattern matching. If False, only collect data.
            collect_ssh_commands: If True, collect all SSH detection commands outputs
            additional_commands: Optional list of additional commands to collect
            sanitize_commands: If True, remove escape characters from command outputs
        
        Returns:
            Tuple of (device_type, ssh_data)
        """
        try:
            # Build SSH connection parameters
            ssh_params = {
                "device_type": "autodetect",
                "host": self.hostname,
                "username": self.ssh_username,
                "password": self.ssh_password,
                "port": self.ssh_port,
                "ssh_version_filter": self.ssh_version_filter,
                "fallback": self.ssh_version_fallback,
                "ssh_timing_profile": self.ssh_timing_profile,
            }
            
            # Add optional enable password
            if self.ssh_enable_password:
                ssh_params["secret"] = self.ssh_enable_password
            
            detector = SSHDetector(**ssh_params)
            
            # Get device type only if detection is enabled
            device_type = None
            if detect_device_type:
                device_type = detector.autodetect()
            
            # Collect command outputs if requested
            detection_cmd_outputs = None
            additional_cmd_outputs = None
            
            if collect_ssh_commands:
                detection_cmd_outputs = detector.collect_detection_commands(sanitize=sanitize_commands)
            
            if additional_commands:
                additional_cmd_outputs = detector.collect_additional_commands(additional_commands, sanitize=sanitize_commands)
            
            # Collect SSH data with command outputs
            ssh_data = detector.get_ssh_data(
                detection_commands=detection_cmd_outputs,
                additional_commands=additional_cmd_outputs
            )
            
            return device_type, ssh_data
            
        except Exception as e:
            logger.error(f"SSH detection error: {e}")
            return None, None
    
    def _calculate_score(self) -> int:
        """
        Calculate detection score based on detection results.
        
        Returns:
            Score (0-100)
        """
        if not self.final_result:
            return 0
        
        # SNMP + SSH verification succeeded (highest confidence)
        if self.ssh_verification_attempted and self.ssh_verification_success:
            return 99
        
        # Both SNMP and SSH detected same device (no verification mode)
        if self.snmp_result and self.ssh_result and self.snmp_result == self.ssh_result:
            return 99
        
        # Only SNMP detected
        if self.snmp_result and not self.ssh_result:
            return 75
        
        # Only SSH detected
        if self.ssh_result and not self.snmp_result:
            return 85
        
        # SNMP + SSH verification failed, then SSH autodetect (using SSH result)
        if self.ssh_verification_attempted and not self.ssh_verification_success:
            return 70
        
        # SNMP and SSH detected different devices (using SSH result)
        if self.snmp_result and self.ssh_result:
            return 70
        
        return 50
    
    def _determine_method(self) -> Optional[str]:
        """
        Determine the detection/collection method based on collected data.
        
        Returns:
            Method string: 'SNMP', 'SSH', 'SNMP+SSH', or None
        """
        has_snmp = self.snmp_data is not None
        has_ssh = self.ssh_data is not None
        
        if has_snmp and has_ssh:
            return "SNMP+SSH"
        elif has_snmp:
            return "SNMP"
        elif has_ssh:
            return "SSH"
        else:
            return None
    
    @staticmethod
    def _get_framework_mappings(device_type: Optional[str]) -> dict:
        """
        Get framework driver mappings for a device type.
        
        Args:
            device_type: Device type to map (e.g., 'cisco_ios')
            
        Returns:
            Dictionary with framework driver fields
        """
        if not device_type:
            return {
                'scrapli_driver': None,
                'napalm_driver': None,
                'nornir_driver': None,
                'ansible_driver': None
            }
        
        mappings = get_framework_drivers(device_type)
        return {
            'scrapli_driver': mappings.get('scrapli'),
            'napalm_driver': mappings.get('napalm'),
            'nornir_driver': mappings.get('nornir'),
            'ansible_driver': mappings.get('ansible')
        }
    
    @staticmethod
    def detect_offline(json_file_path: str) -> DetectionResult:
        """
        Perform offline device detection from pre-collected JSON data.
        
        This method loads collected SNMP/SSH data from a JSON file and
        performs pattern matching without any network calls.
        
        Args:
            json_file_path: Path to JSON file containing collected data
            
        Returns:
            DetectionResult with detected device_type and confidence score
            
        Raises:
            FileNotFoundError: If JSON file doesn't exist
            ValueError: If JSON is invalid or missing required fields
        """
        logger.info(f"Starting offline detection from {json_file_path}")
        
        start_time = datetime.now()
        
        # Load collected data from JSON
        data = load_collected_data(json_file_path)
        
        # Reconstruct data objects
        collected_result = DetectionResult.from_dict(data)
        hostname = collected_result.hostname
        snmp_data = collected_result.snmp_data
        ssh_data = collected_result.ssh_data
        
        # Run pattern matching on collected data
        snmp_result = None
        ssh_result = None
        
        if snmp_data:
            logger.info("Running SNMP pattern matching on collected data")
            snmp_result, _ = detect_from_snmp_data(snmp_data)
            if snmp_result:
                logger.info(f"SNMP pattern matched: {snmp_result}")
        
        if ssh_data:
            logger.info("Running SSH pattern matching on collected data")
            ssh_result, _ = detect_from_ssh_data(ssh_data)
            if ssh_result:
                logger.info(f"SSH pattern matched: {ssh_result}")
        
        # Determine final result
        final_result = None
        if snmp_result and ssh_result:
            if snmp_result == ssh_result:
                logger.info("SNMP and SSH patterns agree")
                final_result = snmp_result
            else:
                logger.warning(f"Pattern mismatch: SNMP={snmp_result}, SSH={ssh_result}")
                # Prefer SSH result as it's more detailed
                final_result = ssh_result
        elif ssh_result:
            final_result = ssh_result
        elif snmp_result:
            final_result = snmp_result
        
        # Calculate score
        matches_agree = snmp_result == ssh_result if (snmp_result and ssh_result) else False
        score = calculate_offline_score(
            snmp_match=snmp_result is not None,
            ssh_match=ssh_result is not None,
            matches_agree=matches_agree
        )
        
        # Determine method
        has_snmp = snmp_data is not None
        has_ssh = ssh_data is not None
        method = "SNMP+SSH" if (has_snmp and has_ssh) else ("SNMP" if has_snmp else ("SSH" if has_ssh else None))
        
        # Calculate timing
        end_time = datetime.now()
        total_seconds = (end_time - start_time).total_seconds()
        
        success = final_result is not None
        if not success:
            logger.warning("Offline detection failed - no pattern matches found")
        else:
            logger.info(f"Offline detection complete: {final_result} (score: {score})")
        
        # Get framework driver mappings
        framework_mappings = DeviceDetect._get_framework_mappings(final_result)
        
        # Build result
        result = DetectionResult(
            hostname=hostname,
            operation_mode="offline",
            method=method,
            success=success,
            device_type=final_result,
            score=score,
            snmp_data=snmp_data,
            ssh_data=ssh_data,
            timing=TimingData(
                total_seconds=total_seconds,
                phase_timings={"offline_detect": total_seconds}
            ),
            **framework_mappings
        )
        
        return result
