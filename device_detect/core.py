"""
Main DeviceDetect orchestrator class.
Coordinates SNMP and SSH detection with configurable options.
"""

import logging
import time
from datetime import datetime
from typing import Optional, List, Dict, Any

from device_detect.snmp.detector import SNMPDetector
from device_detect.ssh.detector import SSHDetector
from device_detect.exceptions import DeviceDetectError
from device_detect.utils import setup_logging
from device_detect.constants import DEFAULT_LOG_LEVEL
from device_detect.models import DetectionResult, SNMPData, SSHData, MethodResult
from device_detect.error_mapping import map_exception_to_error, create_error_record
from device_detect.utils import validate_hostname
from device_detect.validation import validate_config
from device_detect.result_builder import build_detection_result, build_collection_result
from device_detect.operations import DetectionOperation, CollectionOperation
from device_detect.operations.offline import (
    detect_offline, 
    detect_offline_from_dict,
    load_collected_data,
    detect_from_snmp_data,
    detect_from_ssh_data,
    calculate_offline_score
)
from device_detect.mapper import get_framework_drivers
from device_detect.models import TimingData

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
    
    @classmethod
    def create(
        cls,
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
        # Banner options
        include_banners: Optional[bool] = None,
        # Logging
        log_level: str = DEFAULT_LOG_LEVEL,
    ):
        """
        Factory method to create DeviceDetect instance with validation.
        
        Returns DeviceDetect instance if validation succeeds, or DetectionResult
        with error information if validation fails. This prevents exceptions during
        initialization.
        
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
            
        Returns:
            DeviceDetect instance if successful, DetectionResult with error if validation fails
        """
        # Validate hostname
        if not validate_hostname(hostname):
            # Create a simple ValueError for invalid hostname
            exc = ValueError(f"Invalid hostname: {hostname}")
            error_record = create_error_record(
                exception=exc,
                phase="validation",
                method="config",
                context={"hostname": hostname, "reason": "Hostname validation failed"}
            )
            return DetectionResult(
                hostname=hostname,
                operation_mode="detect",
                method=None,
                success=False,
                device_type=None,
                score=0,
                error_records=[error_record]
            )
        
        # Validate credentials - at least one method must be available
        has_snmp = (snmp_version in [1, 2] and snmp_community) or (snmp_version == 3 and snmp_user)
        has_ssh = ssh_username and ssh_password
        
        if not has_snmp and not has_ssh:
            exc = ValueError("No valid credentials provided - need either SNMP or SSH credentials")
            error_record = create_error_record(
                exception=exc,
                phase="validation",
                method="config",
                context={
                    "snmp_available": has_snmp,
                    "ssh_available": has_ssh,
                    "reason": "At least one detection method (SNMP or SSH) must have valid credentials"
                }
            )
            return DetectionResult(
                hostname=hostname,
                operation_mode="detect",
                method=None,
                success=False,
                device_type=None,
                score=0,
                error_records=[error_record]
            )
        
        # All validations passed - create instance
        try:
            return cls(
                hostname=hostname,
                snmp_community=snmp_community,
                snmp_version=snmp_version,
                snmp_user=snmp_user,
                snmp_auth_proto=snmp_auth_proto,
                snmp_auth_password=snmp_auth_password,
                snmp_priv_proto=snmp_priv_proto,
                snmp_priv_password=snmp_priv_password,
                ssh_username=ssh_username,
                ssh_password=ssh_password,
                ssh_enable_password=ssh_enable_password,
                ssh_port=ssh_port,
                ssh_version_filter=ssh_version_filter,
                ssh_version_fallback=ssh_version_fallback,
                ssh_timing_profile=ssh_timing_profile,
                enable_snmp=enable_snmp,
                ssh_verification=ssh_verification,
                include_banners=include_banners,
                log_level=log_level,
            )
        except Exception as e:
            # Catch any unexpected initialization errors
            error_record = create_error_record(
                exception=e,
                phase="initialization",
                method="config",
                context={"exception_type": type(e).__name__, "exception_message": str(e)}
            )
            return DetectionResult(
                hostname=hostname,
                operation_mode="detect",
                method=None,
                success=False,
                device_type=None,
                score=0,
                error_records=[error_record]
            )
    
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
        # Banner options
        include_banners: Optional[bool] = None,
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
        
        # Banner options
        self.include_banners = include_banners
        
        # Results tracking
        self.snmp_result: Optional[str] = None
        self.ssh_result: Optional[str] = None
        self.final_result: Optional[str] = None
        self.snmp_data: Optional[SNMPData] = None
        self.ssh_data: Optional[SSHData] = None
        self.ssh_verification_attempted: bool = False
        self.ssh_verification_success: Optional[bool] = None
        self.verification_notes: Optional[str] = None
        self.warnings: List[str] = []
        
        logger.info(f"DeviceDetect initialized for {hostname}")
    
    def detect(self) -> DetectionResult:
        """
        Execute device type detection and return detailed results.
        
        Returns:
            DetectionResult object with all collected data and timing information
        """
        start_time = datetime.now()
        
        # Execute detection using DetectionOperation
        operation = DetectionOperation(self)
        final_result, snmp_result, ssh_result, error_records, phase_timings = operation.execute()
        
        # Update instance state
        self.final_result = final_result
        self.snmp_result = snmp_result
        self.ssh_result = ssh_result
        
        # Build and return result
        return build_detection_result(
            hostname=self.hostname,
            final_result=final_result,
            snmp_result=snmp_result,
            ssh_result=ssh_result,
            snmp_data=self.snmp_data,
            ssh_data=self.ssh_data,
            ssh_verification_attempted=self.ssh_verification_attempted,
            ssh_verification_success=self.ssh_verification_success,
            verification_notes=self.verification_notes,
            error_records=error_records,
            start_time=start_time,
            phase_timings=phase_timings
        )
    
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
        start_time = datetime.now()
        
        # Execute collection using CollectionOperation
        operation = CollectionOperation(self)
        error_records, phase_timings = operation.execute(
            snmp_only=snmp_only,
            ssh_only=ssh_only,
            collect_ssh_commands=collect_ssh_commands,
            additional_commands=additional_commands,
            sanitize_output=sanitize_output
        )
        
        # Build and return result
        return build_collection_result(
            hostname=self.hostname,
            snmp_data=self.snmp_data,
            ssh_data=self.ssh_data,
            error_records=error_records,
            start_time=start_time,
            phase_timings=phase_timings
        )
    
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
    
    def _try_snmp_detection(self, detect_device_type: bool = True) -> MethodResult:
        """
        Attempt SNMP detection and data collection.
        
        Args:
            detect_device_type: If True, run pattern matching. If False, only collect data.
        
        Returns:
            MethodResult with device_type and snmp_data, or error information
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
            
            # If no SNMP data was collected, treat as a timeout/connection error
            if snmp_data is None:
                exc = TimeoutError("SNMP timeout or connection failure")
                error_record = create_error_record(
                    exception=exc,
                    phase="snmp_detect",
                    method="snmp",
                    context={"reason": "No SNMP data received from device"}
                )
                logger.error(f"SNMP detection error: {error_record.message}")
                return MethodResult(
                    device_type=None,
                    snmp_data=None,
                    error_record=error_record
                )
            
            return MethodResult(device_type=device_type, snmp_data=snmp_data)
            
        except Exception as e:
            # Create standardized error record
            error_record = create_error_record(
                exception=e,
                phase="snmp_detect",
                method="snmp"
            )
            logger.error(f"SNMP detection error: {error_record.message}")
            return MethodResult(
                device_type=None,
                snmp_data=None,
                error_record=error_record
            )
    
    def _try_ssh_verification(self, device_type: str) -> MethodResult:
        """
        Verify a specific device type via SSH.
        
        Args:
            device_type: The device type to verify
        
        Returns:
            MethodResult with verification result (device_type if verified) and ssh_data, or error information
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
            
            # Determine banner inclusion: use self.include_banners if set, otherwise default to False for detect mode
            include_banners = self.include_banners if self.include_banners is not None else False
            
            # Collect SSH data
            ssh_data = detector.get_ssh_data(include_banners=include_banners)
            
            # Return device_type if verified, None otherwise
            return MethodResult(
                device_type=device_type if verified else None,
                ssh_data=ssh_data
            )
            
        except Exception as e:
            # Create standardized error record
            error_record = create_error_record(
                exception=e,
                phase="ssh_verify",
                method="ssh",
                context={"verifying_device_type": device_type}
            )
            logger.error(f"SSH verification error: {error_record.message}")
            return MethodResult(
                device_type=None,
                ssh_data=None,
                error_record=error_record
            )
    
    def _try_ssh_detection(self, detect_device_type: bool = True,
                          collect_ssh_commands: bool = False,
                          additional_commands: Optional[list] = None,
                          sanitize_commands: bool = False) -> MethodResult:
        """
        Attempt SSH detection and data collection.
        
        Args:
            detect_device_type: If True, run pattern matching. If False, only collect data.
            collect_ssh_commands: If True, collect all SSH detection commands outputs
            additional_commands: Optional list of additional commands to collect
            sanitize_commands: If True, remove escape characters from command outputs
        
        Returns:
            MethodResult with device_type and ssh_data, or error information
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
            
            # Determine banner inclusion based on operation mode
            # If include_banners is explicitly set, use that value
            # Otherwise: True for collect mode (detect_device_type=False), False for detect mode
            if self.include_banners is not None:
                include_banners = self.include_banners
            else:
                include_banners = not detect_device_type  # True for collect, False for detect
            
            # Collect SSH data with command outputs
            ssh_data = detector.get_ssh_data(
                detection_commands=detection_cmd_outputs,
                additional_commands=additional_cmd_outputs,
                include_banners=include_banners
            )
            
            return MethodResult(device_type=device_type, ssh_data=ssh_data)
            
        except Exception as e:
            # Create standardized error record
            error_record = create_error_record(
                exception=e,
                phase="ssh_detect",
                method="ssh"
            )
            logger.error(f"SSH detection error: {error_record.message}")
            return MethodResult(
                device_type=None,
                ssh_data=None,
                error_record=error_record
            )
    
    def _select_primary_error(self, all_errors: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
        """
        Select primary error based on severity/actionability priority.
        
        Args:
            all_errors: List of error dictionaries from SNMP/SSH phases
            
        Returns:
            Primary error dictionary, or None if no errors
        """
        if not all_errors:
            return None
        
        # Error priority ranking (lower = higher priority)
        ERROR_PRIORITY = {
            "AuthenticationError": 1,
            "InvalidCredentialsError": 2,
            "HostKeyError": 3,
            "ConnectionError": 4,
            "TimeoutError": 5,
            "SNMPError": 6,
            "NoDataError": 7,
            "UnexpectedError": 8
        }
        
        # Sort by priority (lower number = higher priority)
        # If same priority, later errors (SSH) take precedence
        sorted_errors = sorted(
            all_errors,
            key=lambda e: ERROR_PRIORITY.get(e.get("error_type", "UnexpectedError"), 99)
        )
        
        return sorted_errors[0]
    
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
