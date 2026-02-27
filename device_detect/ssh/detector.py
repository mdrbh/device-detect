"""
SSH-based device type detection.
Refactored from Netmiko's SSHDetect with all original features preserved.
"""

import logging
import re
from typing import Any, Dict, List, Optional, Union

import paramiko

from device_detect.constants import (
    GLOBAL_CMD_VERIFY,
    HIGH_CONFIDENCE_PRIORITY,
    SSH_TIMING_PROFILES,
    DEFAULT_SSH_TIMING_PROFILE,
    SSH_ADAPTIVE_RETRY_ENABLED,
    SSH_MAX_RETRIES,
)
from device_detect.patterns import (
    SSH_MAPPER_DICT,
    DEVICE_TYPE_ALIASES,
)
from device_detect.exceptions import SSHDetectionError
from device_detect.ssh.client import SSHClient
from device_detect.ssh.commands import SSHCommandExecutor
from device_detect.ssh.collector import SSHCollector
from device_detect.ssh.utils import get_ssh_mapper_base

logger = logging.getLogger(__name__)


class SSHDetector:
    """
    SSH-based device type auto-detection.
    
    This class attempts to automatically determine the device type by sending
    commands over SSH and matching patterns in the responses.
    
    Attributes:
        connection: Netmiko SSH connection object
        initial_buffer: Initial output after connection (login messages, etc.)
        potential_matches: Dictionary of {device_type: priority} for all matches found
    """
    
    def __init__(self, *args: Any, **kwargs: Any) -> None:
        """
        Initialize SSH detector and establish connection.
        
        Args:
            *args: Positional arguments passed to netmiko ConnectHandler
            **kwargs: Keyword arguments passed to netmiko ConnectHandler
                Must include device_type='autodetect'
                ssh_version_filter: Enable SSH version filtering (default: True)
                fallback: Test non-matching device types if no match (default: True)
                ssh_timing_profile: Timing profile to use (fast/normal/slow, default: normal)
        """
        if kwargs.get("device_type") != "autodetect":
            raise ValueError("The connection device_type must be 'autodetect'")
        
        # Extract SSH version filtering parameters
        self.ssh_version_filter = kwargs.pop("ssh_version_filter", True)
        self.fallback = kwargs.pop("fallback", True)
        
        # Extract and validate timing profile
        timing_profile = kwargs.pop("ssh_timing_profile", DEFAULT_SSH_TIMING_PROFILE)
        if timing_profile not in SSH_TIMING_PROFILES:
            logger.warning(f"Invalid timing profile '{timing_profile}', using default '{DEFAULT_SSH_TIMING_PROFILE}'")
            timing_profile = DEFAULT_SSH_TIMING_PROFILE
        
        # Apply timing profile
        self.timing_profile = timing_profile
        self.timings = SSH_TIMING_PROFILES[timing_profile]
        logger.info(f"Using SSH timing profile: {timing_profile}")
        
        # Adaptive retry configuration
        self.adaptive_retry_enabled = SSH_ADAPTIVE_RETRY_ENABLED
        self.max_retries = SSH_MAX_RETRIES
        
        # Always disable cmd_verify for autodetect to avoid prompt issues
        kwargs["global_cmd_verify"] = GLOBAL_CMD_VERIFY
        
        # Initialize SSH client (handles connection and banner/prompt capture)
        self.client = SSHClient(self.timings, *args, **kwargs)
        self.connection = self.client.get_connection()
        self.initial_buffer = self.client.initial_buffer
        
        # Get captured SSH data from client
        self.ssh_version = self.client.ssh_version
        self.banner = self.client.banner
        self.banner_auth = self.client.banner_auth
        self.banner_motd = self.client.banner_motd
        self.prompt = self.client.prompt
        
        # Initialize detection state
        self.potential_matches: Dict[str, int] = {}
        self._results_cache: Dict[str, str] = {}
        
        # Initialize command executor
        self.command_executor = SSHCommandExecutor(
            connection=self.connection,
            prompt=self.prompt,
            timings=self.timings,
            results_cache=self._results_cache
        )
        
        # Initialize collector
        self.collector = SSHCollector(self.command_executor)
    
    def verify_device_type(self, device_type: str) -> tuple[bool, int]:
        """
        Verify a specific device type via SSH patterns.
        
        Only tests the patterns for the specified device_type (used for SNMP verification).
        
        Args:
            device_type: The device type to verify (e.g., 'cisco_ios')
            
        Returns:
            Tuple of (success, priority) - success is True if device matches, priority is confidence level
        """
        logger.info(f"Starting SSH verification for device type: {device_type}")
        
        if device_type not in SSH_MAPPER_DICT:
            logger.warning(f"Device type '{device_type}' not found in SSH patterns")
            return False, 0
        
        config = SSH_MAPPER_DICT[device_type].copy()
        call_method = config.pop("dispatch")
        config.pop("ssh_version", None)
        
        method = getattr(self, call_method)
        priority = method(**config)
        
        success = priority > 0
        if success:
            logger.info(f"SSH verification succeeded for {device_type} (priority: {priority})")
        else:
            logger.warning(f"SSH verification failed for {device_type}")
        
        return success, priority
    
    def autodetect(self) -> Union[str, None]:
        """
        Attempt to auto-detect the device type.
        
        Uses SSH version filtering for optimization:
        - Phase 1: Test device types matching SSH version patterns
        - Phase 2 (if fallback enabled): Test remaining device types
        
        Returns on first high-confidence match (priority >= 99)
        or best match after checking all patterns.
        
        Returns:
            device_type string if detected, None if no match found
        """
        logger.info("Starting SSH autodetection")
        
        # Check if SSH version filtering is enabled
        if self.ssh_version_filter and self.ssh_version:
            logger.info(f"SSH version filtering enabled. Detected version: {self.ssh_version}")
            
            # Get device types split by SSH version match
            matching_types, non_matching_types = self._split_device_types_by_ssh_version()
            
            # Phase 1: Test device types matching SSH version
            if matching_types:
                logger.info(f"Phase 1: Testing {len(matching_types)} device types matching SSH version")
                ssh_mapper_phase1 = get_ssh_mapper_base(device_types=matching_types)
                
                result = self._test_device_types(ssh_mapper_phase1, phase="1")
                if result:
                    return result
            else:
                logger.info("Phase 1: No device types match SSH version patterns")
            
            # Phase 2: Fallback to non-matching device types if enabled
            if self.fallback and non_matching_types:
                logger.info(f"Phase 2 (fallback): Testing {len(non_matching_types)} remaining device types")
                ssh_mapper_phase2 = get_ssh_mapper_base(device_types=non_matching_types)
                
                result = self._test_device_types(ssh_mapper_phase2, phase="2")
                if result:
                    return result
            elif not self.fallback:
                logger.info("Phase 2: Fallback disabled, skipping non-matching device types")
        else:
            # SSH version filtering disabled or no SSH version detected
            if not self.ssh_version_filter:
                logger.info("SSH version filtering disabled")
            else:
                logger.warning("SSH version not detected, proceeding with all device types")
            
            ssh_mapper = get_ssh_mapper_base()
            result = self._test_device_types(ssh_mapper)
            if result:
                return result
        
        # No match found
        if not self.potential_matches:
            logger.warning("No device type matches found")
            self.connection.disconnect()
            return None
        
        best_match = self._get_best_match()
        logger.info(f"Detection complete. Best match: {best_match}")
        self.connection.disconnect()
        return best_match
    
    def _split_device_types_by_ssh_version(self) -> tuple[List[str], List[str]]:
        """
        Split device types into matching and non-matching based on SSH version.
        
        Returns:
            Tuple of (matching_device_types, non_matching_device_types)
        """
        matching_types = []
        non_matching_types = []
        
        for device_type, config in SSH_MAPPER_DICT.items():
            ssh_version_patterns = config.get("ssh_version")
            
            if ssh_version_patterns and self.ssh_version:
                # Check if SSH version matches any of the patterns
                matched = False
                for pattern in ssh_version_patterns:
                    try:
                        if re.search(pattern, self.ssh_version, flags=re.IGNORECASE):
                            matched = True
                            logger.debug(f"{device_type}: SSH version matched pattern '{pattern}'")
                            break
                    except Exception as e:
                        logger.warning(f"Invalid regex pattern '{pattern}' for {device_type}: {e}")
                
                if matched:
                    matching_types.append(device_type)
                else:
                    non_matching_types.append(device_type)
            else:
                # No SSH version pattern defined for this device type
                non_matching_types.append(device_type)
        
        logger.debug(f"SSH version filtering: {len(matching_types)} matching, {len(non_matching_types)} non-matching")
        return matching_types, non_matching_types
    
    def _test_device_types(self, ssh_mapper: List[tuple], phase: Optional[str] = None) -> Optional[str]:
        """
        Test device types from the provided SSH mapper.
        
        Args:
            ssh_mapper: List of (device_type, config_dict) tuples to test
            phase: Optional phase identifier for logging (e.g., "1", "2")
            
        Returns:
            device_type string if high-confidence match found, None otherwise
        """
        phase_label = f" (Phase {phase})" if phase else ""
        
        for device_type, autodetect_dict in ssh_mapper:
            tmp_dict = autodetect_dict.copy()
            call_method = tmp_dict.pop("dispatch")
            # Remove ssh_version from dict as it's not a parameter for detection methods
            tmp_dict.pop("ssh_version", None)
            
            # Get the detection method and call it
            autodetect_method = getattr(self, call_method)
            accuracy = autodetect_method(**tmp_dict)
            
            if accuracy:
                self.potential_matches[device_type] = accuracy
                logger.debug(f"Match found{phase_label}: {device_type} with priority {accuracy}")
                
                # Early exit on high-confidence match
                if accuracy >= HIGH_CONFIDENCE_PRIORITY:
                    logger.info(f"High confidence match found{phase_label}: {device_type}")
                    best_match = self._get_best_match()
                    self.connection.disconnect()
                    return best_match
        
        return None
    
    def _get_best_match(self) -> str:
        """
        Get the best matching device type from potential matches.
        
        Returns:
            device_type string after applying aliases
        """
        best_match = sorted(
            self.potential_matches.items(),
            key=lambda t: t[1],
            reverse=True
        )
        
        device_type = best_match[0][0]
        
        # Apply device type aliases (e.g., cisco_wlc_85 -> cisco_wlc)
        if device_type in DEVICE_TYPE_ALIASES:
            device_type = DEVICE_TYPE_ALIASES[device_type]
            logger.debug(f"Applied alias: {best_match[0][0]} -> {device_type}")
        
        return device_type
    
    def _autodetect_std(
        self,
        cmd: str = "",
        search_patterns: Optional[List[str]] = None,
        re_flags: int = re.IGNORECASE,
        priority: int = 99,
    ) -> int:
        """
        Standard autodetect method - send command and match patterns.
        
        Args:
            cmd: Command to send to device
            search_patterns: List of regex patterns to match in output
            re_flags: Regex flags (default: case-insensitive)
            priority: Confidence level (0-99) if match found
            
        Returns:
            priority value if match found, 0 otherwise
        """
        # Invalid responses that indicate command failure
        invalid_responses = [
            r"% Invalid input detected",
            r"syntax error, expecting",
            r"Error: Unrecognized command",
            r"%Error",
            r"command not found",
            r"Syntax Error: unexpected argument",
            r"% Unrecognized command found at",
            r"% Unknown command, the error locates at",
        ]
        
        if not cmd or not search_patterns:
            return 0
        
        try:
            response = self.command_executor.send_command_wrapper(cmd)
            
            # Check for error conditions
            for pattern in invalid_responses:
                if re.search(pattern, response, flags=re.IGNORECASE):
                    logger.debug(f"Invalid response detected for cmd '{cmd}': matched '{pattern}'")
                    return 0
            
            # Check for positive matches
            for pattern in search_patterns:
                if re.search(pattern, response, flags=re_flags):
                    logger.debug(f"Pattern matched: {pattern}")
                    return priority
                    
        except Exception as e:
            logger.warning(f"Exception during autodetect_std for cmd '{cmd}': {e}")
            return 0
        
        return 0
    
    def _autodetect_multi(
        self,
        commands: Optional[List[Dict[str, Any]]] = None,
        re_flags: int = re.IGNORECASE,
        priority: int = 99,
    ) -> int:
        """
        Multi-command autodetect method - ALL commands must match (AND logic).
        
        This method sends multiple commands and checks patterns for each.
        Returns priority only if ALL commands match their respective patterns.
        Useful for distinguishing similar devices (e.g., hp_procurve vs aruba_procurve).
        
        Args:
            commands: List of command dictionaries, each containing:
                - cmd: Command to send
                - search_patterns: List of regex patterns to match
            re_flags: Regex flags (default: case-insensitive)
            priority: Confidence level (0-99) if all matches found
            
        Returns:
            priority value if ALL commands match, 0 otherwise
            
        Example:
            commands = [
                {"cmd": "show version", "search_patterns": [r"Image stamp"]},
                {"cmd": "show dhcp client vendor-specific", "search_patterns": [r"Aruba"]}
            ]
        """
        # Invalid responses that indicate command failure
        invalid_responses = [
            r"% Invalid input detected",
            r"syntax error, expecting",
            r"Error: Unrecognized command",
            r"%Error",
            r"command not found",
            r"Syntax Error: unexpected argument",
            r"% Unrecognized command found at",
            r"% Unknown command, the error locates at",
        ]
        
        if not commands or len(commands) == 0:
            return 0
        
        logger.debug(f"Multi-command detection: checking {len(commands)} commands")
        
        # Track matches - ALL must match
        matched_count = 0
        
        for cmd_dict in commands:
            cmd = cmd_dict.get("cmd", "")
            search_patterns = cmd_dict.get("search_patterns", [])
            
            if not cmd or not search_patterns:
                logger.debug(f"Skipping invalid command dict: {cmd_dict}")
                return 0  # Invalid command structure = fail
            
            try:
                response = self.command_executor.send_command_wrapper(cmd)
                
                # Check for error conditions
                error_found = False
                for pattern in invalid_responses:
                    if re.search(pattern, response, flags=re.IGNORECASE):
                        logger.debug(f"Invalid response for cmd '{cmd}': matched '{pattern}'")
                        error_found = True
                        break
                
                if error_found:
                    return 0  # Any command error = fail entire detection
                
                # Check for positive matches - at least one pattern must match
                cmd_matched = False
                for pattern in search_patterns:
                    if re.search(pattern, response, flags=re_flags):
                        logger.debug(f"Command '{cmd}' matched pattern: {pattern}")
                        cmd_matched = True
                        break
                
                if cmd_matched:
                    matched_count += 1
                else:
                    logger.debug(f"Command '{cmd}' did not match any patterns")
                    return 0  # Any command not matching = fail entire detection
                    
            except Exception as e:
                logger.warning(f"Exception during multi-command detection for cmd '{cmd}': {e}")
                return 0  # Any exception = fail entire detection
        
        # All commands matched successfully
        if matched_count == len(commands):
            logger.debug(f"All {matched_count} commands matched successfully")
            return priority
        
        return 0
    
    def _autodetect_remote_version(
        self,
        search_patterns: Optional[List[str]] = None,
        re_flags: int = re.IGNORECASE,
        priority: int = 99,
        **kwargs: Any
    ) -> int:
        """
        Autodetect based on SSH server's remote version banner.
        
        This method doesn't send commands - it checks the SSH server's
        version string (e.g., for Cisco WLC which identifies in banner).
        
        Args:
            search_patterns: List of regex patterns to match in version banner
            re_flags: Regex flags (default: case-insensitive)
            priority: Confidence level (0-99) if match found
            
        Returns:
            priority value if match found, 0 otherwise
        """
        invalid_responses = [r"^$"]
        
        if not search_patterns:
            return 0
        
        try:
            remote_conn = self.connection.remote_conn
            if not isinstance(remote_conn, paramiko.Channel):
                logger.debug("Remote connection is not a Paramiko channel")
                return 0
            
            if remote_conn.transport is None:
                logger.debug("No transport available on channel")
                return 0
            
            remote_version = remote_conn.transport.remote_version
            logger.debug(f"Remote SSH version: {remote_version}")
            
            # Check for invalid (empty) responses
            for pattern in invalid_responses:
                if re.search(pattern, remote_version, flags=re.IGNORECASE):
                    return 0
            
            # Check for positive matches
            for pattern in search_patterns:
                if re.search(pattern, remote_version, flags=re_flags):
                    logger.debug(f"Remote version pattern matched: {pattern}")
                    return priority
                    
        except Exception as e:
            logger.warning(f"Exception during remote version detection: {e}")
            return 0
        
        return 0
    
    def collect_detection_commands(self, sanitize: bool = False) -> Dict[str, str]:
        """
        Collect outputs from all SSH detection commands.
        
        Extracts unique commands from SSH_MAPPER_DICT and executes each one,
        returning a dictionary mapping commands to their outputs.
        
        Args:
            sanitize: If True, remove escape characters and control codes from outputs
        
        Returns:
            Dict[str, str]: Mapping of {command: output}
        """
        return self.collector.collect_detection_commands(sanitize=sanitize)
    
    def collect_additional_commands(self, commands: List[str], sanitize: bool = False) -> Dict[str, str]:
        """
        Collect outputs from additional user-specified commands.
        
        Filters out commands that are already in the detection commands list
        to avoid duplication, then executes the remaining commands.
        
        Args:
            commands: List of commands to execute
            sanitize: If True, remove escape characters and control codes from outputs
            
        Returns:
            Dict[str, str]: Mapping of {command: output} for non-duplicate commands
        """
        return self.collector.collect_additional_commands(commands, sanitize=sanitize)
    
    def get_ssh_data(self, detection_commands: Optional[Dict[str, str]] = None, 
                     additional_commands: Optional[Dict[str, str]] = None,
                     include_banners: bool = True):
        """
        Get collected SSH data.
        
        Args:
            detection_commands: Optional dict of detection command outputs
            additional_commands: Optional dict of additional command outputs
            include_banners: If False, exclude banner fields from result (default: True)
        
        Returns:
            SSHData object with all banner fields, prompt, and command outputs
        """
        return self.collector.get_ssh_data(
            ssh_version=self.ssh_version,
            banner=self.banner,
            banner_auth=self.banner_auth,
            banner_motd=self.banner_motd,
            prompt=self.prompt,
            detection_commands=detection_commands,
            additional_commands=additional_commands,
            include_banners=include_banners
        )
    
    def disconnect(self) -> None:
        """Disconnect the SSH connection."""
        self.client.disconnect()
