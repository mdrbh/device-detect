"""SSH command collection (detection + additional commands)."""

import logging
from typing import Dict, List, Optional

from device_detect.patterns import SSH_MAPPER_DICT
from device_detect.models import SSHData
from device_detect.ssh.utils import strip_ansi_codes

logger = logging.getLogger(__name__)


class SSHCollector:
    """
    SSH data collector for detection and additional commands.
    
    Handles extraction of unique commands from SSH_MAPPER_DICT,
    execution of detection commands, execution of additional user commands,
    deduplication, and building SSHData objects.
    """
    
    def __init__(self, command_executor) -> None:
        """
        Initialize SSH collector.
        
        Args:
            command_executor: SSHCommandExecutor instance for command execution
        """
        self.command_executor = command_executor
    
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
        logger.info("Collecting SSH detection commands outputs")
        
        # Extract all unique commands from SSH_MAPPER_DICT
        unique_commands = set()
        
        for device_type, config in SSH_MAPPER_DICT.items():
            # Handle single command pattern
            if "cmd" in config:
                unique_commands.add(config["cmd"])
            # Handle multi-command pattern
            elif "commands" in config:
                for cmd_dict in config["commands"]:
                    if "cmd" in cmd_dict:
                        unique_commands.add(cmd_dict["cmd"])
        
        # Remove empty commands
        unique_commands.discard("")
        
        logger.info(f"Found {len(unique_commands)} unique detection commands")
        
        # Execute each command and collect output
        command_outputs = {}
        for cmd in sorted(unique_commands):
            try:
                logger.debug(f"Collecting output for: {cmd}")
                output = self.command_executor.send_command_wrapper(cmd)
                # Sanitize output if requested - strip ANSI codes
                if sanitize and output:
                    output = strip_ansi_codes(output)
                command_outputs[cmd] = output
            except Exception as e:
                logger.warning(f"Failed to collect command '{cmd}': {e}")
                command_outputs[cmd] = f"ERROR: {str(e)}"
        
        logger.info(f"Successfully collected {len(command_outputs)} command outputs")
        return command_outputs
    
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
        if not commands:
            return {}
        
        logger.info(f"Processing {len(commands)} additional commands")
        
        # Get detection commands for deduplication
        detection_commands = set()
        for device_type, config in SSH_MAPPER_DICT.items():
            if "cmd" in config:
                detection_commands.add(config["cmd"])
            elif "commands" in config:
                for cmd_dict in config["commands"]:
                    if "cmd" in cmd_dict:
                        detection_commands.add(cmd_dict["cmd"])
        
        # Filter out duplicates
        filtered_commands = []
        duplicates = []
        for cmd in commands:
            if cmd in detection_commands:
                duplicates.append(cmd)
                logger.debug(f"Skipping duplicate command: {cmd}")
            else:
                filtered_commands.append(cmd)
        
        if duplicates:
            logger.info(f"Skipped {len(duplicates)} duplicate commands already in detection list")
        
        if not filtered_commands:
            logger.info("No additional commands to collect after deduplication")
            return {}
        
        logger.info(f"Collecting {len(filtered_commands)} additional commands")
        
        # Execute each command and collect output
        command_outputs = {}
        for cmd in filtered_commands:
            try:
                logger.debug(f"Collecting output for additional command: {cmd}")
                output = self.command_executor.send_command_wrapper(cmd)
                # Sanitize output if requested - strip ANSI codes
                if sanitize and output:
                    output = strip_ansi_codes(output)
                command_outputs[cmd] = output
            except Exception as e:
                logger.warning(f"Failed to collect additional command '{cmd}': {e}")
                command_outputs[cmd] = f"ERROR: {str(e)}"
        
        logger.info(f"Successfully collected {len(command_outputs)} additional command outputs")
        return command_outputs
    
    def get_ssh_data(
        self,
        ssh_version: Optional[str],
        banner: Optional[str],
        banner_auth: Optional[str],
        banner_motd: Optional[str],
        prompt: Optional[str],
        detection_commands: Optional[Dict[str, str]] = None,
        additional_commands: Optional[Dict[str, str]] = None,
        include_banners: bool = True
    ) -> SSHData:
        """
        Get collected SSH data.
        
        Args:
            ssh_version: SSH server version string
            banner: Combined banner (auth + MOTD)
            banner_auth: Authentication banner
            banner_motd: MOTD banner
            prompt: Device prompt
            detection_commands: Optional dict of detection command outputs
            additional_commands: Optional dict of additional command outputs
            include_banners: If False, exclude banner fields from result (default: True)
        
        Returns:
            SSHData object with all banner fields, prompt, and command outputs
        """
        # Conditionally include banners based on flag
        final_banner = banner if include_banners else None
        final_banner_auth = banner_auth if include_banners else None
        final_banner_motd = banner_motd if include_banners else None
        
        return SSHData(
            ssh_version=ssh_version,
            banner=final_banner,
            banner_auth=final_banner_auth,
            banner_motd=final_banner_motd,
            prompt=prompt,
            detection_commands=detection_commands,
            additional_commands=additional_commands
        )
