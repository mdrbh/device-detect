"""SSH command execution and output cleaning."""

import logging
import time
from typing import Dict

from device_detect.utils import sanitize_output
from device_detect.ssh.utils import strip_ansi_codes

logger = logging.getLogger(__name__)


class SSHCommandExecutor:
    """
    SSH command executor with output cleaning and caching.
    
    Handles command execution, response reading with prompt detection,
    output cleaning (removing echo, prompt, ANSI codes), and result caching.
    """
    
    def __init__(
        self,
        connection,
        prompt: str,
        timings: dict,
        results_cache: Dict[str, str]
    ) -> None:
        """
        Initialize SSH command executor.
        
        Args:
            connection: Netmiko SSH connection object
            prompt: Device prompt string
            timings: Timing profile dictionary
            results_cache: Dictionary for caching command results
        """
        self.connection = connection
        self.prompt = prompt
        self.timings = timings
        self.results_cache = results_cache
    
    def send_command(self, cmd: str = "") -> str:
        """
        Send command and read response using prompt-based detection.
        
        Reads data in a loop until the device prompt is detected at the end of output.
        This generic approach works with any device, handles paging automatically,
        and adapts to device response speed.
        
        Args:
            cmd: Command to send (empty string sends just newline)
            
        Returns:
            Command output as string (with command echo and prompt removed)
        """
        # Get timing parameters from profile
        read_interval = self.timings["read_interval"]
        max_wait = self.timings["max_wait"]
        
        # Send command
        self.connection.write_channel(cmd + "\n")
        time.sleep(0.1)  # Small delay to let command be sent
        
        # Read response in loop until prompt detected
        total_output = ""
        start_time = time.time()
        no_data_count = 0
        
        while time.time() - start_time < max_wait:
            # Wait before reading
            time.sleep(read_interval)
            
            # Read available data
            chunk = self.connection.read_channel()
            
            if chunk:
                # Data received
                chunk = sanitize_output(chunk)
                total_output += chunk
                no_data_count = 0
                
                # Check if prompt appears at end of output (command complete)
                if self.prompt and total_output.strip().endswith(self.prompt):
                    logger.debug(f"Prompt detected, command complete after {time.time() - start_time:.1f}s")
                    break
            else:
                # No data received
                no_data_count += 1
                
                # If no data for 3 consecutive reads, assume done
                if no_data_count >= 3:
                    logger.debug(f"No data for {no_data_count} reads, assuming command complete")
                    break
        
        elapsed = time.time() - start_time
        if elapsed >= max_wait:
            logger.warning(f"Command timed out after {elapsed:.1f}s, returning partial output")
        
        # Clean up the output: remove command echo and trailing prompt
        cleaned_output = self.clean_command_output(total_output, cmd)
        
        return cleaned_output
    
    def clean_command_output(self, output: str, cmd: str) -> str:
        """
        Clean command output by removing command echo, trailing prompt, and ANSI codes.
        
        This method provides a generic cleaning approach that works across different
        device types by:
        1. Stripping all ANSI escape sequences from the output
        2. Removing the command echo from the beginning
        3. Removing the trailing prompt
        
        Args:
            output: Raw command output from device
            cmd: The command that was sent
            
        Returns:
            Cleaned output with command echo, prompt, and ANSI codes removed
        """
        if not output:
            return output
        
        # Step 1: Strip ALL ANSI codes from output for cleaner results
        # This handles devices that send ANSI escape sequences (cursor positioning, colors, etc.)
        cleaned = strip_ansi_codes(output)
        
        # Step 2: Remove command echo from the beginning
        # The device typically echoes the command at the start of output
        if cmd:
            # Try to remove command echo - it can appear in different forms:
            # 1. On a separate line: "show version\nCisco IOS..."
            # 2. On the same line: "show versionCisco IOS..." (some devices)
            # 3. With extra spacing: "show version  \nCisco IOS..."
            
            # First, try exact match at the beginning (handles case 2)
            if cleaned.startswith(cmd):
                cleaned = cleaned[len(cmd):].lstrip()
                logger.debug(f"Removed command echo (inline) from output: '{cmd}'")
            else:
                # Try line-based removal (handles cases 1 and 3)
                lines = cleaned.split('\n')
                if lines and lines[0].strip() == cmd.strip():
                    # Remove the first line (command echo)
                    lines = lines[1:]
                    cleaned = '\n'.join(lines)
                    logger.debug(f"Removed command echo (line) from output: '{cmd}'")
        
        # Step 3: Remove trailing prompt
        if self.prompt:
            # Remove prompt from the end if present
            cleaned = cleaned.rstrip()
            if cleaned.endswith(self.prompt):
                cleaned = cleaned[:-len(self.prompt)].rstrip()
                logger.debug(f"Removed trailing prompt from output: '{self.prompt}'")
        
        # Step 4: Clean up extra whitespace
        # Remove leading/trailing whitespace but preserve internal formatting
        cleaned = cleaned.strip()
        
        return cleaned
    
    def is_response_incomplete(self, response: str, cmd: str) -> bool:
        """
        Check if a command response appears incomplete.
        
        Uses the detected prompt to validate response completeness.
        
        Args:
            response: Command response to validate
            cmd: Command that was sent (for context)
            
        Returns:
            True if response appears incomplete, False otherwise
        """
        if not response:
            # Empty response is considered incomplete
            return True
        
        # If we have a detected prompt, check if response ends with it
        if self.prompt:
            # Strip whitespace and check if response ends with prompt
            response_stripped = response.strip()
            if response_stripped and not response_stripped.endswith(self.prompt):
                logger.debug(f"Response doesn't end with expected prompt '{self.prompt}'")
                return True
        
        # Additional heuristic: very short responses (< 10 chars) might be incomplete
        # unless it's an empty command (just newline)
        if cmd and len(response.strip()) < 10:
            logger.debug(f"Response suspiciously short: {len(response.strip())} characters")
            return True
        
        return False
    
    def send_command_wrapper(self, cmd: str) -> str:
        """
        Send command with caching to avoid duplicate commands.
        
        Args:
            cmd: Command to send
            
        Returns:
            Cached or fresh command output
        """
        cached_result = self.results_cache.get(cmd)
        if cached_result is not None:
            logger.debug(f"Using cached result for command: {cmd}")
            return cached_result
        
        logger.debug(f"Sending command: {cmd}")
        response = self.send_command(cmd)
        self.results_cache[cmd] = response
        return response
