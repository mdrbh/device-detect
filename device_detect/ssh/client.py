"""SSH connection, banners, and prompt identification."""

import logging
import time
import re
from typing import Any, Optional

import paramiko
from netmiko.ssh_dispatcher import ConnectHandler
from netmiko.base_connection import BaseConnection

from device_detect.exceptions import SSHDetectionError
from device_detect.ssh.utils import strip_ansi_codes

logger = logging.getLogger(__name__)


class SSHClient:
    """
    SSH client for device connection and banner/prompt capture.
    
    Handles SSH connection establishment, SSH version capture,
    authentication banner capture, and prompt identification.
    """
    
    def __init__(
        self,
        timings: dict,
        *args: Any,
        **kwargs: Any
    ) -> None:
        """
        Initialize SSH client and establish connection.
        
        Args:
            timings: Timing profile dictionary with connection parameters
            *args: Positional arguments passed to netmiko ConnectHandler
            **kwargs: Keyword arguments passed to netmiko ConnectHandler
        """
        self.timings = timings
        
        logger.info(f"Establishing SSH connection to {kwargs.get('host', 'unknown')}")
        
        try:
            self.connection = ConnectHandler(*args, **kwargs)
        except Exception as e:
            logger.error(f"Failed to establish SSH connection: {e}")
            raise SSHDetectionError(f"SSH connection failed: {e}")
        
        # Post-connection stabilization delay - let login complete
        post_delay = self.timings["post_connection_delay"]
        logger.debug(f"Waiting {post_delay}s for connection to stabilize")
        time.sleep(post_delay)
        
        # Clear initial buffer (login messages, MOTD, etc.)
        output = BaseConnection._test_channel_read(self.connection)
        self.initial_buffer = output
        logger.debug(f"Initial buffer cleared: {len(output)} characters")
        
        # Initialize captured data
        self.ssh_version: Optional[str] = None
        self.banner: Optional[str] = None
        self.banner_auth: Optional[str] = None
        self.banner_motd: Optional[str] = None
        self.prompt: Optional[str] = None
        
        # Capture SSH data
        self.capture_ssh_version()
        self.capture_auth_banner()
        self.identify_prompt()
    
    def capture_ssh_version(self) -> None:
        """Capture SSH server version from paramiko transport."""
        try:
            remote_conn = self.connection.remote_conn
            if isinstance(remote_conn, paramiko.Channel) and remote_conn.transport:
                self.ssh_version = remote_conn.transport.remote_version
                logger.debug(f"Captured SSH version: {self.ssh_version}")
        except Exception as e:
            logger.warning(f"Failed to capture SSH version: {e}")
            self.ssh_version = None
    
    def capture_auth_banner(self) -> None:
        """
        Capture authentication banner from paramiko transport.
        
        This banner is sent during the SSH handshake, before authentication.
        It's typically used for legal notices or welcome messages.
        
        Note: Paramiko stores this in transport.auth_handler.banner
        """
        try:
            remote_conn = self.connection.remote_conn
            if isinstance(remote_conn, paramiko.Channel) and remote_conn.transport:
                transport = remote_conn.transport
                
                # Try to get banner from auth_handler
                if hasattr(transport, 'auth_handler') and transport.auth_handler:
                    if hasattr(transport.auth_handler, 'banner'):
                        auth_banner = transport.auth_handler.banner
                        if auth_banner:
                            # auth_banner is bytes, decode it
                            if isinstance(auth_banner, bytes):
                                self.banner_auth = auth_banner.decode('utf-8', errors='ignore').strip()
                            else:
                                self.banner_auth = str(auth_banner).strip()
                            logger.debug(f"Captured auth banner: {len(self.banner_auth)} characters")
                            return
                
                # Banner not found
                self.banner_auth = None
                logger.debug("No auth banner available")
        except Exception as e:
            logger.warning(f"Failed to capture auth banner: {e}")
            self.banner_auth = None
    
    def identify_prompt(self) -> None:
        """
        Identify device prompt from initial buffer and separate banners.
        
        The prompt is typically the last line of the initial buffer.
        MOTD banner is everything before the prompt (from initial_buffer).
        Combined banner includes both auth banner and MOTD with separators.
        """
        try:
            if not self.initial_buffer:
                logger.warning("No initial buffer to identify prompt")
                return
            
            # Split buffer into lines and filter out empty lines
            lines = [line for line in self.initial_buffer.strip().split('\n') if line.strip()]
            
            if not lines:
                return
            
            # Last non-empty line is typically the prompt
            for line in reversed(lines):
                # Strip ANSI escape sequences
                cleaned_line = strip_ansi_codes(line).strip()
                if cleaned_line:
                    self.prompt = cleaned_line
                    logger.debug(f"Identified prompt (cleaned): {self.prompt}")
                    break
            
            # MOTD banner is everything except the last line (prompt)
            # Only set banner_motd if there's actual content before the prompt
            if self.prompt and len(lines) > 1:
                # Join all lines except the last one (which is the prompt)
                banner_lines = lines[:-1]
                # Clean ANSI codes from MOTD
                banner_text = '\n'.join(banner_lines)
                cleaned_banner = strip_ansi_codes(banner_text).strip()
                
                # Remove any trailing occurrences of the prompt from the banner
                if cleaned_banner and self.prompt:
                    # Keep removing the prompt from the end until it's gone
                    while cleaned_banner.endswith(self.prompt):
                        cleaned_banner = cleaned_banner[:-len(self.prompt)].strip()
                
                # Only set if there's actual content (not just whitespace)
                if cleaned_banner:
                    self.banner_motd = cleaned_banner
                    logger.debug(f"Captured MOTD banner: {len(self.banner_motd)} characters")
                else:
                    self.banner_motd = None
                    logger.debug("No MOTD banner (empty after removing prompts)")
            elif self.prompt and len(lines) == 1:
                # Only the prompt in buffer, no MOTD
                self.banner_motd = None
                logger.debug("No MOTD banner (only prompt in buffer)")
            else:
                # No prompt identified or no lines
                self.banner_motd = None
                logger.debug("No MOTD banner available")
            
            # Build combined banner with separators
            self.build_combined_banner()
                
        except Exception as e:
            logger.warning(f"Failed to identify prompt: {e}")
            self.prompt = None
            self.banner_motd = None
            self.banner_auth = None
            self.banner = None
    
    def build_combined_banner(self) -> None:
        """
        Build combined banner with separators for backwards compatibility.
        
        Format:
            --- [BANNER AUTH] ---
            <auth banner content>
            --- [BANNER MOTD] ---
            <MOTD content>
        """
        parts = []
        
        if self.banner_auth:
            parts.append("--- [BANNER AUTH] ---")
            parts.append(self.banner_auth)
        
        if self.banner_motd:
            parts.append("--- [BANNER MOTD] ---")
            parts.append(self.banner_motd)
        
        if parts:
            self.banner = '\n'.join(parts)
            logger.debug(f"Built combined banner: {len(self.banner)} characters")
        else:
            self.banner = None
    
    def get_connection(self):
        """Get the underlying netmiko connection."""
        return self.connection
    
    def disconnect(self) -> None:
        """Disconnect the SSH connection."""
        if self.connection:
            logger.debug("Disconnecting SSH connection")
            self.connection.disconnect()
