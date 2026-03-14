"""
Data models for device detection results.
"""

from dataclasses import dataclass, field, asdict
from typing import Optional, Dict, List, Any
from datetime import datetime
import json


# Error type priority constants (used for primary_error selection)
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


@dataclass
class SNMPData:
    """SNMP collected data."""
    sys_descr: Optional[str] = None
    sys_object_id: Optional[str] = None
    sys_uptime: Optional[str] = None
    sys_name: Optional[str] = None
    
    @classmethod
    def from_dict(cls, data: Optional[dict]) -> Optional['SNMPData']:
        """Create SNMPData from dictionary."""
        if not data:
            return None
        return cls(**data)


@dataclass
class SSHData:
    """SSH collected data."""
    ssh_version: Optional[str] = None      # Remote SSH server version
    banner: Optional[str] = None           # Complete combined banner (with separators)
    banner_auth: Optional[str] = None      # Authentication banner from SSH handshake
    banner_motd: Optional[str] = None      # MOTD and post-login messages
    prompt: Optional[str] = None           # Identified prompt
    detection_commands: Optional[Dict[str, str]] = None  # Detection commands: {command: output}
    additional_commands: Optional[Dict[str, str]] = None  # Additional commands: {command: output}
    
    @classmethod
    def from_dict(cls, data: Optional[dict]) -> Optional['SSHData']:
        """Create SSHData from dictionary."""
        if not data:
            return None
        return cls(**data)


@dataclass
class TimingData:
    """Detection timing information."""
    total_seconds: float
    phase_timings: Dict[str, float] = field(default_factory=dict)
    # Example: {"snmp_detect": 1.2, "ssh_connect": 0.5, "ssh_detect": 2.1}
    
    @classmethod
    def from_dict(cls, data: Optional[dict]) -> Optional['TimingData']:
        """Create TimingData from dictionary."""
        if not data:
            return None
        return cls(**data)


@dataclass
class ErrorRecord:
    """
    Structured error/warning record with full context.
    
    Provides detailed information about errors and warnings encountered
    during device detection, including timestamp, phase, severity, and context.
    
    Attributes:
        timestamp: ISO 8601 formatted timestamp
        phase: Detection phase (e.g., "snmp_detect", "ssh_connect", "ssh_verify")
        method: Detection method ("snmp" or "ssh")
        severity: Error severity ("error" or "warning")
        error_type: Standardized error type from error_mapping constants
        message: Human-readable error message
        library: Source library ("puresnmp", "netmiko", "paramiko", "socket", None)
        exception_class: Original exception class name
        context: Additional context (command, OID, timeout, etc.)
        stack_trace: Stack trace (only when DEBUG logging enabled)
    """
    timestamp: str                          # ISO 8601 format
    phase: str                              # Detection phase
    method: str                             # "snmp" or "ssh"
    severity: str                           # "error" or "warning"
    error_type: str                         # Standardized error type
    message: str                            # Human-readable message
    library: Optional[str] = None           # Source library
    exception_class: Optional[str] = None   # Original exception class
    context: Optional[Dict[str, Any]] = None  # Additional context
    stack_trace: Optional[str] = None       # Stack trace (DEBUG only)
    
    @classmethod
    def from_dict(cls, data: dict) -> 'ErrorRecord':
        """Create ErrorRecord from dictionary."""
        return cls(**data)
    
    def to_dict(self) -> dict:
        """Convert to dictionary."""
        return asdict(self)


@dataclass
class MethodResult:
    """
    Result from an internal detection method (_try_snmp_detection, _try_ssh_detection, etc.).
    
    This lightweight dataclass encapsulates both success and error states,
    making error handling explicit and type-safe.
    
    Attributes:
        device_type: Detected device type (e.g., 'cisco_ios'), None if not detected or error
        snmp_data: SNMP collected data, None if not applicable or error
        ssh_data: SSH collected data, None if not applicable or error
        error_record: ErrorRecord if operation failed, None if successful
    """
    device_type: Optional[str] = None
    snmp_data: Optional[SNMPData] = None
    ssh_data: Optional[SSHData] = None
    error_record: Optional[ErrorRecord] = None
    
    @property
    def success(self) -> bool:
        """Check if the operation was successful (no error)."""
        return self.error_record is None
    
    @property
    def failed(self) -> bool:
        """Check if the operation failed (has error)."""
        return self.error_record is not None


@dataclass
class DetectionResult:
    """
    Complete device detection result.
    
    Attributes:
        hostname: Target device hostname/IP
        operation_mode: Operation mode ('detect', 'collect', or 'offline')
        method: Detection/collection method ('SNMP', 'SSH', or 'SNMP+SSH')
        success: Whether detection was successful
        device_type: Detected device type (e.g., 'cisco_ios'), None in collection mode
        score: Detection confidence score (0-100), 0 in collection mode
        snmp_data: SNMP collected data (if SNMP was used)
        ssh_data: SSH collected data (if SSH was used)
        timing: Timing information for detection phases
        ssh_verification_attempted: Whether SSH verification of SNMP result was attempted
        ssh_verification_success: Whether SSH verification succeeded (None if not attempted)
        verification_notes: Notes about verification process (errors, edge cases)
        scrapli_platform: Scrapli platform name for the detected device type
        napalm_driver: NAPALM driver name for the detected device type
        nornir_platform: Nornir platform name for the detected device type
        ansible_network_os: Ansible network_os for the detected device type
        error_records: List of ErrorRecord objects (errors and warnings)
    """
    hostname: str
    operation_mode: str  # 'detect', 'collect', or 'offline'
    method: Optional[str]  # 'SNMP', 'SSH', or 'SNMP+SSH'
    success: bool
    device_type: Optional[str]
    score: int  # 0-100 percentage
    snmp_data: Optional[SNMPData] = None
    ssh_data: Optional[SSHData] = None
    timing: Optional[TimingData] = None
    ssh_verification_attempted: bool = False
    ssh_verification_success: Optional[bool] = None
    verification_notes: Optional[str] = None
    scrapli_platform: Optional[str] = None
    napalm_driver: Optional[str] = None
    nornir_platform: Optional[str] = None
    ansible_network_os: Optional[str] = None
    error_records: List[ErrorRecord] = field(default_factory=list)
    
    @property
    def has_errors(self) -> bool:
        """Check if any errors are present."""
        return any(r.severity == "error" for r in self.error_records)
    
    @property
    def has_warnings(self) -> bool:
        """Check if any warnings are present."""
        return any(r.severity == "warning" for r in self.error_records)
    
    @property
    def errors(self) -> List[ErrorRecord]:
        """Get all error records (severity='error')."""
        return [r for r in self.error_records if r.severity == "error"]
    
    @property
    def warnings(self) -> List[ErrorRecord]:
        """Get all warning records (severity='warning')."""
        return [r for r in self.error_records if r.severity == "warning"]
    
    @property
    def primary_error(self) -> Optional[ErrorRecord]:
        """
        Get highest priority error based on error_type.
        
        Returns:
            ErrorRecord with highest priority, or None if no errors
        """
        errors = self.errors
        if not errors:
            return None
        return sorted(errors, key=lambda e: ERROR_PRIORITY.get(e.error_type, 99))[0]
    
    @classmethod
    def from_dict(cls, data: dict) -> 'DetectionResult':
        """
        Create DetectionResult from dictionary.
        
        Args:
            data: Dictionary representation of DetectionResult
            
        Returns:
            DetectionResult instance
        """
        # Reconstruct nested dataclass objects
        snmp_data = SNMPData.from_dict(data.get('snmp_data'))
        ssh_data = SSHData.from_dict(data.get('ssh_data'))
        timing = TimingData.from_dict(data.get('timing'))
        
        # Reconstruct error_records
        error_records = []
        if 'error_records' in data and data['error_records']:
            error_records = [ErrorRecord.from_dict(err) for err in data['error_records']]
        
        return cls(
            hostname=data['hostname'],
            operation_mode=data.get('operation_mode', 'detect'),
            method=data.get('method'),
            success=data['success'],
            device_type=data.get('device_type'),
            score=data.get('score', 0),
            snmp_data=snmp_data,
            ssh_data=ssh_data,
            timing=timing,
            ssh_verification_attempted=data.get('ssh_verification_attempted', False),
            ssh_verification_success=data.get('ssh_verification_success'),
            verification_notes=data.get('verification_notes'),
            scrapli_platform=data.get('scrapli_platform'),
            napalm_driver=data.get('napalm_driver'),
            nornir_platform=data.get('nornir_platform'),
            ansible_network_os=data.get('ansible_network_os'),
            error_records=error_records
        )
    
    def to_dict(self) -> dict:
        """
        Convert to dictionary.
        
        Returns:
            Dictionary representation of the result
        """
        return asdict(self)
    
    def to_json(self, indent: int = 2) -> str:
        """
        Convert to JSON string.
        
        Args:
            indent: JSON indentation level
            
        Returns:
            JSON string representation
        """
        return json.dumps(self.to_dict(), indent=indent)
    
    def save_to_file(self, path: str, format: str = 'json', csv_delimiter: str = ';') -> str:
        """
        Save detection result to a single file.
        
        Args:
            path: Output file path (with or without extension)
            format: Output format - one of: 'json', 'csv', 'excel', 'yaml', 'table'
                   Default: 'json'
            csv_delimiter: CSV delimiter character (default: ';')
            
        Returns:
            str: Path to the saved file
            
        Examples:
            >>> result.save_to_file("output/device1.json")
            'output/device1.json'
            
            >>> result.save_to_file("output/device1.csv", format='csv')
            'output/device1.csv'
            
            >>> result.save_to_file("output/device1", format='excel')
            'output/device1.xlsx'
        """
        from device_detect.cli.formatters import save_output
        
        # Ensure path has correct extension if not provided
        ext_map = {'json': '.json', 'csv': '.csv', 'excel': '.xlsx', 'yaml': '.yaml', 'table': '.txt'}
        expected_ext = ext_map.get(format, f'.{format}')
        
        if not path.endswith(expected_ext):
            # Remove any existing extension and add the correct one
            import os
            base_path = os.path.splitext(path)[0]
            path = base_path + expected_ext
        
        # Wrap self in list to use existing save_output function
        results = [self]
        
        # Save and return path
        message = save_output(results, format, path, csv_delimiter=csv_delimiter)
        return path
    
    def save_to_files(self, base_path: str, formats: list = None, csv_delimiter: str = ';') -> dict:
        """
        Save detection result to multiple file formats simultaneously.
        
        Args:
            base_path: Base output path (without extension)
            formats: List of formats to save - any of: 'json', 'csv', 'excel', 'yaml', 'table'
                    Default: ['json']
            csv_delimiter: CSV delimiter character (default: ';')
            
        Returns:
            dict: Dictionary mapping format names to saved file paths
                 Example: {'json': 'output/device1.json', 'csv': 'output/device1.csv'}
            
        Examples:
            >>> result.save_to_files("output/device1")
            {'json': 'output/device1.json'}
            
            >>> result.save_to_files("output/device1", formats=['json', 'csv'])
            {'json': 'output/device1.json', 'csv': 'output/device1.csv'}
            
            >>> result.save_to_files("output/device1", formats=['json', 'csv', 'excel'])
            {'json': 'output/device1.json', 'csv': 'output/device1.csv', 'excel': 'output/device1.xlsx'}
        """
        if formats is None:
            formats = ['json']
        
        from device_detect.cli.formatters import save_output
        import os
        
        # Remove any extension from base_path
        base_path = os.path.splitext(base_path)[0]
        
        # Extension mapping
        ext_map = {'json': '.json', 'csv': '.csv', 'excel': '.xlsx', 'yaml': '.yaml', 'table': '.txt'}
        
        # Wrap self in list to use existing save_output function
        results = [self]
        
        # Save to each format
        saved_files = {}
        for fmt in formats:
            ext = ext_map.get(fmt, f'.{fmt}')
            file_path = base_path + ext
            save_output(results, fmt, file_path, csv_delimiter=csv_delimiter)
            saved_files[fmt] = file_path
        
        return saved_files