"""
Data models for device detection results.
"""

from dataclasses import dataclass, field, asdict
from typing import Optional, Dict, List, Any
import json


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
class MethodResult:
    """
    Result from an internal detection method (_try_snmp_detection, _try_ssh_detection, etc.).
    
    This lightweight dataclass encapsulates both success and error states,
    making error handling explicit and type-safe.
    
    Attributes:
        device_type: Detected device type (e.g., 'cisco_ios'), None if not detected or error
        snmp_data: SNMP collected data, None if not applicable or error
        ssh_data: SSH collected data, None if not applicable or error
        error: Error message if operation failed, None if successful
        error_type: Error category (e.g., 'TimeoutError', 'AuthenticationError')
        error_details: Additional error context (library, original exception, etc.)
    """
    device_type: Optional[str] = None
    snmp_data: Optional['SNMPData'] = None
    ssh_data: Optional['SSHData'] = None
    error: Optional[str] = None
    error_type: Optional[str] = None
    error_details: Optional[Dict[str, Any]] = None
    
    @property
    def success(self) -> bool:
        """Check if the operation was successful (no error)."""
        return self.error is None
    
    @property
    def failed(self) -> bool:
        """Check if the operation failed (has error)."""
        return self.error is not None


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
        scrapli_driver: Scrapli driver name for the detected device type
        napalm_driver: NAPALM driver name for the detected device type
        nornir_driver: Nornir driver name for the detected device type
        ansible_driver: Ansible network_os for the detected device type
        error: Error message if operation failed (None if successful)
        error_type: Error category (e.g., 'TimeoutError', 'AuthenticationError')
        error_details: Additional error context (library, original exception, etc.)
        warnings: List of non-fatal warnings collected during operation
    """
    hostname: str
    operation_mode: str  # 'detect' or 'collect'
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
    scrapli_driver: Optional[str] = None
    napalm_driver: Optional[str] = None
    nornir_driver: Optional[str] = None
    ansible_driver: Optional[str] = None
    error: Optional[str] = None
    error_type: Optional[str] = None
    error_details: Optional[Dict[str, Any]] = None
    all_errors: Optional[List[Dict[str, Any]]] = None
    warnings: Optional[List[str]] = None
    
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
            scrapli_driver=data.get('scrapli_driver'),
            napalm_driver=data.get('napalm_driver'),
            nornir_driver=data.get('nornir_driver'),
            ansible_driver=data.get('ansible_driver'),
            error=data.get('error'),
            error_type=data.get('error_type'),
            error_details=data.get('error_details'),
            warnings=data.get('warnings')
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
