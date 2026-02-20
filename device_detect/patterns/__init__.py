"""
Device detection patterns organized by vendor and device type.

This module dynamically loads all device patterns from vendor subdirectories.
"""

import importlib
import os
from pathlib import Path
from typing import Dict, Any

# Device type aliases for variants
DEVICE_TYPE_ALIASES = {
    "cisco_wlc_85": "cisco_wlc",
    "cisco_xr_2": "cisco_xr",
}

# Initialize pattern dictionaries
SSH_MAPPER_DICT: Dict[str, Dict[str, Any]] = {}
SNMP_MAPPER_DICT: Dict[str, Dict[str, Any]] = {}


def _load_patterns():
    """Dynamically load all device patterns from vendor subdirectories."""
    patterns_dir = Path(__file__).parent
    
    # Iterate through vendor directories
    for vendor_dir in patterns_dir.iterdir():
        if not vendor_dir.is_dir() or vendor_dir.name.startswith('_'):
            continue
        
        # Iterate through device type files in vendor directory
        for pattern_file in vendor_dir.iterdir():
            if pattern_file.suffix != '.py' or pattern_file.name.startswith('_'):
                continue
            
            # Extract device type name from filename (e.g., cisco_ios.py -> cisco_ios)
            device_type = pattern_file.stem
            
            # Import the module dynamically
            module_path = f"device_detect.patterns.{vendor_dir.name}.{device_type}"
            try:
                module = importlib.import_module(module_path)
                
                # Check if module has PATTERNS attribute
                if hasattr(module, 'PATTERNS'):
                    patterns = module.PATTERNS
                    
                    # Load SSH patterns
                    if patterns.get('ssh'):
                        SSH_MAPPER_DICT[device_type] = patterns['ssh']
                    
                    # Load SNMP patterns
                    if patterns.get('snmp'):
                        SNMP_MAPPER_DICT[device_type] = patterns['snmp']
                        
            except Exception as e:
                # Log error but continue loading other patterns
                import logging
                logger = logging.getLogger(__name__)
                logger.warning(f"Failed to load patterns from {module_path}: {e}")


# Load all patterns on module import
_load_patterns()


# Export public API
__all__ = [
    'SSH_MAPPER_DICT',
    'SNMP_MAPPER_DICT',
    'DEVICE_TYPE_ALIASES',
]
