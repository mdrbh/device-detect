"""
Detection and collection operation workflows.
"""

from device_detect.operations.detect import DetectionOperation
from device_detect.operations.collect import CollectionOperation
from device_detect.operations.offline import (
    detect_offline,
    detect_offline_from_dict,
    detect_from_snmp_data,
    detect_from_ssh_data,
    calculate_offline_score
)

__all__ = [
    'DetectionOperation',
    'CollectionOperation',
    'detect_offline',
    'detect_offline_from_dict',
    'detect_from_snmp_data',
    'detect_from_ssh_data',
    'calculate_offline_score'
]