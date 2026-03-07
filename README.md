# Device-Detect

Automatic network device type detection using SNMP and SSH protocols.

## Features

- Automatic device detection (manufacturer, model, OS version)
- Multi-protocol support: SNMP (v2c, v3) and SSH
- Multi-vendor: Cisco, Aruba, HP, Fortinet, OneAccess
- CLI and Python API
- Parallel processing for multiple devices
- Multiple output formats (JSON, CSV, YAML, Excel)

## Installation

```bash
pip install device-detect
```

Or from source:
```bash
git clone https://github.com/mdrbh/device-detect.git
cd device-detect
pip install -e .
```

## Quick Start

### Python API

```python
from device_detect import DeviceDetector

# SNMP detection
detector = DeviceDetector(
    host="192.168.1.1",
    snmp_community="public"
)
result = detector.detect()
print(f"Device: {result.device_type}")

# SSH detection
detector = DeviceDetector(
    host="192.168.1.1",
    ssh_username="admin",
    ssh_password="password"
)
result = detector.detect(method="ssh")

# Combined (SNMP + SSH)
detector = DeviceDetector(
    host="192.168.1.1",
    snmp_community="public",
    ssh_username="admin",
    ssh_password="password"
)
result = detector.detect(method="auto")
```

### CLI

```bash
# Single device
device-detect detect --host 192.168.1.1 --snmp-community public

# Multiple devices from config
device-detect detect --config devices.yaml --output results.xlsx --parallel

# List supported patterns
device-detect list-patterns
```

## Supported Devices

- **Cisco**: IOS, IOS-XE, IOS-XR, NX-OS, ASA, FTD, WLC, Viptela
- **Aruba**: AOS-CX, ProCurve
- **HP**: Comware, ProCurve
- **Fortinet**: FortiGate
- **OneAccess**: OneOS

## Credits

This project is based on the device autodetection logic from [Netmiko](https://github.com/ktbyers/netmiko) by Kirk Byers. The original code has been refactored, modularized, and extended with comprehensive error handling capabilities.

## License

MIT License - see [LICENSE](LICENSE) file for details.

## Author

Mohamed RABAH ([@mdrbh](https://github.com/mdrbh))
