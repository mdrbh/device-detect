"""
Setup configuration for device-detect package.
"""

from setuptools import setup, find_packages
from pathlib import Path

# Read the contents of README if it exists
readme_file = Path(__file__).parent / "README.md"
long_description = ""
if readme_file.exists():
    long_description = readme_file.read_text(encoding="utf-8")

setup(
    name="device-detect",
    version="0.7.0",
    author="Mohamed RABAH",
    author_email="mdrbh0@gmail.com",
    description="Automatic network device type detection using SNMP and SSH",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/mdrbh/device-detect",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: System Administrators",
        "Intended Audience :: Telecommunications Industry",
        "Topic :: System :: Networking",
        "Topic :: System :: Networking :: Monitoring",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
    ],
    python_requires=">=3.8",
    install_requires=[
        "netmiko>=4.0.0",
        "puresnmp[crypto]>=2.0.0",
        "paramiko>=2.7.0",
        "netutils>=1.0.0",
        "click>=8.0.0",
        "rich>=12.0.0",
        "tabulate>=0.9.0",
        "pyyaml>=6.0.0",
        "pandas>=2.0.0",
        "openpyxl>=3.0.0",
    ],
    entry_points={
        "console_scripts": [
            "device-detect=device_detect.cli.main:cli",
        ],
    },
    include_package_data=True,
    zip_safe=False,
)
