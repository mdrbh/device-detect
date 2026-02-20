"""
Output formatters for CLI results.
"""

import json
import yaml
from typing import List
from tabulate import tabulate
from device_detect.models import DetectionResult


def format_json(results: List[DetectionResult], indent: int = 2) -> str:
    """Format results as JSON."""
    data = [result.to_dict() for result in results]
    return json.dumps(data, indent=indent)


def format_yaml(results: List[DetectionResult]) -> str:
    """Format results as YAML."""
    data = [result.to_dict() for result in results]
    return yaml.dump(data, default_flow_style=False, sort_keys=False)


def format_table(results: List[DetectionResult]) -> str:
    """Format results as table."""
    headers = ["Hostname", "Mode", "Method", "Success", "Device Type", "Confidence", "Total Time (s)"]
    rows = []
    
    for result in results:
        # Show confidence score for detect and offline modes (not for collect mode)
        if result.operation_mode in ["detect", "offline"]:
            confidence = f"{result.score}%" if result.score > 0 else "0%"
        else:
            confidence = "N/A"
        
        rows.append([
            result.hostname,
            result.operation_mode,
            result.method or "N/A",
            "✓" if result.success else "✗",
            result.device_type or "N/A",
            confidence,
            f"{result.timing.total_seconds:.2f}" if result.timing else "N/A"
        ])
    
    return tabulate(rows, headers=headers, tablefmt="grid")


def format_csv(results: List[DetectionResult], delimiter: str = ";") -> str:
    """
    Format results as CSV.
    
    Args:
        results: List of DetectionResult objects
        delimiter: CSV delimiter (default: ";")
    
    Returns:
        CSV formatted string
    """
    import io
    import csv
    
    output = io.StringIO()
    writer = csv.writer(output, delimiter=delimiter, lineterminator='\n')
    
    # Header
    writer.writerow([
        "hostname", "operation_mode", "method", "success", "device_type", "score",
        "total_seconds", "snmp_sys_descr", "snmp_sys_object_id", "snmp_sys_name",
        "ssh_version", "ssh_banner", "ssh_prompt"
    ])
    
    # Data rows
    for result in results:
        writer.writerow([
            result.hostname,
            result.operation_mode,
            result.method or "",
            result.success,
            result.device_type or "",
            result.score,
            result.timing.total_seconds if result.timing else "",
            result.snmp_data.sys_descr if result.snmp_data else "",
            result.snmp_data.sys_object_id if result.snmp_data else "",
            result.snmp_data.sys_name if result.snmp_data else "",
            result.ssh_data.ssh_version if result.ssh_data else "",
            result.ssh_data.banner if result.ssh_data else "",
            result.ssh_data.prompt if result.ssh_data else ""
        ])
    
    return output.getvalue()


def format_excel(results: List[DetectionResult], output_file: str) -> None:
    """Format results as Excel file."""
    try:
        import pandas as pd
    except ImportError:
        raise ImportError("pandas is required for Excel output. Install with: pip install pandas openpyxl")
    
    # Prepare data
    data = []
    for result in results:
        row = {
            "hostname": result.hostname,
            "operation_mode": result.operation_mode,
            "method": result.method or "",
            "success": result.success,
            "device_type": result.device_type or "",
            "score": result.score,
            "total_seconds": result.timing.total_seconds if result.timing else None,
        }
        
        # SNMP data
        if result.snmp_data:
            row["snmp_sys_descr"] = result.snmp_data.sys_descr
            row["snmp_sys_object_id"] = result.snmp_data.sys_object_id
            row["snmp_sys_uptime"] = result.snmp_data.sys_uptime
            row["snmp_sys_name"] = result.snmp_data.sys_name
        
        # SSH data
        if result.ssh_data:
            row["ssh_version"] = result.ssh_data.ssh_version
            row["ssh_banner"] = result.ssh_data.banner
            row["ssh_prompt"] = result.ssh_data.prompt
            row["ssh_banner_length"] = len(result.ssh_data.banner) if result.ssh_data.banner else 0
        
        data.append(row)
    
    # Create DataFrame and save
    df = pd.DataFrame(data)
    df.to_excel(output_file, index=False, engine='openpyxl')


def save_output(results: List[DetectionResult], output_format: str, output_file: str = None, csv_delimiter: str = ";") -> str:
    """
    Save or return formatted output.
    
    Args:
        results: List of DetectionResult objects
        output_format: One of: json, yaml, table, csv, excel
        output_file: Optional output file path
        csv_delimiter: CSV delimiter character (default: ";")
        
    Returns:
        Formatted string (except for excel which writes to file)
    """
    if output_format == "json":
        content = format_json(results)
    elif output_format == "yaml":
        content = format_yaml(results)
    elif output_format == "table":
        content = format_table(results)
    elif output_format == "csv":
        content = format_csv(results, delimiter=csv_delimiter)
    elif output_format == "excel":
        if not output_file:
            raise ValueError("output_file required for Excel format")
        format_excel(results, output_file)
        return f"Results saved to {output_file}"
    else:
        raise ValueError(f"Unsupported format: {output_format}")
    
    # Write to file if specified
    if output_file and output_format != "excel":
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(content)
        return f"Results saved to {output_file}"
    
    return content
