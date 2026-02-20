"""
Parallel processing utilities for CLI commands.
Handles concurrent device detection/collection using ThreadPoolExecutor.
"""

import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Callable, List, Any, Optional
from rich.console import Console

console = Console()
output_lock = threading.Lock()


def process_devices_parallel(
    hosts: List[str],
    process_func: Callable[[str], Any],
    max_workers: int = 10,
    sequential: bool = False,
    operation_name: str = "Processing"
) -> List[Any]:
    """
    Process multiple devices in parallel using ThreadPoolExecutor.
    
    Args:
        hosts: List of hostnames/IPs to process
        process_func: Function to call for each host. Should accept hostname as first arg.
        max_workers: Maximum number of concurrent workers (default: 10)
        sequential: If True, process devices sequentially (default: False)
        operation_name: Name of operation for display (e.g., "Detecting", "Collecting")
    
    Returns:
        List of results in completion order
    """
    results = []
    total = len(hosts)
    
    # Single device - no threading overhead
    if total == 1:
        host = hosts[0]
        try:
            result = process_func(host)
            results.append(result)
            with output_lock:
                _print_success(host, result, operation_name)
        except Exception as e:
            with output_lock:
                _print_error(host, e, operation_name)
        return results
    
    # Sequential mode (old behavior)
    if sequential:
        with output_lock:
            console.print(f"[cyan]{operation_name} {total} devices sequentially...[/cyan]\n")
        
        for idx, host in enumerate(hosts, 1):
            try:
                result = process_func(host)
                results.append(result)
                with output_lock:
                    _print_success(host, result, operation_name, idx, total)
            except Exception as e:
                with output_lock:
                    _print_error(host, e, operation_name, idx, total)
        return results
    
    # Parallel mode (default)
    with output_lock:
        console.print(f"[cyan]{operation_name} {total} devices in parallel ({max_workers} workers)...[/cyan]\n")
    
    completed_count = 0
    success_count = 0
    failed_count = 0
    
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        # Submit all tasks
        future_to_host = {executor.submit(process_func, host): host for host in hosts}
        
        # Process as they complete
        for future in as_completed(future_to_host):
            completed_count += 1
            host = future_to_host[future]
            
            try:
                result = future.result()
                results.append(result)
                success_count += 1
                
                with output_lock:
                    _print_success(host, result, operation_name, completed_count, total)
                    
            except Exception as e:
                failed_count += 1
                
                with output_lock:
                    _print_error(host, e, operation_name, completed_count, total)
    
    # Print summary
    with output_lock:
        console.print()
        if failed_count == 0:
            console.print(f"[green]✓ Completed: {success_count}/{total} successful[/green]")
        else:
            console.print(f"[yellow]⚠ Completed: {success_count}/{total} successful, {failed_count} failed[/yellow]")
    
    return results


def _print_success(host: str, result: Any, operation: str, idx: Optional[int] = None, total: Optional[int] = None):
    """Print success message for a device."""
    prefix = f"[{idx}/{total}] " if idx and total else ""
    
    # Extract device_type if available
    device_info = ""
    if hasattr(result, 'device_type') and result.device_type:
        device_info = f" → {result.device_type}"
    
    # Extract timing if available
    timing_info = ""
    if hasattr(result, 'timing') and result.timing:
        timing_info = f" ({result.timing.total_seconds:.1f}s)"
    
    console.print(f"{prefix}[green]✓[/green] {host}{device_info}{timing_info}")


def _print_error(host: str, error: Exception, operation: str, idx: Optional[int] = None, total: Optional[int] = None):
    """Print error message for a device."""
    prefix = f"[{idx}/{total}] " if idx and total else ""
    error_msg = str(error)
    
    # Truncate very long error messages
    if len(error_msg) > 100:
        error_msg = error_msg[:97] + "..."
    
    console.print(f"{prefix}[red]✗[/red] {host} → Failed: {error_msg}")
