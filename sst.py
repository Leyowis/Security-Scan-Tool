import psutil
import platform
import logging
import socket
import os
import glob

# Logger setup
logging.basicConfig(
    filename="security_scan.log",
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    encoding="utf-8",
)

def log_and_print(message, level="info"):
    """Helper function to log and print messages."""
    log_func = getattr(logging, level, logging.info)
    log_func(message)
    print(message)

def skip_scan(scan_name):
    """Prompt the user to skip a scan."""
    while True:
        response = input(f"Do you want to start the {scan_name} scan? (Y/N): ").strip().lower()
        if response in ['y', 'yes']:
            return True
        elif response in ['n', 'no']:
            log_and_print(f"{scan_name} scan skipped by user.", level="info")
            return False

# DLLs/Modules to check based on OS
MODULES = {
    "windows": ["rsaenh.dll", "netapi32.dll", "wkscli.dll", "psapi.dll", "cscapi.dll"],
    "linux": ["libssl.so", "libcrypto.so", "libc.so", "ld-linux.so"],
    "darwin": ["libssl.dylib", "libcrypto.dylib", "libc.dylib", "libSystem.dylib"]
}

SUSPICIOUS_PROCESS_NAMES = ["meterpreter"]
SUSPICIOUS_PORTS = [4444, 5555, 6666]
SUSPICIOUS_KEYWORDS = ["meterpreter", "shell", "malware", "exploit"]

MEMORY_THRESHOLD_MB = 50
CPU_USAGE_THRESHOLD = 10

def get_suspicious_modules():
    """Return the list of suspicious modules based on the OS."""
    return MODULES.get(platform.system().lower(), [])

def get_process_name_by_pid(pid):
    """Get the process name by PID."""
    try:
        return psutil.Process(pid).name()
    except psutil.NoSuchProcess:
        return "Unknown"

def scan_processes():
    """Scan running processes and check for suspicious activity."""
    if not skip_scan("Process"):
        return
    
    meterpreter_found = False
    suspicious_modules_found = []
    log_and_print("Scanning all processes...\n")

    suspicious_modules = get_suspicious_modules()
    for process in psutil.process_iter(attrs=['pid', 'name', 'memory_info', 'cpu_percent']):
        try:
            pid, name, memory_usage, cpu_usage = (
                process.info['pid'],
                process.info['name'] or "Unknown",
                process.info['memory_info'].rss / (1024 * 1024),  # Memory in MB
                process.info['cpu_percent'] or 0  # CPU usage
            )

            # Check for Meterpreter
            if any(susp_name in name.lower() for susp_name in SUSPICIOUS_PROCESS_NAMES):
                meterpreter_found = True
                log_and_print(f"[ALERT] Meterpreter session detected! PID: {pid}, Name: {name}", level="alert")

            # Check for suspicious modules
            try:
                loaded_modules = [m.path.split("/")[-1].lower() for m in process.memory_maps()]
                for module in suspicious_modules:
                    if module.lower() in loaded_modules:
                        suspicious_modules_found.append((module, name, pid))
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                continue

            # Check for high resource usage
            if memory_usage > MEMORY_THRESHOLD_MB or cpu_usage > CPU_USAGE_THRESHOLD:
                log_and_print(f"[WARNING] High resource usage: PID: {pid}, Name: {name}, Memory: {memory_usage:.2f} MB, CPU: {cpu_usage:.2f}%", level="warning")

        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue

    if meterpreter_found:
        log_and_print("\n[ALERT] Meterpreter sessions detected!", level="alert")
    else:
        log_and_print("\n[INFO] No Meterpreter sessions found.", level="info")

    if suspicious_modules_found:
        log_and_print("\n[WARNING] Suspicious modules detected:", level="warning")
        for module, pname, pid in suspicious_modules_found:
            log_and_print(f"- Module: {module}, Process Name: {pname}, PID: {pid}", level="warning")

def scan_network_connections():
    """Scan network connections and ports."""
    if not skip_scan("Network connections"):
        return
    
    log_and_print("\nScanning network connections...\n")
    suspicious_connections = []

    for conn in psutil.net_connections(kind="inet"):
        try:
            laddr, raddr, status, pid = conn.laddr, conn.raddr, conn.status, conn.pid
            process_name = get_process_name_by_pid(pid)

            # Check for suspicious ports
            if laddr.port in SUSPICIOUS_PORTS or (raddr and raddr.port in SUSPICIOUS_PORTS):
                suspicious_connections.append((pid, process_name, conn.laddr, conn.raddr, status))

            # Check connection status
            if status not in ['ESTABLISHED', 'LISTENING']:
                log_and_print(f"[WARNING] Suspicious connection status: {status}, PID: {pid}, Process: {process_name}, Local: {conn.laddr}, Remote: {conn.raddr}", level="warning")

        except (psutil.AccessDenied, psutil.NoSuchProcess):
            continue

    if suspicious_connections:
        log_and_print("[ALERT] Suspicious network connections detected:", level="alert")
        for pid, process_name, laddr, raddr, status in suspicious_connections:
            log_and_print(f"- PID: {pid}, Process: {process_name}, Local: {laddr}, Remote: {raddr}, Status: {status}", level="alert")
    else:
        log_and_print("[INFO] No suspicious network connections found.", level="info")

def check_suspicious_files():
    """Check for suspicious files (e.g., Meterpreter-related files)."""
    if not skip_scan("File"):
        return
    
    log_and_print("\nScanning suspicious files...\n")
    suspicious_files = []
    potential_meterpreter_files = ["*.exe", "*.dll", "*.sys", "*.vbs", "*.bat", "*.sh"]

    for file_pattern in potential_meterpreter_files:
        for file_path in glob.glob(f"/**/{file_pattern}", recursive=True):
            if "meterpreter" in file_path.lower():
                suspicious_files.append(file_path)

    if suspicious_files:
        log_and_print("[ALERT] Suspicious files detected:", level="alert")
        for file in suspicious_files:
            log_and_print(f"- File: {file}", level="alert")
    else:
        log_and_print("[INFO] No suspicious files found.", level="info")

def main():
    """Main function to start the scans."""
    try:
        log_and_print(f"Operating System: {platform.system()} {platform.release()}")
        scan_processes()
        scan_network_connections()
        check_suspicious_files()
    except Exception as e:
        log_and_print(f"[ERROR] An error occurred: {e}", level="alert")

if __name__ == "__main__":
    main()
