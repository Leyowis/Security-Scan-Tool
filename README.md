# Security Scan Tool

This script is a security scanning tool designed to identify potential threats on a system by checking for suspicious processes, network connections, and files. It performs checks based on the operating system (Windows, Linux, macOS) and logs any detected anomalies for further investigation.

## Features

- **Process Scanning**: Checks running processes for suspicious activity, such as Meterpreter sessions and high resource usage (memory and CPU).
- **Network Connection Scanning**: Scans network connections for suspicious ports and connection statuses, specifically looking for common malware ports.
- **File Scanning**: Searches the system for files related to Meterpreter or other potentially harmful scripts (e.g., `.exe`, `.dll`, `.vbs`).
- **Logging**: All scan results are logged into a file (`security_scan.log`), and alerts or warnings are displayed to the user.
- **Cross-platform Support**: Compatible with Windows, Linux, and macOS, with OS-specific checks for suspicious modules.
