import psutil
import time
import os
from colorama import init, Fore, Style

# Initialize colorama for Windows
init(autoreset=True, convert=True, strip=False)

# List of known suspicious process names
suspicious_names = [
    "mimikatz", "netcat", "ncat", "powersploit", "meterpreter",
    "psexec", "procdump", "taskkill", "cscript", "wscript", "cmd.exe", "powershell.exe"
]

# File extensions often used in malicious scripts or payloads
suspicious_extensions = [".exe", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".dll", ".scr"]

# Trusted base paths (used to reduce false positives)
trusted_paths = [
    "C:\\Windows",
    "C:\\Program Files",
    "C:\\Program Files (x86)"
]

monitor_duration = 60  # Total monitoring time in seconds
scan_interval = 1      # Time between scans

print(f"[INFO] Monitoring running processes for {monitor_duration} seconds...\n")

previous_pids = set()
detected_suspicious = []

for _ in range(0, monitor_duration, scan_interval):
    current_pids = set()
    for proc in psutil.process_iter(['pid', 'name', 'exe', 'cmdline']):
        try:
            pid = proc.info['pid']
            name = proc.info.get('name', '').lower()
            exe_path = proc.info.get('exe', '')
            cmdline = proc.info.get('cmdline', [])

            if not exe_path:
                continue

            normalized_path = os.path.normpath(exe_path)
            extension = os.path.splitext(normalized_path)[1].lower()
            cmdline_str = ' '.join(cmdline).lower() if isinstance(cmdline, list) else ''

            current_pids.add(pid)

            if pid in previous_pids:
                continue

            name_is_suspicious = any(s in name for s in suspicious_names)
            extension_is_suspicious = extension in suspicious_extensions
            outside_trusted_path = not any(normalized_path.startswith(tp) for tp in trusted_paths)
            script_called_in_cmdline = any(ext in cmdline_str for ext in suspicious_extensions)

            if name_is_suspicious or (extension_is_suspicious and outside_trusted_path) or script_called_in_cmdline:
                print(
                    f"[SUSPICIOUS] "
                    f"PID: {Fore.LIGHTMAGENTA_EX}{pid}{Style.RESET_ALL} | "
                    f"Name: {Fore.LIGHTMAGENTA_EX}{name}{Style.RESET_ALL} | "
                    f"Path: {Fore.LIGHTMAGENTA_EX}{normalized_path}{Style.RESET_ALL}"
                )
                if cmdline_str:
                    print(f"             Command Line: {cmdline_str}")
                print()  # Single blank line for spacing
                detected_suspicious.append((pid, name, normalized_path))

        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue

    previous_pids = current_pids
    time.sleep(scan_interval)

if not detected_suspicious:
    print("\n[INFO] No suspicious processes detected.")
else:
    print(f"\n[INFO] Total suspicious processes detected: {len(detected_suspicious)}")
