# Process Inspector – Threat Hunting Tool (Windows)

This is a lightweight Python script designed to assist threat hunters and cybersecurity analysts in identifying suspicious processes running on a Windows system.

It scans all active processes and alerts the user if any of them match known malicious names, suspicious file extensions (e.g., `.bat`, `.vbs`, `.ps1`), or are running from unusual directories.

---

## Features

- Detects processes with suspicious or uncommon file types
- Flags processes with known offensive tool names (e.g., `mimikatz`, `netcat`)
- Checks if files are running outside trusted directories (`C:\Windows`, `Program Files`, etc.)
- Command-line interface with color-coded output
- No admin privileges required

---

## Requirements

- Python 3.8 or higher  
- Colorama  
- psutil

Install the dependencies using pip:

```bash
pip install psutil colorama
