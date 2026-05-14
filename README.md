# PentestKit - Penetration Testing Toolkit

A comprehensive multi-functional penetration testing toolkit built in Python, similar to popular security tools like Nmap and Dirsearch. This toolkit provides essential utilities for various pentesting tasks including port scanning, directory brute-forcing, network mapping, and HTTP header analysis.

## Features

PentestKit includes four powerful tools:

### 1. TinyScanner (Simple Port Scanner)
Checks for open, closed, or filtered ports on a target host using TCP scanning.
- Supports scanning individual ports or port ranges
- Identifies common services running on open ports
- Concurrent scanning for faster results

### 2. DirFinder (Small Dirsearch)
Discovers hidden directories and files on a web server by brute-forcing common paths.
- Uses customizable wordlists
- Concurrent requests for efficient scanning
- Detects various HTTP status codes

### 3. HostMapper
Performs ping sweeps to identify live hosts on a subnet.
- Supports CIDR notation (e.g., 192.168.1.0/24)
- ICMP and TCP ping fallback
- Latency measurement for live hosts

### 4. HeaderGrabber
Retrieves and analyzes HTTP headers from web servers.
- Identifies missing security headers
- Detects information disclosure
- Comprehensive security analysis

## Requirements

- Python 3.6 or higher
- No external dependencies required (uses only Python standard library)

## Installation

1. Clone or download this repository
2. Make the main script executable (optional):
```bash
chmod +x pentestkit.py
```

## Usage

### User Interface Options

PentestKit provides three ways to interact with the tools:

#### 1. Command Line Interface (CLI)
```bash
python pentestkit.py --help
```

#### 2. Interactive Menu Interface (Recommended for non-technical users)
A simple text-based menu interface for easy tool selection and parameter input:

```bash
python pentestkit_menu.py
```

Features:
- Numbered menu to select tools
- Interactive prompts with default values
- No technical knowledge required
- Works on all systems

#### 3. Graphical User Interface (GUI)
A tkinter-based GUI for visual tool selection (may have compatibility issues on some macOS versions):

```bash
python pentestkit_gui.py
```

**Note:** If the GUI fails to run due to macOS compatibility, use the menu interface instead.

### General Help

```bash
python pentestkit.py --help
```

### TinyScanner - Port Scanner

Scan specific ports on a target host:

```bash
python pentestkit.py -t 192.168.1.1 -p 22,80,443 -o result.txt
```

Scan a range of ports:

```bash
python pentestkit.py -t 192.168.1.1 -p 1-1000 -o result.txt
```

**Options:**
- `-t, --tinyscanner`: Target IP address or hostname
- `-p, --ports`: Ports to scan (comma-separated or range, e.g., 22,80,443 or 1-1000)
- `-o, --output`: Output file name (optional)

**Example Output:**
```
Port 22 is open (SSH)
Port 80 is open (HTTP)
Port 443 is closed
Data Saved in result.txt
```

### DirFinder - Directory Brute-Forcer

Discover hidden directories and files:

```bash
python pentestkit.py -d http://example.com -w wordlist.txt -o result.txt
```

**Options:**
- `-d, --dirfinder`: Target URL
- `-w, --wordlist`: Path to wordlist file
- `-o, --output`: Output file name (optional)

**Example Output:**
```
/admin            [Status: 200]
/uploads          [Status: 403]
/login            [Status: 200]
Data Saved in result.txt
```

### HostMapper - Network Host Mapper

Perform a ping sweep on a subnet:

```bash
python pentestkit.py -h 192.168.1.0/24 -o result.txt
```

**Options:**
- `-m, --hostmapper`: Subnet in CIDR notation
- `-o, --output`: Output file name (optional)

**Example Output:**
```
192.168.1.1 (2.45ms)
192.168.1.10 (5.12ms)
192.168.1.15 (3.78ms)
Live hosts found: 3
Data Saved in result.txt
```

### HeaderGrabber - HTTP Header Analyzer

Analyze HTTP headers of a web server:

```bash
python pentestkit.py -g http://example.com -o result.txt
```

**Options:**
- `-g, --headergrabber`: Target URL
- `-o, --output`: Output file name (optional)

**Example Output:**
```
HTTP/1.1 200 OK
Date: Mon, 01 Jan 2022 12:00:00 GMT
Server: Apache/2.4.41 (Ubuntu)
X-Powered-By: PHP/7.4.3

Security Headers Analysis:
--------------------------------------------------
✓ X-Frame-Options: DENY
✗ X-Content-Type-Options: MISSING
✗ Content-Security-Policy: MISSING

Warning: Missing Security Headers - X-Content-Type-Options, Content-Security-Policy

Information Disclosure:
--------------------------------------------------
⚠ Server: Apache/2.4.41 (Ubuntu)
⚠ X-Powered-By: PHP/7.4.3

Data saved in result.txt
```

## Wordlist

A sample wordlist (`wordlist.txt`) is included with common directory and file names. You can create your own wordlist or use larger ones from other sources.

## Project Structure

```
Penetration-testing-scaning-tool/
├── pentestkit.py          # Main CLI interface
├── pentestkit_menu.py     # Interactive menu interface
├── pentestkit_gui.py      # Graphical user interface
├── tinyscanner.py         # Port scanner implementation
├── dirfinder.py           # Directory brute-forcer
├── hostmapper.py          # Ping sweep tool
├── headergrabber.py       # HTTP header analyzer
├── wordlist.txt           # Sample wordlist
├── tests.md               # Test commands reference
└── README.md              # This file
```

## Ethical Considerations

This toolkit is designed for educational purposes and authorized security testing only. Always:

- Obtain proper authorization before scanning any system
- Use these tools only on systems you own or have explicit permission to test
- Follow responsible disclosure practices for any vulnerabilities found
- Adhere to local laws and regulations regarding security testing

## Implementation Notes

- All tools are built from scratch using Python's standard library
- No external CLI tools are called - all functionality is implemented natively
- Concurrent execution is used for improved performance
- Results can be saved to text files for analysis

## Troubleshooting

### HostMapper requires root/sudo for ICMP
If you get permission errors with HostMapper, the tool will automatically fall back to TCP ping on common ports (80, 443, 22, etc.).

### DirFinder SSL errors
For HTTPS targets with self-signed certificates, DirFinder will accept all certificates by default (for testing purposes).

### TinyScanner timeouts
Adjust the timeout in `tinyscanner.py` if you're scanning over high-latency networks.

## Author
malakaljamri
