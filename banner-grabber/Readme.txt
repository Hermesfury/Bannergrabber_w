Enhanced Banner Grabbing Tool for Reconnaissance

This is a powerful, multi-threaded banner grabbing tool designed for security reconnaissance. It supports scanning multiple targets across various protocols and ports, extracting detailed service information.

Features:
- Multi-target scanning (IPs and hostnames)
- Customizable port ranges (comma-separated or ranges like 1-1000)
- Support for multiple protocols: HTTP, HTTPS, FTP, SSH, SMTP, POP3, IMAP, Telnet, RDP, and generic TCP
- Detailed banner extraction including server software, versions, OS info, and protocol-specific data
- Multi-threading for fast scanning
- Stealth mode with random delays
- Configurable timeouts and verbosity
- Output in JSON or CSV format
- Timestamped result files
- Cross-platform compatible (Python 3.x)

Requirements:
- Python 3.x
- Standard library modules: socket, ssl, threading, argparse, json, csv, datetime, time, random, re, concurrent.futures

Usage:
python bannergrab.py [targets] [options]

Examples:
# Scan default ports on a single target
python bannergrab.py example.com

# Scan specific ports with verbose output
python bannergrab.py example.com -p 21,22,80,443 -v

# Scan port range with stealth mode
python bannergrab.py example.com -p 1-1000 -s --threads 5

# Multiple targets with CSV output
python bannergrab.py site1.com site2.com -p 80,443 -o csv

# Custom timeout and filename
python bannergrab.py target.com -t 10 -f my_scan_results.json

Options:
  -p, --ports PORTS     Port range (e.g., 1-1000) or comma-separated (default: common service ports)
  -t, --timeout TIMEOUT Connection timeout in seconds (default: 5.0)
  -v, --verbose         Verbose output showing all scan attempts
  -s, --stealth         Enable stealth mode with random delays
  -o, --output {json,csv} Output format (default: json)
  -f, --filename FILENAME Custom output filename
  --threads THREADS     Number of threads (default: 10)

Output:
Results are saved to timestamped files (e.g., banner_grab_results_20231201_120000.json)
Each result includes: target IP, port, protocol, timestamp, banner text, extracted server info, and any errors.



py bannergrab.py nacosogitech.com.ng -p 21,22,23,25,53,80,110,143,443,993,995,3389 -v -o json
Note: Use this tool responsibly and only on systems you have permission to scan.
