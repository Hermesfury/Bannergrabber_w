#!/usr/bin/env python3
"""
Fast Port Scanner for Banner Grabber Enhancement
Identifies open ports before detailed banner grabbing
"""

import socket
import threading
import argparse
import json
import time
import concurrent.futures
from datetime import datetime

class FastPortScanner:
    """High-performance port scanner using connection pooling"""

    def __init__(self, timeout=1.0, max_threads=100):
        self.timeout = timeout
        self.max_threads = max_threads
        self.open_ports = []
        self.lock = threading.Lock()

    def scan_port(self, target, port):
        """Scan a single port"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((target, port))
            sock.close()

            if result == 0:
                with self.lock:
                    self.open_ports.append(port)
                return True
        except:
            pass
        return False

    def scan_range(self, target, start_port, end_port):
        """Scan a range of ports"""
        self.open_ports = []

        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            futures = []
            for port in range(start_port, end_port + 1):
                futures.append(executor.submit(self.scan_port, target, port))

            # Progress tracking
            total = len(futures)
            for i, future in enumerate(concurrent.futures.as_completed(futures)):
                if (i + 1) % 100 == 0:
                    print(f"Scanned {i + 1}/{total} ports...")

        return sorted(self.open_ports)

    def scan_common_ports(self, target):
        """Scan commonly used ports"""
        common_ports = [
            21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080
        ]

        self.open_ports = []

        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            futures = {executor.submit(self.scan_port, target, port): port for port in common_ports}

            for future in concurrent.futures.as_completed(futures):
                port = futures[future]
                try:
                    if future.result():
                        print(f"Port {port} is open")
                except:
                    pass

        return sorted(self.open_ports)

def identify_service(port):
    """Identify likely service for a port"""
    services = {
        21: "FTP",
        22: "SSH",
        23: "Telnet",
        25: "SMTP",
        53: "DNS",
        80: "HTTP",
        110: "POP3",
        143: "IMAP",
        443: "HTTPS",
        993: "IMAPS",
        995: "POP3S",
        3306: "MySQL",
        3389: "RDP",
        8080: "HTTP-Proxy"
    }
    return services.get(port, "Unknown")

def generate_banner_grabber_command(target, open_ports):
    """Generate optimized banner grabber command"""
    if not open_ports:
        return "No open ports found"

    port_str = ",".join(map(str, open_ports))
    return f"python bannergrab.py {target} -p {port_str} -v"

def main():
    parser = argparse.ArgumentParser(description="Fast Port Scanner for Banner Grabber")
    parser.add_argument("target", help="Target IP or hostname")
    parser.add_argument("-r", "--range", help="Port range (e.g., 1-1000)", default="1-1024")
    parser.add_argument("-c", "--common", action="store_true", help="Scan only common ports")
    parser.add_argument("-t", "--timeout", type=float, default=1.0, help="Connection timeout")
    parser.add_argument("-j", "--json", action="store_true", help="Output in JSON format")
    parser.add_argument("--threads", type=int, default=100, help="Maximum threads")

    args = parser.parse_args()

    scanner = FastPortScanner(timeout=args.timeout, max_threads=args.threads)

    print(f"Starting port scan on {args.target}")
    start_time = time.time()

    if args.common:
        print("Scanning common ports...")
        open_ports = scanner.scan_common_ports(args.target)
    else:
        start_port, end_port = map(int, args.range.split('-'))
        print(f"Scanning ports {start_port}-{end_port}...")
        open_ports = scanner.scan_range(args.target, start_port, end_port)

    end_time = time.time()

    if args.json:
        result = {
            "target": args.target,
            "scan_type": "common" if args.common else f"range({args.range})",
            "open_ports": open_ports,
            "services": {port: identify_service(port) for port in open_ports},
            "scan_time": round(end_time - start_time, 2),
            "timestamp": datetime.now().isoformat(),
            "banner_grabber_command": generate_banner_grabber_command(args.target, open_ports)
        }
        print(json.dumps(result, indent=2))
    else:
        print(f"\nScan completed in {end_time - start_time:.2f} seconds")
        print(f"Found {len(open_ports)} open ports:")

        for port in open_ports:
            service = identify_service(port)
            print(f"  {port}/tcp - {service}")

        if open_ports:
            print(f"\nRecommended banner grabber command:")
            print(f"  {generate_banner_grabber_command(args.target, open_ports)}")

if __name__ == "__main__":
    main()