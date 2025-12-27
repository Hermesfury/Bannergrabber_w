#!/usr/bin/env python3
"""
Enhanced Banner Grabbing Tool for Reconnaissance
Supports multiple protocols, multi-threading, and detailed extraction
"""

import socket
import ssl
import threading
import argparse
import json
import csv
from datetime import datetime
import time
import random
import re
import concurrent.futures

# Default common service ports
DEFAULT_PORTS = {
    21: 'FTP',
    22: 'SSH',
    23: 'Telnet',
    25: 'SMTP',
    53: 'DNS',
    80: 'HTTP',
    110: 'POP3',
    143: 'IMAP',
    443: 'HTTPS',
    993: 'IMAPS',
    995: 'POP3S',
    3389: 'RDP'
}

class BannerGrabber:
    def __init__(self, timeout=5, verbose=False, stealth=False):
        self.timeout = timeout
        self.verbose = verbose
        self.stealth = stealth

    def grab_banner(self, target, port):
        """Grab banner from target:port"""
        protocol = DEFAULT_PORTS.get(port, 'TCP')
        result = {
            'target': target,
            'port': port,
            'protocol': protocol,
            'timestamp': datetime.now().isoformat(),
            'banner': '',
            'server_info': {},
            'error': None
        }

        try:
            if protocol in ['HTTP', 'HTTPS']:
                result.update(self._grab_http_banner(target, port))
            elif protocol == 'FTP':
                result.update(self._grab_ftp_banner(target, port))
            elif protocol == 'SSH':
                result.update(self._grab_ssh_banner(target, port))
            elif protocol in ['SMTP', 'POP3', 'IMAP', 'POP3S', 'IMAPS']:
                result.update(self._grab_mail_banner(target, port, protocol))
            elif protocol == 'Telnet':
                result.update(self._grab_telnet_banner(target, port))
            elif protocol == 'RDP':
                result.update(self._grab_rdp_banner(target, port))
            else:
                result.update(self._grab_generic_banner(target, port))

        except Exception as e:
            result['error'] = str(e)
            if self.verbose:
                print(f"Error scanning {target}:{port} - {e}")

        return result

    def _grab_http_banner(self, target, port):
        """Grab HTTP/HTTPS banner"""
        try:
            if port == 443:
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                sock = context.wrap_socket(
                    socket.socket(socket.AF_INET, socket.SOCK_STREAM),
                    server_hostname=target
                )
            else:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

            sock.settimeout(self.timeout)
            sock.connect((target, port))

            request = (
                "GET / HTTP/1.1\r\n"
                f"Host: {target}\r\n"
                "User-Agent: Mozilla/5.0 (compatible; BannerGrabber/1.0)\r\n"
                "Connection: close\r\n\r\n"
            )

            sock.send(request.encode())
            response = sock.recv(4096).decode(errors='ignore')
            sock.close()

            # Parse response
            lines = response.split('\n')
            status_line = lines[0] if lines else ''
            headers = {}

            for line in lines[1:]:
                if ': ' in line:
                    key, value = line.split(': ', 1)
                    headers[key.strip()] = value.strip()

            server_info = {
                'status_line': status_line,
                'server': headers.get('Server', ''),
                'powered_by': headers.get('X-Powered-By', ''),
                'content_type': headers.get('Content-Type', ''),
                'os_info': self._extract_os_info(response)
            }

            return {
                'banner': response[:200],  # First 200 chars
                'server_info': server_info
            }

        except Exception as e:
            return {'error': str(e)}

    def _grab_ftp_banner(self, target, port):
        """Grab FTP banner"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((target, port))
            banner = sock.recv(1024).decode(errors='ignore').strip()
            sock.close()

            server_info = {
                'server': self._extract_server_info(banner, r'(\w+.*FTP.*)'),
                'version': self._extract_version(banner)
            }

            return {
                'banner': banner,
                'server_info': server_info
            }

        except Exception as e:
            return {'error': str(e)}

    def _grab_ssh_banner(self, target, port):
        """Grab SSH banner"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((target, port))
            banner = sock.recv(1024).decode(errors='ignore').strip()
            sock.close()

            server_info = {
                'server': self._extract_server_info(banner, r'(SSH-\d+\.\d+.*)'),
                'version': self._extract_version(banner)
            }

            return {
                'banner': banner,
                'server_info': server_info
            }

        except Exception as e:
            return {'error': str(e)}

    def _grab_mail_banner(self, target, port, protocol):
        """Grab mail service banner (SMTP, POP3, IMAP)"""
        try:
            if protocol in ['POP3S', 'IMAPS']:
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                sock = context.wrap_socket(
                    socket.socket(socket.AF_INET, socket.SOCK_STREAM),
                    server_hostname=target
                )
            else:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

            sock.settimeout(self.timeout)
            sock.connect((target, port))
            banner = sock.recv(1024).decode(errors='ignore').strip()
            sock.close()

            server_info = {
                'server': self._extract_server_info(banner, r'(\w+.*)'),
                'version': self._extract_version(banner)
            }

            return {
                'banner': banner,
                'server_info': server_info
            }

        except Exception as e:
            return {'error': str(e)}

    def _grab_telnet_banner(self, target, port):
        """Grab Telnet banner"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((target, port))
            banner = sock.recv(1024).decode(errors='ignore').strip()
            sock.close()

            server_info = {
                'server': self._extract_server_info(banner, r'(\w+.*)'),
                'os_info': self._extract_os_info(banner)
            }

            return {
                'banner': banner,
                'server_info': server_info
            }

        except Exception as e:
            return {'error': str(e)}

    def _grab_rdp_banner(self, target, port):
        """Grab RDP banner"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((target, port))
            # RDP initial response
            banner = sock.recv(1024).decode(errors='ignore')
            sock.close()

            server_info = {
                'server': 'Microsoft Terminal Services',
                'protocol': 'RDP'
            }

            return {
                'banner': banner[:200],
                'server_info': server_info
            }

        except Exception as e:
            return {'error': str(e)}

    def _grab_generic_banner(self, target, port):
        """Grab generic TCP banner"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((target, port))
            banner = sock.recv(1024).decode(errors='ignore').strip()
            sock.close()

            server_info = {
                'server': self._extract_server_info(banner, r'(\w+.*)'),
                'os_info': self._extract_os_info(banner)
            }

            return {
                'banner': banner,
                'server_info': server_info
            }

        except Exception as e:
            return {'error': str(e)}

    def _extract_server_info(self, banner, pattern):
        """Extract server info using regex"""
        match = re.search(pattern, banner, re.I)
        return match.group(1) if match else ''

    def _extract_version(self, banner):
        """Extract version from banner"""
        match = re.search(r'(\d+\.\d+(?:\.\d+)*)', banner)
        return match.group(1) if match else ''

    def _extract_os_info(self, banner):
        """Extract OS information"""
        os_patterns = {
            'Linux': r'Linux',
            'Windows': r'Windows|Microsoft',
            'Unix': r'Unix|BSD',
            'macOS': r'macOS|Darwin'
        }

        for os_name, pattern in os_patterns.items():
            if re.search(pattern, banner, re.I):
                return os_name
        return ''

def resolve_target(target):
    """Resolve hostname to IP"""
    try:
        return socket.gethostbyname(target)
    except socket.gaierror:
        return target

def scan_target(grabber, target, ports, results, lock):
    """Scan a single target across multiple ports"""
    ip = resolve_target(target)

    for port in ports:
        if grabber.stealth:
            time.sleep(random.uniform(0.1, 1.0))  # Random delay

        result = grabber.grab_banner(ip, port)

        with lock:
            results.append(result)

        if grabber.verbose:
            status = "SUCCESS" if not result['error'] else "ERROR"
            print(f"[{status}] {target}:{port} ({result['protocol']})")

def save_results(results, output_format, filename):
    """Save results to file"""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = filename or f"banner_grab_results_{timestamp}.{output_format}"

    if output_format == 'json':
        with open(filename, 'w') as f:
            json.dump(results, f, indent=2)
    elif output_format == 'csv':
        if results:
            # Collect all possible server_info keys
            all_server_keys = set()
            for result in results:
                all_server_keys.update(result['server_info'].keys())

            fieldnames = ['target', 'port', 'protocol', 'timestamp', 'banner', 'error'] + sorted(list(all_server_keys))
            with open(filename, 'w', newline='') as f:
                writer = csv.DictWriter(f, fieldnames=fieldnames)
                writer.writeheader()
                for result in results:
                    row = {k: v for k, v in result.items() if k != 'server_info'}
                    row.update(result['server_info'])
                    writer.writerow(row)

    print(f"Results saved to {filename}")

def main():
    parser = argparse.ArgumentParser(description="Enhanced Banner Grabbing Tool")
    parser.add_argument('targets', nargs='+', help='Target IPs or hostnames')
    parser.add_argument('-p', '--ports', help='Port range (e.g., 1-1000) or comma-separated (e.g., 21,22,80)', default='21,22,23,25,53,80,110,143,443,993,995,3389')
    parser.add_argument('-t', '--timeout', type=float, default=5.0, help='Connection timeout in seconds')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
    parser.add_argument('-s', '--stealth', action='store_true', help='Enable stealth mode (random delays)')
    parser.add_argument('-w', '--waf-evasion', action='store_true', help='Enable WAF evasion techniques for HTTP requests')
    parser.add_argument('-o', '--output', choices=['json', 'csv'], default='json', help='Output format')
    parser.add_argument('-f', '--filename', help='Output filename (auto-generated if not specified)')
    parser.add_argument('--threads', type=int, default=10, help='Number of threads')

    args = parser.parse_args()

    # Parse ports
    if '-' in args.ports:
        start, end = map(int, args.ports.split('-'))
        ports = list(range(start, end + 1))
    else:
        ports = [int(p.strip()) for p in args.ports.split(',')]

    grabber = BannerGrabber(timeout=args.timeout, verbose=args.verbose, stealth=args.stealth)
    results = []
    lock = threading.Lock()

    print(f"Starting banner grab on {len(args.targets)} target(s) across {len(ports)} port(s)")
    print(f"Using {args.threads} threads")

    start_time = time.time()

    with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as executor:
        futures = []
        for target in args.targets:
            futures.append(executor.submit(scan_target, grabber, target, ports, results, lock))

        concurrent.futures.wait(futures)

    end_time = time.time()

    # Filter out errors if not verbose
    if not args.verbose:
        results = [r for r in results if not r['error']]

    print(f"\nScan completed in {end_time - start_time:.2f} seconds")
    print(f"Found {len(results)} successful connections")

    if results:
        save_results(results, args.output, args.filename)

if __name__ == "__main__":
    main()