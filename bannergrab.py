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
import logging
import base64
from urllib.parse import quote

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

class ConnectionManager:
    """Advanced connection management with retry logic and timeout handling"""

    def __init__(self, max_retries=3, base_timeout=5.0, backoff_factor=2.0):
        self.max_retries = max_retries
        self.base_timeout = base_timeout
        self.backoff_factor = backoff_factor
        self.logger = logging.getLogger(__name__)

    def create_connection(self, target, port, use_ssl=False, timeout=None):
        """Create socket connection with retry logic"""
        if timeout is None:
            timeout = self.base_timeout

        last_exception = None

        for attempt in range(self.max_retries):
            try:
                if use_ssl:
                    context = ssl.create_default_context()
                    context.check_hostname = False
                    context.verify_mode = ssl.CERT_NONE
                    sock = context.wrap_socket(
                        socket.socket(socket.AF_INET, socket.SOCK_STREAM),
                        server_hostname=target
                    )
                else:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

                sock.settimeout(timeout)
                sock.connect((target, port))

                self.logger.debug(f"Successfully connected to {target}:{port} on attempt {attempt + 1}")
                return sock

            except (socket.timeout, socket.error, OSError) as e:
                last_exception = e
                wait_time = (self.backoff_factor ** attempt) * random.uniform(0.1, 1.0)
                self.logger.debug(f"Connection attempt {attempt + 1} failed for {target}:{port}: {e}. Retrying in {wait_time:.2f}s")
                time.sleep(wait_time)

        self.logger.error(f"Failed to connect to {target}:{port} after {self.max_retries} attempts")
        raise last_exception

    def send_request(self, sock, request, timeout=None):
        """Send request with proper error handling"""
        try:
            if isinstance(request, str):
                request = request.encode()

            sock.send(request)

            # Receive response with larger buffer
            response = b""
            sock.settimeout(timeout or self.base_timeout)

            while True:
                chunk = sock.recv(8192)
                if not chunk:
                    break
                response += chunk
                # Break if we have headers (for HTTP responses)
                if b"\r\n\r\n" in response:
                    break

            return response.decode(errors='ignore')

        except (socket.timeout, socket.error) as e:
            self.logger.error(f"Error sending request: {e}")
            raise

class FingerprintEngine:
    """Multi-stage server fingerprinting engine"""

    def __init__(self):
        self.logger = logging.getLogger(__name__)

    def identify_server(self, response, target, port):
        """Identify server using multi-stage detection"""
        server_info = {
            'server': '',
            'version': '',
            'os_info': '',
            'cdn': '',
            'waf': ''
        }

        # Parse response headers
        headers = self._parse_headers(response)

        # Stage 1: Direct header analysis
        server_info.update(self._analyze_headers(headers))

        # Stage 2: Advanced fingerprinting if basic detection failed
        if not server_info['server'] or not server_info['version']:
            server_info.update(self._advanced_fingerprinting(response, headers, target, port))

        # Stage 3: CDN/WAF detection
        cdn_waf_info = self._detect_cdn_waf(headers, response)
        server_info.update(cdn_waf_info)

        return server_info

    def _parse_headers(self, response):
        """Parse HTTP headers from response"""
        headers = {}
        lines = response.split('\n')

        for line in lines[1:]:
            line = line.strip()
            if ': ' in line:
                key, value = line.split(': ', 1)
                headers[key.lower()] = value

        return headers

    def _analyze_headers(self, headers):
        """Analyze headers for server information"""
        info = {'server': '', 'version': '', 'os_info': ''}

        # Server header analysis
        server_header = headers.get('server', '')
        if server_header:
            info['server'] = server_header.split('/')[0]
            if '/' in server_header:
                info['version'] = server_header.split('/', 1)[1]

        # OS detection from headers
        info['os_info'] = self._detect_os_from_headers(headers)

        return info

    def _advanced_fingerprinting(self, response, headers, target, port):
        """Advanced fingerprinting techniques"""
        info = {'server': '', 'version': ''}

        # Try to identify server from response patterns
        response_lower = response.lower()

        # Apache detection
        if 'apache' in response_lower:
            info['server'] = 'Apache'
            # Try to find version in various places
            version_match = re.search(r'apache/(\d+\.\d+(?:\.\d+)*)', response_lower, re.I)
            if version_match:
                info['version'] = version_match.group(1)

        # Nginx detection
        elif 'nginx' in response_lower:
            info['server'] = 'Nginx'
            version_match = re.search(r'nginx/(\d+\.\d+(?:\.\d+)*)', response_lower, re.I)
            if version_match:
                info['version'] = version_match.group(1)

        # IIS detection
        elif 'microsoft-iis' in response_lower or 'iis' in response_lower:
            info['server'] = 'IIS'
            version_match = re.search(r'iis/(\d+\.\d+)', response_lower, re.I)
            if version_match:
                info['version'] = version_match.group(1)

        return info

    def _detect_cdn_waf(self, headers, response):
        """Detect CDN and WAF systems"""
        info = {'cdn': '', 'waf': ''}

        response_lower = response.lower()
        header_keys = {k.lower() for k in headers.keys()}

        # Cloudflare detection
        if 'cf-ray' in header_keys or 'cloudflare' in response_lower:
            info['cdn'] = 'Cloudflare'

        # Incapsula/Imperva detection
        if 'x-iinfo' in header_keys or 'incapsula' in response_lower:
            info['waf'] = 'Incapsula'

        # Akamai detection
        if 'akamai' in response_lower or 'x-akamai' in header_keys:
            info['cdn'] = 'Akamai'

        # Sucuri detection
        if 'sucuri' in response_lower or 'x-sucuri' in header_keys:
            info['waf'] = 'Sucuri'

        return info

    def _detect_os_from_headers(self, headers):
        """Detect OS from response headers"""
        os_indicators = {
            'windows': ['windows', 'microsoft', 'iis'],
            'linux': ['linux', 'ubuntu', 'centos', 'redhat'],
            'unix': ['unix', 'bsd', 'freebsd', 'openbsd'],
            'macos': ['macos', 'darwin', 'osx']
        }

        response_text = ' '.join(headers.values()).lower()

        for os_name, indicators in os_indicators.items():
            if any(indicator in response_text for indicator in indicators):
                return os_name.title()

        return ''

class BannerGrabber:
    def __init__(self, timeout=5, verbose=False, stealth=False, max_retries=3, waf_evasion=False):
        self.timeout = timeout
        self.verbose = verbose
        self.stealth = stealth
        self.max_retries = max_retries
        self.waf_evasion = waf_evasion

        # Initialize core components
        self.connection_manager = ConnectionManager(max_retries=max_retries, base_timeout=timeout)
        self.fingerprint_engine = FingerprintEngine()

        # Setup logging
        self._setup_logging()

    def _setup_logging(self):
        """Setup logging configuration"""
        self.logger = logging.getLogger(__name__)
        if not self.logger.handlers:
            handler = logging.StreamHandler()
            formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
            handler.setFormatter(formatter)
            self.logger.addHandler(handler)
            self.logger.setLevel(logging.INFO if self.verbose else logging.WARNING)

    def _get_random_user_agent(self):
        user_agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.114 Safari/537.36",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.101 Safari/537.36",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15",
            "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:89.0) Gecko/20100101 Firefox/89.0"
        ]
        return random.choice(user_agents)

    def _encode_payload(self, payload, encoding):
        if encoding == 'base64':
            return base64.b64encode(payload.encode()).decode()
        elif encoding == 'url':
            return quote(payload)
        else:
            return payload

    def _fragment_request(self, request, fragments):
        # Split the request into fragments
        lines = request.split('\r\n')
        fragmented = []
        for i in range(0, len(lines), fragments):
            fragmented.append('\r\n'.join(lines[i:i+fragments]))
        return fragmented

    def _add_custom_headers(self, headers):
        custom_headers = {
            'X-Forwarded-For': f'192.168.{random.randint(1,255)}.{random.randint(1,255)}',
            'X-Real-IP': f'10.0.{random.randint(1,255)}.{random.randint(1,255)}',
            'X-Requested-With': 'XMLHttpRequest',
            'Referer': 'https://www.google.com/'
        }
        headers.update(custom_headers)
        return headers

    def _apply_waf_evasion(self, request):
        # Randomize User-Agent
        ua = self._get_random_user_agent()
        request = request.replace("User-Agent: Mozilla/5.0 (compatible; BannerGrabber/1.0)\r\n", f"User-Agent: {ua}\r\n")

        # Add custom headers
        headers_part = request.split('\r\n\r\n')[0]
        headers_lines = headers_part.split('\r\n')
        headers_dict = {}
        for line in headers_lines[1:]:
            if ': ' in line:
                k, v = line.split(': ', 1)
                headers_dict[k] = v
        headers_dict = self._add_custom_headers(headers_dict)
        new_headers = '\r\n'.join([f"{k}: {v}" for k, v in headers_dict.items()])
        request = request.replace(headers_part, f"{headers_lines[0]}\r\n{new_headers}")

        # Encode payload if needed (for GET requests, encode query)
        if 'GET' in request and '?' in request:
            url_part = request.split('\r\n')[0].split(' ')[1]
            if '?' in url_part:
                base, query = url_part.split('?', 1)
                encoded_query = self._encode_payload(query, 'url')
                request = request.replace(url_part, f"{base}?{encoded_query}")

        # Fragment request if needed
        fragmented = self._fragment_request(request, 2)
        if len(fragmented) > 1:
            # For simplicity, send the first fragment, but in real, send multiple
            request = fragmented[0]

        # Add timing delay
        time.sleep(random.uniform(0.1, 0.5))

        return request

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
                print(f"Error scanning {target}:{port} ({protocol}) - {e}")

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
                "HEAD / HTTP/1.1\r\n"
                f"Host: {target}\r\n"
                "User-Agent: Mozilla/5.0 (compatible; BannerGrabber/1.0)\r\n"
                "Connection: close\r\n\r\n"
            )

            if self.waf_evasion:
                # Apply WAF evasion techniques
                # Header manipulation: randomize User-Agent
                ua = self._get_random_user_agent()
                request = request.replace("User-Agent: Mozilla/5.0 (compatible; BannerGrabber/1.0)\r\n", f"User-Agent: {ua}\r\n")

                # Add custom headers
                headers = self._add_custom_headers({})
                custom_headers_str = '\r\n'.join([f"{k}: {v}" for k, v in headers.items()]) + '\r\n'
                request = request.replace(f"Host: {target}\r\n", f"Host: {target}\r\n{custom_headers_str}")

                # Payload encoding: not applicable for HEAD /

                # Request fragmentation: send request in parts with delays
                parts = [request[i:i+50] for i in range(0, len(request), 50)]  # Split into 50-byte chunks
                for part in parts:
                    sock.send(part.encode())
                    time.sleep(random.uniform(0.1, 0.5))  # Timing delay
            else:
                sock.send(request.encode())

            response = sock.recv(8192).decode(errors='ignore')
            sock.close()

            # Parse response
            lines = response.split('\n')
            status_line = lines[0] if lines else ''
            headers = {}

            for line in lines[1:]:
                if ': ' in line:
                    key, value = line.split(': ', 1)
                    headers[key.strip()] = value.strip()

            # Use FingerprintEngine for comprehensive server identification
            server_info = self.fingerprint_engine.identify_server(response, target, port)

            # Parse status line
            lines = response.split('\n')
            status_line = lines[0] if lines else ''

            # Add HTTP-specific information
            server_info.update({
                'status_line': status_line,
                'powered_by': self._extract_header(response, 'X-Powered-By'),
                'content_type': self._extract_header(response, 'Content-Type')
            })

            return {
                'banner': response[:300],  # Increased banner length for better info
                'server_info': server_info
            }

        except Exception as e:
            if sock:
                try:
                    sock.close()
                except:
                    pass
            self.logger.error(f"Error grabbing HTTP banner from {target}:{port}: {e}")
            return {'error': str(e)}

    def _extract_header(self, response, header_name):
        """Extract specific header from HTTP response"""
        lines = response.split('\n')
        for line in lines[1:]:
            line = line.strip()
            if line.lower().startswith(header_name.lower() + ': '):
                return line.split(': ', 1)[1]
        return ''

    def _try_alternative_version_detection(self, sock, target, port, is_https=False):
        """Try alternative methods to detect server version"""
        try:
            # Try OPTIONS method
            options_request = (
                "OPTIONS / HTTP/1.1\r\n"
                f"Host: {target}\r\n"
                "User-Agent: Mozilla/5.0 (compatible; BannerGrabber/1.0)\r\n"
                "Connection: close\r\n\r\n"
            )
            sock.send(options_request.encode())
            response = sock.recv(4096).decode(errors='ignore')
            version = self._extract_version(response)
            if version:
                return version

            # Try GET on root to parse body for version
            get_request = (
                "GET / HTTP/1.1\r\n"
                f"Host: {target}\r\n"
                "User-Agent: Mozilla/5.0 (compatible; BannerGrabber/1.0)\r\n"
                "Connection: close\r\n\r\n"
            )
            sock.send(get_request.encode())
            response = sock.recv(8192).decode(errors='ignore')
            version = self._extract_version(response)
            if version:
                return version

            # Try GET on a non-existent page to trigger error page
            error_request = (
                "GET /nonexistent-page-12345 HTTP/1.1\r\n"
                f"Host: {target}\r\n"
                "User-Agent: Mozilla/5.0 (compatible; BannerGrabber/1.0)\r\n"
                "Connection: close\r\n\r\n"
            )
            sock.send(error_request.encode())
            response = sock.recv(8192).decode(errors='ignore')
            version = self._extract_version(response)
            if version:
                return version

            # Try different User-Agent with HEAD
            ua_request = (
                "HEAD / HTTP/1.1\r\n"
                f"Host: {target}\r\n"
                "User-Agent: curl/7.68.0\r\n"
                "Connection: close\r\n\r\n"
            )
            sock.send(ua_request.encode())
            response = sock.recv(4096).decode(errors='ignore')
            version = self._extract_version(response)
            if version:
                return version

        except Exception:
            pass
        return ''

    def _grab_ftp_banner(self, target, port):
        """Grab FTP banner with enhanced connection handling"""
        sock = None
        try:
            # Use ConnectionManager for reliable connections
            sock = self.connection_manager.create_connection(target, port, use_ssl=False)

            # Send FTP USER command to trigger banner response
            sock.send(b"USER anonymous\r\n")
            banner = sock.recv(1024).decode(errors='ignore').strip()

            # Extract clean banner (first line usually contains version)
            banner_lines = banner.split('\n')
            clean_banner = banner_lines[0] if banner_lines else banner

            sock.close()
            sock = None

            server_info = {
                'server': self._extract_server_info(clean_banner, r'(\w+.*FTP.*)'),
                'version': self._extract_version(clean_banner)
            }

            return {
                'banner': clean_banner,
                'server_info': server_info
            }

        except Exception as e:
            if sock:
                try:
                    sock.close()
                except:
                    pass
            self.logger.debug(f"FTP banner grab failed for {target}:{port}: {e}")
            return {'error': f"FTP service unavailable or blocked: {str(e)}"}

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
        """Grab Telnet banner with enhanced connection handling"""
        sock = None
        try:
            sock = self.connection_manager.create_connection(target, port, use_ssl=False)
            banner = sock.recv(1024).decode(errors='ignore').strip()
            sock.close()
            sock = None

            server_info = {
                'server': self._extract_server_info(banner, r'(\w+.*)'),
                'os_info': self._extract_os_info(banner)
            }

            return {
                'banner': banner,
                'server_info': server_info
            }

        except Exception as e:
            if sock:
                try:
                    sock.close()
                except:
                    pass
            self.logger.debug(f"Telnet banner grab failed for {target}:{port}: {e}")
            return {'error': f"Telnet service unavailable: {str(e)}"}

    def _grab_rdp_banner(self, target, port):
        """Grab RDP banner with enhanced connection handling"""
        sock = None
        try:
            sock = self.connection_manager.create_connection(target, port, use_ssl=False)
            # RDP initial response
            banner = sock.recv(1024).decode(errors='ignore')
            sock.close()
            sock = None

            server_info = {
                'server': 'Microsoft Terminal Services',
                'protocol': 'RDP'
            }

            return {
                'banner': banner[:200],
                'server_info': server_info
            }

        except Exception as e:
            if sock:
                try:
                    sock.close()
                except:
                    pass
            self.logger.debug(f"RDP banner grab failed for {target}:{port}: {e}")
            return {'error': f"RDP service unavailable: {str(e)}"}

    def _grab_generic_banner(self, target, port):
        """Grab generic TCP banner with enhanced connection handling"""
        sock = None
        try:
            sock = self.connection_manager.create_connection(target, port, use_ssl=False)
            banner = sock.recv(1024).decode(errors='ignore').strip()
            sock.close()
            sock = None

            server_info = {
                'server': self._extract_server_info(banner, r'(\w+.*)'),
                'os_info': self._extract_os_info(banner)
            }

            return {
                'banner': banner,
                'server_info': server_info
            }

        except Exception as e:
            if sock:
                try:
                    sock.close()
                except:
                    pass
            self.logger.debug(f"Generic TCP banner grab failed for {target}:{port}: {e}")
            return {'error': f"Service unavailable: {str(e)}"}

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

    grabber = BannerGrabber(timeout=args.timeout, verbose=args.verbose, stealth=args.stealth, max_retries=3, waf_evasion=args.waf_evasion)

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