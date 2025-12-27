#!/usr/bin/env python3
"""
Advanced Service Detection Module
Enhanced service fingerprinting for banner grabber
"""

import socket
import ssl
import re
import time
from typing import Dict, List, Optional, Tuple

class ServiceDetector:
    """Advanced service detection and fingerprinting"""

    def __init__(self, timeout=5.0):
        self.timeout = timeout
        self.service_signatures = self._load_signatures()

    def _load_signatures(self) -> Dict[int, List[Dict]]:
        """Load service detection signatures"""
        return {
            21: [  # FTP
                {"pattern": r"220.*FTP", "service": "FTP", "confidence": 0.9},
                {"pattern": r"220.*Pure-FTPd", "service": "Pure-FTPd", "confidence": 0.95},
                {"pattern": r"220.*vsftpd", "service": "vsftpd", "confidence": 0.95},
                {"pattern": r"220.*FileZilla", "service": "FileZilla FTP", "confidence": 0.9}
            ],
            22: [  # SSH
                {"pattern": r"SSH-\d+\.\d+", "service": "SSH", "confidence": 0.95},
                {"pattern": r"SSH-.*OpenSSH", "service": "OpenSSH", "confidence": 0.9},
                {"pattern": r"SSH-.*libssh", "service": "libssh", "confidence": 0.8}
            ],
            25: [  # SMTP
                {"pattern": r"220.*SMTP", "service": "SMTP", "confidence": 0.9},
                {"pattern": r"220.*Postfix", "service": "Postfix", "confidence": 0.9},
                {"pattern": r"220.*Sendmail", "service": "Sendmail", "confidence": 0.9},
                {"pattern": r"220.*Exim", "service": "Exim", "confidence": 0.9}
            ],
            80: [  # HTTP
                {"pattern": r"HTTP/\d+\.\d+", "service": "HTTP", "confidence": 0.95},
                {"pattern": r"Server:\s*Apache", "service": "Apache", "confidence": 0.9},
                {"pattern": r"Server:\s*nginx", "service": "nginx", "confidence": 0.9},
                {"pattern": r"Server:\s*IIS", "service": "IIS", "confidence": 0.9}
            ],
            110: [  # POP3
                {"pattern": r"\+OK.*POP3", "service": "POP3", "confidence": 0.9},
                {"pattern": r"\+OK.*Dovecot", "service": "Dovecot POP3", "confidence": 0.9}
            ],
            143: [  # IMAP
                {"pattern": r"\* OK.*IMAP", "service": "IMAP", "confidence": 0.9},
                {"pattern": r"\* OK.*Dovecot", "service": "Dovecot IMAP", "confidence": 0.9}
            ],
            443: [  # HTTPS
                {"pattern": r"HTTP/\d+\.\d+", "service": "HTTPS", "confidence": 0.95}
            ],
            993: [  # IMAPS
                {"pattern": r"\* OK.*IMAP", "service": "IMAPS", "confidence": 0.9}
            ],
            995: [  # POP3S
                {"pattern": r"\+OK.*POP3", "service": "POP3S", "confidence": 0.9}
            ],
            3306: [  # MySQL
                {"pattern": r"\d+\.\d+\.\d+", "service": "MySQL", "confidence": 0.7}
            ],
            3389: [  # RDP
                {"pattern": r".", "service": "RDP", "confidence": 0.8}  # RDP has binary protocol
            ]
        }

    def detect_service(self, target: str, port: int) -> Dict:
        """Detect service on target:port with enhanced fingerprinting"""
        result = {
            "port": port,
            "service": "Unknown",
            "version": "",
            "confidence": 0.0,
            "banner": "",
            "ssl": False,
            "error": None
        }

        try:
            # Try SSL first for SSL-enabled services
            use_ssl = port in [443, 993, 995, 465, 587]
            banner = self._get_banner(target, port, use_ssl)

            if banner:
                result["banner"] = banner
                result["ssl"] = use_ssl

                # Analyze banner against signatures
                detection = self._analyze_banner(banner, port)
                result.update(detection)

        except Exception as e:
            result["error"] = str(e)

        return result

    def _get_banner(self, target: str, port: int, use_ssl: bool = False) -> Optional[str]:
        """Get service banner with protocol-specific handling"""
        sock = None
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

            sock.settimeout(self.timeout)
            sock.connect((target, port))

            # Protocol-specific banner retrieval
            if port in [21, 25, 110, 143]:  # Text-based protocols
                banner = sock.recv(1024).decode(errors='ignore').strip()
            elif port == 22:  # SSH
                banner = sock.recv(1024).decode(errors='ignore').strip()
            elif port in [80, 443]:  # HTTP/HTTPS
                request = f"HEAD / HTTP/1.1\r\nHost: {target}\r\nConnection: close\r\n\r\n"
                sock.send(request.encode())
                response = sock.recv(4096).decode(errors='ignore')
                banner = response.split('\n')[0] if response else ""
            elif port in [993, 995]:  # SSL IMAP/POP3
                banner = sock.recv(1024).decode(errors='ignore').strip()
            else:  # Generic
                banner = sock.recv(1024).decode(errors='ignore').strip()

            sock.close()
            return banner

        except Exception as e:
            if sock:
                try:
                    sock.close()
                except:
                    pass
            return None

    def _analyze_banner(self, banner: str, port: int) -> Dict:
        """Analyze banner against service signatures"""
        if not banner or port not in self.service_signatures:
            return {"service": "Unknown", "version": "", "confidence": 0.0}

        best_match = {"service": "Unknown", "version": "", "confidence": 0.0}

        for signature in self.service_signatures[port]:
            pattern = signature["pattern"]
            matches = re.search(pattern, banner, re.IGNORECASE)

            if matches:
                confidence = signature["confidence"]

                # Extract version if available
                version = ""
                if len(matches.groups()) > 0:
                    version = matches.group(1)

                # Update if better confidence
                if confidence > best_match["confidence"]:
                    best_match = {
                        "service": signature["service"],
                        "version": version,
                        "confidence": confidence
                    }

        return best_match

    def batch_detect(self, target: str, ports: List[int]) -> List[Dict]:
        """Detect services on multiple ports"""
        results = []
        for port in ports:
            result = self.detect_service(target, port)
            results.append(result)
            time.sleep(0.1)  # Rate limiting
        return results

def main():
    """Command-line interface for service detection"""
    import argparse

    parser = argparse.ArgumentParser(description="Advanced Service Detection")
    parser.add_argument("target", help="Target IP or hostname")
    parser.add_argument("-p", "--ports", help="Ports to scan (comma-separated)", default="21,22,80,443")
    parser.add_argument("-t", "--timeout", type=float, default=5.0, help="Connection timeout")
    parser.add_argument("-j", "--json", action="store_true", help="Output in JSON format")

    args = parser.parse_args()

    ports = [int(p.strip()) for p in args.ports.split(',')]
    detector = ServiceDetector(timeout=args.timeout)

    print(f"Detecting services on {args.target}...")
    results = detector.batch_detect(args.target, ports)

    if args.json:
        import json
        output = {
            "target": args.target,
            "detections": results,
            "timestamp": time.time()
        }
        print(json.dumps(output, indent=2))
    else:
        print(f"\nService detection results for {args.target}:")
        print("-" * 50)

        for result in results:
            status = "✅" if result["service"] != "Unknown" else "❌"
            print(f"{status} Port {result['port']}: {result['service']}")
            if result["version"]:
                print(f"   Version: {result['version']}")
            if result["confidence"] > 0:
                print(f"   Confidence: {result['confidence']:.1%}")
            if result["error"]:
                print(f"   Error: {result['error']}")
            print()

if __name__ == "__main__":
    main()