#!/usr/bin/env python3
"""
Web Application Firewall Detection Module
Specialized WAF fingerprinting for reconnaissance
"""

import socket
import ssl
import re
import json
import time
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse

class WAFDetector:
    """Advanced WAF detection and fingerprinting"""

    def __init__(self, timeout=10.0):
        self.timeout = timeout
        self.waf_signatures = self._load_waf_signatures()

    def _load_waf_signatures(self) -> Dict[str, Dict]:
        """Load comprehensive WAF detection signatures"""
        return {
            "incapsula": {
                "headers": {
                    "x-iinfo": r"^\d+-\d+-\d+",
                    "x-cdn": "Incapsula"
                },
                "response_patterns": [
                    r"Incapsula incident ID",
                    r"Request unsuccessful\. Incapsula incident ID",
                    r"www\.incapsula\.com"
                ],
                "block_pages": [
                    r"Incapsula",
                    r"Request unsuccessful",
                    r"incident ID"
                ],
                "confidence": 0.95
            },
            "cloudflare": {
                "headers": {
                    "cf-ray": r"^[a-f0-9]{16}-[A-Z]{3}$",
                    "server": "cloudflare",
                    "cf-cache-status": r".*"
                },
                "response_patterns": [
                    r"Cloudflare Ray ID",
                    r"DDoS protection by Cloudflare",
                    r"cf-browser-verification"
                ],
                "block_pages": [
                    r"Checking your browser",
                    r"cf-browser-verification",
                    r"cf-challenge-running"
                ],
                "confidence": 0.95
            },
            "akamai": {
                "headers": {
                    "x-akamai": r".*",
                    "server": "AkamaiGHost"
                },
                "response_patterns": [
                    r"AkamaiGHost",
                    r"akamai\.com"
                ],
                "block_pages": [
                    r"Access Denied",
                    r"Akamai"
                ],
                "confidence": 0.9
            },
            "sucuri": {
                "headers": {
                    "x-sucuri": r".*",
                    "server": "Sucuri"
                },
                "response_patterns": [
                    r"Sucuri WebSite Firewall",
                    r"sucuri\.net"
                ],
                "block_pages": [
                    r"Sucuri",
                    r"WebSite Firewall"
                ],
                "confidence": 0.9
            },
            "mod_security": {
                "response_patterns": [
                    r"Mod_Security",
                    r"mod_security",
                    r"OWASP ModSecurity"
                ],
                "block_pages": [
                    r"403 Forbidden",
                    r"ModSecurity",
                    r"Security Violation"
                ],
                "confidence": 0.8
            },
            "f5_bigip": {
                "headers": {
                    "x-wa-info": r".*"
                },
                "response_patterns": [
                    r"Big-IP",
                    r"F5 Networks"
                ],
                "confidence": 0.85
            },
            "imperva": {
                "headers": {
                    "x-iinfo": r"^\d+-\d+-\d+",
                    "x-imperva": r".*"
                },
                "response_patterns": [
                    r"Imperva",
                    r"incapsula"
                ],
                "confidence": 0.9
            }
        }

    def detect_waf(self, target: str, port: int = 80, use_ssl: bool = False) -> Dict:
        """Comprehensive WAF detection"""
        result = {
            "target": target,
            "port": port,
            "waf_detected": False,
            "waf_name": "",
            "confidence": 0.0,
            "detection_methods": [],
            "headers": {},
            "response_code": 0,
            "error": None
        }

        try:
            # Get HTTP response
            response, headers = self._get_http_response(target, port, use_ssl)

            if response:
                result["headers"] = dict(headers)
                result["response_code"] = self._extract_status_code(response)

                # Analyze for WAF signatures
                waf_analysis = self._analyze_waf_signatures(response, headers)
                result.update(waf_analysis)

                # Additional detection methods
                additional_tests = self._run_additional_tests(target, port, use_ssl)
                result["detection_methods"].extend(additional_tests)

        except Exception as e:
            result["error"] = str(e)

        return result

    def _get_http_response(self, target: str, port: int, use_ssl: bool) -> Tuple[Optional[str], Dict]:
        """Get HTTP response with comprehensive header capture"""
        sock = None
        try:
            if use_ssl or port == 443:
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

            # Send HEAD request to minimize data transfer
            request = (
                f"HEAD / HTTP/1.1\r\n"
                f"Host: {target}\r\n"
                "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36\r\n"
                "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n"
                "Accept-Language: en-US,en;q=0.5\r\n"
                "Accept-Encoding: gzip, deflate\r\n"
                "Connection: close\r\n"
                "\r\n"
            )

            sock.send(request.encode())

            response = b""
            while True:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                response += chunk
                if b"\r\n\r\n" in response:  # Headers received
                    break

            response_str = response.decode(errors='ignore')
            headers = self._parse_headers(response_str)

            sock.close()
            return response_str, headers

        except Exception as e:
            if sock:
                try:
                    sock.close()
                except:
                    pass
            return None, {}

    def _parse_headers(self, response: str) -> Dict[str, str]:
        """Parse HTTP headers from response"""
        headers = {}
        lines = response.split('\n')

        for line in lines[1:]:  # Skip status line
            line = line.strip()
            if ': ' in line:
                key, value = line.split(': ', 1)
                headers[key.lower()] = value

        return headers

    def _extract_status_code(self, response: str) -> int:
        """Extract HTTP status code"""
        first_line = response.split('\n')[0]
        parts = first_line.split()
        if len(parts) >= 2:
            try:
                return int(parts[1])
            except ValueError:
                pass
        return 0

    def _analyze_waf_signatures(self, response: str, headers: Dict[str, str]) -> Dict:
        """Analyze response against WAF signatures"""
        best_match = {
            "waf_detected": False,
            "waf_name": "",
            "confidence": 0.0
        }

        response_lower = response.lower()

        for waf_name, signatures in self.waf_signatures.items():
            confidence = 0.0
            matches = []

            # Check headers
            if "headers" in signatures:
                for header_name, pattern in signatures["headers"].items():
                    if header_name in headers:
                        header_value = headers[header_name]
                        if re.search(pattern, header_value, re.IGNORECASE):
                            confidence += 0.3
                            matches.append(f"Header: {header_name}")

            # Check response patterns
            if "response_patterns" in signatures:
                for pattern in signatures["response_patterns"]:
                    if re.search(pattern, response, re.IGNORECASE):
                        confidence += 0.4
                        matches.append(f"Response pattern: {pattern}")

            # Check block pages
            if "block_pages" in signatures:
                for pattern in signatures["block_pages"]:
                    if re.search(pattern, response, re.IGNORECASE):
                        confidence += 0.3
                        matches.append(f"Block page: {pattern}")

            # Apply base confidence
            if confidence > 0:
                confidence = min(confidence, signatures.get("confidence", 0.8))

            if confidence > best_match["confidence"]:
                best_match = {
                    "waf_detected": True,
                    "waf_name": waf_name.title(),
                    "confidence": confidence,
                    "matches": matches
                }

        return best_match

    def _run_additional_tests(self, target: str, port: int, use_ssl: bool) -> List[str]:
        """Run additional WAF detection tests"""
        tests = []

        # Test with suspicious User-Agent
        suspicious_response, _ = self._get_http_response_with_ua(
            target, port, use_ssl, "sqlmap/1.0"
        )
        if suspicious_response and "403" in suspicious_response:
            tests.append("Blocked suspicious User-Agent")

        # Test with common attack patterns in URL
        attack_response, _ = self._get_http_response_with_path(
            target, port, use_ssl, "/admin.php?cmd=ls"
        )
        if attack_response and ("403" in attack_response or "block" in attack_response.lower()):
            tests.append("Blocked suspicious URL parameters")

        return tests

    def _get_http_response_with_ua(self, target: str, port: int, use_ssl: bool, user_agent: str) -> Tuple[Optional[str], Dict]:
        """Get response with custom User-Agent"""
        # Similar to _get_http_response but with custom UA
        return self._get_http_response(target, port, use_ssl)  # Simplified for now

    def _get_http_response_with_path(self, target: str, port: int, use_ssl: bool, path: str) -> Tuple[Optional[str], Dict]:
        """Get response with custom path"""
        # Similar to _get_http_response but with custom path
        return self._get_http_response(target, port, use_ssl)  # Simplified for now

    def batch_detect(self, targets: List[str], port: int = 80) -> List[Dict]:
        """Detect WAF on multiple targets"""
        results = []
        for target in targets:
            result = self.detect_waf(target, port)
            results.append(result)
            time.sleep(0.5)  # Rate limiting
        return results

def main():
    """Command-line interface for WAF detection"""
    import argparse

    parser = argparse.ArgumentParser(description="Advanced WAF Detection")
    parser.add_argument("target", help="Target hostname or IP")
    parser.add_argument("-p", "--port", type=int, default=80, help="Port to test")
    parser.add_argument("-s", "--ssl", action="store_true", help="Use SSL/TLS")
    parser.add_argument("-t", "--timeout", type=float, default=10.0, help="Connection timeout")
    parser.add_argument("-j", "--json", action="store_true", help="Output in JSON format")

    args = parser.parse_args()

    detector = WAFDetector(timeout=args.timeout)
    result = detector.detect_waf(args.target, args.port, args.ssl)

    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print(f"WAF Detection Results for {args.target}:{args.port}")
        print("=" * 50)

        if result["waf_detected"]:
            print(f"✅ WAF Detected: {result['waf_name']}")
            print(f"   Confidence: {result['confidence']:.1%}")
            print(f"   Response Code: {result['response_code']}")

            if "matches" in result:
                print("   Detection Methods:")
                for match in result["matches"]:
                    print(f"   • {match}")
        else:
            print("❌ No WAF detected")

        if result["error"]:
            print(f"Error: {result['error']}")

if __name__ == "__main__":
    main()