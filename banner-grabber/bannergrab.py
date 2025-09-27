# web_fingerprinter.py
# Advanced stack detection: Apache, PHP, WordPress, OpenSSL, OS
import socket
import ssl
import re
from datetime import datetime
import urllib.parse

def fetch_response(ip, port, path="/", method="GET", headers={}):
    """Fetch HTTP/HTTPS response with custom headers"""
    try:
        if port == 443:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            sock = context.wrap_socket(
                socket.socket(socket.AF_INET, socket.SOCK_STREAM),
                server_hostname=headers.get("Host", ip)
            )
        else:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        sock.settimeout(5)
        sock.connect((ip, port))

        host = headers.get("Host", ip)
        request_lines = [
            f"{method} {path} HTTP/1.1",
            f"Host: {host}",
            "User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
            "Accept: text/html,application/xhtml+xml",
            "Accept-Language: en-US",
            "Connection: close"
        ]
        for k, v in headers.items():
            if k != "Host":
                request_lines.append(f"{k}: {v}")

        request = "\r\n".join(request_lines) + "\r\n\r\n"
        sock.send(request.encode())
        response = sock.recv(8192).decode(errors='ignore')
        sock.close()
        return response
    except Exception as e:
        return f"Error: {e}"

def extract_header(response, header):
    for line in response.splitlines():
        if line.lower().startswith(header.lower() + ":"):
            return line.strip()
    return None

def detect_php(response):
    """Detect PHP version from headers or body"""
    # 1. X-Powered-By: PHP/8.1.12
    powered = extract_header(response, "X-Powered-By")
    if powered and "PHP" in powered:
        ver_match = re.search(r'PHP\/([\d\.]+)', powered, re.I)
        if ver_match:
            return f"PHP {ver_match.group(1)}", powered

    # 2. Set-Cookie: PHPSESSID=
    if "PHPSESSID" in response:
        return "PHP (session detected)", None

    # 3. HTML comments or paths like /wp-includes/
    if re.search(r'/wp-content/|/wp-includes/|/xmlrpc.php', response, re.I):
        return "PHP (WordPress pattern)", None

    return None, None

def detect_wordpress(response, url):
    """Detect WordPress and version"""
    clues = []

    # 1. Meta generator: <meta name="generator" content="WordPress 6.5.3" />
    gen_match = re.search(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']WordPress ([\d\.]+)', response, re.I)
    if gen_match:
        clues.append(f"✅ WordPress {gen_match.group(1)} (via meta tag)")

    # 2. Readme.html or license.txt
    if "liCENSE" in response.upper() and "GNU" in response and "WordPress" in response:
        clues.append("✅ WordPress license.txt detected")

    # 3. /wp-login.php or /wp-admin/
    if "wp-login" in response or "wp-admin" in response:
        clues.append("🔹 wp-login/wp-admin detected")

    # 4. REST API endpoint
    if '/wp-json/wp/v2/' in response:
        clues.append("✅ WordPress REST API exposed")

    # 5. Version in JS/CSS paths: /wp-includes/js/jquery/jquery.min.js?ver=6.5.3
    ver_match = re.search(r'[\?&]ver=([\d\.]+)', response)
    if ver_match:
        clues.append(f"📌 Possible version {ver_match.group(1)} from script")

    return clues

def detect_apache(response, ip, port):
    """Detect Apache version even when hidden"""
    clues = []

    # 1. Direct Server header
    server = extract_header(response, "Server")
    if server and "Apache" in server:
        clues.append(f"🔹 {server}")
        ver = re.search(r'Apache[/ ]([\d\.]+)', server, re.I)
        if ver:
            clues.append(f"✅ Apache Version: {ver.group(1)}")

    # 2. Default "It works!" page
    if re.search(r"It works[\!]*[\s\S]*Apache Server", response, re.I):
        clues.append("✅ Apache default page detected")

    # 3. 404 Error page leak
    error_resp = fetch_response(ip, port, "/nonexistent_" + str(hash(datetime.now())), "GET", {"Host": ip})
    if "Apache" in error_resp and "404" in error_resp:
        clues.append("✅ 404 error page leaks Apache")

    # 4. mod_php in headers
    if "X-Powered-By" in response and "PHP" in response:
        clues.append("🔸 mod_php likely in use")

    return clues

def detect_ssl_version(ip):
    """Try to get SSL/TLS version and OpenSSL clues"""
    try:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        conn = context.wrap_socket(socket.socket(), server_hostname=ip)
        conn.connect((ip, 443))
        cert = conn.getpeercert()

        # Subject/Issuer may leak software
        subject = dict(x[0] for x in cert.get('subject', []))
        issuer = dict(x[0] for x in cert.get('issuer', []))

        cn = subject.get('commonName', '')
        issuer_name = issuer.get('organizationName', '')

        conn.close()

        return {
            "protocol": conn.version(),
            "common_name": cn,
            "issuer": issuer_name
        }
    except Exception as e:
        return {"error": str(e)}

def main():
    print("🔍 FULL-STACK WEBSITE FINGERPRINTER")
    print("🎯 Detects Apache, PHP, WordPress, SSL, and more")
    print("🔐 Even when servers try to hide versions")
    print("=" * 60)

    target = input("🌐 Enter domain (e.g., yoursite.com): ").strip()
    if not target:
        print("❌ Target required!")
        return

    print("🔄 Resolving...")
    try:
        ip = socket.gethostbyname(target)
        print(f"✅ IP: {ip}")
    except socket.gaierror:
        print("❌ Could not resolve domain.")
        return

    # Scan both HTTP and HTTPS
    ports = [80, 443]
    results = {}

    for port in ports:
        print(f"\n📡 Probing port {port}...")
        response = fetch_response(ip, port, headers={"Host": target})
        if response.startswith("Error"):
            print(f"   ❌ {response}")
            continue

        results[port] = response

        # Extract Server header
        server = extract_header(response, "Server")
        print(f"   {server or 'No Server header'}")

    if not results:
        print("❌ No responses. Check connectivity.")
        return

    print("\n" + "="*60)
    print("🔍 FINAL ANALYSIS")
    print("="*60)

    # Run all detectors
    for port, response in results.items():
        print(f"\n📋 PORT {port} FINDINGS:")

        # Apache
        apache_clues = detect_apache(response, ip, port)
        if apache_clues:
            for c in apache_clues:
                print(f"  {c}")

        # PHP
        php_ver, _ = detect_php(response)
        if php_ver:
            print(f"  ✅ {php_ver}")

        # WordPress
        wp_clues = detect_wordpress(response, target)
        for c in wp_clues:
            print(f"  {c}")

    # SSL Info
    if 443 in results:
        print(f"\n🔐 SSL/TLS INFO (port 443):")
        ssl_info = detect_ssl_version(target)
        if "error" not in ssl_info:
            print(f"  Protocol: {ssl_info['protocol']}")
            print(f"  Issuer: {ssl_info['issuer']}")
            if "Let's Encrypt" not in ssl_info['issuer']:
                print(f"  Common Name: {ssl_info['common_name']}")
        else:
            print(f"  ❌ SSL detection failed: {ssl_info['error']}")

    # Summary
    print("\n💡 SUMMARY:")
    found = []
    if any("Apache" in c for r in results.values() for c in detect_apache(r, ip, 80)):
        found.append("Apache")
    php_ver, _ = detect_php(results.get(80) or results.get(443))
    if php_ver:
        found.append("PHP")
    if any("WordPress" in c for r in results.values() for c in detect_wordpress(r, target)):
        found.append("WordPress")

    if found:
        print(f"✅ Detected stack: {', '.join(found)}")
    else:
        print("❌ No clear stack detected (highly hardened or behind CDN)")

    print("\n🛡️  Hermes Banner grabber Use this to secure your site — not to attack others.")

if __name__ == "__main__":
    main()