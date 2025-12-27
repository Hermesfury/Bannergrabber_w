# Enhanced Banner Grabber - Professional Reconnaissance Tool

A comprehensive, industry-ready banner grabbing and reconnaissance suite for security research and penetration testing.

## 🛠️ Complete Reconnaissance Suite

### **bannergrab.py** - All-in-One Intelligence Tool
**Professional-grade banner grabbing with advanced reconnaissance capabilities:**

#### **Core Scanning Engine**
- **Multi-Protocol Support**: HTTP/S, FTP, SSH, SMTP, POP3, IMAP, RDP, Telnet
- **Intelligent Connection Management**: 3-retry exponential backoff, SSL/TLS handling
- **Advanced Error Handling**: Graceful failures with comprehensive logging

#### **Intelligence & Detection**
- **WAF Detection**: Incapsula, Cloudflare, Akamai, Sucuri, ModSecurity, F5, Imperva
- **Server Fingerprinting**: Apache, nginx, IIS with advanced version detection
- **CDN Identification**: Cloudflare, Akamai, Fastly, and enterprise CDNs
- **OS Detection**: Windows, Linux, Unix, macOS inference from responses

#### **Evasion & Stealth**
- **WAF Evasion**: Header manipulation, request fragmentation, timing delays
- **Stealth Mode**: Random delays to avoid detection and rate limiting
- **User-Agent Rotation**: Multiple browser signatures for better reconnaissance

#### **Analysis & Reporting**
- **Comprehensive Output**: JSON/CSV with detailed server analysis
- **Security Assessment**: Automatic risk scoring and recommendations
- **Multi-format Export**: JSON, CSV, and structured text reports

## 🚀 Usage Guide

### Basic Banner Grabbing
```bash
# Scan default ports on target
python bannergrab.py example.com

# Scan specific ports
python bannergrab.py example.com -p 80,443,8080

# Verbose output with detailed logging
python bannergrab.py example.com -p 80,443 -v
```

### Advanced Reconnaissance

#### Web Server Intelligence
```bash
# Comprehensive web analysis
python bannergrab.py site.com -p 80,443,8080,8443

# WAF-protected sites with evasion
python bannergrab.py protected-site.com -p 80,443 -w

# Stealth scanning
python bannergrab.py target.com -p 80,443 -s
```

#### Mail Server Enumeration
```bash
# Complete mail infrastructure
python bannergrab.py mail.company.com -p 25,465,587,993,995 -v
```

#### Remote Access Assessment
```bash
# SSH and RDP analysis
python bannergrab.py server.company.com -p 22,3389 -v
```

#### Multi-Target Campaigns
```bash
# Infrastructure mapping
python bannergrab.py web01.target.com web02.target.com api.target.com -p 80,443
```

### Performance Optimization
```bash
# High-throughput scanning
python bannergrab.py target.com --threads 50 -t 2.0

# Low-and-slow reconnaissance
python bannergrab.py target.com -s -t 15.0 --threads 1

# Custom timeout
python bannergrab.py target.com -t 10.0
```

## 📊 Understanding Results

### Sample Output
```json
{
  "target": "example.com",
  "port": 80,
  "protocol": "HTTP",
  "server_info": {
    "server": "Apache",
    "version": "",
    "waf": "Incapsula",
    "status_line": "HTTP/1.1 503 Service Unavailable"
  }
}
```

### Key Fields Explained
- **`server`**: Web server type (Apache, nginx, IIS)
- **`version`**: Version when detectable
- **`waf`**: WAF protection (Incapsula, Cloudflare, etc.)
- **`status_line`**: HTTP response analysis

## 🔒 Security Analysis

### Risk Assessment
The tool provides automatic analysis of:
- **Exposed high-risk services** (FTP, SSH, RDP)
- **WAF protection status**
- **Outdated software versions**
- **Insecure protocol usage**

### WAF Detection Examples
```
✅ Incapsula: X-Iinfo header detected
✅ Cloudflare: CF-RAY header found
✅ Akamai: Akamai-specific headers
```

## 📖 Why Services Fail

### Common Reasons for "Service Unavailable"

1. **Security by Design**
   - Web servers don't expose FTP/SSH for security
   - WAF blocks non-HTTP traffic
   - Corporate firewalls restrict access

2. **Service Not Running**
   - FTP/SSH disabled on web servers
   - Mail services not configured
   - Legacy protocols removed

3. **Network Protection**
   - Firewalls block high-risk ports
   - Cloud security groups
   - DDoS protection systems

### Success Rate Expectations

| Target Type | Expected Success | Common Ports |
|-------------|------------------|--------------|
| Web Server | 20-40% | 80, 443 |
| Mail Server | 60-80% | 25, 110, 143 |
| File Server | 70-90% | 21, 22 |

## 🛡️ Best Practices

### Ethical Scanning
- Get explicit permission before scanning
- Respect robots.txt and ToS
- Use rate limiting to avoid disruption
- Comply with local laws and regulations

### Result Interpretation
- "Access denied" often means "security working"
- WAF detection indicates enterprise protection
- Service unavailability is normal for web servers
- Focus on accessible services for reconnaissance

## 🔧 Command Line Options

```
positional arguments:
  targets               Target hostnames or IPs

optional arguments:
  -p PORTS, --ports PORTS
                        Ports to scan (default: 21,22,23,25,53,80,110,143,443,993,995,3389)
  -t TIMEOUT, --timeout TIMEOUT
                        Connection timeout in seconds (default: 5.0)
  -v, --verbose         Enable verbose output
  -s, --stealth         Enable stealth mode with random delays
  -w, --waf-evasion     Enable WAF evasion techniques
  -o {json,csv}, --output {json,csv}
                        Output format (default: json)
  -f FILENAME, --filename FILENAME
                        Output filename
  --threads THREADS     Number of concurrent threads (default: 10)
```

## 📚 Documentation

- `service_accessibility_guide.md` - Detailed explanation of why services fail
- `implementation_plan.md` - Technical architecture and development details
- `Readme.txt` - Original project documentation

## ⚠️ Legal & Ethical Notice

This tool is designed for authorized security research and penetration testing only. Users are responsible for:

- Obtaining explicit permission before scanning
- Complying with applicable laws and regulations
- Using results responsibly and ethically
- Not causing disruption to production systems

**Unauthorized use may violate laws and terms of service.**

---

**Remember**: In cybersecurity, "access denied" often means "security working correctly" 🔒
