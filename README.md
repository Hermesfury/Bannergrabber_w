# Enhanced Banner Grabber Suite

A comprehensive reconnaissance toolkit for network service enumeration and security analysis.

## 🛠️ Banner Grabber Ecosystem

### **bannergrab.py** - Core Intelligence Tool
**Primary reconnaissance engine with advanced capabilities:**
- **Multi-Protocol Support**: HTTP/S, FTP, SSH, SMTP, POP3, IMAP, RDP, Telnet
- **WAF Evasion**: Bypass protection with header manipulation and timing
- **Intelligent Retry**: 3-attempt exponential backoff for reliability
- **Advanced Fingerprinting**: Server, WAF, CDN, and OS detection
- **Stealth Mode**: Random delays to avoid detection
- **Comprehensive Output**: JSON/CSV with detailed server analysis

### **Complementary Analysis Tools**

#### **service_detector.py** - Deep Service Analysis
- Signature-based service identification
- Version detection with confidence scoring
- Protocol-specific banner analysis

#### **waf_detector.py** - WAF Specialist
- Dedicated WAF fingerprinting (Incapsula, Cloudflare, Akamai, etc.)
- Protection mechanism identification
- Bypass strategy insights

#### **report_generator.py** - Intelligence Synthesis
- Security posture analysis
- Risk assessment and recommendations
- Multi-format reporting (Text/JSON/CSV)
- Executive summary generation

## 🚀 Banner Grabber Usage Guide

### Basic Banner Grabbing
```bash
# Scan default ports (21,22,23,25,53,80,110,143,443,993,995,3389)
python bannergrab.py example.com

# Scan specific ports
python bannergrab.py example.com -p 80,443

# Verbose output with detailed logging
python bannergrab.py example.com -p 80,443 -v
```

### Advanced Scanning Techniques

#### Web Server Analysis
```bash
# HTTP/HTTPS banner grabbing
python bannergrab.py example.com -p 80,443,8080,8443

# With WAF evasion for protected sites
python bannergrab.py example.com -p 80,443 -w

# Stealth mode with random delays
python bannergrab.py example.com -p 80,443 -s
```

#### Mail Server Enumeration
```bash
# SMTP, POP3, IMAP analysis
python bannergrab.py mail.example.com -p 25,110,143,465,993,995

# Secure mail protocols only
python bannergrab.py mail.example.com -p 465,993,995
```

#### Remote Access Services
```bash
# SSH and RDP scanning
python bannergrab.py server.example.com -p 22,3389

# File transfer services
python bannergrab.py ftp.example.com -p 21
```

#### Comprehensive Multi-Protocol Scan
```bash
# Full service enumeration
python bannergrab.py target.com -p 21,22,23,25,53,80,110,143,443,993,995,3389 -v

# High-value target with maximum evasion
python bannergrab.py target.com -p 80,443 -w -s -v
```

### Performance & Reliability Options

#### Connection Optimization
```bash
# Custom timeout for slow networks
python bannergrab.py target.com -t 10.0

# Adjust thread count for performance
python bannergrab.py target.com --threads 20

# Quiet mode for scripting
python bannergrab.py target.com -p 80,443
```

#### Output Customization
```bash
# JSON output (default)
python bannergrab.py target.com -o json

# CSV format for analysis
python bannergrab.py target.com -o csv

# Custom output filename
python bannergrab.py target.com -f my_scan_results.json
```

### Specialized Reconnaissance Scenarios

#### WAF Detection & Bypass Testing
```bash
# Test WAF-protected sites
python bannergrab.py protected-site.com -p 80,443 -w -v

# Analyze CDN-protected content
python bannergrab.py cdn-site.com -p 80,443 -w
```

#### Vulnerability Assessment Prep
```bash
# Gather service banners for version analysis
python bannergrab.py target.com -p 21,22,80,443,3306 -v

# Mail server reconnaissance
python bannergrab.py mail.target.com -p 25,110,143,993,995 -v
```

#### Network Infrastructure Mapping
```bash
# Web farm analysis
python bannergrab.py web01.target.com web02.target.com -p 80,443

# Load balancer detection
python bannergrab.py lb.target.com -p 80,443 -w -v
```

### Analysis & Reporting Workflow

#### Generate Comprehensive Reports
```bash
# Run comprehensive scan
python bannergrab.py target.com -p 21,22,80,443,993,995 -v -w

# Generate detailed analysis report
python report_generator.py banner_grab_results_*.json

# Export to different formats
python report_generator.py results.json -f json -o full_analysis.json
python report_generator.py results.json -f csv -o summary.csv
```

## 📊 Understanding Results

### Banner Grabber Output
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
- **server**: Web server type (Apache, nginx, IIS)
- **version**: Version number (when detectable)
- **waf**: Web Application Firewall (if detected)
- **cdn**: Content Delivery Network (if detected)
- **status_line**: HTTP response code and version

## 🔒 Security Analysis

### Risk Assessment
The tools provide automatic risk scoring based on:
- Exposed high-risk services (FTP, SSH, RDP)
- Missing WAF protection
- Outdated software versions
- Insecure protocol usage

### WAF Detection Results
```
✅ WAF Detected: Incapsula
   Confidence: 95.0%
   Detection Methods:
   • Header: x-iinfo
   • Response pattern: Request unsuccessful. Incapsula incident ID
```

## 📖 Why Services Fail

### Common Reasons for "Service Unavailable"

1. **Security by Design**
   - Web servers don't expose FTP/SSH for security
   - WAF blocks suspicious traffic patterns
   - Geographic/corporate restrictions

2. **Service Not Running**
   - FTP server not installed on web hosts
   - SSH disabled for security
   - Mail services not configured

3. **Network Protection**
   - Firewalls block non-essential ports
   - Cloud security groups restrict access
   - DDoS protection systems

### Expected Success Rates

| Target Type | Typical Success Rate | Common Open Ports |
|-------------|---------------------|-------------------|
| Web Server | 20-40% | 80, 443 |
| Mail Server | 60-80% | 25, 110, 143, 993, 995 |
| File Server | 70-90% | 21, 22, 80, 443 |
| Development | 80-100% | All ports |

## 🛡️ Best Practices

### Ethical Scanning
1. **Get Permission**: Always obtain authorization
2. **Rate Limiting**: Don't overwhelm targets
3. **Respect robots.txt**: Follow web crawler guidelines
4. **Legal Compliance**: Adhere to local laws

### Result Interpretation
- **"Access Denied" = Good Security** (not a vulnerability)
- **WAF Detection = Enterprise Protection**
- **Service Unavailability = Normal** for web servers
- **Focus on What's Accessible** for reconnaissance

## 🔧 Advanced Banner Grabber Techniques

### WAF Evasion Strategies
```bash
# Maximum evasion for protected sites
python bannergrab.py target.com -p 80,443 -w -s -v

# Test different evasion combinations
python bannergrab.py target.com -p 80 -w  # Basic evasion
python bannergrab.py target.com -p 443 -w -s  # Evasion + stealth
```

### Multi-Target Campaigns
```bash
# Scan multiple related targets
python bannergrab.py web01.target.com web02.target.com api.target.com -p 80,443

# Infrastructure mapping
python bannergrab.py lb.target.com cdn.target.com origin.target.com -p 80,443 -w
```

### Protocol-Specific Intelligence
```bash
# Web server deep analysis
python bannergrab.py web.target.com -p 80,443,8080,8443 -w -v

# Mail infrastructure reconnaissance
python bannergrab.py mail.target.com -p 25,465,587,993,995 -v

# Remote administration assessment
python bannergrab.py admin.target.com -p 22,3389,5900 -v
```

### Performance Optimization
```bash
# High-throughput scanning
python bannergrab.py target.com --threads 50 -t 2.0

# Low-and-slow reconnaissance
python bannergrab.py target.com -s -t 15.0 --threads 1

# Balanced performance
python bannergrab.py target.com --threads 10 -t 5.0
```

### Intelligence Analysis Pipeline
```bash
# 1. Initial reconnaissance
python bannergrab.py target.com -p 80,443 -v

# 2. WAF-specific analysis
python waf_detector.py target.com

# 3. Service deep-dive
python service_detector.py target.com -p 21,22,80,443

# 4. Comprehensive reporting
python report_generator.py results.json -f json
```

## 🐛 Troubleshooting

### Common Issues

**High Error Rates**
- Check network connectivity
- Reduce scan intensity
- Use longer timeouts

**WAF False Positives**
- Some CDNs mimic WAF behavior
- Check confidence scores
- Manual verification recommended

**Version Detection Failures**
- Security: Servers hide versions
- WAF: Strips version headers
- Use alternative fingerprinting

### Debug Mode
```bash
# Enable verbose logging
python bannergrab.py target.com -v --max-retries 1
```

## 📚 Documentation

- `service_accessibility_guide.md`: Why services fail and expectations
- `architecture_plan.md`: Technical design and implementation details
- `implementation_plan.md`: Development roadmap and phases

## 🤝 Contributing

### Adding New Signatures
1. Update `service_detector.py` for new services
2. Update `waf_detector.py` for new WAFs
3. Test against known targets
4. Submit pull request

### Improving Detection
1. Analyze false positives/negatives
2. Enhance signature patterns
3. Add confidence scoring
4. Validate against real targets

## 📄 License

This toolkit is for authorized security research and penetration testing only. Users are responsible for complying with applicable laws and regulations.

## ⚠️ Disclaimer

This tool is designed for security research and authorized testing only. Unauthorized use may violate laws and terms of service. Always obtain explicit permission before scanning targets.

---

**Remember**: In cybersecurity, "access denied" often means "security working correctly" 🔒