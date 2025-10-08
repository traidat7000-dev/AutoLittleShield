# 🛡️ AutoLittleShield - Advanced DDoS Protection System

<div align="center">

![Python](https://img.shields.io/badge/Python-3.7+-blue.svg)
![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux%20%7C%20macOS-green.svg)
![License](https://img.shields.io/badge/License-MIT-yellow.svg)
![Status](https://img.shields.io/badge/Status-Production%20Ready-brightgreen.svg)

**Real-time DDoS Protection & Advanced Threat Detection System**

*Protecting your web servers from hackers, bots, and malicious traffic with intelligent pattern recognition and automatic IP blocking.*

</div>

---

## 📋 Table of Contents

- [🚀 Features](#-features)
- [🔧 Installation & Setup](#-installation--setup)
- [⚙️ Configuration](#️-configuration)
- [🖥️ Platform Support](#️-platform-support)
- [📊 Usage Examples](#-usage-examples)
- [🔍 Attack Detection](#-attack-detection)
- [📈 Monitoring & Analytics](#-monitoring--analytics)
- [🛠️ Advanced Configuration](#️-advanced-configuration)
- [🤝 Contributing](#-contributing)
- [📄 License](#-license)

---

## 🚀 Features

### 🎯 **Core Protection Features**

- **🔄 Real-time Log Monitoring** - Continuous scanning of web server logs
- **🌐 Multi-Platform Support** - Windows (netsh), Linux (iptables), macOS (pfctl)
- **🚨 Automatic IP Blocking** - Instant blocking of malicious IPs
- **📧 Email Alerts** - Real-time notifications of blocked threats
- **⚡ High Performance** - Optimized for large log files with minimal resource usage

### 🛡️ **Advanced Attack Detection**

#### **DDoS & Flood Protection**
- **Rate Limiting** - Configurable request limits per IP/subnet
- **Connection Flood Detection** - SYN flood and connection flooding
- **Behavioral Analysis** - User agent spoofing and scanning detection
- **Emergency Mode** - Automatic activation during high system load

#### **Threat Intelligence**
- **Geographic Blocking** - Block IPs from specific countries
- **IP Reputation Checking** - Known malicious IP detection
- **Bot Detection** - 100+ bot user-agent patterns
- **Zero-day Exploit Detection** - Advanced pattern matching for new threats

#### **Web Application Security**
- **SQL Injection Detection** - Comprehensive SQL injection patterns
- **XSS Protection** - Cross-site scripting attempt detection
- **Directory Traversal** - Path traversal and file inclusion attacks
- **API Abuse Monitoring** - Dedicated API endpoint protection
- **OWASP Top 10 2025** - Latest web security threat patterns

#### **Advanced Persistent Threats (APT)**
- **Long Session Detection** - Persistent connection monitoring
- **Privilege Escalation** - Unauthorized access attempts
- **Anomaly Detection** - Unusual hour access patterns
- **Session Analysis** - Multi-session behavior tracking

### 📊 **Monitoring & Analytics**

- **Real-time Dashboard** - Live attack statistics
- **Attack Type Classification** - Detailed threat categorization
- **Performance Metrics** - System load and processing statistics
- **Historical Data** - Suspicious activity tracking
- **Custom Reporting** - Configurable alert thresholds

---

## 🔧 Installation & Setup

### **Prerequisites**

- Python 3.7 or higher
- Administrator/Root privileges (for firewall rules)
- Web server access logs (Apache, Nginx, IIS)

### **1. Clone the Repository**

```bash
git clone https://github.com/yourusername/AutoLittleShield.git
cd AutoLittleShield
```

### **2. Install Dependencies**

#### **Core Dependencies**
```bash
pip install -r requirements.txt
```

#### **Optional Dependencies** (Enhanced Features)
```bash
# GeoIP Location Detection
pip install geoip2 maxminddb

# System Monitoring
pip install psutil

# Performance Optimization
pip install blist
```

### **3. Platform-Specific Setup**

#### **🪟 Windows Setup**
```bash
# Run as Administrator
# Windows Firewall must be enabled
python UplenGIT.py
```

#### **🐧 Linux Setup**
```bash
# Install iptables (Ubuntu/Debian)
sudo apt-get update
sudo apt-get install iptables

# Install iptables (RHEL/CentOS)
sudo yum install iptables

# Run with root privileges
sudo python UplenGIT.py
```

#### **🍎 macOS Setup**
```bash
# Enable Packet Filter in System Preferences > Security & Privacy
# Run with root privileges
sudo python UplenGIT.py
```

---

## ⚙️ Configuration

### **Basic Configuration**

Edit the configuration section in `UplenGIT.py`:

```python
# Log file path (required)
LOG_FILE = r'/var/log/apache2/access.log'  # Linux
LOG_FILE = r'C:\inetpub\logs\LogFiles\W3SVC1\ex*.log'  # Windows

# Blocked IPs storage
BLOCKED_IPS_FILE = 'blocked_ips.txt'

# Suspicious requests tracking
SUSPICIOUS_FILE = 'suspicious_requests.json'
```

### **Email Alerts Setup**

```python
# Gmail SMTP Configuration
gmail_email = "your-email@gmail.com"
gmail_password = "your-app-password"  # Use App Password, not regular password
```

### **Rate Limiting Configuration**

```python
RATE_LIMITS = {
    "IP": {"requests": 100, "window": 60},        # 100 requests/minute per IP
    "SUBNET": {"requests": 1000, "window": 60},   # 1000 requests/minute per subnet
    "GLOBAL": {"requests": 5000, "window": 60},   # 5000 requests/minute globally
    "API": {"requests": 50, "window": 60}         # 50 API requests/minute per IP
}
```

### **Geographic Blocking**

```python
# Blocked countries (ISO codes)
blocked_countries = {'CN', 'RU', 'UA', 'TR', 'BR'}

# Allowed countries (whitelist)
allowed_countries = {'VN', 'US', 'SG'}
```

---

## 🖥️ Platform Support

| Platform | Firewall | Tailing | Status |
|----------|----------|---------|---------|
| **Windows** | netsh | PowerShell | ✅ Full Support |
| **Linux** | iptables/ip6tables | tail -f | ✅ Full Support |
| **macOS** | pfctl | tail -f | ✅ Full Support |

### **Platform-Specific Features**

- **IPv4/IPv6 Support** - All platforms support both IP versions
- **Subnet Blocking** - Automatic subnet-level protection
- **Real-time Monitoring** - Platform-optimized log tailing
- **Root Privilege Detection** - Automatic permission checking

---

## 📊 Usage Examples

### **Basic Usage**

```bash
# Start protection system
python UplenGIT.py

# With specific log file
python UplenGIT.py --log-file /var/log/nginx/access.log

# Verbose output
python UplenGIT.py --verbose
```

### **Configuration Examples**

#### **High-Traffic Website**
```python
RATE_LIMITS = {
    "IP": {"requests": 200, "window": 60},
    "SUBNET": {"requests": 2000, "window": 60},
    "API": {"requests": 100, "window": 60}
}
```

#### **API-Focused Protection**
```python
WHITELIST_API_PATTERNS = [
    r'/api/health',
    r'/api/status',
    r'/api/version'
]
```

#### **E-commerce Security**
```python
HACKER_PATTERNS.extend([
    r'/admin.*login',
    r'/wp-admin',
    r'/phpmyadmin',
    r'/\.env',
    r'/config\.php'
])
```

---

## 🔍 Attack Detection

### **Detected Attack Types**

| Attack Type | Description | Auto-Block |
|-------------|-------------|------------|
| **RATE_LIMIT** | Excessive requests per time window | ✅ |
| **HACKER_PATTERN** | Known exploit patterns | ✅ |
| **GEO_BLOCKED** | IPs from blocked countries | ✅ |
| **BEHAVIOR_ANOMALY** | Unusual user behavior | ✅ |
| **CONNECTION_FLOOD** | SYN flood attacks | ✅ |
| **API_ABUSE** | API endpoint abuse | ✅ |
| **APT_SUSPICIOUS** | Advanced persistent threats | ✅ |
| **ZERO_DAY_ANOMALY** | Unknown exploit patterns | ✅ |

### **Pattern Examples**

```python
# SQL Injection Detection
r'SELECT.*UNION.*ALL.*DROP.*INSERT.*UPDATE.*DELETE'

# XSS Protection
r'<script>.*</script>.*javascript:.*onerror.*onload'

# Directory Traversal
r'/\.\./.*%2e%2e%2f.*%252e%252e%2f'

# Bot Detection
r'sqlmap.*nikto.*gobuster.*dirbuster.*wfuzz'

# Zero-day Exploits
r'\$\{jndi:ldap://.*CVE-2021-44228.*Log4j'
```

---

## 📈 Monitoring & Analytics

### **Real-time Dashboard**

```
==================================================
🛡️ DDoS PROTECTION DASHBOARD
==================================================
Total Requests: 15,432
Blocked Requests: 89
Unique IPs: 1,234
Attack Types: {
    'HACKER_PATTERN': 45,
    'RATE_LIMIT': 23,
    'GEO_BLOCKED': 12,
    'API_ABUSE': 9
}
==================================================
```

### **Performance Metrics**

- **Processing Speed**: ~10,000 lines/second
- **Memory Usage**: <100MB typical
- **CPU Usage**: <5% during normal operation
- **Emergency Mode**: Automatic activation at 85% CPU/90% Memory

---

## 🛠️ Advanced Configuration

### **Custom Attack Patterns**

Add your own detection patterns:

```python
CUSTOM_PATTERNS = [
    r'/your-specific-endpoint',
    r'your-custom-header:.*malicious-value',
    r'your-app-specific-exploit'
]

HACKER_PATTERNS.extend(CUSTOM_PATTERNS)
```

### **Whitelist Configuration**

```python
# Whitelist trusted IPs
WHITELIST_IPS = {
    '192.168.1.0/24',  # Local network
    '10.0.0.0/8',      # Corporate network
    '203.0.113.1'      # Trusted server
}

# Whitelist API patterns
WHITELIST_API_PATTERNS = [
    r'/api/health',
    r'/api/metrics',
    r'/api/status'
]
```

### **Emergency Mode Configuration**

```python
emergency_thresholds = {
    "cpu": 85,           # Activate at 85% CPU
    "memory": 90,        # Activate at 90% Memory
    "connections": 10000 # Activate at 10k connections
}
```

---

## 🔧 Troubleshooting

### **Common Issues**

#### **Permission Denied**
```bash
# Linux/macOS
sudo python UplenGIT.py

# Windows
# Run Command Prompt as Administrator
```

#### **iptables Not Found**
```bash
# Ubuntu/Debian
sudo apt-get install iptables

# RHEL/CentOS
sudo yum install iptables
```

#### **GeoIP Database Missing**
```bash
# Download GeoLite2 database
wget https://geolite.maxmind.com/download/geoip/database/GeoLite2-Country.mmdb.gz
gunzip GeoLite2-Country.mmdb.gz
```

### **Debug Mode**

Enable detailed logging:

```python
import logging
logging.basicConfig(level=logging.DEBUG)
```

---

## 🤝 Contributing

We welcome contributions! Here's how you can help:

### **Ways to Contribute**

- 🐛 **Bug Reports** - Found an issue? Open an issue!
- 💡 **Feature Requests** - Have an idea? Let us know!
- 🔧 **Code Contributions** - Submit a pull request!
- 📚 **Documentation** - Help improve our docs!
- 🧪 **Testing** - Test on different platforms!

### **Development Setup**

```bash
# Fork and clone the repository
git clone https://github.com/yourusername/AutoLittleShield.git

# Install development dependencies
pip install -r requirements-dev.txt

# Run tests
python -m pytest tests/

# Run linting
flake8 UplenGIT.py
```

### **Pull Request Guidelines**

- Follow PEP 8 style guidelines
- Add tests for new features
- Update documentation
- Ensure cross-platform compatibility

---

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## 🙏 Acknowledgments

- **OWASP Foundation** - For security pattern definitions
- **MaxMind** - For GeoIP database
- **Python Community** - For excellent libraries and tools

---

<div align="center">

**Made with ❤️ for Web Security**

[⭐ Star this repo](https://github.com/yourusername/AutoLittleShield) | [🐛 Report Bug](https://github.com/yourusername/AutoLittleShield/issues) | [💡 Request Feature](https://github.com/yourusername/AutoLittleShield/issues)

</div>
