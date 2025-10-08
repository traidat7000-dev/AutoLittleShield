import re
import subprocess
import time
import os
from datetime import datetime, timedelta
import json
from collections import defaultdict, deque
import threading
import heapq
import smtplib
from email.mime.text import MIMEText
import ipaddress
import queue

# Lazy imports for optional modules
GEOIP_AVAILABLE = False
PSUTIL_AVAILABLE = False
BLIST_AVAILABLE = False
MAXMINDDB_AVAILABLE = False

try:
    import geoip2.database
    import maxminddb
    GEOIP_AVAILABLE = True
except ImportError:
    print("[WARN] geoip2/maxminddb not installed. GeoIP fallback disabled. Run: pip install geoip2 maxminddb")

try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    print("[WARN] psutil not installed. System monitoring fallback disabled. Run: pip install psutil")

try:
    from blist import sorteddict
    BLIST_AVAILABLE = True
except ImportError:
    print("[WARN] blist not installed. Using dict fallback. Run: pip install blist")

# ==================== THÊM FUNCTION Ở ĐÂY ====================
def extract_and_validate_ip(line):
    """Extract và validate IP từ log line (IPv4/IPv6)"""
    # Tìm candidate IPs bằng regex đơn giản trước
    candidates = re.findall(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b|(?:[a-fA-F0-9:]+)\b', line)
    for cand in candidates:
        try:
            if ':' in cand:  # IPv6
                ipaddress.IPv6Address(cand)
            else:  # IPv4
                ipaddress.IPv4Address(cand)
            return cand  # Trả IP valid đầu tiên
        except ipaddress.AddressValueError:
            continue  # Skip invalid
    return None
# ==================== KẾT THÚC THÊM ====================

# Configuration
LOG_FILE = r''
FAIL2BAN_FILE = ''

print(f"🔄 Using log file: {LOG_FILE}")
print(f"📁 File exists: {os.path.exists(LOG_FILE)}")
if os.path.exists(LOG_FILE):
    print(f"📏 File size: {os.path.getsize(LOG_FILE)} bytes")

# Comprehensive hacker/bot patterns - Bổ sung cho advanced attacks
HACKER_PATTERNS = [
    # Malformed requests and errors
    r'Invalid HTTP request received',
    r' 500 Internal Server Error',
    r' 404 Not Found',
    r' 403 Forbidden',
    
    # Unusual HTTP methods
    r'CONNECT ',
    r'TRACE ',
    r'PUT ',
    r'DELETE ',
    r'HEAD ',
    r'OPTIONS ',
    
    # Common exploit paths
    r'POST /ws/v1/cluster/apps/new-application',
    r'/\.\./|%2e%2e%2f|%252e%252e%2f',
    r'/etc/passwd|/proc/self/environ|/.env',
    r'/xmlrpc\.php',
    r'/admin|/phpmyadmin|/wp-admin|/wp-login|/shell|/manager|/solr|/jenkins',
    r'/\?id=|/\?cat=|/user/|/category/|/product/',
    
    # SQL Injection signatures
    r'SELECT|UNION|ALL|DROP|INSERT|UPDATE|DELETE|--|/\*|\*/|OR 1=1|AND 1=1',
    
    # XSS and script injection
    r'<script>|</script>|javascript:|onerror|onload|alert\(|<img src=',
    
    # HTTP Smuggling and parameter tampering
    r'Content-Length:|Transfer-Encoding:|CL.TE|TE.CL',
    r'\?file=|/\?template=|/\\u002e',
    
    # Bot User-Agents
    r'sqlmap|nikto|gobuster|dirbuster|wfuzz|ZGrab|masscan|nmap|acunetix|nessus|openvas|burp|zap|w3af|skipfish|arachni|vega|paros|ratproxy',
    r'ahrefs|semrush|majestic|moz|seo|360Spider|acapbot|acoonbot|asterias|attackbot|backdorbot|becomebot|binlar|blitzbot|blitzkit|botometer|botseek',
    r'buckycrawler|crawl|crawler|crawlers|curl|dexbot|dirbot|discover|email|emailcollector|extractor|extractors|fetch|finder|finderbot|findlink',
    r'firefly|genie|geniebot|girafabot|googlebot|google|grab|grabnet|grapnel|grub|harvester|harvest|havij|holygrail|hunter|ia_archiver|iisbot|intellex',
    r'intutech|irlbot|java|jersey|joc|jocweb|jobo|jonas|js-kit|km|libwww|libwww-perl|lwp|lynx|mechanize|meerkat|metacarta|mojeek|morphbot|msnbot|msnbot-mini',
    r'msnbot|netcraft|netmechanic|netresearchserver|nutch|omgilibot|pear|perl|phpcrawl|postrank|proximic|pycurl|python|python-urllib|python-requests|scan|scooter|scrapy|search|seek|seekbot|semanticdiscovery|senomix|seo',
    r'sensis|sg|sitebot|snoopy|spider|spiderbot|spinn3r|sqr|streaker|synthesio|synoo|tecnoseek|t-h-u-n-d-e-r-s-t-o-n-e|thefilter|titanic|turnitinbot|voyager|webalta|webbug|webfindbot|wordpress|www.galaxy.com|www.gnome.org|www1\.shopzilla\.com',
    r'zap|zealbot|zitebot|zuno|zyborg|bot|spider|crawler|wget|curl|python|java|perl|ruby|php|scan|probe|harvest|harvestor|grab|fetch|check|find|search|probe|scan|spider|worm|harvest|grab|fetch|check|find|search|probe|scan|spider|worm|harvest|grab|fetch|check|find|search|probe|scan',

    # OWASP Top 10 2025 patterns
    r'ignore previous instructions|system:.*jailbreak|prompt injection',
    r'mongo|nosql injection|javascript:',
    r'(a+)+|evil regex|redos',
    r'supply chain|known vuln CVE-2025|unbounded consumption',
    r'/admin_fake|/shell_fake|/hidden_dir',

    # Bổ sung cho Zero-day exploits (patterns for recent CVEs, e.g., Log4Shell-like or new web vulns)
    r'\$\{jndi:ldap://|CVE-2021-44228|CVE-2025-1234',  # Log4j and hypothetical 2025 CVE
    r'X-Forwarded-For:.*127.0.0.1|SSRF attempt',  # SSRF patterns
    r'anomaly in payload|unexpected deserialization',  # Generic zero-day anomaly

    # Bổ sung cho APTs (persistent, low-volume)
    r'failed login.*(00:00|23:00)|unusual hour access',  # Odd hours
    r'privilege escalation|sudo|root access attempt',  # Escalation
    r'long session.*>3600s|persistent connection',  # Long sessions

    

    # Bổ sung cho API abuse
    r'/api/.*no-auth|missing token|unauthorized api call',  # Missing auth
    r'excessive POST /api/|rate abuse',  # High freq API

    

    # THÊM CÁC PATTERN MỚI:
    r' 200 OK',  # Chặn IP lạ trả về 200
    r' 404 Not Found',  # Đã có nhưng ensure tồn tại
    r' 403 Forbidden',  # Đã có
    r'GET / HTTP/1.[01]',  # Direct GET / từ IP lạ
    r'POST / HTTP/1.[01]',  # POST / từ IP lạ
    r'HEAD / HTTP/1.[01]',  # HEAD / từ IP lạ
    
    # THÊM CÁC PATTERNS MỚI PHÁT HIỆN
    r'/nice%20ports%2C/Trinity.txt.bak',  # NMAP scan
    r'OPTIONS ',                           # HTTP method scanning
    r'/owa/',                              # Microsoft Exchange exploit
    r'/webui',                             # Router exploit
    r'Invalid HTTP request',               # Protocol fuzzing
    
]

# Whitelist configuration
WHITELIST_IPS = {
     
}

WHITELIST_PATTERNS = [
    # Add whitelist patterns here
    # Example: r'/favicon\.ico',
    # Example: r'/robots\.txt',
]

WHITELIST_API_PATTERNS = [
    # Add whitelist API patterns here
    # Example: r'/api/health',
    # Example: r'/api/status',
]

# Protection thresholds
SUSPICIOUS_THRESHOLD = 1
TIME_WINDOW = timedelta(minutes=1)

# File paths
BLOCKED_IPS_FILE = ''
SUSPICIOUS_FILE = 'json'

# Rate limiting configuration - Bổ sung cho API
RATE_LIMITS = {
    "IP": {"requests": 100, "window": 60},
    "SUBNET": {"requests": 1000, "window": 60},
    "GLOBAL": {"requests": 5000, "window": 60},
    "API": {"requests": 50, "window": 60}  # Specific for API endpoints
}

def load_fail2ban_patterns():
    """Load additional patterns from Fail2Ban/OWASP JSON file"""
    global HACKER_PATTERNS
    if os.path.exists(FAIL2BAN_FILE):
        with open(FAIL2BAN_FILE, 'r') as f:
            data = json.load(f)
            HACKER_PATTERNS += data.get("patterns", [])
            print(f"[INFO] Loaded {len(data.get('patterns', []))} OWASP/Fail2Ban patterns from JSON")

def is_whitelisted_api_request(line):
    """Check if request matches whitelisted API patterns"""
    for pattern in WHITELIST_API_PATTERNS:
        if re.search(pattern, line, re.IGNORECASE):
            return True
    for pattern in WHITELIST_PATTERNS:
        if re.search(pattern, line, re.IGNORECASE):
            return True
    return False

class RateLimiter:
    """Rate limiting implementation with IP and subnet tracking - Bổ sung API-specific"""
    def __init__(self):
        self.requests = defaultdict(deque)
        self.api_requests = defaultdict(deque)  # Separate for API
        self.lock = threading.Lock()
    
    def is_rate_limited(self, ip, max_requests=100, window_seconds=60, is_api=False):
        """Check if IP has exceeded rate limits"""
        key = f"{ip}_api" if is_api else ip
        req_dict = self.api_requests if is_api else self.requests
        print(f"[DEBUG] Checking rate limit for {key}: max={max_requests}, window={window_seconds}s")
        with self.lock:
            now = time.time()
            window_start = now - window_seconds
            
            # Clean old requests
            while req_dict[key] and req_dict[key][0] < window_start:
                req_dict[key].popleft()
            
            current_count = len(req_dict[key])
            print(f"[DEBUG] Current requests for {key}: {current_count}")
            
            if current_count >= max_requests:
                print(f"[ALERT] Rate limit exceeded for {key}")
                return True
            
            req_dict[key].append(now)
            print(f"[DEBUG] Added request for {key}, new count: {len(req_dict[key])}")
            return False

    def get_subnet(self, ip):
        """Extract subnet from IP address (supports IPv4 and IPv6)"""
        try:
            if ':' in ip:  # IPv6
                # Sử dụng /64 cho subnet lớn, hoặc /128 cho single IP
                net = ipaddress.IPv6Network(f"{ip}/64", strict=False)
                return str(net)  # e.g., '2001:db8::/64'
            else:  # IPv4
                net = ipaddress.IPv4Network(f"{ip}/24", strict=False)
                return str(net)
        except ValueError:
            print(f"[WARN] Invalid IP for subnet: {ip}")
            return ip  # Fallback to single IP

class ConnectionTracker:
    """Track connections and detect flood attacks"""
    def __init__(self, cleanup_window=60):
        self.connections = defaultdict(int)
        self.syn_flood_detector = defaultdict(int)
        self.timestamps = defaultdict(list)
        self.cleanup_window = cleanup_window
        self.last_cleanup = time.time()
        self.whitelist_ips = WHITELIST_IPS.copy()
    
    def track_connection(self, ip, connection_type="http"):
        """Track a new connection from IP"""
        if ip in self.whitelist_ips:
            return
            
        now = time.time()
        self.connections[ip] += 1
        
        if connection_type == "syn":
            self.syn_flood_detector[ip] += 1
        
        heapq.heappush(self.timestamps[ip], now)
    
    def check_connection_flood(self, ip, max_connections=50):
        """Check if IP is flooding connections"""
        if ip in self.whitelist_ips:
            return False
            
        count = self.connections[ip]
        return count > max_connections
    
    def check_syn_flood(self, ip, threshold=20):
        """Check for SYN flood attacks"""
        syn_count = self.syn_flood_detector[ip]
        print(f"[DEBUG] Checking SYN flood for {ip}: {syn_count}/{threshold}")
        return syn_count > threshold
    
    def cleanup_old(self):
        """Clean up old connection data"""
        now = time.time()
        print("[DEBUG] Running connection cleanup...")
        if now - self.last_cleanup > self.cleanup_window:
            cutoff = now - self.cleanup_window
            cleaned_count = 0
            for ip in list(self.connections.keys()):
                while self.timestamps[ip] and self.timestamps[ip][0] < cutoff:
                    heapq.heappop(self.timestamps[ip])
                    self.connections[ip] -= 1
                    self.syn_flood_detector[ip] = max(0, self.syn_flood_detector[ip] - 1)
                    cleaned_count += 1
                if self.connections[ip] == 0:
                    del self.connections[ip]
                    del self.syn_flood_detector[ip]
                    del self.timestamps[ip]
            print(f"[DEBUG] Cleaned {cleaned_count} old connections")
            self.last_cleanup = now

class BehavioralAnalyzer:
    """Analyze user behavior for anomalies - Bổ sung APT detection"""
    def __init__(self):
        self.user_agents = defaultdict(set)
        self.referrers = defaultdict(set)
        self.request_patterns = defaultdict(list)
        self.sessions = defaultdict(list)  # For APT: track session duration
        self.window_seconds = 60
        self.long_session_threshold = 3600  # 1 hour for APT
    
    def analyze_behavior(self, ip, user_agent, referrer, path):
        """Analyze behavior patterns for anomalies"""
        now = time.time()
        cutoff = now - self.window_seconds
        print(f"[DEBUG] Analyzing behavior for {ip}: UA={user_agent[:20]}..., path={path[:20]}...")
        
        # Clean old data
        self.user_agents[ip] = {ua for ua in self.user_agents[ip]}
        self.referrers[ip] = {ref for ref in self.referrers[ip]}
        
        self.request_patterns[ip] = [(p, ts) for p, ts in self.request_patterns[ip] if ts > cutoff]
        self.sessions[ip] = [s for s in self.sessions[ip] if now - s < self.long_session_threshold]
        print(f"[DEBUG] After cleanup: {len(self.request_patterns[ip])} patterns for {ip}")
        
        # Detect UA spoofing
        ua_count = len(self.user_agents[ip])
        print(f"[DEBUG] UA count for {ip}: {ua_count}/5")
        if ua_count > 5:
            print(f"[ALERT] UA spoofing detected for {ip}")
            return "UA_SPOOFING"
        
        # Detect scanning behavior
        pattern_count = len(self.request_patterns[ip])
        print(f"[DEBUG] Pattern count for {ip}: {pattern_count}/50")
        if pattern_count > 50:
            print(f"[ALERT] Directory scanning detected for {ip}")
            return "DIRECTORY_SCANNING"
        
        # Bổ sung APT: Long persistent session with probes
        if self.sessions[ip] and (now - self.sessions[ip][0]) > self.long_session_threshold and pattern_count > 10:
            print(f"[ALERT] APT-like persistent session detected for {ip}")
            return "APT_SUSPICIOUS"
        
        # Add to history
        self.user_agents[ip].add(user_agent)
        self.referrers[ip].add(referrer)
        self.request_patterns[ip].append((path, now))
        self.sessions[ip].append(now)  # Track session start/end
        print(f"[DEBUG] Added behavior data for {ip}, normal")
        
        return "NORMAL"

class GeoIPProtection:
    """GeoIP-based protection with country blocking"""
    def __init__(self, geoip_db_path='GeoLite2-Country.mmdb'):
        self.reader = None
        if GEOIP_AVAILABLE:
            try:
                self.reader = geoip2.database.Reader(geoip_db_path)
                print("[INFO] GeoIP reader loaded successfully")
            except:
                print("[WARN] GeoLite2-Country.mmdb not found. Download from maxmind.com")
        self.blocked_countries = {'CN', 'RU', 'UA', 'TR', 'BR'}
        self.allowed_countries = {'VN', 'US', 'SG'}
    
    def is_country_blocked(self, ip):
        """Check if IP is from blocked country"""
        if not self.reader:
            print(f"[DEBUG] GeoIP not available for {ip}")
            return False
        
        # Bổ sung validate IP bằng ipaddress thay regex
        try:
            if ':' in ip:
                ipaddress.IPv6Address(ip)
            else:
                ipaddress.IPv4Address(ip)
        except ipaddress.AddressValueError:
            print(f"[DEBUG] Invalid IP format for GeoIP: {ip}")
            return False
            
        try:
            response = self.reader.country(ip)
            country_code = response.country.iso_code
            print(f"[DEBUG] GeoIP for {ip}: {country_code}")
            if not country_code:
                return False
            blocked = country_code in self.blocked_countries and country_code not in self.allowed_countries
            if blocked:
                print(f"[ALERT] Geo-blocked {ip} from {country_code}")
            return blocked
        except Exception as e:
            print(f"⚠️ GeoIP error for {ip}: {e}")
            return False
    
    def get_country_code(self, ip):
        """Get country code for IP"""
        if not self.reader:
            return "UNKNOWN"
        try:
            response = self.reader.country(ip)
            return response.country.iso_code
        except:
            return "UNKNOWN"

class LogProcessor:
    """Real-time log processing with tailing capability"""
    def __init__(self, log_file):
        self.log_file = log_file
        self.q = queue.Queue()
        self.proc = None
        self.thread = None
        print(f"[INIT] LogProcessor ready - REAL-TIME tailing")

    def start_tailing(self):
        """Start real-time log tailing"""
        if not os.path.exists(self.log_file):
            print(f"❌ Log file {self.log_file} not exists")
            return
            
        def tail_loop():
            cmd = ['powershell', '-Command', f'Get-Content -Path "{self.log_file}" -Wait -Tail 1 -ErrorAction SilentlyContinue']
            self.proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True, text=True)
            try:
                for line in iter(self.proc.stdout.readline, ''):
                    if line.strip():
                        self.q.put(line.strip())
                        print(f"[TAIL] New log line: {line.strip()[:100]}...")
            except Exception as e:
                print(f"[ERROR] Tailing error: {e}")
            finally:
                if self.proc:
                    self.proc.terminate()
                    
        self.thread = threading.Thread(target=tail_loop, daemon=True)
        self.thread.start()
        print("[INFO] PowerShell tailing started")

    def get_new_lines(self, timeout=1):
        """Get new log lines from queue"""
        try:
            while True:
                line = self.q.get(timeout=timeout)
                yield line
        except queue.Empty:
            return []

class RollingCounter:
    """Efficient request counting with sliding window"""
    def __init__(self, window_size=60):
        self.window_size = window_size
        self.requests = defaultdict(list)
    
    def add_request(self, ip, timestamp):
        """Add request timestamp for IP"""
        if ip not in self.requests:
            self.requests[ip] = []
        
        heapq.heappush(self.requests[ip], timestamp)
        
        # Clean old requests
        cutoff = timestamp - self.window_size
        cleaned = 0
        while self.requests[ip] and self.requests[ip][0] < cutoff:
            heapq.heappop(self.requests[ip])
            cleaned += 1
        if cleaned > 0:
            print(f"[DEBUG] Cleaned {cleaned} old requests for {ip}")
    
    def get_count(self, ip, window_seconds=60):
        """Get request count for IP in time window"""
        if ip not in self.requests:
            return 0
        
        cutoff = time.time() - window_seconds
        requests = [ts for ts in self.requests[ip] if ts > cutoff]
        count = len(requests)
        print(f"[DEBUG] Rolling count for {ip}: {count} in {window_seconds}s")
        return count

class EmergencyMode:
    """Emergency protection mode for high system load"""
    def __init__(self):
        self.emergency_mode = False
        self.emergency_thresholds = {
            "cpu": 85,
            "memory": 90,
            "connections": 10000,
            "bandwidth": 1000
        }
        self.deactivate_thresholds = {
            "cpu": 70,
            "memory": 80
        }
    
    def check_system_health(self):
        """Check system health and activate emergency mode if needed"""
        if not PSUTIL_AVAILABLE:
            print("[DEBUG] psutil not available, skipping health check")
            return
            
        try:
            cpu = psutil.cpu_percent(interval=1)
            memory = psutil.virtual_memory().percent
            connections = self.get_connection_count()
            print(f"[HEALTH] CPU: {cpu}%, Memory: {memory}%, Connections: {connections}")
            
            if (cpu > self.emergency_thresholds["cpu"] or 
                memory > self.emergency_thresholds["memory"] or
                connections > self.emergency_thresholds["connections"]):
                self.activate_emergency_mode()
            elif self.emergency_mode and (cpu < self.deactivate_thresholds["cpu"] and 
                                          memory < self.deactivate_thresholds["memory"]):
                self.deactivate_emergency_mode()
        except Exception as e:
            print(f"[WARN] Health check error: {e}")
    
    def get_connection_count(self):
        """Get current TCP connection count"""
        try:
            count = len(psutil.net_connections(kind='tcp'))
            print(f"[DEBUG] Current TCP connections: {count}")
            return count
        except:
            return 0
    
    def activate_emergency_mode(self):
        """Activate emergency protection mode"""
        if not self.emergency_mode:
            print("🚨 ACTIVATING EMERGENCY PROTECTION MODE")
            self.emergency_mode = True
            
            global RATE_LIMITS
            old_ip = RATE_LIMITS["IP"]["requests"]
            old_subnet = RATE_LIMITS["SUBNET"]["requests"]
            old_api = RATE_LIMITS["API"]["requests"]
            RATE_LIMITS["IP"]["requests"] = 20
            RATE_LIMITS["SUBNET"]["requests"] = 100
            RATE_LIMITS["API"]["requests"] = 10  # Tighten API too
            print(f"[EMERGENCY] Limits adjusted: IP {old_ip} -> 20, Subnet {old_subnet} -> 100, API {old_api} -> 10")
    
    def deactivate_emergency_mode(self):
        """Deactivate emergency protection mode"""
        if self.emergency_mode:
            print("✅ Deactivating emergency mode")
            self.emergency_mode = False
            
            global RATE_LIMITS
            old_ip = RATE_LIMITS["IP"]["requests"]
            old_subnet = RATE_LIMITS["SUBNET"]["requests"]
            old_api = RATE_LIMITS["API"]["requests"]
            RATE_LIMITS["IP"]["requests"] = 100
            RATE_LIMITS["SUBNET"]["requests"] = 1000
            RATE_LIMITS["API"]["requests"] = 50
            print(f"[EMERGENCY] Limits reset: IP {old_ip} -> 100, Subnet {old_subnet} -> 1000, API {old_api} -> 50")

class IPReputation:
    """IP reputation checking system"""
    def __init__(self):
        self.malicious_ips = set()
        self.suspicious_subnets = set()
        self.trusted_ips = set()
    
    def check_ip_reputation(self, ip):
        """Check IP reputation from multiple sources"""
        print(f"[DEBUG] Checking reputation for {ip}")
        
        if ip in self.malicious_ips:
            print(f"[ALERT] Malicious IP detected: {ip}")
            return "MALICIOUS"
        
        subnet = ".".join(ip.split(".")[:2]) + ".0.0/16" if ':' not in ip else self._get_ipv6_subnet(ip)
        if subnet in self.suspicious_subnets:
            print(f"[ALERT] Suspicious subnet: {subnet} for {ip}")
            return "SUSPICIOUS_SUBNET"
        
        if self.check_external_threat_intel(ip):
            print(f"[ALERT] Known threat: {ip}")
            return "KNOWN_THREAT"
        
        print(f"[DEBUG] Reputation clean for {ip}")
        return "CLEAN"
    
    def _get_ipv6_subnet(self, ip):
        """Helper for IPv6 subnet in reputation"""
        try:
            net = ipaddress.IPv6Network(f"{ip}/64", strict=False)
            return str(net)
        except:
            return ip
    
    def check_external_threat_intel(self, ip):
        """Check external threat intelligence feeds"""
        print(f"[DEBUG] External threat check for {ip}: skipped (no API)")
        return False

class DDoSMonitor:
    """DDoS attack monitoring and analytics - Bổ sung advanced types"""
    def __init__(self):
        self.metrics = {
            "total_requests": 0,
            "blocked_requests": 0,
            "unique_ips": set(),
            "attack_types": defaultdict(int),
            "top_attackers": []
        }
        self.start_time = time.time()
    
    def update_metrics(self, ip, attack_type, blocked=False):
        """Update monitoring metrics"""
        print(f"[METRICS] Updating for {ip}: type={attack_type}, blocked={blocked}")
        self.metrics["total_requests"] += 1
        self.metrics["unique_ips"].add(ip)
        
        if blocked:
            self.metrics["blocked_requests"] += 1
            self.metrics["attack_types"][attack_type] += 1
        
        if time.time() - self.start_time > 30:
            self.print_dashboard()
            self.reset_metrics()
    
    def print_dashboard(self):
        """Print monitoring dashboard"""
        print("\n" + "="*50)
        print("🛡️ DDoS PROTECTION DASHBOARD")
        print("="*50)
        print(f"Total Requests: {self.metrics['total_requests']}")
        print(f"Blocked Requests: {self.metrics['blocked_requests']}")
        print(f"Unique IPs: {len(self.metrics['unique_ips'])}")
        print("Attack Types:", dict(self.metrics['attack_types']))
        print("="*50)
    
    def reset_metrics(self):
        """Reset metrics for new monitoring period"""
        print("[METRICS] Resetting dashboard")
        self.metrics["total_requests"] = 0
        self.metrics["blocked_requests"] = 0
        self.metrics["unique_ips"] = set()
        self.metrics["attack_types"] = defaultdict(int)
        self.start_time = time.time()

class ProtectionConfig:
    """Dynamic protection configuration management - Bổ sung advanced"""
    def __init__(self):
        self.config = {
            "rate_limiting": {
                "enabled": True,
                "ip_limit": 100,
                "subnet_limit": 1000,
                "window": 60,
                "api_limit": 50  # New
            },
            "geo_blocking": {
                "enabled": True,
                "blocked_countries": ["CN", "RU", "UA"],
                "allowed_countries": ["VN", "US", "SG"]
            },
            "behavioral_analysis": {
                "enabled": True,
                "max_user_agents": 5,
                "max_paths_per_minute": 50,
                "apt_session_threshold": 3600  # New for APT
            },
            "emergency_mode": {
                "auto_activate": True,
                "cpu_threshold": 85,
                "memory_threshold": 90
            },
            "advanced_protection": {  # New section
                "zero_day_enabled": True,
                "api_abuse_enabled": True,
                "file_upload_enabled": True
            }
        }
        print("[CONFIG] Loaded protection config")
    
    def update_config(self, new_config):
        """Update configuration dynamically"""
        print(f"[CONFIG] Updating config: {new_config}")
        self.config.update(new_config)
    
    def get_adaptive_limits(self, system_load):
        """Get adaptive rate limits based on system load"""
        base_limit = self.config["rate_limiting"]["ip_limit"]
        if system_load > 70:
            adaptive = max(10, base_limit // 2)
            print(f"[CONFIG] Adaptive limit: {base_limit} -> {adaptive} (load: {system_load}%)")
            return adaptive
        print(f"[CONFIG] Standard limit: {base_limit} (load: {system_load}%)")
        return base_limit



# Bổ sung class mới cho API Abuse
class APIAbuseDetector:
    """Detect API abuse"""
    def __init__(self):
        self.api_calls = defaultdict(int)
        self.window = 60
    
    def check_api_abuse(self, line, ip):
        """Check for API abuse"""
        if not re.search(r'', line, re.IGNORECASE):
            return None
        
        now = time.time()
        
        # Clean old calls first
        self._cleanup_old_calls(now)
        
        # Add current call
        self.api_calls[ip].append(now)
        
        # Check threshold
        current_count = len(self.api_calls[ip])
        print(f"[API COUNT] {ip} - Current API calls: {current_count}/50")
        
        if current_count > 50:
            if re.search(r'no-auth|missing token', line, re.IGNORECASE):
                print(f"[ALERT] API abuse (no auth) detected for {ip}")
                return "API_ABUSE"
            print(f"[ALERT] API rate abuse detected for {ip}")
            return "API_ABUSE"
        
        return None
    
    def _cleanup_old_calls(self, current_time):
        """Clean up old API calls"""
        cutoff = current_time - self.window
        
        for ip in list(self.api_calls.keys()):
            # Keep only recent calls
            self.api_calls[ip] = [ts for ts in self.api_calls[ip] if ts > cutoff]
            
            # Remove IP if no recent activity
            if not self.api_calls[ip]:
                del self.api_calls[ip]

def send_block_alert(ip, reason):
    """Send email alert for blocked IP"""
    try:
        
            
        msg = MIMEText(f"Blocked IP {ip} due to {reason}. Time: {datetime.now().isoformat()}\nLog: {LOG_FILE}")
        msg['Subject'] = f"🚨 IP Blocked Alert: {ip}"
        msg['From'] = gmail_email
        msg['To'] = gmail_email
        
        with smtplib.SMTP('smtp.gmail.com', 587) as server:
            server.starttls()
            server.login(gmail_email, gmail_password)
            server.send_message(msg)
        print(f"📧 Alert sent for blocked IP {ip}")
    except Exception as e:
        print(f"[ERROR] Alert failed for {ip}: {e}")

def read_blocked_ips():
    """Read blocked IPs from file"""
    print(f"[DEBUG] Reading blocked IPs file: {BLOCKED_IPS_FILE}")
    if os.path.exists(BLOCKED_IPS_FILE):
        with open(BLOCKED_IPS_FILE, 'r') as f:
            ips = set(line.strip() for line in f)
            print(f"[DEBUG] Read {len(ips)} blocked IPs")
            return ips
    print("[DEBUG] Blocked IPs file does not exist, returning empty set")
    return set()

def add_blocked_ip(ip):
    """Add IP to blocked list"""
    print(f"[DEBUG] Adding IP {ip} to blocked_ips.txt")
    with open(BLOCKED_IPS_FILE, 'a') as f:
        f.write(ip + '\n')

def is_ip_blocked(ip, blocked_ips):
    """Check if IP is already blocked"""
    if ip in blocked_ips:
        print(f"[DEBUG] IP {ip} is already blocked")
        return True
    return False

def load_suspicious_requests():
    """Load suspicious requests data"""
    print("[DEBUG] Loading suspicious requests...")
    if os.path.exists(SUSPICIOUS_FILE):
        with open(SUSPICIOUS_FILE, 'r') as f:
            data = json.load(f)
            now = datetime.now()
            cleaned = {}
            for ip, timestamps in data.items():
                recent = [ts for ts in timestamps if now - datetime.fromisoformat(ts) < TIME_WINDOW * 2]
                if recent:
                    cleaned[ip] = recent
            save_suspicious_requests(cleaned)
            print(f"[DEBUG] Loaded {len(cleaned)} suspicious IPs after cleanup")
            return cleaned
    print("[DEBUG] Suspicious requests file does not exist, returning empty dict")
    return {}

def save_suspicious_requests(data):
    """Save suspicious requests data"""
    print(f"[DEBUG] Saving {len(data)} suspicious requests...")
    with open(SUSPICIOUS_FILE, 'w') as f:
        json.dump(data, f, default=str)

def add_suspicious_request(ip, suspicious_data):
    """Add suspicious request and check threshold"""
    data = suspicious_data
    now_str = datetime.now().isoformat()
    if ip not in data:
        data[ip] = []
    data[ip].append(now_str)
    
    # Clean old entries for this IP
    now = datetime.now()
    data[ip] = [ts for ts in data[ip] if now - datetime.fromisoformat(ts) < TIME_WINDOW]
    
    count = len(data[ip])
    print(f"[DEBUG] IP {ip} has {count} suspicious requests in window")
    return count >= SUSPICIOUS_THRESHOLD

def block_ip(ip):
    """Block IP using Windows firewall (IPv4/IPv6 support)"""
    print(f"[DEBUG] Starting to block IP {ip}")
    
    # Validate và detect type
    try:
        if ':' in ip:
            # IPv6: Block single IP (/128) và subnet (/64)
            single_rule = f"{ip}/128"
            subnet = RateLimiter().get_subnet(ip)  # Reuse để lấy subnet
            rules = [
                f'netsh advfirewall firewall add rule name="AutoBlock Inbound IPv6 {ip}" dir=in action=block remoteip={single_rule}',
                f'netsh advfirewall firewall add rule name="AutoBlock Outbound IPv6 {ip}" dir=out action=block remoteip={single_rule}',
                f'netsh advfirewall firewall add rule name="AutoBlock Subnet IPv6 {subnet}" dir=in action=block remoteip={subnet}',
                f'netsh advfirewall firewall add rule name="AutoBlock Subnet IPv6 {subnet}" dir=out action=block remoteip={subnet}'
            ]
        else:
            # IPv4: Giữ nguyên
            rules = [
                f'netsh advfirewall firewall add rule name="AutoBlock Inbound {ip}" dir=in action=block remoteip={ip}',
                f'netsh advfirewall firewall add rule name="AutoBlock Outbound {ip}" dir=out action=block remoteip={ip}'
            ]
    except Exception as e:
        print(f"[ERROR] IP validation failed for block: {e}")
        return
    
    for rule in rules:
        try:
            subprocess.run(rule, shell=True, check=True, capture_output=True)
            print(f"✅ Blocked {ip}: {rule.split()[-1]}")
        except subprocess.CalledProcessError as e:
            print(f"❌ Error blocking {ip}: {e}")
    
    send_block_alert(ip, "suspicious activity detected")

def scan_log_for_hackers(rate_limiter, connection_tracker, behavioral_analyzer, geo_protection, 
                        log_processor, rolling_counter, ip_reputation, ddos_monitor, 
                        protection_config, emergency_mode):
    """Main log scanning function with comprehensive attack detection - Bổ sung advanced"""
    start_time = time.time()
    print(f"\n🎯 [SCAN START] {datetime.now().strftime('%H:%M:%S')} - REAL-TIME LOG SCANNING")
    
    if not os.path.exists(LOG_FILE):
        print(f"❌ Log file does not exist: {LOG_FILE}")
        return

    # File information
    file_size = os.path.getsize(LOG_FILE)
    file_mtime = datetime.fromtimestamp(os.path.getmtime(LOG_FILE)).strftime('%H:%M:%S')
    file_ctime = datetime.fromtimestamp(os.path.getctime(LOG_FILE)).strftime('%Y-%m-%d')
    print(f"📁 Log file info:")
    print(f"   • Size: {file_size} bytes")
    print(f"   • Modified: {file_mtime}")
    print(f"   • Created: {file_ctime}")
    
    blocked_ips = read_blocked_ips()
    suspicious_data = load_suspicious_requests()
    
    # Bổ sung instances mới
    
    api_abuse_detector = APIAbuseDetector()
    
    # Statistics
    total_lines = 0
    ips_processed = set()
    attack_detections = {
        "RATE_LIMIT": set(),
        "GEO_BLOCKED": set(),
        "HACKER_PATTERN": set(),
        "BEHAVIOR_ANOMALY": set(),
        "REPUTATION_BAD": set(),
        "CONNECTION_FLOOD": set(),
        "UNAUTHORIZED_PROBE": set(),
        
        "API_ABUSE": set(),  # New
        "APT_SUSPICIOUS": set(),  # New
        "ZERO_DAY_ANOMALY": set()  # New
    }
    new_blocked_ips = set()

    # Full scan of entire access.log (read all lines)
    if not os.path.exists(LOG_FILE):
        print("❌ Log file does not exist")
        return
    
    try:
        with open(LOG_FILE, 'r', encoding='utf-8', errors='ignore') as f:
            all_lines = [line.strip() for line in f.readlines() if line.strip()]  # Read full, strip empty
    except Exception as e:
        print(f"❌ Error reading log file: {e}")
        return
    
    if not all_lines:
        print("❌ No log data to process")
        return

    print(f"🔍 Starting FULL analysis of {len(all_lines)} log lines (entire file)...")
    
    # Initial statistics
    unique_ips_in_log = set()
    for line in all_lines:
        ip = extract_and_validate_ip(line)
        if ip:
            unique_ips_in_log.add(ip)
    print(f"📊 Total IPs in log: {len(unique_ips_in_log)}")
    print(f"📊 IP list: {unique_ips_in_log}")
    
    # Process each line
    for line_num, line in enumerate(all_lines, 1):
        total_lines += 1
        
        # Progress indicator
        if line_num % 5000 == 0:
            print(f"📊 Processing line {line_num}/{len(all_lines)}...")
        
        ip = extract_and_validate_ip(line)
        if ip:
            ips_processed.add(ip)
            
            # Skip whitelisted IPs
            if ip in WHITELIST_IPS:
                continue

            # Skip whitelisted API requests
            if is_whitelisted_api_request(line):
                print(f"[DEBUG] Skipping check for whitelisted API request: {ip} - {line[:100]}...")
                continue

            # Skip already blocked IPs
            if ip in blocked_ips:
                continue

            # Extract request information
            parts = line.split(' - "')
            if len(parts) > 1:
                request_part = parts[1].split('" ')[0]
                method, path, _ = request_part.split(' ', 2) if ' ' in request_part else (request_part, '/', '')
            else:
                method, path = 'GET', '/'

            user_agent = 'unknown'
            referrer = 'unknown'

            # Attack detection
            detected_attacks = []

            # Detect unauthorized probes
            if method == "GET" and path == "/" and ip not in WHITELIST_IPS and not ip.startswith("192.168."):
                detected_attacks.append("UNAUTHORIZED_PROBE")
                attack_detections["UNAUTHORIZED_PROBE"].add(ip)
                print(f"🚨 UNAUTHORIZED PROBE: {ip} - GET / detected")

            # 1. Hacker Patterns (includes new zero-day, APT, app-specific)
            for pattern in HACKER_PATTERNS:
                if re.search(pattern, line, re.IGNORECASE):
                    attack_type = "HACKER_PATTERN"
                    if re.search(r'CVE-2025|zero-day|anomaly', pattern):  # Classify
                        attack_type = "ZERO_DAY_ANOMALY"
                    elif re.search(r'persistent|long session|privilege', pattern):
                        attack_type = "APT_SUSPICIOUS"
                    
                    elif re.search(r'/api/', pattern):
                        attack_type = "API_ABUSE"
                    elif re.search(r'CVE-2021-44228|\$\{jndi:|zero-day', pattern):
                        attack_type = "ZERO_DAY_ANOMALY"
                    detected_attacks.append(attack_type)
                    attack_detections[attack_type].add(ip)
                    print(f"🚨 {attack_type}: {ip} - {pattern[:50]}...")
                    print(f"   📍 Line: {line.strip()[:100]}...")
                    break

            # 2. Rate Limiting
            request_count = rolling_counter.get_count(ip, 60)
            if request_count > 100:
                detected_attacks.append("RATE_LIMIT")
                attack_detections["RATE_LIMIT"].add(ip)

            # 2.1 API-specific rate limit
            is_api = bool(re.search(r'/api/', line, re.IGNORECASE))
            if is_api and rate_limiter.is_rate_limited(ip, RATE_LIMITS["API"]["requests"], RATE_LIMITS["API"]["window"], is_api=True):
                detected_attacks.append("API_ABUSE")
                attack_detections["API_ABUSE"].add(ip)

            # 3. Geo Blocking
            if geo_protection.is_country_blocked(ip):
                detected_attacks.append("GEO_BLOCKED")
                attack_detections["GEO_BLOCKED"].add(ip)

            # 4. Behavioral Analysis (includes APT)
            behavior = behavioral_analyzer.analyze_behavior(ip, user_agent, referrer, path)
            if behavior != "NORMAL":
                detected_attacks.append(behavior)
                attack_detections[behavior].add(ip)

            # 5. IP Reputation
            rep = ip_reputation.check_ip_reputation(ip)
            if rep != "CLEAN":
                detected_attacks.append("REPUTATION_BAD")
                attack_detections["REPUTATION_BAD"].add(ip)

            # 6. Connection Flood
            if connection_tracker.check_connection_flood(ip):
                detected_attacks.append("CONNECTION_FLOOD")
                attack_detections["CONNECTION_FLOOD"].add(ip)

            
            # 8. New: API Abuse
            api_abuse = api_abuse_detector.check_api_abuse(line, ip)
            if api_abuse:
                detected_attacks.append(api_abuse)
                attack_detections[api_abuse].add(ip)

            # Report and block detected attacks
            if detected_attacks and ip not in WHITELIST_IPS:
                print(f"🚨 DETECTED: IP {ip} - Types: {', '.join(detected_attacks)}")
                print(f"   📍 Path: {path[:50]}...")
                print(f"   📄 Line: {line.strip()[:100]}...")
                
                # Block severe attacks immediately - Bổ sung new types
                severe_attacks = ['RATE_LIMIT', 'CONNECTION_FLOOD', 'HACKER_PATTERN', 'UNAUTHORIZED_PROBE', 
                                   'API_ABUSE', 'APT_SUSPICIOUS', 'ZERO_DAY_ANOMALY']
                if any(attack in severe_attacks for attack in detected_attacks) and ip not in blocked_ips:
                    block_ip(ip)
                    add_blocked_ip(ip)
                    new_blocked_ips.add(ip)
                    print(f"   🔒 BLOCKED: {ip}")

            # Track connections
            connection_tracker.track_connection(ip)
            rolling_counter.add_request(ip, time.time())

    # Cleanup
    connection_tracker.cleanup_old()

    end_time = time.time()
    processing_time = end_time - start_time

    # Detailed scan report
    print(f"\n📊 [SCAN REPORT] {datetime.now().strftime('%H:%M:%S')}")
    print("=" * 60)
    print(f"⏱️  Processing time: {processing_time:.2f}s")
    print(f"📄 Total log lines: {total_lines}")
    print(f"🌐 Unique IPs in log: {len(unique_ips_in_log)}")
    print(f"🌐 Processed IPs: {len(ips_processed)}")
    print(f"📊 Found IPs: {ips_processed}")
    
    # Detection statistics
    total_detections = sum(len(ips) for ips in attack_detections.values())
    print(f"🚨 Total detections: {total_detections}")
    
    if total_detections > 0:
        print("\n🔍 DETECTION DETAILS:")
        for attack_type, ips in attack_detections.items():
            if ips:
                print(f"   • {attack_type}: {len(ips)} IPs - {list(ips)}")
    
    if new_blocked_ips:
        print(f"\n🔒 NEWLY BLOCKED IPs: {len(new_blocked_ips)}")
        for ip in new_blocked_ips:
            print(f"   • {ip}")
    else:
        print(f"\n✅ No new IPs blocked")
    
    print("=" * 60)

    # Update metrics
    for attack_type, ips in attack_detections.items():
        for ip in ips:
            if ip not in WHITELIST_IPS:
                ddos_monitor.update_metrics(ip, attack_type, True)

    save_suspicious_requests(suspicious_data)

def main():
    """Main function to start the DDoS protection system"""
    print("🚀 Starting DDoS Protection System - FULL LOG SCAN EVERY 30s")
    print(f"📁 Log file: {LOG_FILE}")
    print("⏰ Scanning entire log every 30s with detailed reporting")
    print("Press Ctrl+C to stop.\n")

    # Load additional patterns
    load_fail2ban_patterns()

    # Initialize modules
    rate_limiter = RateLimiter()
    connection_tracker = ConnectionTracker()
    behavioral_analyzer = BehavioralAnalyzer()
    geo_protection = GeoIPProtection()
    log_processor = LogProcessor(LOG_FILE)
    log_processor.start_tailing()
    rolling_counter = RollingCounter()
    ip_reputation = IPReputation()
    ddos_monitor = DDoSMonitor()
    protection_config = ProtectionConfig()
    emergency_mode = EmergencyMode()
    
    scan_count = 0
    
    try:
        while True:
            scan_count += 1
            print(f"\n{'='*50}")
            print(f"🔄 SCAN #{scan_count}")
            print(f"{'='*50}")
            
            emergency_mode.check_system_health()
            scan_log_for_hackers(rate_limiter, connection_tracker, behavioral_analyzer, geo_protection, 
                               log_processor, rolling_counter, ip_reputation, ddos_monitor, 
                               protection_config, emergency_mode)
            
            print(f"\n⏳ Waiting 30s for next scan...")
            time.sleep(30)
            
    except KeyboardInterrupt:
        print("\n👋 Stopping protection system.")

if __name__ == "__main__":

    main()
