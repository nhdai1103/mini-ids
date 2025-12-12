# Mini IDS - Quick Start Guide 🚀

## 📦 Installation

### Step 1: Install Dependencies
```bash
cd mini-ids
pip install -r requirements.txt
```

### Step 2: Verify Installation
```bash
python demo.py
```

You should see output showing:
- ✅ Log parsing demo
- ✅ Attack detection demo  
- ✅ Alert statistics
- ✅ Full analysis

## 🎯 Running the System

### Option 1: Web Dashboard Only (No Monitoring)

```bash
python app.py
```

Then open: **http://localhost:5000**

Features:
- View existing alerts
- Check statistics
- Filter by threat level, IP

### Option 2: Full System (Dashboard + Real-time Monitoring)

**Terminal 1 - Run Dashboard:**
```bash
python app.py
```

**Terminal 2 - Run Log Monitor:**
```bash
python monitor.py
```

Now:
- Monitor will watch `logs/` folder
- New log entries trigger detection
- Alerts appear in dashboard in real-time

## 📝 Sample Data

The project includes sample logs with various attacks:

### logs/access.log
Contains Apache/Nginx access log entries with:
- ✅ SQL Injection attempts
- ✅ XSS payloads
- ✅ Path traversal
- ✅ Brute force logins
- ✅ Port scanning

### logs/auth.log
Contains SSH authentication logs with:
- ✅ Failed login attempts
- ✅ Brute force attempts
- ✅ Connection events

## 🔍 Testing Attacks

### Method 1: Use Sample Logs
The system comes with pre-populated sample logs that demonstrate various attack patterns.

### Method 2: Add New Log Entries

To test real-time detection, add entries to `logs/access.log`:

```bash
# Terminal 1: Start monitor
python monitor.py

# Terminal 2: Append to log
echo '10.0.0.1 - - [01/Dec/2024:12:00:00 +0000] "GET /search.php?q=1'" OR "'"1"'"="'"1 HTTP/1.1" 200 1024 "-" "Mozilla/5.0"' >> logs/access.log
```

Watch the alert appear in the dashboard!

## 📊 Dashboard Features

### Main Dashboard
- **Total Alerts**: Count of all detected attacks
- **Critical Threats**: Count of critical severity alerts
- **Blocked IPs**: Count of unique attacker IPs
- **Attack Types**: Count of different attack categories

### Recent Alerts Table
- Filterable by threat level, IP
- Clickable for details
- Shows: timestamp, source IP, attack type, signature, severity

### Statistics Charts
- **Top Attack Types**: Bar chart of most common attacks
- **Top Blocked IPs**: Most active attackers
- **Threat Distribution**: Breakdown by severity level

### Blocked IPs Table
- IP address and threat count
- Threat level
- First and last seen timestamps

## 🔧 API Endpoints

Access via curl or fetch:

```bash
# Get statistics
curl http://localhost:5000/api/statistics

# Get recent alerts
curl http://localhost:5000/api/alerts?limit=50&threat_level=high

# Get blocked IPs
curl http://localhost:5000/api/blocked-ips

# Health check
curl http://localhost:5000/api/health
```

## 💻 Python API Usage

### Load and Analyze Logs

```python
from src.log_parser import LogParser
from src.detection_engine import DetectionEngine
from src.alert_manager import AlertManager

# Parse logs
entries = LogParser.parse_log_file('logs/access.log', log_type='apache')

# Detect attacks
engine = DetectionEngine()
for entry in entries:
    signature = engine.check_payload(entry.uri)
    if signature:
        print(f"Found {signature.name} from {entry.source_ip}")

# Manage alerts
alert_mgr = AlertManager()
stats = alert_mgr.get_statistics()
print(f"Total alerts: {stats['total_alerts']}")
```

## 🎓 Understanding Detections

### Attack Types

**SQLi (SQL Injection)**
- Pattern: `UNION SELECT`, `OR '1'='1`, `--`, `; DROP`
- Examples: `?id=1' OR '1'='1`
- Severity: Medium to Critical

**XSS (Cross-Site Scripting)**
- Pattern: `<script>`, `onmouseover=`, `javascript:`
- Examples: `?search=<script>alert('xss')</script>`
- Severity: High

**Path Traversal**
- Pattern: `../`, `..%2f`, `...`
- Examples: `GET /../../etc/passwd`
- Severity: High

**Brute Force**
- Pattern: Multiple failed logins from same IP
- Threshold: >5 attempts in 5 minutes
- Severity: High

**Port Scan**
- Pattern: Many different URIs from same IP
- Threshold: >10 unique URIs in 1 minute
- Severity: Medium

## 🔴 Color Codes

- 🟢 **GREEN (Low)**: Reconnaissance, suspicious methods
- 🟡 **YELLOW (Medium)**: Boolean SQLi, certain XSS
- 🟠 **ORANGE (High)**: Script tags, path traversal
- 🔴 **RED (Critical)**: Stacked queries, command injection

## 🐛 Common Issues

### Dashboard shows "No alerts"
- Make sure sample logs are in `logs/` folder
- Run `demo.py` to load sample data
- Check that monitor is running

### Monitor not detecting changes
- Restart monitor process with Ctrl+C then re-run
- Check file permissions on logs folder
- Ensure log files are being modified

### "sqlite3.OperationalError: database is locked"
- Close other instances
- Delete `alerts.db` to reset
- Restart the application

## 📚 Learn More

See **README.md** for:
- Detailed module documentation
- Advanced configuration
- Performance tuning
- Security considerations
- Extension ideas

## 🎉 Next Steps

1. ✅ Run the dashboard: `python app.py`
2. ✅ Start monitoring: `python monitor.py`
3. ✅ Add custom rules to `detection_engine.py`
4. ✅ Integrate with your systems
5. ✅ Deploy to production (with security hardening)

---

**Happy threat hunting! 🔍**
