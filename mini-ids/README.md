# Mini IDS - Hệ thống Phát Hiện Tấn Công Từ Log

## 🎯 Tổng Quan

Mini IDS là một hệ thống Python đơn giản nhưng mạnh mẽ để phát hiện các cuộc tấn công từ log files (Apache, Nginx, SSH). Hệ thống sử dụng các rules phát hiện dựa trên pattern matching và behavioral analysis, tương tự như Suricata IDS và Fail2ban.

### Các tính năng chính:
- ✅ **Đọc & Parse Log Files**: Apache, Nginx, SSH logs
- ✅ **Phát Hiện Tấn Công**: SQLi, XSS, Path Traversal, Command Injection, Brute-Force, Port Scan
- ✅ **Real-time Monitoring**: Theo dõi log files trực tiếp
- ✅ **Web Dashboard**: Giao diện quản lý cảnh báo
- ✅ **Database Alert**: Lưu trữ alerts trong SQLite
- ✅ **IP Blocking Tracking**: Theo dõi các IP bị chặn

## 📁 Cấu Trúc Dự Án

```
mini-ids/
├── app.py                      # Flask web application
├── monitor.py                  # Log file monitor (watchdog)
├── requirements.txt            # Dependencies
├── logs/
│   ├── access.log             # Apache/Nginx access log sample
│   └── auth.log               # SSH auth log sample
├── src/
│   ├── __init__.py
│   ├── log_parser.py          # Log parser module
│   ├── detection_engine.py    # Attack detection rules
│   └── alert_manager.py       # Alert management & storage
├── templates/
│   └── dashboard.html         # Web dashboard UI
├── static/                    # (CSS, JS files)
├── alerts.db                  # SQLite database (auto-generated)
└── alerts.json                # JSON alerts backup
```

## 🚀 Cài Đặt & Chạy

### 1. Cài đặt Dependencies

```bash
cd mini-ids
pip install -r requirements.txt
```

### 2. Chạy Web Dashboard

```bash
python app.py
```

Truy cập: `http://localhost:5000`

### 3. Chạy Log Monitor (trong terminal khác)

```bash
python monitor.py
```

## 📋 Các Module Chính

### 1. **log_parser.py** - Log Parser
Parse các loại log khác nhau:

```python
from src.log_parser import LogParser

# Parse Apache/Nginx access log
entry = LogParser.parse_apache_access_log(log_line)

# Parse SSH log
entry = LogParser.parse_ssh_log(log_line)

# Parse file
entries = LogParser.parse_log_file('logs/access.log', log_type='apache')
```

**Hỗ trợ:**
- Apache: `192.168.1.1 - - [01/Dec/2021:12:34:56 +0000] "GET /index.html HTTP/1.1" 200 1234 "-" "Mozilla/5.0"`
- Nginx: Tương tự Apache
- SSH: `Failed password`, `Invalid user`, `Connection` events

### 2. **detection_engine.py** - Detection Engine
Phát hiện các cuộc tấn công dựa trên rules:

```python
from src.detection_engine import DetectionEngine

engine = DetectionEngine()

# Check payload cho SQLi/XSS
signature = engine.check_payload("1' OR '1'='1")
# Output: AttackSignature(name="SQLi_BOOLEAN", threat_level=MEDIUM)

# Detect brute-force
detection = engine.detect_brute_force(
    "192.168.1.100", "admin", is_failed=True, timestamp="now"
)

# Detect port scan
detection = engine.detect_port_scan(
    "10.0.0.50", "/test", timestamp="now"
)
```

**Các Attack Signatures được phát hiện:**

#### SQL Injection
- `SQLi_UNION`: `UNION SELECT` patterns
- `SQLi_BOOLEAN`: `OR '1'='1` patterns
- `SQLi_COMMENT`: `--`, `/**/`, `#` patterns
- `SQLi_STACKED`: `; DROP` patterns (CRITICAL)

#### Cross-Site Scripting (XSS)
- `XSS_SCRIPT_TAG`: `<script>` tags
- `XSS_EVENT_HANDLER`: Event handlers (`onload`, `onclick`, etc)
- `XSS_JAVASCRIPT`: `javascript:` protocol
- `XSS_IFRAME`: `<iframe>` injection

#### Khác
- `PATH_TRAVERSAL`: `../`, `..\\` patterns
- `CMD_INJECTION`: `;`, `|`, `&&` patterns
- `PORT_SCAN`: Nhiều URI từ cùng IP
- `BRUTE_FORCE`: Nhiều failed login attempts

#### Threat Levels
- 🟢 **LOW**: Reconnaissance tools, suspicious methods
- 🟡 **MEDIUM**: Boolean SQLi, XSS iframes, port scans
- 🟠 **HIGH**: Script tags, event handlers, path traversal
- 🔴 **CRITICAL**: Stacked SQLi queries

### 3. **alert_manager.py** - Alert Manager
Quản lý cảnh báo và lưu trữ:

```python
from src.alert_manager import AlertManager

alert_mgr = AlertManager()

# Add alert
alert_id = alert_mgr.add_alert(detection_result)

# Get alerts
alerts = alert_mgr.get_alerts(limit=100, threat_level='high')

# Get blocked IPs
ips = alert_mgr.get_blocked_ips()

# Get statistics
stats = alert_mgr.get_statistics()
```

**Database Schema:**
```sql
-- alerts table
id, timestamp, source_ip, attack_type, signature_name, threat_level, details, raw_log, created_at

-- blocked_ips table
id, ip_address, threat_count, threat_level, first_seen, last_seen

-- attack_stats table
id, attack_type, count, threat_level, last_seen
```

## 🌐 Web Dashboard

### Endpoints API

| Endpoint | Mô Tả | Ví Dụ |
|----------|-------|-------|
| `GET /` | Dashboard chính | - |
| `GET /api/statistics` | Thống kê tổng quan | `{"total_alerts": 150, "total_blocked_ips": 15, ...}` |
| `GET /api/alerts` | Danh sách alerts | `?limit=50&threat_level=high&source_ip=10.0.0.1` |
| `GET /api/blocked-ips` | IPs bị chặn | `?limit=20` |
| `GET /api/attack-stats` | Thống kê tấn công | - |
| `GET /api/health` | Health check | `{"status": "ok"}` |

### Tính Năng Dashboard
- 📊 Thống kê real-time (total alerts, critical threats, blocked IPs)
- 🔍 Danh sách alerts có thể filter (by threat level, IP)
- 🚫 Top blocked IPs
- 📈 Charts: Top attack types, threat distribution
- 🔄 Auto-refresh mỗi 10 giây

## 📝 Sample Logs

### Apache Access Log (logs/access.log)

```
192.168.1.100 - - [01/Dec/2024:12:00:00 +0000] "GET /index.html HTTP/1.1" 200 1234 "-" "Mozilla/5.0"
192.168.1.102 - - [01/Dec/2024:12:00:03 +0000] "POST /login HTTP/1.1" 401 100 "-" "Mozilla/5.0"
10.0.0.50 - - [01/Dec/2024:12:01:00 +0000] "GET /search.php?q=1' OR '1'='1 HTTP/1.1" 200 1024 "-" "Mozilla/5.0"
172.16.0.25 - - [01/Dec/2024:12:02:00 +0000] "GET /comments.php?text=<script>alert('xss')</script> HTTP/1.1" 200 500 "-" "Mozilla/5.0"
```

### SSH Auth Log (logs/auth.log)

```
Dec  1 12:00:00 server sshd[1234]: Failed password for invalid user admin from 192.168.1.100 port 54321 ssh2
Dec  1 12:00:05 server sshd[1235]: Failed password for admin from 192.168.1.100 port 54322 ssh2
Dec  1 12:00:10 server sshd[1236]: Failed password for admin from 192.168.1.100 port 54323 ssh2
```

## 🔧 Sử Dụng Programmatically

### Ví dụ 1: Parse Log & Detect Attacks

```python
from src.log_parser import LogParser
from src.detection_engine import DetectionEngine
from src.alert_manager import AlertManager

# Initialize
engine = DetectionEngine()
alert_mgr = AlertManager()

# Parse log file
entries = LogParser.parse_log_file('logs/access.log', log_type='apache')

# Check each entry
for entry in entries:
    # Check URI for attacks
    sig = engine.check_payload(entry.uri)
    if sig:
        # Create detection and add alert
        detection = engine._create_detection(
            timestamp=entry.timestamp,
            source_ip=entry.source_ip,
            signature=sig,
            raw_log=entry.uri
        )
        alert_id = alert_mgr.add_alert(detection)
        print(f"⚠️ Alert #{alert_id}: {sig.name} from {entry.source_ip}")
```

### Ví dụ 2: Get Statistics

```python
from src.alert_manager import AlertManager

alert_mgr = AlertManager()
stats = alert_mgr.get_statistics()

print(f"Total Alerts: {stats['total_alerts']}")
print(f"Blocked IPs: {stats['total_blocked_ips']}")
print(f"Top attacks: {stats['top_attacks']}")

# Output:
# Total Alerts: 150
# Blocked IPs: 15
# Top attacks: [{'attack_type': 'SQLi', 'count': 45}, ...]
```

### Ví dụ 3: Monitor Log File

```python
from monitor import LogMonitor

monitor = LogMonitor(['logs', '/var/log/apache2'])
monitor.start()  # Blocks until Ctrl+C
```

## 🎓 So Sánh Với IDS/Prevention Tools

### Mini IDS vs Fail2ban
| Tính năng | Mini IDS | Fail2ban |
|-----------|----------|----------|
| Phát hiện Brute-Force | ✅ | ✅ |
| SQLi/XSS Detection | ✅ | ❌ |
| Web Dashboard | ✅ | ❌ |
| Ban tự động | ❌ | ✅ |
| Lightweight | ✅ | ✅ |

### Mini IDS vs Suricata
| Tính năng | Mini IDS | Suricata |
|-----------|----------|----------|
| Rule-based Detection | ✅ | ✅ |
| Real-time Alerting | ✅ | ✅ |
| Traffic Analysis | ❌ | ✅ |
| Performance | ✅ | ⚠️ |
| Ease of Use | ✅ | ⚠️ |
| Python-based | ✅ | ❌ |

## 📊 Performance & Tuning

### Ngưỡng Detection (có thể tùy chỉnh)
- **Brute-Force**: > 5 failed logins từ cùng IP trong 5 phút
- **Port Scan**: > 10 different URIs từ cùng IP trong 1 phút
- **Payload**: Regex matching trên URI, user-agent

### Cách tối ưu
1. **Tăng Database Performance**: Thêm indexes
2. **Batch Processing**: Process multiple logs cùng lúc
3. **Caching**: Cache blocked IPs để lookup nhanh
4. **Pruning**: Xóa old alerts: `alert_mgr.clear_old_alerts(days=7)`

## 🔐 Security Considerations

- ⚠️ **Chưa có IP blocking**: Mini IDS chỉ detect và alert, không block firewall-level
- ⚠️ **Chưa có encryption**: Alerts stored in plain text JSON/SQLite
- ⚠️ **Chưa có auth**: Web dashboard không có login
- 💡 **Để production ready**: Thêm WAF rules, IP blocking via iptables, HTTPS

## 📚 Extension Ideas

1. **Thêm Network-based Detection**: Analyze network packets (tùy chọn)
2. **Machine Learning**: Anomaly detection với ML
3. **IP Blocking**: Tích hợp iptables/Windows Firewall
4. **Email Alerts**: Gửi email khi phát hiện CRITICAL threats
5. **Slack/Discord Webhooks**: Real-time notifications
6. **Custom Rules**: Allow users để write custom detection rules
7. **Geo-IP Blocking**: Block từ specific countries

## 🐛 Troubleshooting

### Issue: "No module named 'flask'"
```bash
pip install -r requirements.txt
```

### Issue: Monitor không detect log changes
- Kiểm tra đường dẫn folder tồn tại: `os.path.exists(path)`
- Restart monitor process
- Kiểm tra file permissions

### Issue: SQLite "database is locked"
- Một process đang access DB
- Xóa `alerts.db`, restart app

## 📄 License

MIT License - Feel free to use and modify

## 🤝 Contributing

Feel free to fork, submit issues, or make pull requests!

---

**Tạo bởi**: Mini IDS Team
**Version**: 1.0.0
**Last Updated**: Dec 2024
