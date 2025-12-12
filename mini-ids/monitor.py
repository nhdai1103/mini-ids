import os
import sys
from pathlib import Path
from watchdog.observers.polling import PollingObserver as Observer
from watchdog.events import FileSystemEventHandler
import time
import threading

# Add src directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

from log_parser import LogParser
from detection_engine import DetectionEngine
from alert_manager import AlertManager


class LogMonitorHandler(FileSystemEventHandler):
    """Handler cho log file changes - Tối ưu cho SSH logs"""
    
    def __init__(self):
        super().__init__()
        self.detection_engine = DetectionEngine()
        self.alert_manager = AlertManager()
        self.processed_positions = {}  # Track file positions
        self.last_inode = {}  # Track inodes for log rotation detection
    
    def on_modified(self, event):
        """Xử lý khi log file thay đổi"""
        if event.is_directory:
            return
        
        # Chỉ xử lý các file log
        if not any(event.src_path.endswith(ext) for ext in ['.log']):
            return
        
        self.analyze_log_file(event.src_path)
    
    def analyze_log_file(self, file_path: str):
        """Phân tích log file - Hỗ trợ SSH logs và log rotation"""
        try:
            file_path = os.path.abspath(file_path)
            
            # Kiểm tra file tồn tại
            if not os.path.exists(file_path):
                return
            
            # Phát hiện log rotation bằng inode
            try:
                current_inode = os.stat(file_path).st_ino
                if file_path in self.last_inode and self.last_inode[file_path] != current_inode:
                    print(f"🔄 Log rotation detected: {file_path}")
                    self.processed_positions[file_path] = 0
                self.last_inode[file_path] = current_inode
            except:
                pass
            
            # Xác định loại log
            if 'access' in file_path.lower():
                log_type = 'apache' if 'apache' in file_path.lower() else 'nginx'
            elif any(name in file_path.lower() for name in ['auth', 'ssh', 'secure']):
                log_type = 'ssh'
            else:
                log_type = 'auto'
            
            # Đọc từ vị trí đã xử lý
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                # Nhảy đến vị trí đã đọc
                if file_path in self.processed_positions:
                    f.seek(self.processed_positions[file_path])
                
                # Đọc các dòng mới
                new_lines = f.readlines()
                current_position = f.tell()
                
                # Process từng dòng
                for line in new_lines:
                    line = line.strip()
                    if line:
                        self._process_log_line(line, log_type, file_path)
                
                # Cập nhật vị trí đã đọc
                self.processed_positions[file_path] = current_position
            
        except PermissionError:
            print(f"⚠️  Permission denied: {file_path}")
        except Exception as e:
            print(f"❌ Error analyzing {file_path}: {e}")
    
    def _process_log_line(self, line: str, log_type: str, file_path: str = None):
        """Xử lý một dòng log"""
        try:
            # Parse log line
            entry = None
            if log_type == 'apache':
                entry = LogParser.parse_apache_access_log(line)
            elif log_type == 'nginx':
                entry = LogParser.parse_nginx_access_log(line)
            elif log_type == 'ssh':
                entry = LogParser.parse_ssh_log(line)
            else:
                # Auto detect
                if 'sshd' in line:
                    entry = LogParser.parse_ssh_log(line)
                elif 'HTTP' in line:
                    entry = LogParser.parse_apache_access_log(line)
            
            if not entry:
                return
            
            # Kiểm tra attacks
            detections = self._detect_attacks(entry)
            
            # Add alerts và hiển thị chi tiết
            for detection in detections:
                alert_id = self.alert_manager.add_alert(detection)
                threat = "🔴" if detection.threat_level.value == "critical" else \
                         "🟠" if detection.threat_level.value == "high" else \
                         "🟡" if detection.threat_level.value == "medium" else "🟢"
                
                print(f"\n{threat} CẢNH BÁO TẤN CÔNG!")
                print(f"   🆔 Alert: #{alert_id}")
                print(f"   🎯 Loại: {detection.attack_type}")
                print(f"   📍 IP: {detection.source_ip}")
                if entry.username:
                    print(f"   👤 User: {entry.username}")
                print(f"   ⚠️  Mức độ: {detection.threat_level.value.upper()}")
                if file_path:
                    print(f"   📄 File: {os.path.basename(file_path)}")
                print(f"   📝 Chi tiết: {detection.signature_name}")
        
        except Exception as e:
            pass  # Bỏ qua lỗi parse để không spam console
    
    def _detect_attacks(self, entry):
        """Phát hiện các tấn công từ log entry"""
        detections = []
        
        # 1. Check payload (URI) cho SQLi/XSS
        if entry.uri:
            sig = self.detection_engine.check_payload(entry.uri)
            if sig:
                detections.append(self.detection_engine._create_detection(
                    timestamp=entry.timestamp,
                    source_ip=entry.source_ip,
                    signature=sig,
                    raw_log=entry.uri
                ))
            
            # Check port scan
            port_scan_detection = self.detection_engine.detect_port_scan(
                entry.source_ip, entry.uri, entry.timestamp
            )
            if port_scan_detection:
                detections.append(port_scan_detection)
        
        # 2. Check HTTP method
        if entry.method:
            method_detection = self.detection_engine.detect_suspicious_http_methods(
                entry.method, entry.source_ip, entry.uri or '', entry.timestamp
            )
            if method_detection:
                detections.append(method_detection)
        
        # 3. Check user agent cho suspicious patterns
        if entry.user_agent:
            sig = self.detection_engine.check_payload(entry.user_agent)
            if sig:
                detections.append(self.detection_engine._create_detection(
                    timestamp=entry.timestamp,
                    source_ip=entry.source_ip,
                    signature=sig,
                    raw_log=f"User-Agent: {entry.user_agent}"
                ))
        
        # 4. SSH-specific detection
        if entry.log_type == 'ssh':
            # Kiểm tra brute-force cho SSH
            if entry.username:  # Failed login với username
                brute_force_detection = self.detection_engine.detect_brute_force(
                    entry.source_ip, entry.timestamp
                )
                if brute_force_detection:
                    detections.append(brute_force_detection)
            
            # Kiểm tra payload trong username (SQL injection, command injection)
            if entry.username:
                sig = self.detection_engine.check_payload(entry.username)
                if sig:
                    detections.append(self.detection_engine._create_detection(
                        timestamp=entry.timestamp,
                        source_ip=entry.source_ip,
                        signature=sig,
                        raw_log=f"SSH username: {entry.username}"
                    ))
        
        return detections
    
    @staticmethod
    def _create_detection(timestamp, source_ip, signature, raw_log):
        """Helper để tạo DetectionResult"""
        from detection_engine import DetectionResult
        return DetectionResult(
            timestamp=timestamp,
            source_ip=source_ip,
            attack_type=signature.attack_type,
            signature_name=signature.name,
            threat_level=signature.threat_level,
            details={'signature': signature.name},
            raw_log=raw_log
        )


class LogMonitor:
    """Monitor log files cho tấn công"""
    
    def __init__(self, log_directories: list):
        """
        Initialize log monitor
        
        Args:
            log_directories: List các thư mục chứa log files
        """
        self.log_directories = log_directories
        self.observer = Observer()
        self.event_handler = LogMonitorHandler()
    
    def start(self):
        """Bắt đầu monitoring"""
        print("🔍 Starting Log Monitor...")
        
        for log_dir in self.log_directories:
            if os.path.exists(log_dir):
                self.observer.schedule(self.event_handler, log_dir, recursive=True)
                print(f"   📁 Monitoring: {log_dir}")
        
        self.observer.start()
        print("✅ Log Monitor started\n")
        
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            self.stop()
    
    def stop(self):
        """Dừng monitoring"""
        print("\n\n⏹️  Stopping Log Monitor...")
        self.observer.stop()
        self.observer.join()
        print("✅ Log Monitor stopped")


if __name__ == '__main__':
    print("""
╔════════════════════════════════════════════════════════════╗
║        🛡️  LOG MONITOR - MINI IDS 🛡️                    ║
║     Giám sát Apache/Nginx/SSH logs real-time             ║
╚════════════════════════════════════════════════════════════╝
    """)
    
    # Directories to monitor - ưu tiên SSH logs trên Ubuntu
    log_dirs = [
        'logs',  # Local logs directory (development)
    ]
    
    # Ubuntu/Debian SSH logs
    ubuntu_ssh_logs = [
        '/var/log/auth.log',      # SSH authentication logs
        '/var/log/secure',         # CentOS/RHEL SSH logs
    ]
    
    # Web server logs
    web_logs = [
        '/var/log/apache2',        # Apache on Ubuntu
        '/var/log/nginx',          # Nginx logs
        '/var/log/httpd',          # Apache on CentOS
    ]
    
    # Kiểm tra các log paths có tồn tại không
    existing_dirs = [d for d in log_dirs if os.path.exists(d)]
    
    # Thêm SSH log directories nếu tồn tại
    for log_path in ubuntu_ssh_logs:
        if os.path.exists(log_path):
            log_dir = os.path.dirname(log_path) if os.path.isfile(log_path) else log_path
            if log_dir not in existing_dirs:
                existing_dirs.append(log_dir)
            print(f"✅ Tìm thấy SSH log: {log_path}")
    
    # Thêm web log directories nếu tồn tại
    for log_path in web_logs:
        if os.path.exists(log_path):
            if log_path not in existing_dirs:
                existing_dirs.append(log_path)
            print(f"✅ Tìm thấy Web log: {log_path}")
    
    if not existing_dirs:
        print("⚠️  Không tìm thấy log directories hệ thống")
        print("📁 Sử dụng local logs directory: ./logs")
        existing_dirs = ['logs']
    
    # Hiển thị hướng dẫn nếu không có quyền đọc system logs
    if not any('/var/log' in d for d in existing_dirs):
        print("\n💡 TIP: Để đọc SSH logs trên Ubuntu:")
        print("   1. Chạy với sudo: sudo python3 monitor.py")
        print("   2. Hoặc thêm user vào group: sudo usermod -a -G adm $USER")
        print("   3. Sau đó logout và login lại\n")
    
    print(f"\n📂 Monitoring {len(existing_dirs)} directories...\n")
    
    monitor = LogMonitor(existing_dirs)
    monitor.start()
