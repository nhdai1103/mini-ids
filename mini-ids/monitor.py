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
    """Handler cho log file changes"""
    
    def __init__(self):
        super().__init__()
        self.detection_engine = DetectionEngine()
        self.alert_manager = AlertManager()
        self.processed_lines = {}  # Track line numbers to avoid reprocessing
    
    def on_modified(self, event):
        """Xử lý khi log file thay đổi"""
        if event.is_directory:
            return
        
        # Chỉ xử lý các file log
        if not any(event.src_path.endswith(ext) for ext in ['.log']):
            return
        
        self.analyze_log_file(event.src_path)
    
    def analyze_log_file(self, file_path: str):
        """Phân tích log file"""
        try:
            file_path = os.path.abspath(file_path)
            
            # Đọc file
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()
            
            # Xác định loại log
            if 'access' in file_path.lower():
                log_type = 'apache' if 'apache' in file_path.lower() else 'nginx'
            elif 'ssh' in file_path.lower():
                log_type = 'ssh'
            else:
                log_type = 'auto'
            
            # Track lines đã process
            if file_path not in self.processed_lines:
                self.processed_lines[file_path] = 0
            
            start_idx = self.processed_lines[file_path]
            
            # Chỉ process dòng mới
            for idx in range(start_idx, len(lines)):
                line = lines[idx].strip()
                if not line:
                    continue
                
                self._process_log_line(line, log_type)
            
            # Update tracked lines
            self.processed_lines[file_path] = len(lines)
            
        except Exception as e:
            print(f"❌ Error analyzing {file_path}: {e}")
    
    def _process_log_line(self, line: str, log_type: str):
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
            
            # Add alerts
            for detection in detections:
                alert_id = self.alert_manager.add_alert(detection)
                threat = "🔴" if detection.threat_level.value == "critical" else \
                         "🟠" if detection.threat_level.value == "high" else \
                         "🟡" if detection.threat_level.value == "medium" else "🟢"
                
                print(f"{threat} Alert #{alert_id}: {detection.attack_type} from {detection.source_ip}")
        
        except Exception as e:
            print(f"❌ Error processing line: {e}")
    
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
            if 'Failed' in entry.uri or entry.username:  # Failed login
                brute_force_detection = self.detection_engine.detect_brute_force(
                    entry.source_ip, entry.username or 'unknown', True, entry.timestamp
                )
                if brute_force_detection:
                    detections.append(brute_force_detection)
        
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
    # Directories to monitor
    log_dirs = [
        'logs',  # Local logs directory
        '/var/log',  # Linux system logs
        'C:\\Windows\\System32\\winevt\\Logs',  # Windows event logs
    ]
    
    # Filter existing directories
    existing_dirs = [d for d in log_dirs if os.path.exists(d)]
    
    # Add more directories if they exist
    other_dirs = [
        '/var/log/apache2',
        '/var/log/nginx',
        '/var/log/auth.log',
        '/var/log/syslog',
    ]
    existing_dirs.extend([d for d in other_dirs if os.path.exists(d)])
    
    if not existing_dirs:
        existing_dirs = ['logs']  # Fallback to local logs
    
    monitor = LogMonitor(existing_dirs)
    monitor.start()
