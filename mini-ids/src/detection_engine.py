import re
from typing import List, Dict, Optional
from dataclasses import dataclass
from enum import Enum
from datetime import datetime, timedelta


class ThreatLevel(Enum):
    """Mức độ mối đe dọa"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class AttackSignature:
    """Biểu diễn một chữ ký tấn công"""
    name: str
    pattern: str
    threat_level: ThreatLevel
    description: str
    attack_type: str


@dataclass
class DetectionResult:
    """Kết quả phát hiện một tấn công"""
    timestamp: str
    source_ip: str
    attack_type: str
    signature_name: str
    threat_level: ThreatLevel
    details: Dict
    raw_log: str


class DetectionEngine:
    """Engine phát hiện các cuộc tấn công dựa trên rule"""
    
    def __init__(self):
        self.signatures = self._load_signatures()
        self.brute_force_tracker = {}  # {ip: [(timestamp, username), ...]}
        self.scan_tracker = {}  # {ip: [uri, uri, ...]}
    
    @staticmethod
    def _load_signatures() -> List[AttackSignature]:
        """Tải các chữ ký tấn công"""
        return [
            # SQL Injection patterns
            AttackSignature(
                name="SQLi_UNION",
                pattern=r"(\bUNION\b.*\bSELECT\b|\bUNION\s+ALL\s+SELECT\b)",
                threat_level=ThreatLevel.HIGH,
                description="SQL Injection - UNION based",
                attack_type="SQLi"
            ),
            AttackSignature(
                name="SQLi_BOOLEAN",
                pattern=r"(\bOR\s+['\d]+\s*=\s*['\d]+\b|\bAND\s+['\d]+\s*=\s*['\d]+\b)",
                threat_level=ThreatLevel.MEDIUM,
                description="SQL Injection - Boolean based",
                attack_type="SQLi"
            ),
            AttackSignature(
                name="SQLi_COMMENT",
                pattern=r"(--|\/\*|\*\/|#|;)",
                threat_level=ThreatLevel.MEDIUM,
                description="SQL Injection - Comment pattern",
                attack_type="SQLi"
            ),
            AttackSignature(
                name="SQLi_STACKED",
                pattern=r"(;\s*(DROP|DELETE|INSERT|UPDATE|CREATE|ALTER)\b)",
                threat_level=ThreatLevel.CRITICAL,
                description="SQL Injection - Stacked queries",
                attack_type="SQLi"
            ),
            
            # XSS patterns
            AttackSignature(
                name="XSS_SCRIPT_TAG",
                pattern=r"<\s*script[^>]*>",
                threat_level=ThreatLevel.HIGH,
                description="XSS - Script tag",
                attack_type="XSS"
            ),
            AttackSignature(
                name="XSS_EVENT_HANDLER",
                pattern=r"on(load|click|error|focus|blur|change|submit|mouseover|keypress|keydown|keyup)\s*=",
                threat_level=ThreatLevel.HIGH,
                description="XSS - Event handler",
                attack_type="XSS"
            ),
            AttackSignature(
                name="XSS_JAVASCRIPT",
                pattern=r"javascript\s*:",
                threat_level=ThreatLevel.HIGH,
                description="XSS - JavaScript protocol",
                attack_type="XSS"
            ),
            AttackSignature(
                name="XSS_IFRAME",
                pattern=r"<\s*iframe[^>]*>",
                threat_level=ThreatLevel.MEDIUM,
                description="XSS - IFrame injection",
                attack_type="XSS"
            ),
            
            # Path Traversal
            AttackSignature(
                name="PATH_TRAVERSAL",
                pattern=r"(\.\./|\.\.\\|\.\.%2f|\.\.%5c|%2e%2e)",
                threat_level=ThreatLevel.HIGH,
                description="Path Traversal attack",
                attack_type="PathTraversal"
            ),
            
            # Command Injection
            AttackSignature(
                name="CMD_INJECTION",
                pattern=r"([;|&]|\|\||&&|\`|\\$\(|<\()",
                threat_level=ThreatLevel.HIGH,
                description="Command Injection",
                attack_type="CommandInjection"
            ),
            
            # Port Scan Detection
            AttackSignature(
                name="PORT_SCAN",
                pattern=r"(nmap|masscan|shodan|nikto|-A|-sV|-sU|-sS|-p-)",
                threat_level=ThreatLevel.MEDIUM,
                description="Port scanning tool detected",
                attack_type="Reconnaissance"
            ),
            
            # Suspicious methods
            AttackSignature(
                name="SUSPICIOUS_METHOD",
                pattern=r"(CONNECT|TRACE|MOVE|COPY|PROPFIND|PROPPATCH|MKCOL)",
                threat_level=ThreatLevel.LOW,
                description="Suspicious HTTP method",
                attack_type="Reconnaissance"
            ),
        ]
    
    def check_payload(self, payload: str, attack_type_hint: str = "") -> Optional[AttackSignature]:
        """
        Kiểm tra payload có chứa chữ ký tấn công không
        
        Args:
            payload: String cần kiểm tra
            attack_type_hint: Gợi ý loại tấn công để filter
        
        Returns:
            AttackSignature nếu tìm thấy, None nếu không
        """
        if not payload:
            return None
        
        for sig in self.signatures:
            # Nếu có hint, chỉ check signature cùng loại
            if attack_type_hint and sig.attack_type != attack_type_hint:
                continue
            
            try:
                if re.search(sig.pattern, payload, re.IGNORECASE):
                    return sig
            except:
                pass
        
        return None
    
    def detect_brute_force(self, source_ip: str, timestamp: str, 
                          username: str = 'unknown', is_failed: bool = True) -> Optional[DetectionResult]:
        """
        Phát hiện brute-force attack
        
        Ngưỡng: ≥ 5 failed login attempts từ cùng IP trong 60 giây
        """
        if source_ip not in self.brute_force_tracker:
            self.brute_force_tracker[source_ip] = []
        
        # Thêm attempt mới
        self.brute_force_tracker[source_ip].append({
            'timestamp': timestamp,
            'username': username,
            'failed': is_failed
        })
        
        # Xóa old attempts (> 60 giây trước)
        cutoff_time = datetime.now() - timedelta(seconds=60)
        
        # Giữ lại chỉ attempts trong 60s gần nhất
        recent_attempts = []
        for attempt in self.brute_force_tracker[source_ip]:
            try:
                # Parse ISO timestamp hoặc BSD syslog timestamp
                if 'T' in str(attempt['timestamp']):
                    # ISO format: 2025-12-13T04:48:42.702117+07:00
                    attempt_time = datetime.fromisoformat(attempt['timestamp'].replace('+07:00', ''))
                else:
                    # BSD format - sử dụng current year
                    attempt_time = datetime.now()
                
                if attempt_time > cutoff_time or len(self.brute_force_tracker[source_ip]) <= 10:
                    recent_attempts.append(attempt)
            except:
                recent_attempts.append(attempt)  # Giữ lại nếu parse fail
        
        self.brute_force_tracker[source_ip] = recent_attempts[-20:]  # Giữ max 20 attempts
        
        # Kiểm tra ngưỡng
        failed_count = sum(1 for a in self.brute_force_tracker[source_ip] if a.get('failed', True))
        
        if failed_count >= 5:
            return DetectionResult(
                timestamp=timestamp,
                source_ip=source_ip,
                attack_type="SSH_BRUTE_FORCE",
                signature_name="SSH Brute Force Attack",
                threat_level=ThreatLevel.HIGH,
                details={
                    'failed_attempts': failed_count,
                    'timeframe': '60 seconds',
                    'usernames': list(set(a.get('username', 'unknown') for a in self.brute_force_tracker[source_ip] if a.get('failed', True)))
                },
                raw_log=f"Phát hiện {failed_count} lần đăng nhập thất bại trong 60s"
            )
        
        return None
    
    def detect_port_scan(self, source_ip: str, uri: str, 
                        timestamp: str) -> Optional[DetectionResult]:
        """
        Phát hiện port scanning activity
        
        Ngưỡng: > 10 different ports/paths từ cùng IP trong 1 phút
        """
        if source_ip not in self.scan_tracker:
            self.scan_tracker[source_ip] = []
        
        # Thêm URI mới
        self.scan_tracker[source_ip].append({
            'uri': uri,
            'timestamp': timestamp
        })
        
        # Xóa old entries (> 1 phút trước)
        cutoff_time = datetime.now() - timedelta(minutes=1)
        
        # Giữ lại chỉ entries gần đây
        recent_entries = []
        for entry in self.scan_tracker[source_ip]:
            try:
                if 'T' in str(entry['timestamp']):
                    # ISO format
                    entry_time = datetime.fromisoformat(entry['timestamp'].replace('+07:00', ''))
                    if entry_time > cutoff_time:
                        recent_entries.append(entry)
                else:
                    recent_entries.append(entry)  # Giữ lại nếu không parse được
            except:
                recent_entries.append(entry)
        
        self.scan_tracker[source_ip] = recent_entries[-50:]  # Giữ max 50 entries
        
        # Kiểm tra số lượng unique URIs
        unique_uris = len(set(entry['uri'] for entry in self.scan_tracker[source_ip]))
        
        if unique_uris >= 10:
            return DetectionResult(
                timestamp=timestamp,
                source_ip=source_ip,
                attack_type="PortScan",
                signature_name="EXCESSIVE_URI_REQUESTS",
                threat_level=ThreatLevel.MEDIUM,
                details={
                    'unique_uris_accessed': unique_uris,
                    'timeframe': '1 minute',
                    'sample_uris': list(set(entry['uri'] for entry in self.scan_tracker[source_ip]))[:5]
                },
                raw_log=f"{unique_uris} different URIs accessed"
            )
        
        return None
    
    def detect_suspicious_http_methods(self, method: str, 
                                       source_ip: str, uri: str,
                                       timestamp: str) -> Optional[DetectionResult]:
        """Phát hiện HTTP methods bất thường"""
        # Chỉ check các method không phổ biến
        suspicious_methods = ['TRACE', 'TRACK', 'DEBUG', 'OPTIONS', 'CONNECT']
        
        if method and method.upper() in suspicious_methods:
            return DetectionResult(
                timestamp=timestamp,
                source_ip=source_ip,
                attack_type="Reconnaissance",
                signature_name="SUSPICIOUS_METHOD",
                threat_level=ThreatLevel.LOW,
                details={
                    'method': method,
                    'uri': uri,
                    'reason': f'Suspicious HTTP method: {method}'
                },
                raw_log=f"{method} {uri}"
            )
        
        return None
    
    @staticmethod
    def _is_recent(timestamp_str: str, cutoff_time: datetime) -> bool:
        """Kiểm tra timestamp có gần đây không"""
        try:
            # ISO timestamp: 2025-12-13T04:48:42.702117+07:00
            if 'T' in str(timestamp_str):
                ts = datetime.fromisoformat(timestamp_str.replace('+07:00', ''))
                return ts > cutoff_time
            
            # Try multiple BSD formats
            for fmt in ['%d/%b/%Y:%H:%M:%S', '%Y-%m-%d %H:%M:%S', '%b %d %H:%M:%S']:
                try:
                    ts = datetime.strptime(timestamp_str.split()[0], fmt)
                    return ts > cutoff_time
                except:
                    continue
            return True  # Giữ lại nếu không parse được
        except:
            return True
    
    def _create_detection(self, timestamp: str, source_ip: str, 
                         signature: AttackSignature, raw_log: str) -> DetectionResult:
        """Helper để tạo DetectionResult"""
        return DetectionResult(
            timestamp=timestamp,
            source_ip=source_ip,
            attack_type=signature.attack_type,
            signature_name=signature.name,
            threat_level=signature.threat_level,
            details={'signature': signature.name},
            raw_log=raw_log
        )
