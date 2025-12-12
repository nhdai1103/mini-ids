import json
import sqlite3
from pathlib import Path
from typing import List, Dict, Optional
from datetime import datetime
from dataclasses import asdict

try:
    from .detection_engine import DetectionResult, ThreatLevel
except ImportError:
    from detection_engine import DetectionResult, ThreatLevel


class AlertManager:
    """Quản lý cảnh báo và lưu trữ"""
    
    def __init__(self, db_path: str = "alerts.db", json_path: str = "alerts.json"):
        self.db_path = db_path
        self.json_path = json_path
        self.alerts = []
        
        self._init_db()
        self._load_alerts()
    
    def _init_db(self):
        """Khởi tạo SQLite database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                source_ip TEXT,
                attack_type TEXT,
                signature_name TEXT,
                threat_level TEXT,
                details TEXT,
                raw_log TEXT,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS blocked_ips (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip_address TEXT UNIQUE,
                threat_count INTEGER DEFAULT 1,
                threat_level TEXT,
                first_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
                last_seen DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS attack_stats (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                attack_type TEXT,
                count INTEGER DEFAULT 1,
                threat_level TEXT,
                last_seen DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        conn.commit()
        conn.close()
    
    def add_alert(self, detection: DetectionResult) -> int:
        """
        Thêm cảnh báo mới
        
        Returns:
            Alert ID
        """
        alert = {
            'timestamp': detection.timestamp,
            'source_ip': detection.source_ip,
            'attack_type': detection.attack_type,
            'signature_name': detection.signature_name,
            'threat_level': detection.threat_level.value,
            'details': json.dumps(detection.details),
            'raw_log': detection.raw_log
        }
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO alerts 
            (timestamp, source_ip, attack_type, signature_name, threat_level, details, raw_log)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', tuple(alert.values()))
        
        alert_id = cursor.lastrowid
        
        # Update blocked IPs
        self._update_blocked_ip(cursor, detection.source_ip, detection.threat_level)
        
        # Update attack stats
        self._update_attack_stats(cursor, detection.attack_type, detection.threat_level)
        
        conn.commit()
        conn.close()
        
        # Lưu vào JSON file
        self._save_to_json(alert, alert_id)
        
        return alert_id
    
    def _update_blocked_ip(self, cursor, ip: str, threat_level: ThreatLevel):
        """Cập nhật thông tin blocked IP"""
        cursor.execute(
            'SELECT id, threat_count FROM blocked_ips WHERE ip_address = ?',
            (ip,)
        )
        result = cursor.fetchone()
        
        if result:
            ip_id, count = result
            cursor.execute(
                'UPDATE blocked_ips SET threat_count = ?, last_seen = CURRENT_TIMESTAMP WHERE id = ?',
                (count + 1, ip_id)
            )
        else:
            cursor.execute(
                'INSERT INTO blocked_ips (ip_address, threat_level) VALUES (?, ?)',
                (ip, threat_level.value)
            )
    
    def _update_attack_stats(self, cursor, attack_type: str, threat_level: ThreatLevel):
        """Cập nhật thống kê tấn công"""
        cursor.execute(
            'SELECT id, count FROM attack_stats WHERE attack_type = ?',
            (attack_type,)
        )
        result = cursor.fetchone()
        
        if result:
            stat_id, count = result
            cursor.execute(
                'UPDATE attack_stats SET count = ?, last_seen = CURRENT_TIMESTAMP WHERE id = ?',
                (count + 1, stat_id)
            )
        else:
            cursor.execute(
                'INSERT INTO attack_stats (attack_type, threat_level) VALUES (?, ?)',
                (attack_type, threat_level.value)
            )
    
    def _save_to_json(self, alert: dict, alert_id: int):
        """Lưu alert vào JSON file"""
        alert_with_id = {'id': alert_id, **alert}
        
        # Đọc alerts hiện tại
        alerts = []
        if Path(self.json_path).exists():
            try:
                with open(self.json_path, 'r') as f:
                    alerts = json.load(f)
            except:
                alerts = []
        
        # Thêm alert mới
        alerts.append(alert_with_id)
        
        # Giữ chỉ 1000 alerts gần đây nhất
        if len(alerts) > 1000:
            alerts = alerts[-1000:]
        
        # Lưu
        with open(self.json_path, 'w') as f:
            json.dump(alerts, f, indent=2)
    
    def _load_alerts(self):
        """Load alerts từ file"""
        if Path(self.json_path).exists():
            try:
                with open(self.json_path, 'r') as f:
                    self.alerts = json.load(f)
            except:
                self.alerts = []
    
    def get_alerts(self, limit: int = 100, threat_level: Optional[str] = None,
                   source_ip: Optional[str] = None, attack_type: Optional[str] = None) -> List[Dict]:
        """
        Lấy alerts với các filter
        
        Args:
            limit: Số alerts tối đa
            threat_level: Filter theo mức độ (low, medium, high, critical)
            source_ip: Filter theo IP source
            attack_type: Filter theo loại tấn công
        
        Returns:
            List of alerts
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        query = 'SELECT * FROM alerts WHERE 1=1'
        params = []
        
        if threat_level:
            query += ' AND threat_level = ?'
            params.append(threat_level)
        
        if source_ip:
            query += ' AND source_ip = ?'
            params.append(source_ip)
        
        if attack_type:
            query += ' AND attack_type = ?'
            params.append(attack_type)
        
        query += ' ORDER BY created_at DESC LIMIT ?'
        params.append(limit)
        
        cursor.execute(query, params)
        columns = [description[0] for description in cursor.description]
        alerts = [dict(zip(columns, row)) for row in cursor.fetchall()]
        
        conn.close()
        
        return alerts
    
    def get_blocked_ips(self, limit: int = 50) -> List[Dict]:
        """Lấy danh sách các IP bị chặn"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute(
            'SELECT * FROM blocked_ips ORDER BY threat_count DESC LIMIT ?',
            (limit,)
        )
        columns = [description[0] for description in cursor.description]
        ips = [dict(zip(columns, row)) for row in cursor.fetchall()]
        
        conn.close()
        
        return ips
    
    def get_attack_stats(self) -> List[Dict]:
        """Lấy thống kê tấn công"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('SELECT * FROM attack_stats ORDER BY count DESC')
        columns = [description[0] for description in cursor.description]
        stats = [dict(zip(columns, row)) for row in cursor.fetchall()]
        
        conn.close()
        
        return stats
    
    def get_statistics(self) -> Dict:
        """Lấy thống kê tổng quan"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Tổng số alerts
        cursor.execute('SELECT COUNT(*) FROM alerts')
        total_alerts = cursor.fetchone()[0]
        
        # Alerts theo threat level
        cursor.execute('''
            SELECT threat_level, COUNT(*) as count 
            FROM alerts 
            GROUP BY threat_level
        ''')
        threat_dist = dict(cursor.fetchall())
        
        # Tổng số IPs bị block
        cursor.execute('SELECT COUNT(*) FROM blocked_ips')
        total_blocked_ips = cursor.fetchone()[0]
        
        # Top IPs
        cursor.execute('''
            SELECT ip_address, threat_count 
            FROM blocked_ips 
            ORDER BY threat_count DESC 
            LIMIT 10
        ''')
        top_ips = [dict(zip(['ip', 'threat_count'], row)) for row in cursor.fetchall()]
        
        # Top attack types
        cursor.execute('''
            SELECT attack_type, count 
            FROM attack_stats 
            ORDER BY count DESC 
            LIMIT 10
        ''')
        top_attacks = [dict(zip(['attack_type', 'count'], row)) for row in cursor.fetchall()]
        
        conn.close()
        
        return {
            'total_alerts': total_alerts,
            'threat_distribution': threat_dist,
            'total_blocked_ips': total_blocked_ips,
            'top_ips': top_ips,
            'top_attacks': top_attacks
        }
    
    def clear_old_alerts(self, days: int = 7):
        """Xóa alerts cũ hơn N ngày"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute(
            "DELETE FROM alerts WHERE created_at < datetime('now', ? || ' days')",
            (f'-{days}',)
        )
        
        conn.commit()
        conn.close()
