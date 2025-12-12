import re
from datetime import datetime
from typing import Dict, List, Optional
from dataclasses import dataclass


@dataclass
class LogEntry:
    """Biểu diễn một dòng log"""
    timestamp: str
    source_ip: str
    method: Optional[str] = None
    uri: Optional[str] = None   
    status_code: Optional[int] = None
    user_agent: Optional[str] = None
    username: Optional[str] = None
    log_type: str = "unknown"


class LogParser:
    """Parser cho các loại log khác nhau"""
    
    # Apache/Nginx access log pattern
    # 192.168.1.1 - - [01/Dec/2021:12:34:56 +0000] "GET /index.html HTTP/1.1" 200 1234 "-" "Mozilla/5.0"
    APACHE_PATTERN = re.compile(
        r'^(?P<ip>[\d\.]+)\s+-\s+-\s+\[(?P<timestamp>[^\]]+)\]\s+'
        r'"(?P<method>\w+)\s+(?P<uri>[^\s]+)\s+[^"]*"\s+(?P<status>\d+)\s+'
        r'(?P<size>\d+|-)\s+"(?P<referer>[^"]*)"\s+"(?P<useragent>[^"]*)"'
    )
    
    # Nginx access log pattern (tương tự Apache)
    NGINX_PATTERN = APACHE_PATTERN
    
    # SSH log pattern - Failed password (hỗ trợ cả BSD và ISO timestamp)
    # BSD: Dec  1 12:34:56 server sshd[1234]: Failed password for invalid user admin from 192.168.1.1 port 54321 ssh2
    # ISO: 2025-12-13T04:19:57.569380+07:00 Dai sshd[766]: Failed password for invalid user fakeuser from 127.0.0.1 port 57990 ssh2
    SSH_FAILED_PATTERN = re.compile(
        r'^(?P<timestamp>(?:\d{4}-\d{2}-\d{2}T[\d:.+-]+|\w+\s+\d+\s+\d+:\d+:\d+))\s+'
        r'(?P<hostname>[\w\-\.]+)\s+sshd\[\d+\]:\s+'
        r'(?P<event>Failed password|Invalid user|Accepted[^:]*|Connection closed|Disconnected)\s+'
        r'(?:for\s+(?:invalid user\s+)?(?P<username>[\w\'\"\;\|\&\.\-\/\\]+)\s+)?'
        r'(?:from\s+|by\s+(?:invalid user\s+[\w]+\s+)?)?'
        r'(?P<ip>[\d\.]+)\s+port\s+\d+',
        re.IGNORECASE
    )
    
    # SSH log pattern - Authentication failure (pam_unix)
    SSH_AUTH_FAILURE_PATTERN = re.compile(
        r'^(?P<timestamp>(?:\d{4}-\d{2}-\d{2}T[\d:.+-]+|\w+\s+\d+\s+\d+:\d+:\d+))\s+'
        r'(?P<hostname>[\w\-\.]+)\s+sshd\[\d+\]:\s+'
        r'(?:pam_unix\(sshd:auth\):\s+)?authentication failure.*rhost=(?P<ip>[\d\.]+)',
        re.IGNORECASE
    )
    
    # SSH log pattern - Connection events
    SSH_CONNECTION_PATTERN = re.compile(
        r'^(?P<timestamp>(?:\d{4}-\d{2}-\d{2}T[\d:.+-]+|\w+\s+\d+\s+\d+:\d+:\d+))\s+'
        r'(?P<hostname>[\w\-\.]+)\s+sshd\[\d+\]:\s+'
        r'(?P<event>Connection from|Connection closed|Disconnected from)\s+'
        r'(?:invalid user\s+(?P<username>[\w]+)\s+)?'
        r'(?P<ip>[\d\.]+)\s+port\s+\d+',
        re.IGNORECASE
    )

    @staticmethod
    def parse_apache_access_log(line: str) -> Optional[LogEntry]:
        """Parse Apache/Nginx access log"""
        match = LogParser.APACHE_PATTERN.match(line)
        if not match:
            return None
        
        data = match.groupdict()
        return LogEntry(
            timestamp=data['timestamp'],
            source_ip=data['ip'],
            method=data['method'],
            uri=data['uri'],
            status_code=int(data['status']),
            user_agent=data['useragent'],
            log_type='apache'
        )
    
    @staticmethod
    def parse_nginx_access_log(line: str) -> Optional[LogEntry]:
        """Parse Nginx access log"""
        match = LogParser.NGINX_PATTERN.match(line)
        if not match:
            return None
        
        data = match.groupdict()
        return LogEntry(
            timestamp=data['timestamp'],
            source_ip=data['ip'],
            method=data['method'],
            uri=data['uri'],
            status_code=int(data['status']),
            user_agent=data['useragent'],
            log_type='nginx'
        )
    
    @staticmethod
    def parse_ssh_log(line: str) -> Optional[LogEntry]:
        """Parse SSH log - Hỗ trợ nhiều định dạng"""
        # Thử pattern Failed password/Accepted/Invalid user
        match = LogParser.SSH_FAILED_PATTERN.match(line)
        if match:
            data = match.groupdict()
            return LogEntry(
                timestamp=data.get('timestamp', ''),
                source_ip=data['ip'],
                username=data.get('username'),
                uri=data.get('event', ''),  # Lưu event type vào uri
                log_type='ssh'
            )
        
        # Thử pattern Authentication failure
        match = LogParser.SSH_AUTH_FAILURE_PATTERN.match(line)
        if match:
            data = match.groupdict()
            return LogEntry(
                timestamp=data.get('timestamp', ''),
                source_ip=data['ip'],
                uri='Authentication failure',
                log_type='ssh'
            )
        
        # Thử pattern Connection events
        match = LogParser.SSH_CONNECTION_PATTERN.match(line)
        if match:
            data = match.groupdict()
            return LogEntry(
                timestamp=data.get('timestamp', ''),
                source_ip=data['ip'],
                username=data.get('username'),
                uri=data.get('event', 'Connection'),
                log_type='ssh'
            )
        
        return None
    
    @staticmethod
    def parse_log_file(file_path: str, log_type: str = 'auto') -> List[LogEntry]:
        """
        Parse log file based on type
        
        Args:
            file_path: Path to log file
            log_type: 'apache', 'nginx', 'ssh', or 'auto' để tự detect
        
        Returns:
            List of parsed LogEntry objects
        """
        entries = []
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    
                    entry = None
                    if log_type == 'auto':
                        # Tự detect loại log
                        if 'sshd' in line:
                            entry = LogParser.parse_ssh_log(line)
                        elif 'HTTP' in line:
                            entry = LogParser.parse_apache_access_log(line) or \
                                    LogParser.parse_nginx_access_log(line)
                    elif log_type == 'apache':
                        entry = LogParser.parse_apache_access_log(line)
                    elif log_type == 'nginx':
                        entry = LogParser.parse_nginx_access_log(line)
                    elif log_type == 'ssh':
                        entry = LogParser.parse_ssh_log(line)
                    
                    if entry:
                        entries.append(entry)
        
        except FileNotFoundError:
            print(f"Lỗi: File không tìm thấy: {file_path}")
        except Exception as e:
            print(f"Lỗi khi parse file: {e}")
        
        return entries
