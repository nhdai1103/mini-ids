"""
Mini IDS - Intrusion Detection System
Phát hiện các cuộc tấn công từ log files
"""

__version__ = "1.0.0"
__author__ = "Mini IDS Team"

try:
    from .log_parser import LogParser, LogEntry
    from .detection_engine import DetectionEngine, DetectionResult, ThreatLevel
    from .alert_manager import AlertManager
except ImportError:
    from log_parser import LogParser, LogEntry
    from detection_engine import DetectionEngine, DetectionResult, ThreatLevel
    from alert_manager import AlertManager

__all__ = [
    'LogParser',
    'LogEntry',
    'DetectionEngine',
    'DetectionResult',
    'ThreatLevel',
    'AlertManager',
]
