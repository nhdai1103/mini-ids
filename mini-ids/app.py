from flask import Flask, render_template, jsonify, request
from datetime import datetime
import os
import sys

# Add src directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

from alert_manager import AlertManager
from detection_engine import DetectionEngine

app = Flask(__name__)
alert_manager = AlertManager()
detection_engine = DetectionEngine()


@app.route('/')
def dashboard():
    """Dashboard chính"""
    return render_template('dashboard.html')


@app.route('/api/statistics')
def get_statistics():
    """API: Lấy thống kê"""
    stats = alert_manager.get_statistics()
    return jsonify(stats)


@app.route('/api/alerts')
def get_alerts_api():
    """API: Lấy danh sách alerts"""
    limit = request.args.get('limit', 100, type=int)
    threat_level = request.args.get('threat_level', None)
    source_ip = request.args.get('source_ip', None)
    attack_type = request.args.get('attack_type', None)
    
    alerts = alert_manager.get_alerts(
        limit=limit,
        threat_level=threat_level,
        source_ip=source_ip,
        attack_type=attack_type
    )
    
    return jsonify(alerts)


@app.route('/api/blocked-ips')
def get_blocked_ips():
    """API: Lấy danh sách IPs bị chặn"""
    limit = request.args.get('limit', 50, type=int)
    ips = alert_manager.get_blocked_ips(limit=limit)
    return jsonify(ips)


@app.route('/api/attack-stats')
def get_attack_stats():
    """API: Lấy thống kê tấn công"""
    stats = alert_manager.get_attack_stats()
    return jsonify(stats)


@app.route('/api/alerts/recent')
def get_recent_alerts():
    """API: Lấy alerts gần đây nhất (Real-time)"""
    limit = request.args.get('limit', 10, type=int)
    alerts = alert_manager.get_alerts(limit=limit)
    return jsonify(alerts)


@app.route('/api/health')
def health_check():
    """Health check"""
    return jsonify({
        'status': 'ok',
        'timestamp': datetime.now().isoformat()
    })


@app.template_filter('threat_color')
def threat_color_filter(threat_level):
    """Filter để chuyển threat level thành màu"""
    colors = {
        'low': '#28a745',
        'medium': '#ffc107',
        'high': '#fd7e14',
        'critical': '#dc3545'
    }
    return colors.get(threat_level, '#6c757d')


@app.template_filter('format_datetime')
def format_datetime_filter(value):
    """Format datetime"""
    try:
        if isinstance(value, str):
            return value
        return value.strftime('%Y-%m-%d %H:%M:%S')
    except:
        return value


if __name__ == '__main__':
    print("🔍 Mini IDS Dashboard running on http://localhost:5000")
    app.run(debug=False, host='0.0.0.0', port=5000)
