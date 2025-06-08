# Security Event Monitor Dashboard
# A real-time security monitoring dashboard for SOC operations

from flask import Flask, render_template, jsonify, request
import sqlite3
import json
import datetime
import random
import threading
import time
from collections import defaultdict

app = Flask(__name__)

# Database setup
def init_db():
    conn = sqlite3.connect('security_events.db')
    cursor = conn.cursor()
    
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS security_events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT NOT NULL,
        event_type TEXT NOT NULL,
        severity TEXT NOT NULL,
        source_ip TEXT,
        destination_ip TEXT,
        description TEXT,
        status TEXT DEFAULT 'Open'
    )
    ''')
    
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS alert_thresholds (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        alert_type TEXT NOT NULL,
        threshold_value INTEGER NOT NULL,
        time_window INTEGER NOT NULL
    )
    ''')
    
    # Insert default thresholds
    cursor.execute('''
    INSERT OR IGNORE INTO alert_thresholds (alert_type, threshold_value, time_window)
    VALUES 
    ('failed_login', 5, 300),
    ('port_scan', 10, 60),
    ('malware_detection', 1, 1)
    ''')
    
    conn.commit()
    conn.close()

# Generate sample security events
def generate_sample_events():
    event_types = [
        'Failed Login Attempt',
        'Port Scan Detected',
        'Malware Detection',
        'Suspicious File Access',
        'Network Anomaly',
        'Brute Force Attack',
        'SQL Injection Attempt',
        'DDoS Attack'
    ]
    
    severities = ['Low', 'Medium', 'High', 'Critical']
    
    conn = sqlite3.connect('security_events.db')
    cursor = conn.cursor()
    
    for _ in range(50):  # Generate 50 sample events
        event = {
            'timestamp': datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'event_type': random.choice(event_types),
            'severity': random.choice(severities),
            'source_ip': f"192.168.{random.randint(1,254)}.{random.randint(1,254)}",
            'destination_ip': f"10.0.{random.randint(1,254)}.{random.randint(1,254)}",
            'description': f"Automated detection of suspicious activity",
            'status': random.choice(['Open', 'Investigating', 'Resolved'])
        }
        
        cursor.execute('''
        INSERT INTO security_events 
        (timestamp, event_type, severity, source_ip, destination_ip, description, status)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (event['timestamp'], event['event_type'], event['severity'], 
              event['source_ip'], event['destination_ip'], event['description'], event['status']))
    
    conn.commit()
    conn.close()

@app.route('/')
def dashboard():
    return render_template('dashboard.html')

@app.route('/api/events')
def get_events():
    conn = sqlite3.connect('security_events.db')
    cursor = conn.cursor()
    
    cursor.execute('''
    SELECT * FROM security_events 
    ORDER BY timestamp DESC 
    LIMIT 100
    ''')
    
    events = []
    for row in cursor.fetchall():
        events.append({
            'id': row[0],
            'timestamp': row[1],
            'event_type': row[2],
            'severity': row[3],
            'source_ip': row[4],
            'destination_ip': row[5],
            'description': row[6],
            'status': row[7]
        })
    
    conn.close()
    return jsonify(events)

@app.route('/api/stats')
def get_stats():
    conn = sqlite3.connect('security_events.db')
    cursor = conn.cursor()
    
    # Get event counts by severity
    cursor.execute('''
    SELECT severity, COUNT(*) 
    FROM security_events 
    WHERE date(timestamp) = date('now')
    GROUP BY severity
    ''')
    severity_stats = dict(cursor.fetchall())
    
    # Get event counts by type
    cursor.execute('''
    SELECT event_type, COUNT(*) 
    FROM security_events 
    WHERE date(timestamp) = date('now')
    GROUP BY event_type
    ORDER BY COUNT(*) DESC
    LIMIT 10
    ''')
    type_stats = dict(cursor.fetchall())
    
    # Get hourly event counts for the last 24 hours
    cursor.execute('''
    SELECT strftime('%H', timestamp) as hour, COUNT(*) 
    FROM security_events 
    WHERE datetime(timestamp) >= datetime('now', '-24 hours')
    GROUP BY hour
    ORDER BY hour
    ''')
    hourly_stats = dict(cursor.fetchall())
    
    conn.close()
    
    return jsonify({
        'severity': severity_stats,
        'event_types': type_stats,
        'hourly': hourly_stats
    })

@app.route('/api/alerts')
def get_alerts():
    # Check for alerts based on thresholds
    conn = sqlite3.connect('security_events.db')
    cursor = conn.cursor()
    
    alerts = []
    
    # Check failed login attempts
    cursor.execute('''
    SELECT COUNT(*) FROM security_events 
    WHERE event_type = 'Failed Login Attempt' 
    AND datetime(timestamp) >= datetime('now', '-5 minutes')
    ''')
    failed_logins = cursor.fetchone()[0]
    
    if failed_logins >= 5:
        alerts.append({
            'type': 'High Failed Login Activity',
            'count': failed_logins,
            'severity': 'High',
            'message': f'{failed_logins} failed login attempts in the last 5 minutes'
        })
    
    # Check port scans
    cursor.execute('''
    SELECT COUNT(*) FROM security_events 
    WHERE event_type = 'Port Scan Detected' 
    AND datetime(timestamp) >= datetime('now', '-1 minutes')
    ''')
    port_scans = cursor.fetchone()[0]
    
    if port_scans >= 3:
        alerts.append({
            'type': 'Port Scan Activity',
            'count': port_scans,
            'severity': 'Medium',
            'message': f'{port_scans} port scans detected in the last minute'
        })
    
    conn.close()
    return jsonify(alerts)

@app.route('/api/event/update', methods=['POST'])
def update_event():
    data = request.json
    event_id = data.get('id')
    new_status = data.get('status')
    
    conn = sqlite3.connect('security_events.db')
    cursor = conn.cursor()
    
    cursor.execute('''
    UPDATE security_events 
    SET status = ? 
    WHERE id = ?
    ''', (new_status, event_id))
    
    conn.commit()
    conn.close()
    
    return jsonify({'success': True})

# Background thread to simulate real-time events
def simulate_events():
    while True:
        time.sleep(random.randint(10, 30))  # Generate event every 10-30 seconds
        
        event_types = [
            'Failed Login Attempt',
            'Port Scan Detected',
            'Network Anomaly',
            'Suspicious File Access'
        ]
        
        severities = ['Low', 'Medium', 'High']
        
        conn = sqlite3.connect('security_events.db')
        cursor = conn.cursor()
        
        event = {
            'timestamp': datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'event_type': random.choice(event_types),
            'severity': random.choice(severities),
            'source_ip': f"192.168.{random.randint(1,254)}.{random.randint(1,254)}",
            'destination_ip': f"10.0.{random.randint(1,254)}.{random.randint(1,254)}",
            'description': f"Real-time detection of {random.choice(event_types).lower()}",
            'status': 'Open'
        }
        
        cursor.execute('''
        INSERT INTO security_events 
        (timestamp, event_type, severity, source_ip, destination_ip, description, status)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (event['timestamp'], event['event_type'], event['severity'], 
              event['source_ip'], event['destination_ip'], event['description'], event['status']))
        
        conn.commit()
        conn.close()

if __name__ == '__main__':
    init_db()
    generate_sample_events()
    
    # Start background event simulation
    event_thread = threading.Thread(target=simulate_events, daemon=True)
    event_thread.start()
    
    app.run(debug=True, host='0.0.0.0', port=5000)
