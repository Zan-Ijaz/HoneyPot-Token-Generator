from flask import Flask, request, jsonify, render_template, redirect, url_for, session
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
import secrets
import requests
import os
import json
import pytz
from functools import wraps

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)  
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///alerts.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

ADMIN_USERNAME = "admin"
ADMIN_PASSWORD = "admin123"  

PKT = pytz.timezone('Asia/Karachi')
def get_current_time_pkt():
    """Return current datetime in Pakistan Standard Time"""
    return datetime.now(PKT)

class Alert(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    token_id = db.Column(db.String(50), nullable=False)
    api_key_used = db.Column(db.String(100), nullable=False)
    endpoint = db.Column(db.String(200))
    ip_address = db.Column(db.String(50))
    user_agent = db.Column(db.String(500))
    geo_location = db.Column(db.String(200))
    timestamp = db.Column(db.DateTime, default=get_current_time_pkt)

class ValidToken(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    token_id = db.Column(db.String(50), unique=True)
    api_key = db.Column(db.String(100), unique=True)
    service_name = db.Column(db.String(100))
    created_at = db.Column(db.DateTime, default=get_current_time_pkt)
    status = db.Column(db.String(20), default='active')

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('logged_in'):
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        if request.form['username'] == ADMIN_USERNAME and request.form['password'] == ADMIN_PASSWORD:
            session['logged_in'] = True
            return redirect(url_for('dashboard'))
        else:
            return render_template('login.html', error="Invalid credentials")
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('logged_in', None)
    return redirect(url_for('login'))

def generate_fake_env():
    """Creates a fake .env file containing decoy API keys"""
    
    ValidToken.query.delete()
    db.session.commit()
    
    tokens = [
        {
            'id': 'STRIPE_001',
            'key': 'sk_live_' + secrets.token_urlsafe(24),
            'service': 'Stripe Payment API'
        },
        {
            'id': 'AWS_001', 
            'key': 'AKIA' + secrets.token_urlsafe(16).upper(),
            'service': 'AWS S3 Production'
        },
        {
            'id': 'GITHUB_001',
            'key': 'ghp_' + secrets.token_urlsafe(32),
            'service': 'GitHub Private Repos'
        },
        {
            'id': 'DB_001',
            'key': 'mongodb+srv://' + secrets.token_urlsafe(10) + ':' + secrets.token_urlsafe(16) + '@cluster0.mongodb.net',
            'service': 'Production Database'
        },
        {
            'id': 'JWT_001',
            'key': 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.' + secrets.token_urlsafe(32) + '.' + secrets.token_urlsafe(43),
            'service': 'Admin JWT Secret'
        }
    ]
    
    env_content = "# WARNING: DO NOT COMMIT THIS FILE TO VERSION CONTROL\n"
    env_content += "# Production API Keys - Keep Secure!\n\n"
    
    for token in tokens:
        env_content += f"{token['id']}={token['key']}\n"
        valid = ValidToken(
            token_id=token['id'],
            api_key=token['key'],
            service_name=token['service']
        )
        db.session.add(valid)
    
    db.session.commit()
    
    # Write to .env file
    with open('.env', 'w') as f:
        f.write(env_content)
    
    return tokens

def get_geo_location(ip):
    """Get geolocation from IP address"""
    try:
        if ip in ['127.0.0.1', 'localhost', '::1']:
            return "Localhost (Demo)"
        
        # Private IP ranges
        if ip.startswith(('192.168.', '10.', '172.16.', '172.17.', '172.18.', '172.19.', 
                          '172.20.', '172.21.', '172.22.', '172.23.', '172.24.', '172.25.',
                          '172.26.', '172.27.', '172.28.', '172.29.', '172.30.', '172.31.')):
            return f"Private IP ({ip})"
        
        response = requests.get(f'http://ip-api.com/json/{ip}', timeout=3)
        if response.status_code == 200:
            data = response.json()
            if data.get('status') == 'success':
                return f"{data.get('city', 'Unknown')}, {data.get('country', 'Unknown')} (ISP: {data.get('isp', 'Unknown')})"
        
        return f"IP: {ip} (location unavailable)"
    except:
        return f"IP: {ip} (lookup error)"

@app.route('/')
def dummy_site():
    """The legitimate-looking website that gets hacked"""
    return render_template('dummy_site.html')

@app.route('/.env')
def serve_env():
    """Intentionally expose the fake .env file"""
    print(f" .env file accessed from {request.remote_addr}")
    with open('.env', 'r') as f:
        content = f.read()
    return content, 200, {'Content-Type': 'text/plain'}

@app.route('/env')
@app.route('/config.env')
@app.route('/.env.backup')
def serve_env_backup():
    print(f" Backup .env accessed from {request.remote_addr}")
    with open('.env', 'r') as f:
        content = f.read()
    return content, 200, {'Content-Type': 'text/plain'}

@app.route('/api/v1/payments', methods=['GET', 'POST'])
def stripe_api():
    api_key = request.headers.get('Authorization', '').replace('Bearer ', '')
    if not api_key:
        api_key = request.args.get('api_key', '')
    
    token = ValidToken.query.filter_by(api_key=api_key).first()
    
    if token:
        alert = Alert(
            token_id=token.token_id,
            api_key_used=api_key[:30] + "...",
            endpoint='/api/v1/payments',
            ip_address=request.remote_addr,
            user_agent=request.headers.get('User-Agent', 'Unknown'),
            geo_location=get_geo_location(request.remote_addr)
        )
        db.session.add(alert)
        db.session.commit()
        
        print(f"\n ALERT! Honey token triggered at {get_current_time_pkt().strftime('%Y-%m-%d %H:%M:%S PKT')}")
        print(f" Token: {token.token_id} ({token.service_name})")
        print(f" IP: {request.remote_addr}")
        print(f" Location: {alert.geo_location}\n")
        
        return jsonify({"error": "Invalid API key", "message": "Authentication failed"}), 401
    
    return jsonify({"error": "Unauthorized"}), 401

@app.route('/api/v1/aws/s3', methods=['GET'])
def aws_s3_api():
    api_key = request.headers.get('X-API-Key', '')
    if not api_key:
        api_key = request.args.get('key', '')
    
    token = ValidToken.query.filter_by(api_key=api_key).first()
    
    if token:
        alert = Alert(
            token_id=token.token_id,
            api_key_used=api_key[:30] + "...",
            endpoint='/api/v1/aws/s3',
            ip_address=request.remote_addr,
            user_agent=request.headers.get('User-Agent', 'Unknown'),
            geo_location=get_geo_location(request.remote_addr)
        )
        db.session.add(alert)
        db.session.commit()
        print(f"\n🚨 AWS HONEY TOKEN TRIGGERED from {request.remote_addr}")
        return jsonify({"error": "Invalid AWS credentials"}), 403
    
    return jsonify({"error": "Unauthorized"}), 401

@app.route('/api/v1/database/query', methods=['POST'])
def database_api():
    api_key = request.json.get('api_key', '') if request.is_json else ''
    
    token = ValidToken.query.filter_by(api_key=api_key).first()
    
    if token:
        alert = Alert(
            token_id=token.token_id,
            api_key_used=api_key[:30] + "...",
            endpoint='/api/v1/database/query',
            ip_address=request.remote_addr,
            user_agent=request.headers.get('User-Agent', 'Unknown'),
            geo_location=get_geo_location(request.remote_addr)
        )
        db.session.add(alert)
        db.session.commit()
        print(f"\n🚨 DATABASE HONEY TOKEN TRIGGERED from {request.remote_addr}")
        return jsonify({"error": "Access denied", "code": "DB_AUTH_FAILED"}), 403
    
    return jsonify({"error": "Authentication required"}), 401

# ========== ADMIN DASHBOARD (Protected) ==========
@app.route('/dashboard')
@login_required
def dashboard():
    alerts = Alert.query.order_by(Alert.timestamp.desc()).limit(50).all()
    stats = {
        'total_alerts': Alert.query.count(),
        'unique_attackers': db.session.query(Alert.ip_address).distinct().count(),
        'tokens_deployed': ValidToken.query.count(),
        'triggered_tokens': db.session.query(Alert.token_id).distinct().count()
    }
    return render_template('dashboard.html', alerts=alerts, stats=stats)

@app.route('/api/alerts')
@login_required
def get_alerts():
    alerts = Alert.query.order_by(Alert.timestamp.desc()).limit(100).all()
    return jsonify([{
        'id': a.id,
        'token_id': a.token_id,
        'endpoint': a.endpoint,
        'ip': a.ip_address,
        'location': a.geo_location,
        'time': a.timestamp.strftime('%Y-%m-%d %H:%M:%S PKT')
    } for a in alerts])

@app.route('/api/tokens')
@login_required
def get_tokens():
    tokens = ValidToken.query.all()
    return jsonify([{
        'id': t.token_id,
        'service': t.service_name,
        'status': t.status,
        'created': t.created_at.strftime('%Y-%m-%d %H:%M:%S PKT')
    } for t in tokens])

with app.app_context():
    db.create_all()
    FAKE_TOKENS = generate_fake_env()

if __name__ == '__main__':
    print("\n" + "="*60)
    print(" HONEY TOKEN HONEYPOT SYSTEM ")
    print("="*60)
    print(f"\n Dummy website: http://localhost:5000/")
    print(f" Attacker steals .env from: http://localhost:5000/.env")
    print(f"\n Fake API endpoints:")
    print("   POST /api/v1/payments")
    print("   GET  /api/v1/aws/s3")
    print("   POST /api/v1/database/query")
    print(f"\🔐 Admin Dashboard: http://localhost:5000/dashboard")
    print(f"   Username: {ADMIN_USERNAME} | Password: {ADMIN_PASSWORD}")
    print("\n  Any attempt to use stolen keys triggers alerts!")
    print("="*60 + "\n")
    
    app.run(debug=True, host='0.0.0.0', port=5000)