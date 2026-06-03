from flask import (
    Flask,
    request,
    jsonify,
    render_template,
    session,
    redirect,
    url_for,
    Response
)
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime, timedelta
import secrets
import requests
import os
import json
import csv
import io
import pytz
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from functools import wraps
from collections import Counter
# ---------- Config ----------
from config import ADMIN_USERNAME, ADMIN_PASSWORD, WEBHOOK_URL, SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASS, ALERT_EMAIL

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', secrets.token_hex(32))
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///alerts.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)


PKT = pytz.timezone('Asia/Karachi')

def now_pkt():
    return datetime.now(PKT)

# ---------- Heuristics / AI Attack Classification ----------
def classify_attacker(ip, user_agent, path):
    """
    AI-based heuristic classification model.
    Analyzes user agents, endpoint request sequences, and rates to profile attacker identity.
    """
    ua = user_agent.lower()
    
    # 1. Search Engine Crawlers
    bot_agents = ['googlebot', 'bingbot', 'yandexbot', 'duckduckbot', 'baiduspider', 'twitterbot']
    if any(bot in ua for bot in bot_agents):
        return 'Search Engine Bot', 'Benign automated crawler querying public assets.'
        
    # 2. Recognized Vulnerability & Port Scanners
    scanners = ['nmap', 'sqlmap', 'nikto', 'dirbuster', 'gobuster', 'w3af', 'metasploit', 
                'zgrab', 'masscan', 'censys', 'shodan', 'acunetix', 'nessus', 'arachni']
    if any(s in ua for s in scanners):
        return 'Automated Security Scanner', 'Security scanning utility targeting potential vulnerability entry points.'
        
    # 3. Direct HTTP Clients & Custom Exploits
    libs = ['python-requests', 'python', 'curl', 'wget', 'http-client', 'go-http-client', 'postman', 'urllib', 'aiohttp', 'axios']
    if any(l in ua for l in libs):
        # Look up count of separate tokens accessed by this IP
        prev_hits = db.session.query(Alert.token_id).filter(Alert.ip_address == ip).distinct().count()
        if prev_hits > 1:
            return 'Credential Stuffer', 'Exploit agent trying multiple compromised credentials across disparate endpoints.'
        return 'Scripted exploit / CLI tool', 'Automated curl or script request targeting API routes.'
        
    # 4. Standard Web Browsers
    browsers = ['mozilla', 'chrome', 'safari', 'firefox', 'edge', 'opera']
    if any(b in ua for b in browsers):
        if '/api/' in path or '/track/' in path:
            return 'Targeted Manual Adversary', 'Human actor exploring application APIs manually using a web browser.'
        return 'Browser Explorer', 'Interactive browser scanning exposed web directories.'
        
    return 'Unknown Threat Actor', 'Suspicious client requesting config payloads using custom agent details.'

# ---------- Risk scoring & Threat prediction ----------
def predict_threat_level(ip, token_id, endpoint):
    """
    Evaluates incident sequence history from this source to predict current breach likelihood.
    """
    prev_alerts = Alert.query.filter_by(ip_address=ip).all()
    count = len(prev_alerts)
    unique_tokens = len(set(a.token_id for a in prev_alerts))
    
    if count >= 4 or unique_tokens >= 3:
        return 'CRITICAL', 'Persistent malicious adversary. Active horizontal scan across internal assets detected.'
    elif count >= 2:
        return 'HIGH', 'Focused attack. Multi-step credential validation probes detected.'
    elif count >= 1:
        return 'MEDIUM', 'Suspicious activity. Stolen configuration key applied from external source.'
        
    if '/.env' in endpoint or 'config' in endpoint:
        return 'HIGH', 'Direct discovery attempt on configuration and environment backups.'
        
    return 'LOW', 'Isolated trigger event. Potential false trigger or standard crawler matching.'

RISK_COLOR = {
    'LOW':      '#3fa85f',
    'MEDIUM':   '#d4a030',
    'HIGH':     '#c23b22',
    'CRITICAL': '#ff5533',
}

# ---------- Models ----------
class Alert(db.Model):
    id               = db.Column(db.Integer, primary_key=True)
    token_id         = db.Column(db.String(50), nullable=False)
    api_key_used     = db.Column(db.String(200), nullable=False)
    endpoint         = db.Column(db.String(200))
    ip_address       = db.Column(db.String(50))
    user_agent       = db.Column(db.String(500))
    geo_location     = db.Column(db.String(200))
    risk_level       = db.Column(db.String(20), default='LOW')
    attacker_type    = db.Column(db.String(50), default='Unknown')
    predicted_threat = db.Column(db.String(200), default='')
    timestamp        = db.Column(db.DateTime, default=now_pkt)

class ValidToken(db.Model):
    id           = db.Column(db.Integer, primary_key=True)
    token_id     = db.Column(db.String(50), unique=True)
    api_key      = db.Column(db.String(300), unique=True)
    service_name = db.Column(db.String(100))
    token_type   = db.Column(db.String(30), default='api_key')
    created_at   = db.Column(db.DateTime, default=now_pkt)
    status       = db.Column(db.String(20), default='active')
    notes        = db.Column(db.String(300), default='')

class BlockedIP(db.Model):
    id         = db.Column(db.Integer, primary_key=True)
    ip_address = db.Column(db.String(50), unique=True, nullable=False)
    reason     = db.Column(db.String(200), default='Manual Administrative Block')
    blocked_at = db.Column(db.DateTime, default=now_pkt)

# ---------- Active Defense Block Filter ----------
@app.before_request
def check_ip_blocklist():
    # Never block dashboard access or static assets to avoid local admin lockout
    whitelisted = ['/dashboard', '/login', '/logout', '/static/']
    if any(request.path.startswith(w) for w in whitelisted):
        return
        
    blocked = BlockedIP.query.filter_by(ip_address=request.remote_addr).first()
    if blocked:
        # Return blocked JSON structure for APIs, or render blocked warning on dummy web app
        if request.path.startswith('/api/'):
            return jsonify({
                'error': 'AccessDenied',
                'message': 'This IP address has been blocklisted due to anomalous access attempts.',
                'incident_id': secrets.token_hex(8)
            }), 403
        return render_template('dummy_site.html', blocked=True, ip=request.remote_addr), 403

# ---------- Auth ----------
def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get('logged_in'):
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        u = request.form.get('username', '')
        p = request.form.get('password', '')
        if u == ADMIN_USERNAME and p == ADMIN_PASSWORD:
            session['logged_in'] = True
            return redirect(url_for('dashboard'))
        return render_template('login.html', error='Invalid credentials')
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('logged_in', None)
    return redirect(url_for('login'))

# ---------- Token generation helpers ----------
TOKEN_GENERATORS = {
    'stripe':  lambda: ('sk_live_' + secrets.token_urlsafe(24),  'Stripe Payment API'),
    'aws':     lambda: ('AKIA' + secrets.token_urlsafe(16).upper()[:16], 'AWS S3 Production'),
    'github':  lambda: ('ghp_' + secrets.token_urlsafe(32),      'GitHub Private Repos'),
    'mongodb': lambda: (
        'mongodb+srv://' + secrets.token_urlsafe(8) + ':' + secrets.token_urlsafe(12) + '@cluster0.mongodb.net',
        'Production Database'
    ),
    'jwt':     lambda: (
        'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.' +
        secrets.token_urlsafe(32) + '.' + secrets.token_urlsafe(43),
        'Admin JWT Secret'
    ),
    'azure':   lambda: (
        secrets.token_hex(16) + '-' + secrets.token_hex(4) + '-' +
        secrets.token_hex(4) + '-' + secrets.token_hex(12),
        'Azure Subscription Key'
    ),
    'ssh':     lambda: (
        '-----BEGIN OPENSSH PRIVATE KEY-----\n' +
        secrets.token_urlsafe(64) + '\n-----END OPENSSH PRIVATE KEY-----',
        'SSH Private Key'
    ),
    'gcp':     lambda: ('AIza' + secrets.token_urlsafe(32)[:32], 'GCP Service Account Key'),
    'slack':   lambda: ('xoxb-' + secrets.token_urlsafe(12) + '-' + secrets.token_urlsafe(12), 'Slack Bot Token'),
    'generic': lambda: (secrets.token_urlsafe(40), 'Generic Secret Token'),
}

def generate_default_tokens():
    """Seed the DB with default tokens and write the fake .env"""
    ValidToken.query.delete()
    db.session.commit()

    defaults = [
        ('STRIPE_001', 'stripe'),
        ('AWS_001',    'aws'),
        ('GITHUB_001', 'github'),
        ('DB_001',     'mongodb'),
        ('JWT_001',    'jwt'),
        ('ENV_TRAP_001', 'generic'),
    ]

    tokens = []
    env_lines = ['# WARNING: DO NOT COMMIT THIS FILE TO VERSION CONTROL\n',
                 '# Production API Keys - Keep Secure!\n\n']

    for tid, ttype in defaults:
        key, svc = TOKEN_GENERATORS[ttype]()
        if tid == 'ENV_TRAP_001':
            svc = 'Decoy Config (.env)'
        vt = ValidToken(token_id=tid, api_key=key, service_name=svc, token_type=ttype)
        db.session.add(vt)
        env_lines.append(f'{tid}={key}\n')
        tokens.append({'id': tid, 'key': key, 'service': svc})

    db.session.commit()
    with open('.env', 'w', encoding='utf-8') as f:
        f.writelines(env_lines)
    return tokens

# ---------- Geo lookup ----------
def get_geo_location(ip):
    try:
        if ip in ('127.0.0.1', 'localhost', '::1'):
            return 'Localhost (Demo)'
        private_prefixes = ('192.168.', '10.', '172.16.', '172.17.', '172.18.',
                            '172.19.', '172.20.', '172.21.', '172.22.', '172.23.',
                            '172.24.', '172.25.', '172.26.', '172.27.', '172.28.',
                            '172.29.', '172.30.', '172.31.')
        if ip.startswith(private_prefixes):
            return f'Private IP ({ip})'
        r = requests.get(f'http://ip-api.com/json/{ip}', timeout=3)
        if r.status_code == 200:
            d = r.json()
            if d.get('status') == 'success':
                return (f"{d.get('city','?')}, {d.get('country','?')} "
                        f"(ISP: {d.get('isp','?')})")
        return f'IP: {ip} (location unavailable)'
    except Exception:
        return f'IP: {ip} (lookup error)'

# ---------- Alert notification ----------
def send_webhook_alert(alert, token):
    if not WEBHOOK_URL:
        return
    try:
        payload = {
            "text": (
                f":rotating_light: *HoneyToken Triggered!*\n"
                f"Token: `{token.token_id}` ({token.service_name})\n"
                f"IP: `{alert.ip_address}` — {alert.geo_location}\n"
                f"Endpoint: `{alert.endpoint}`\n"
                f"Attacker Profile: *{alert.attacker_type}*\n"
                f"Risk: *{alert.risk_level}*\n"
                f"Time: {alert.timestamp.strftime('%Y-%m-%d %H:%M:%S PKT')}"
            )
        }
        requests.post(WEBHOOK_URL, json=payload, timeout=3)
    except Exception:
        pass

def send_email_alert(alert, token, attacker_type, explanation):
    if not SMTP_HOST or not ALERT_EMAIL:
        return
    try:
        msg = MIMEMultipart('alternative')
        msg['Subject'] = f"🚨 HONEYTOKEN ALERT: Compromise Detected [{alert.risk_level}]"
        msg['From'] = SMTP_USER or 'honeytoken@alerts.io'
        msg['To'] = 'saadsadi083@gmail.com'
        
        html = f"""
        <html>
        <body style="font-family: sans-serif; background-color: #f6f6f9; padding: 24px; color: #1a1a24;">
            <div style="max-width: 600px; margin: 0 auto; background: white; border: 1px solid #e2e2ec; border-radius: 12px; overflow: hidden; box-shadow: 0 4px 20px rgba(0,0,0,0.06);">
                <div style="background: #c23b22; color: white; padding: 24px; text-align: center;">
                    <h2 style="margin: 0; font-size: 20px; font-weight: 800; letter-spacing: 0.05em;">HONEYTOKEN COMPROMISED</h2>
                    <p style="margin: 6px 0 0; opacity: 0.85; font-size: 13px;">Risk Threshold: {alert.risk_level}</p>
                </div>
                <div style="padding: 24px; font-size: 14px; line-height: 1.6;">
                    <p>The system has logged an access attempt on a decoy asset.</p>
                    <table style="width: 100%; border-collapse: collapse; margin: 20px 0;">
                        <tr style="border-bottom: 1px solid #f0f0f5;"><td style="padding: 8px 0; font-weight: bold; width: 140px; color:#5a5a72;">Token ID:</td><td style="padding: 8px 0;">{token.token_id}</td></tr>
                        <tr style="border-bottom: 1px solid #f0f0f5;"><td style="padding: 8px 0; font-weight: bold; color:#5a5a72;">Decoy Asset:</td><td style="padding: 8px 0;">{token.service_name}</td></tr>
                        <tr style="border-bottom: 1px solid #f0f0f5;"><td style="padding: 8px 0; font-weight: bold; color:#5a5a72;">Trigger Path:</td><td style="padding: 8px 0; font-family: monospace;">{alert.endpoint}</td></tr>
                        <tr style="border-bottom: 1px solid #f0f0f5;"><td style="padding: 8px 0; font-weight: bold; color:#5a5a72;">IP Address:</td><td style="padding: 8px 0; font-family: monospace;">{alert.ip_address}</td></tr>
                        <tr style="border-bottom: 1px solid #f0f0f5;"><td style="padding: 8px 0; font-weight: bold; color:#5a5a72;">Location:</td><td style="padding: 8px 0;">{alert.geo_location}</td></tr>
                        <tr style="border-bottom: 1px solid #f0f0f5;"><td style="padding: 8px 0; font-weight: bold; color:#5a5a72;">AI Profile:</td><td style="padding: 8px 0; color:#c23b22; font-weight:bold;">{attacker_type}</td></tr>
                        <tr style="border-bottom: 1px solid #f0f0f5;"><td style="padding: 8px 0; font-weight: bold; color:#5a5a72;">AI Prediction:</td><td style="padding: 8px 0;">{explanation}</td></tr>
                        <tr style="border-bottom: 1px solid #f0f0f5;"><td style="padding: 8px 0; font-weight: bold; color:#5a5a72;">Timestamp:</td><td style="padding: 8px 0;">{alert.timestamp.strftime('%Y-%m-%d %H:%M:%S PKT')}</td></tr>
                    </table>
                    <div style="background: #fff8f7; border-left: 4px solid #c23b22; padding: 14px; margin: 20px 0; font-size: 13px; color: #7a2218;">
                        <strong>Defensive Action:</strong> { 'IP address blocklisted automatically.' if alert.risk_level == 'CRITICAL' else 'Request pattern logged. Defensive escalation active.' }
                    </div>
                </div>
                <div style="background: #f0f0f5; color: #8a8a9e; font-size: 11px; padding: 14px; text-align: center; border-top: 1px solid #e2e2ec;">
                    This is an automated alert generated by Honey Token System.
                </div>
            </div>
        </body>
        </html>
        """
        msg.attach(MIMEText(html, 'html'))
        
        server = smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=5)
        if SMTP_USER and SMTP_PASS:
            server.starttls()
            server.login(SMTP_USER, SMTP_PASS)
        server.sendmail(msg['From'], msg['To'], msg.as_string())
        server.quit()
        print(f"[EMAIL] Alert email sent to {ALERT_EMAIL}")
    except Exception as e:
        print(f"[ERROR] Failed to send email alert: {e}")

# ---------- SIEM Logger ----------
def write_siem_log(alert, token, attacker_type, explanation):
    log_dir = os.path.join(app.root_path, 'instance')
    os.makedirs(log_dir, exist_ok=True)
    log_file = os.path.join(log_dir, 'siem.log')
    
    timestamp_iso = alert.timestamp.isoformat()
    sev_map = {'LOW': 3, 'MEDIUM': 5, 'HIGH': 8, 'CRITICAL': 10}
    severity = sev_map.get(alert.risk_level, 1)
    
    # Common Event Format (CEF)
    cef_msg = (
        f"CEF:0|HoneyTokenSys|API_Generator|2.0|{token.token_type.upper()}_TRIGGERED|Honeytoken Trigger Event|{severity}|"
        f"src={alert.ip_address} request={alert.endpoint} msg=Honeytoken compromised: {token.service_name} "
        f"cs1Label=AttackerProfile cs1={attacker_type} cs2Label=AIExplanation cs2={explanation} "
        f"cn1Label=RiskLevel cn1={alert.risk_level} deviceCustomDate1={timestamp_iso}"
    )
    
    # JSON Structured Format
    json_msg = {
        'event': 'honeytoken_trigger',
        'timestamp': timestamp_iso,
        'token_id': token.token_id,
        'token_type': token.token_type,
        'service': token.service_name,
        'endpoint': alert.endpoint,
        'src_ip': alert.ip_address,
        'location': alert.geo_location,
        'user_agent': alert.user_agent,
        'risk_level': alert.risk_level,
        'profile': attacker_type,
        'prediction': explanation
    }
    
    try:
        with open(log_file, 'a', encoding='utf-8') as f:
            f.write(cef_msg + '\n')
            f.write(json.dumps(json_msg) + '\n')
    except Exception as e:
        print(f"[ERROR] Failed to write SIEM logs: {e}")

# ---------- Generic trigger handler ----------
def record_trigger(token, endpoint):
    ip = request.remote_addr
    ua = request.headers.get('User-Agent', 'Unknown')
    
    # 1. Run AI heuristic analysis and risk prediction
    attacker_type, details = classify_attacker(ip, ua, endpoint)
    risk, explanation = predict_threat_level(ip, token.token_id, endpoint)
    
    alert = Alert(
        token_id         = token.token_id,
        api_key_used     = token.api_key[:40] + '...',
        endpoint         = endpoint,
        ip_address       = ip,
        user_agent       = ua,
        geo_location     = get_geo_location(ip),
        risk_level       = risk,
        attacker_type    = attacker_type,
        predicted_threat = explanation
    )
    db.session.add(alert)
    db.session.commit()
    print(f'\n[ALERT] [{risk}] | Profile: {attacker_type} | Token: {token.token_id} | IP: {ip} | {endpoint}')
    
    # 2. Trigger Active Defense automatic IP blacklisting
    if risk == 'CRITICAL':
        existing = BlockedIP.query.filter_by(ip_address=ip).first()
        if not existing:
            block = BlockedIP(
                ip_address=ip,
                reason=f"Auto-blocked: Triggered critical threshold ({attacker_type} at {endpoint})"
            )
            db.session.add(block)
            db.session.commit()
            print(f"[BLOCKED] ACTIVE DEFENSE: IP {ip} blacklisted.")
            
    # 3. Notification dispatch
    send_webhook_alert(alert, token)
    send_email_alert(alert, token, attacker_type, explanation)
    write_siem_log(alert, token, attacker_type, explanation)
    
    return alert

# ---------- Honeytoken trap endpoints ----------
@app.route('/.env')
@app.route('/env')
@app.route('/config.env')
@app.route('/.env.backup')
@app.route('/.env.local')
def serve_env():
    token = ValidToken.query.filter_by(token_id='ENV_TRAP_001', status='active').first()
    if token:
        record_trigger(token, request.path)
    else:
        print(f'[WARNING] .env file accessed from {request.remote_addr}')
        
    try:
        with open('.env', 'r', encoding='utf-8') as f:
            content = f.read()
    except Exception:
        content = "# Decoy API Configurations\nSTAG_SECRET=key_abc123"
    return content, 200, {'Content-Type': 'text/plain'}

@app.route('/api/v1/payments', methods=['GET', 'POST'])
def stripe_api():
    key = (request.headers.get('Authorization', '').replace('Bearer ', '')
           or request.args.get('api_key', '')
           or (request.json or {}).get('api_key', ''))
    token = ValidToken.query.filter_by(api_key=key, status='active').first()
    if token:
        record_trigger(token, '/api/v1/payments')
        return jsonify({'error': 'Invalid API key', 'message': 'Authentication failed'}), 401
    return jsonify({'error': 'Unauthorized'}), 401

@app.route('/api/v1/aws/s3', methods=['GET', 'POST'])
def aws_s3_api():
    key = (request.headers.get('X-API-Key', '')
           or request.args.get('key', '')
           or (request.json or {}).get('key', ''))
    token = ValidToken.query.filter_by(api_key=key, status='active').first()
    if token:
        record_trigger(token, '/api/v1/aws/s3')
        return jsonify({'error': 'InvalidClientTokenId', 'message': 'The security token is invalid'}), 403
    return jsonify({'error': 'Unauthorized'}), 401

@app.route('/api/v1/database/query', methods=['POST'])
def database_api():
    key = (request.json or {}).get('api_key', '') if request.is_json else ''
    token = ValidToken.query.filter_by(api_key=key, status='active').first()
    if token:
        record_trigger(token, '/api/v1/database/query')
        return jsonify({'error': 'Access denied', 'code': 'DB_AUTH_FAILED'}), 403
    return jsonify({'error': 'Authentication required'}), 401

@app.route('/api/v1/github/repos', methods=['GET'])
def github_api():
    key = (request.headers.get('Authorization', '').replace('token ', '').replace('Bearer ', '')
           or request.args.get('token', ''))
    token = ValidToken.query.filter_by(api_key=key, status='active').first()
    if token:
        record_trigger(token, '/api/v1/github/repos')
        return jsonify({'message': 'Bad credentials', 'documentation_url': 'https://docs.github.com/rest'}), 401
    return jsonify({'error': 'Unauthorized'}), 401

@app.route('/api/v1/azure/resources', methods=['GET'])
def azure_api():
    key = (request.headers.get('Ocp-Apim-Subscription-Key', '')
           or request.headers.get('X-API-Key', '')
           or request.args.get('subscription-key', ''))
    token = ValidToken.query.filter_by(api_key=key, status='active').first()
    if token:
        record_trigger(token, '/api/v1/azure/resources')
        return jsonify({'error': {'code': 'AuthorizationFailed', 'message': 'The client does not have authorization to perform action'}}), 403
    return jsonify({'error': 'Unauthorized'}), 401

@app.route('/api/v1/slack/post', methods=['POST'])
def slack_api():
    key = (request.headers.get('Authorization', '').replace('Bearer ', '')
           or (request.json or {}).get('token', ''))
    token = ValidToken.query.filter_by(api_key=key, status='active').first()
    if token:
        record_trigger(token, '/api/v1/slack/post')
        return jsonify({'ok': False, 'error': 'invalid_auth'}), 401
    return jsonify({'ok': False, 'error': 'not_authed'}), 401

@app.route('/api/v1/auth/verify', methods=['GET', 'POST'])
def jwt_verify_api():
    auth_header = request.headers.get('Authorization', '')
    token_str = ''
    if auth_header.startswith('Bearer '):
        token_str = auth_header.split(' ')[1]
    else:
        token_str = request.args.get('token', '') or (request.json or {}).get('token', '')
        
    token = ValidToken.query.filter_by(api_key=token_str, status='active').first()
    if token:
        record_trigger(token, '/api/v1/auth/verify (JWT)')
        return jsonify({'status': 'error', 'message': 'Signature verification failed'}), 401
    return jsonify({'status': 'error', 'message': 'Invalid token'}), 401

# ---------- Document web bug tracking ----------
@app.route('/track/doc/<tid>')
def track_doc(tid):
    token = ValidToken.query.filter_by(token_id=tid, status='active').first()
    if token:
        record_trigger(token, f'/track/doc/{tid} (Document web bug access)')
    pixel = b'\x47\x49\x46\x38\x39\x61\x01\x00\x01\x00\x80\x00\x00\xff\xff\xff\x00\x00\x00\x21\xf9\x04\x01\x00\x00\x00\x00\x2c\x00\x00\x00\x00\x01\x00\x01\x00\x00\x02\x02\x4c\x01\x00\x3b'
    return Response(pixel, mimetype='image/gif')

# ---------- Trap links ----------
@app.route('/secure/backups/credentials.json')
@app.route('/api/v1/storage/backup-secrets')
def trap_files():
    token = ValidToken.query.filter_by(token_id='ENV_TRAP_001', status='active').first()
    if token:
        record_trigger(token, f'{request.path} (Trap URL accessed)')
    return jsonify({
        'error': 'AccessDenied',
        'code': 'UNAUTHORIZED_STORAGE_REQUEST',
        'details': 'Direct access to backup files is restricted.'
    }), 403

# ---------- Payload Download Handlers ----------
@app.route('/api/tokens/<tid>/download/env')
@login_required
def download_env(tid):
    token = ValidToken.query.filter_by(token_id=tid).first_or_404()
    content = (
        f"# WARNING: DO NOT COMMIT THIS FILE TO VERSION CONTROL\n"
        f"# Decoy local configurations generated on {now_pkt().strftime('%Y-%m-%d')}\n\n"
        f"API_SECRET_KEY={token.api_key}\n"
        f"STAGING_DB_PASSWORD=stag_admin_2026\n"
    )
    return Response(
        content,
        mimetype='text/plain',
        headers={'Content-Disposition': f'attachment; filename=.env'}
    )

@app.route('/api/tokens/<tid>/download/aws')
@login_required
def download_aws(tid):
    token = ValidToken.query.filter_by(token_id=tid).first_or_404()
    content = (
        f"[default]\n"
        f"aws_access_key_id={token.api_key}\n"
        f"aws_secret_access_key={secrets.token_urlsafe(40)}\n"
        f"region=us-east-1\n"
    )
    return Response(
        content,
        mimetype='text/plain',
        headers={'Content-Disposition': f'attachment; filename=credentials'}
    )

@app.route('/api/tokens/<tid>/download/readme')
@login_required
def download_readme(tid):
    token = ValidToken.query.filter_by(token_id=tid).first_or_404()
    content = (
        f"# Internal Developer Guidelines\n\n"
        f"## Local Dev Configuration\n"
        f"To pull private repositories for testing, configure your client using the temporary token:\n\n"
        f"```bash\n"
        f"git config --global url.\"https://{token.api_key}@github.com/\".insteadOf \"https://github.com/\"\n"
        f"```\n\n"
        f"Ensure this credential is not shared outside the dev team.\n"
    )
    return Response(
        content,
        mimetype='text/markdown',
        headers={'Content-Disposition': f'attachment; filename=README.md'}
    )

@app.route('/api/tokens/<tid>/download/doc')
@login_required
def download_doc(tid):
    token = ValidToken.query.filter_by(token_id=tid).first_or_404()
    host_url = request.host_url.rstrip('/')
    tracking_url = f"{host_url}/track/doc/{token.token_id}"
    content = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>CONFIDENTIAL - Q3 Staff Payroll & Salary Adjustments</title>
    <style>
        body {{ font-family: 'Segoe UI', Arial, sans-serif; background: #fafafa; padding: 40px; color: #222; }}
        .doc-container {{ max-width: 800px; margin: 0 auto; background: #fff; border: 1px solid #ddd; padding: 40px; box-shadow: 0 4px 10px rgba(0,0,0,0.05); }}
        .header {{ border-bottom: 2px solid #c23b22; padding-bottom: 15px; margin-bottom: 25px; }}
        .header h1 {{ margin: 0; color: #c23b22; font-size: 24px; text-transform: uppercase; letter-spacing: 1px; }}
        .warning {{ background: #fff5f5; border-left: 4px solid #c23b22; padding: 15px; color: #a61c00; font-size: 13px; font-weight: bold; margin-bottom: 25px; }}
        table {{ width: 100%; border-collapse: collapse; margin-top: 15px; }}
        th, td {{ border: 1px solid #ddd; padding: 10px; text-align: left; font-size: 13px; }}
        th {{ background: #f5f5f5; font-weight: bold; }}
    </style>
</head>
<body>
    <div class="doc-container">
        <div class="header">
            <h1>Strictly Confidential</h1>
            <p style="color:#777; margin:5px 0 0 0; font-size:12px;">Document ID: SEC-PAY-2026-V1 · Class: INTERNAL ONLY</p>
        </div>
        <div class="warning">
            WARNING: Unauthorized copying, distribution, or scanning of this document violates policy SEC-09. All access is logged.
        </div>
        <p>The following sheet contains approved salary changes for Q3. Adjustments take effect on July 1st.</p>
        <table>
            <thead>
                <tr>
                    <th>Department</th>
                    <th>Role</th>
                    <th>Average Adjustment</th>
                    <th>Approval Status</th>
                </tr>
            </thead>
            <tbody>
                <tr>
                    <td>Engineering</td>
                    <td>Principal Architect</td>
                    <td>+4.5%</td>
                    <td>Approved</td>
                </tr>
                <tr>
                    <td>Security Operations</td>
                    <td>Lead Threat Hunter</td>
                    <td>+6.2%</td>
                    <td>Approved</td>
                </tr>
                <tr>
                    <td>Product Management</td>
                    <td>VP of Product</td>
                    <td>+3.8%</td>
                    <td>Pending</td>
                </tr>
                <tr>
                    <td>Sales & Marketing</td>
                    <td>Account Director</td>
                    <td>+5.1%</td>
                    <td>Approved</td>
                </tr>
            </tbody>
        </table>
    </div>
    <img src="{tracking_url}" width="1" height="1" style="display:none;" alt="" />
</body>
</html>
"""
    return Response(
        content,
        mimetype='text/html',
        headers={'Content-Disposition': f'attachment; filename=Confidential_Payroll_Q3.html'}
    )

# ---------- Public dummy site ----------
@app.route('/')
def dummy_site():
    return render_template('dummy_site.html')

# ---------- Dashboard & API ----------
@app.route('/dashboard')
@login_required
def dashboard():
    alerts = Alert.query.order_by(Alert.timestamp.desc()).limit(100).all()
    tokens = ValidToken.query.order_by(ValidToken.created_at.desc()).all()

    # Attack timeline (last 7 days)
    from_date = datetime.now(PKT) - timedelta(days=6)
    timeline = {}
    for i in range(7):
        d = (from_date + timedelta(days=i)).strftime('%b %d')
        timeline[d] = 0
    for a in Alert.query.filter(Alert.timestamp >= from_date).all():
        label = a.timestamp.strftime('%b %d')
        if label in timeline:
            timeline[label] += 1

    # Top attacker IPs
    ip_counts = Counter(a.ip_address for a in Alert.query.all())
    top_ips = ip_counts.most_common(5)

    # Risk breakdown
    risk_counts = {
        'LOW':      Alert.query.filter_by(risk_level='LOW').count(),
        'MEDIUM':   Alert.query.filter_by(risk_level='MEDIUM').count(),
        'HIGH':     Alert.query.filter_by(risk_level='HIGH').count(),
        'CRITICAL': Alert.query.filter_by(risk_level='CRITICAL').count(),
    }

    stats = {
        'total_alerts':      Alert.query.count(),
        'unique_attackers':  db.session.query(Alert.ip_address).distinct().count(),
        'tokens_deployed':   ValidToken.query.filter_by(status='active').count(),
        'triggered_tokens':  db.session.query(Alert.token_id).distinct().count(),
    }

    return render_template('dashboard.html',
        alerts=alerts, tokens=tokens, stats=stats,
        timeline=json.dumps(timeline),
        top_ips=top_ips,
        risk_counts=json.dumps(risk_counts),
        risk_color=RISK_COLOR,
        token_types=list(TOKEN_GENERATORS.keys()),
    )

@app.route('/api/alerts/export')
@login_required
def export_alerts():
    alerts = Alert.query.order_by(Alert.timestamp.desc()).all()
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(['ID', 'Token ID', 'Endpoint', 'IP Address', 'Geo Location',
                     'User Agent', 'Risk Level', 'Attacker Profile', 'Threat Prediction', 'Timestamp'])
    for a in alerts:
        writer.writerow([a.id, a.token_id, a.endpoint, a.ip_address,
                         a.geo_location, a.user_agent, a.risk_level,
                         a.attacker_type, a.predicted_threat,
                         a.timestamp.strftime('%Y-%m-%d %H:%M:%S')])
    output.seek(0)
    return Response(
        output.getvalue(),
        mimetype='text/csv',
        headers={'Content-Disposition': 'attachment; filename=honeytoken_alerts.csv'}
    )

@app.route('/api/alerts/clear', methods=['POST'])
@login_required
def clear_alerts():
    Alert.query.delete()
    db.session.commit()
    return jsonify({'status': 'ok', 'message': 'All alerts cleared'})

@app.route('/api/tokens/create', methods=['POST'])
@login_required
def create_token():
    data = request.json or {}
    ttype = data.get('type', 'generic')
    notes = data.get('notes', '')
    if ttype not in TOKEN_GENERATORS:
        return jsonify({'error': 'Unknown token type'}), 400
    key, svc = TOKEN_GENERATORS[ttype]()
    existing = ValidToken.query.count()
    tid = f'{ttype.upper()}_{existing + 1:03d}'
    vt = ValidToken(token_id=tid, api_key=key, service_name=svc,
                    token_type=ttype, notes=notes)
    db.session.add(vt)
    db.session.commit()
    return jsonify({'id': tid, 'service': svc, 'key': key, 'status': 'active'})

@app.route('/api/tokens/<tid>/toggle', methods=['POST'])
@login_required
def toggle_token(tid):
    token = ValidToken.query.filter_by(token_id=tid).first_or_404()
    token.status = 'disabled' if token.status == 'active' else 'active'
    db.session.commit()
    return jsonify({'id': tid, 'status': token.status})

@app.route('/api/tokens/<tid>/delete', methods=['DELETE'])
@login_required
def delete_token(tid):
    token = ValidToken.query.filter_by(token_id=tid).first_or_404()
    db.session.delete(token)
    db.session.commit()
    return jsonify({'status': 'deleted', 'id': tid})

@app.route('/api/tokens/regenerate', methods=['POST'])
@login_required
def regenerate_tokens():
    generate_default_tokens()
    return jsonify({'status': 'ok', 'message': 'Default tokens regenerated'})

@app.route('/api/alerts/json')
@login_required
def get_alerts_json():
    alerts = Alert.query.order_by(Alert.timestamp.desc()).limit(100).all()
    return jsonify([{
        'id':            a.id,
        'token_id':      a.token_id,
        'endpoint':      a.endpoint,
        'ip':            a.ip_address,
        'location':      a.geo_location,
        'risk':          a.risk_level,
        'attacker_type': a.attacker_type,
        'prediction':    a.predicted_threat,
        'time':          a.timestamp.strftime('%Y-%m-%d %H:%M:%S PKT'),
    } for a in alerts])

# ---------- Blocklist endpoints ----------
@app.route('/api/blocklist', methods=['GET'])
@login_required
def get_blocklist():
    blocked = BlockedIP.query.order_by(BlockedIP.blocked_at.desc()).all()
    return jsonify([{
        'id': b.id,
        'ip': b.ip_address,
        'reason': b.reason,
        'time': b.blocked_at.strftime('%Y-%m-%d %H:%M:%S PKT')
    } for b in blocked])

@app.route('/api/blocklist/add', methods=['POST'])
@login_required
def add_blocklist():
    data = request.json or {}
    ip = data.get('ip', '').strip()
    reason = data.get('reason', 'Manual administrative block').strip()
    if not ip:
        return jsonify({'error': 'IP address required'}), 400
    existing = BlockedIP.query.filter_by(ip_address=ip).first()
    if existing:
        return jsonify({'message': f'IP {ip} is already blocked'}), 200
        
    b = BlockedIP(ip_address=ip, reason=reason)
    db.session.add(b)
    db.session.commit()
    return jsonify({'status': 'ok', 'message': f'IP {ip} blocked successfully'})

@app.route('/api/blocklist/remove', methods=['POST'])
@login_required
def remove_blocklist():
    data = request.json or {}
    ip = data.get('ip', '').strip()
    if not ip:
        return jsonify({'error': 'IP address required'}), 400
    b = BlockedIP.query.filter_by(ip_address=ip).first()
    if b:
        db.session.delete(b)
        db.session.commit()
        return jsonify({'status': 'ok', 'message': f'IP {ip} unblocked successfully'})
    return jsonify({'error': f'IP {ip} not found in blocklist'}), 404

# ---------- SIEM export endpoint ----------
@app.route('/api/siem/logs', methods=['GET'])
@login_required
def download_siem_logs():
    log_file = os.path.join(app.root_path, 'instance', 'siem.log')
    if not os.path.exists(log_file):
        return Response("No SIEM events recorded yet.", mimetype='text/plain')
    try:
        with open(log_file, 'r', encoding='utf-8') as f:
            content = f.read()
    except Exception as e:
        content = f"Error reading logs: {e}"
    return Response(
        content,
        mimetype='text/plain',
        headers={'Content-Disposition': 'attachment; filename=siem.log'}
    )

# ---------- Schema verification and Bootstrap ----------
def check_db_schema():
    try:
        with app.app_context():
            from sqlalchemy import inspect
            inspector = inspect(db.engine)
            if 'alert' in inspector.get_table_names():
                columns = [col['name'] for col in inspector.get_columns('alert')]
                if 'attacker_type' not in columns or 'predicted_threat' not in columns:
                    print("Schema mismatch detected in 'alert' table. Recreating database...")
                    db.drop_all()
                    db.create_all()
                    generate_default_tokens()
                    return
            db.create_all()
    except Exception as e:
        print(f"Error checking database schema: {e}. Recreating...")
        try:
            db.drop_all()
            db.create_all()
            generate_default_tokens()
        except Exception:
            pass

with app.app_context():
    check_db_schema()
    if ValidToken.query.count() == 0:
        generate_default_tokens()
        
# TEMPORARY EMAIL TEST - delete after confirming it works
import smtplib
from email.mime.text import MIMEText
try:
    msg = MIMEText("Test email from HoneyToken!")
    msg['Subject'] = 'HoneyToken Test'
    msg['From'] = 'saadsadi0067@gmail.com'
    msg['To'] = 'saadsadi083@gmail.com'
    s = smtplib.SMTP('smtp.gmail.com', 587, timeout=5)
    s.starttls()
    s.login('saadsadi0067@gmail.com', 'oqcoikleiosattps')
    s.sendmail(msg['From'], msg['To'], msg.as_string())
    s.quit()
    print("✅ TEST EMAIL SENT SUCCESSFULLY!")
except Exception as e:
    print(f"❌ EMAIL FAILED: {e}")

if __name__ == '__main__':
    print('\n' + '='*60)
    print('  HONEY TOKEN SYSTEM - Enterprise Security Platform')
    print('='*60)
    print(f'\n  Dummy target site  : http://localhost:5000/')
    print(f'  Exposed .env trap  : http://localhost:5000/.env')
    print(f'\n  Honeytoken endpoints:')
    for ep in ['/api/v1/payments', '/api/v1/aws/s3', '/api/v1/database/query',
               '/api/v1/github/repos', '/api/v1/azure/resources', '/api/v1/slack/post',
               '/api/v1/auth/verify']:
        print(f'    {ep}')
    print(f'\n  Admin Dashboard    : http://localhost:5000/dashboard')
    print(f'  Login              : {ADMIN_USERNAME} / {ADMIN_PASSWORD}')
    print('\n  Set ADMIN_PASSWORD env var to override default password')
    print('='*60 + '\n')
    app.run(debug=True, host='0.0.0.0', port=5000)