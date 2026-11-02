"""Sentinel educational endpoint-monitoring backend. Run `python server.py --help`."""
import argparse
import base64
import hashlib
import hmac
import json
import math
import os
from pathlib import Path
import re
import secrets
import sqlite3
import struct
import threading
import time
from functools import wraps

from flask import Flask, abort, jsonify, request, render_template, g
from werkzeug.exceptions import HTTPException
import detection

BASE = Path(__file__).resolve().parent
DATA = Path(os.environ.get('SENTINEL_DATA', str(BASE / 'data')))
SCHEMA = '''
CREATE TABLE IF NOT EXISTS devices (
 id TEXT PRIMARY KEY, token_hash TEXT NOT NULL, created REAL NOT NULL,
 device_group TEXT NOT NULL DEFAULT 'default', agent_version TEXT NOT NULL DEFAULT '1.0.0',
 maintenance_window_until REAL NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS telemetry (
 id INTEGER PRIMARY KEY AUTOINCREMENT, device_id TEXT NOT NULL REFERENCES devices(id),
 sample_id TEXT NOT NULL, received REAL NOT NULL, observed REAL NOT NULL,
 payload TEXT NOT NULL, score REAL, anomaly INTEGER NOT NULL DEFAULT 0,
 UNIQUE(device_id, sample_id));
CREATE INDEX IF NOT EXISTS telemetry_device_time ON telemetry(device_id, received);
CREATE TABLE IF NOT EXISTS alerts (
 id INTEGER PRIMARY KEY AUTOINCREMENT, device_id TEXT NOT NULL REFERENCES devices(id),
 created REAL NOT NULL, kind TEXT NOT NULL, severity TEXT NOT NULL,
 message TEXT NOT NULL, acknowledged INTEGER NOT NULL DEFAULT 0,
 assigned_to TEXT, notes TEXT, incident_id TEXT);
CREATE INDEX IF NOT EXISTS alerts_device_kind ON alerts(device_id, kind, created);
CREATE INDEX IF NOT EXISTS alerts_incident ON alerts(incident_id);
CREATE TABLE IF NOT EXISTS models (
 device_id TEXT PRIMARY KEY REFERENCES devices(id), trained REAL NOT NULL,
 baseline TEXT NOT NULL, sample_count INTEGER NOT NULL,
 version INTEGER NOT NULL DEFAULT 1, metadata TEXT NOT NULL DEFAULT '{}',
 previous_baseline TEXT DEFAULT NULL);
CREATE TABLE IF NOT EXISTS commands (
 id INTEGER PRIMARY KEY AUTOINCREMENT, device_id TEXT NOT NULL REFERENCES devices(id),
 action TEXT NOT NULL, payload TEXT NOT NULL, created REAL NOT NULL,
 expires_at REAL NOT NULL, status TEXT NOT NULL DEFAULT 'queued',
 attempts INTEGER NOT NULL DEFAULT 0, result TEXT, updated_at REAL NOT NULL);
CREATE INDEX IF NOT EXISTS commands_device_status ON commands(device_id, status);
CREATE TABLE IF NOT EXISTS notification_queue (
 id INTEGER PRIMARY KEY AUTOINCREMENT, channel TEXT NOT NULL,
 device_id TEXT NOT NULL, severity TEXT NOT NULL, kind TEXT NOT NULL,
 message TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'pending',
 attempts INTEGER NOT NULL DEFAULT 0, next_retry REAL NOT NULL,
 last_error TEXT, created REAL NOT NULL, updated_at REAL NOT NULL);
CREATE INDEX IF NOT EXISTS notif_status_retry ON notification_queue(status, next_retry);
CREATE TABLE IF NOT EXISTS settings (
 key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS users (
 username TEXT PRIMARY KEY, password_hash TEXT NOT NULL, role TEXT NOT NULL DEFAULT 'viewer',
 totp_secret TEXT, mfa_enabled INTEGER NOT NULL DEFAULT 0, created REAL NOT NULL, updated_at REAL NOT NULL);
CREATE TABLE IF NOT EXISTS sessions (
 token_hash TEXT PRIMARY KEY, username TEXT NOT NULL REFERENCES users(username),
 role TEXT NOT NULL, created REAL NOT NULL, expires_at REAL NOT NULL, revoked INTEGER NOT NULL DEFAULT 0);
CREATE INDEX IF NOT EXISTS sessions_token ON sessions(token_hash);
CREATE TABLE IF NOT EXISTS audit_logs (
 id INTEGER PRIMARY KEY AUTOINCREMENT, actor TEXT NOT NULL, action TEXT NOT NULL,
 target TEXT, details TEXT, ip_address TEXT, timestamp REAL NOT NULL, outcome TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS audit_logs_time ON audit_logs(timestamp);
'''

PROTECTED_PROCESS_NAMES = {
    'system', 'idle', 'kernel_task', 'launchd', 'init', 'systemd',
    'explorer.exe', 'csrss.exe', 'smss.exe', 'wininit.exe', 'services.exe',
    'lsass.exe', 'svchost.exe', 'fontdrvhost.exe', 'winlogon.exe'
}


class AuthRateLimiter:
    """Sliding-window rate limiter for failed authentication attempts to protect against brute force."""
    def __init__(self, max_attempts=10, window_seconds=60):
        self.max_attempts = max_attempts
        self.window_seconds = window_seconds
        self.lock = threading.Lock()
        self.failures = {}

    def is_blocked(self, ip):
        with self.lock:
            now = time.time()
            ts = [t for t in self.failures.get(ip, []) if now - t < self.window_seconds]
            self.failures[ip] = ts
            return len(ts) >= self.max_attempts

    def record_failure(self, ip):
        with self.lock:
            now = time.time()
            ts = [t for t in self.failures.get(ip, []) if now - t < self.window_seconds]
            ts.append(now)
            self.failures[ip] = ts

    def record_success(self, ip):
        with self.lock:
            self.failures.pop(ip, None)


class HeartbeatMonitor:
    """Independent background worker for detecting heartbeat loss and offline endpoints."""
    def __init__(self, db_path, interval=15, offline_threshold=90):
        self.db_path = db_path
        self.interval = interval
        self.offline_threshold = offline_threshold
        self._stop_event = threading.Event()
        self._thread = None

    def start(self):
        if self._thread is None or not self._thread.is_alive():
            self._stop_event.clear()
            self._thread = threading.Thread(target=self._run, daemon=True, name="HeartbeatMonitor")
            self._thread.start()

    def stop(self, timeout=5):
        if self._thread and self._thread.is_alive():
            self._stop_event.set()
            self._thread.join(timeout=timeout)

    def check_devices(self, db, now):
        # Maintenance window check
        maint_row = db.execute("SELECT value FROM settings WHERE key='maintenance_window_until'").fetchone()
        if maint_row and maint_row['value']:
            try:
                if now < float(maint_row['value']):
                    return
            except ValueError:
                pass

        for device in db.execute('SELECT id FROM devices ORDER BY id'):
            device_id = device['id']
            dev_maint = db.execute("SELECT value FROM settings WHERE key=?", (f'maint_{device_id}',)).fetchone()
            if dev_maint and dev_maint['value']:
                try:
                    if now < float(dev_maint['value']):
                        continue
                except ValueError:
                    pass

            last_row = db.execute('SELECT received FROM telemetry WHERE device_id=? ORDER BY id DESC LIMIT 1', (device_id,)).fetchone()
            if not last_row:
                continue
            last_received = last_row['received']
            silence = now - last_received

            if silence >= self.offline_threshold and silence < 86400 * 30:
                # Deduplicate: check if an unacknowledged offline alert exists since last_received
                existing = db.execute(
                    "SELECT 1 FROM alerts WHERE device_id=? AND kind='device_offline' AND created >= ?",
                    (device_id, last_received)
                ).fetchone()
                if not existing:
                    elapsed = int(silence)
                    db.execute(
                        "INSERT INTO alerts(device_id,created,kind,severity,message) VALUES (?,?,?,?,?)",
                        (device_id, now, 'device_offline', 'medium',
                         f"Device '{device_id}' heartbeat lost ({elapsed}s silent). Endpoint is offline or unreachable.")
                    )
                    db.execute(
                        "INSERT INTO notification_queue(channel, device_id, severity, kind, message, status, attempts, next_retry, created, updated_at) "
                        "VALUES ('all', ?, 'medium', 'device_offline', ?, 'pending', 0, ?, ?, ?)",
                        (device_id, f"Device '{device_id}' heartbeat lost ({elapsed}s silent).", now, now, now)
                    )

    def _run(self):
        while not self._stop_event.is_set():
            try:
                now = time.time()
                with connect(self.db_path) as db:
                    self.check_devices(db, now)
            except Exception as exc:
                print(f"[HEARTBEAT MONITOR ERROR] {exc}", flush=True)
            self._stop_event.wait(self.interval)


THREAT_SIGNATURES = {
    'wireshark': ('T1040', 'Network Sniffing', 'high', 'Packet sniffing tool detected. Unauthorized traffic inspection risk.'),
    'tshark': ('T1040', 'Network Sniffing', 'high', 'Command-line packet capture tool detected.'),
    'tcpdump': ('T1040', 'Network Sniffing', 'high', 'Packet analysis utility detected.'),
    'nmap': ('T1046', 'Network Service Discovery', 'high', 'Port scanner detected. Reconnaissance activity suspected.'),
    'zenmap': ('T1046', 'Network Service Discovery', 'high', 'Port scanner GUI detected.'),
    'mimikatz': ('T1003', 'OS Credential Dumping', 'critical', 'Credential dumper detected. High severity credential theft risk.'),
    'xmrig': ('T1496', 'Resource Hijacking', 'critical', 'Cryptominer process detected. System computing resources hijacked.'),
    'minerd': ('T1496', 'Resource Hijacking', 'critical', 'Cryptominer process detected.'),
    'netcat': ('T1059', 'Command & Scripting Interpreter', 'high', 'Netcat utility detected. Potential reverse shell listener.'),
    'nc': ('T1059', 'Command & Scripting Interpreter', 'medium', 'Netcat utility active.'),
    'ncat': ('T1059', 'Command & Scripting Interpreter', 'high', 'Ncat network utility detected.'),
    'tor': ('T1090.003', 'Multi-hop Proxy (Tor)', 'high', 'Tor anonymity network client detected. Obfuscated traffic risk.'),
    'hydra': ('T1110', 'Brute Force', 'high', 'Network login brute-forcing tool detected (THC Hydra).'),
    'john': ('T1110.002', 'Password Cracking', 'high', 'Password cracker detected (John the Ripper).'),
    'hashcat': ('T1110.002', 'Password Cracking', 'high', 'GPU password cracker detected (hashcat).'),
    'powersploit': ('T1059.001', 'PowerShell Execution', 'critical', 'PowerSploit post-exploitation framework detected.')
}

RESTRICTED_KEYWORDS = (
    'porn', 'xxx', 'xvideos', 'pornhub', 'xnxx', 'redtube', 'youporn', 'brazzers',
    'torrent', 'piratebay', '1337x', 'rarbg', 'kickass',
    'gambling', 'bet365', '1xbet', 'stake.com', 'casino', 'poker',
    'darknet', 'silkroad'
)

DLP_EXFILTRATION_DOMAINS = (
    'mega.nz', 'wetransfer.com', 'mediafire.com', 'pastebin.com', 'anonfiles.com',
    'sendspace.com', 'filetransfer.io', 'gofile.io', 'catbox.moe', 'transfer.sh',
    'dropbox.com', '1fichier.com', 'rapidgator.net'
)


def check_process_threat(name):
    if not isinstance(name, str):
        return None
    base = os.path.basename(name).lower()
    if base.endswith('.exe'):
        base = base[:-4]
    return THREAT_SIGNATURES.get(base)


def dispatch_telegram(db_path, device, severity, kind, message, conn=None):
    """Synchronously dispatch alert to configured Telegram bot; returns error message or None."""
    try:
        if conn is not None:
            token_row = conn.execute("SELECT value FROM settings WHERE key='telegram_bot_token'").fetchone()
            chat_row = conn.execute("SELECT value FROM settings WHERE key='telegram_chat_id'").fetchone()
        else:
            with connect(db_path) as db:
                token_row = db.execute("SELECT value FROM settings WHERE key='telegram_bot_token'").fetchone()
                chat_row = db.execute("SELECT value FROM settings WHERE key='telegram_chat_id'").fetchone()

        if not token_row or not chat_row:
            return None  # Channel not configured
        bot_token = token_row['value'].strip()
        chat_id = chat_row['value'].strip()
        if not bot_token or not chat_id:
            return None

        text = (
            f"🚨 *SENTINEL SECURITY ALERT*\n\n"
            f"🖥️ *Endpoint:* `{device}`\n"
            f"⚠️ *Severity:* *{severity.upper()}*\n"
            f"📌 *Category:* `{kind}`\n"
            f"📝 *Details:* {message}\n"
            f"⏱️ *Time:* {time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime())}"
        )
        import urllib.request
        url = f"https://api.telegram.org/bot{bot_token}/sendMessage"
        payload = json.dumps({'chat_id': chat_id, 'text': text, 'parse_mode': 'Markdown'}).encode('utf-8')
        req = urllib.request.Request(url, data=payload, headers={'Content-Type': 'application/json'}, method='POST')
        with urllib.request.urlopen(req, timeout=10):
            pass
        return None
    except Exception as exc:
        return str(exc)


def dispatch_mobile_sms(db_path, device, severity, kind, message, conn=None):
    """Synchronously dispatch alert to configured mobile provider; returns error message or None."""
    try:
        if conn is not None:
            phone_row = conn.execute("SELECT value FROM settings WHERE key='mobile_phone'").fetchone()
            prov_row = conn.execute("SELECT value FROM settings WHERE key='mobile_provider'").fetchone()
            key_row = conn.execute("SELECT value FROM settings WHERE key='mobile_api_key'").fetchone()
            sid_row = conn.execute("SELECT value FROM settings WHERE key='mobile_account_sid'").fetchone()
            from_row = conn.execute("SELECT value FROM settings WHERE key='mobile_from_number'").fetchone()
        else:
            with connect(db_path) as db:
                phone_row = db.execute("SELECT value FROM settings WHERE key='mobile_phone'").fetchone()
                prov_row = db.execute("SELECT value FROM settings WHERE key='mobile_provider'").fetchone()
                key_row = db.execute("SELECT value FROM settings WHERE key='mobile_api_key'").fetchone()
                sid_row = db.execute("SELECT value FROM settings WHERE key='mobile_account_sid'").fetchone()
                from_row = db.execute("SELECT value FROM settings WHERE key='mobile_from_number'").fetchone()

        if not phone_row or not key_row:
            return None  # Not configured
        phone = phone_row['value'].strip()
        provider = (prov_row['value'].strip() if prov_row else 'fast2sms').lower()
        api_key = key_row['value'].strip()
        if not phone or not api_key:
            return None

        import urllib.request
        import urllib.parse

        if provider == 'fast2sms':
            clean_phone = re.sub(r'[^0-9]', '', phone)[-10:]
            url = "https://www.fast2sms.com/dev/bulkV2"
            short_msg = f"SENTINEL ALERT [{severity.upper()}]: {device} - {message[:85]}"
            payload = json.dumps({
                "route": "q",
                "message": short_msg,
                "language": "english",
                "flash": 0,
                "numbers": clean_phone
            }).encode('utf-8')
            req = urllib.request.Request(
                url, data=payload,
                headers={"authorization": api_key, "Content-Type": "application/json"},
                method="POST"
            )
            with urllib.request.urlopen(req, timeout=10):
                pass
            return None

        elif provider == 'whatsapp':
            clean_phone = phone if phone.startswith('+') else ('+' + phone)
            text = f"🚨 *SENTINEL SECURITY ALERT*\n*Device:* `{device}`\n*Severity:* *{severity.upper()}*\n*Details:* {message}"
            encoded = urllib.parse.quote(text)
            url = f"https://api.callmebot.com/whatsapp.php?phone={clean_phone}&text={encoded}&apikey={api_key}"
            req = urllib.request.Request(url, headers={"User-Agent": "Sentinel-EDR/1.0"})
            with urllib.request.urlopen(req, timeout=10):
                pass
            return None

        elif provider == 'twilio':
            sid = sid_row['value'].strip() if sid_row else ''
            from_num = from_row['value'].strip() if from_row else ''
            if not sid or not from_num:
                return "Twilio provider incomplete: account_sid or from_number missing"
            url = f"https://api.twilio.com/2010-04-01/Accounts/{sid}/Messages.json"
            data = urllib.parse.urlencode({
                'To': phone,
                'From': from_num,
                'Body': f"SENTINEL EDR ALERT [{severity.upper()}]: {device} - {message[:120]}"
            }).encode('utf-8')
            import base64
            creds = base64.b64encode(f"{sid}:{api_key}".encode('utf-8')).decode('utf-8')
            req = urllib.request.Request(
                url, data=data,
                headers={"Authorization": f"Basic {creds}", "Content-Type": "application/x-www-form-urlencoded"},
                method="POST"
            )
            with urllib.request.urlopen(req, timeout=10):
                pass
            return None

        return f"Unknown provider: {provider}"
    except Exception as exc:
        return str(exc)


class NotificationWorker:
    """Bounded persistent notification worker with exponential backoff and delivery tracking."""
    def __init__(self, db_path, poll_interval=5):
        self.db_path = Path(db_path)
        self.poll_interval = poll_interval
        self._stop_event = threading.Event()
        self._thread = None

    def start(self):
        if self._thread is None or not self._thread.is_alive():
            self._stop_event.clear()
            self._thread = threading.Thread(target=self._run, daemon=True, name="NotificationWorker")
            self._thread.start()

    def stop(self, timeout=5):
        if self._thread and self._thread.is_alive():
            self._stop_event.set()
            self._thread.join(timeout=timeout)

    def process_queue(self, db, now):
        rows = db.execute(
            "SELECT * FROM notification_queue WHERE status='pending' AND next_retry <= ? ORDER BY id ASC LIMIT 10",
            (now,)
        ).fetchall()
        for row in rows:
            notif_id = row['id']
            device = row['device_id']
            severity = row['severity']
            kind = row['kind']
            message = row['message']
            attempts = row['attempts'] + 1

            errors = []
            tg_err = dispatch_telegram(self.db_path, device, severity, kind, message, conn=db)
            if tg_err:
                errors.append(f"Telegram: {tg_err}")
            sms_err = dispatch_mobile_sms(self.db_path, device, severity, kind, message, conn=db)
            if sms_err:
                errors.append(f"SMS: {sms_err}")

            if not errors:
                db.execute(
                    "UPDATE notification_queue SET status='delivered', attempts=?, updated_at=? WHERE id=?",
                    (attempts, now, notif_id)
                )
            else:
                err_msg = '; '.join(errors)[:500]
                if attempts >= 5:
                    db.execute(
                        "UPDATE notification_queue SET status='failed', attempts=?, last_error=?, updated_at=? WHERE id=?",
                        (attempts, err_msg, now, notif_id)
                    )
                else:
                    delay = 10.0 * (2 ** (attempts - 1))
                    db.execute(
                        "UPDATE notification_queue SET attempts=?, next_retry=?, last_error=?, updated_at=? WHERE id=?",
                        (attempts, now + delay, err_msg, now, notif_id)
                    )

    def _run(self):
        while not self._stop_event.is_set():
            try:
                now = time.time()
                with connect(self.db_path) as db:
                    self.process_queue(db, now)
            except Exception as exc:
                print(f"[NOTIFICATION WORKER ERROR] {exc}", flush=True)
            self._stop_event.wait(self.poll_interval)


def send_telegram(db_path, device, severity, kind, message):
    """Enqueue alert notification to Telegram."""
    try:
        now = time.time()
        with connect(db_path) as db:
            db.execute(
                "INSERT INTO notification_queue(channel, device_id, severity, kind, message, status, attempts, next_retry, created, updated_at) "
                "VALUES ('telegram', ?, ?, ?, ?, 'pending', 0, ?, ?, ?)",
                (device, severity, kind, message, now, now, now)
            )
    except Exception as exc:
        print(f"[ENQUEUE TELEGRAM ERROR] {exc}", flush=True)


def send_mobile_sms(db_path, device, severity, kind, message):
    """Enqueue alert notification to mobile SMS/WhatsApp."""
    try:
        now = time.time()
        with connect(db_path) as db:
            db.execute(
                "INSERT INTO notification_queue(channel, device_id, severity, kind, message, status, attempts, next_retry, created, updated_at) "
                "VALUES ('mobile', ?, ?, ?, ?, 'pending', 0, ?, ?, ?)",
                (device, severity, kind, message, now, now, now)
            )
    except Exception as exc:
        print(f"[ENQUEUE MOBILE ERROR] {exc}", flush=True)


ROLE_LEVELS = {'viewer': 1, 'analyst': 2, 'administrator': 3}


def hash_password(password, salt=None):
    if salt is None:
        salt = secrets.token_hex(16)
    pw_hash = hashlib.pbkdf2_hmac('sha256', str(password).encode('utf-8'), salt.encode('utf-8'), 100000).hex()
    return f"{salt}${pw_hash}"


def verify_password(password, stored_hash):
    try:
        salt, expected_hash = stored_hash.split('$', 1)
        actual_hash = hashlib.pbkdf2_hmac('sha256', str(password).encode('utf-8'), salt.encode('utf-8'), 100000).hex()
        return hmac.compare_digest(actual_hash, expected_hash)
    except Exception:
        return False


def generate_totp_secret():
    return base64.b32encode(secrets.token_bytes(20)).decode('utf-8').rstrip('=')


def get_totp_code(secret, time_step=None):
    if time_step is None:
        time_step = int(time.time() // 30)
    key = base64.b32decode(secret + '=' * ((8 - len(secret) % 8) % 8))
    msg = struct.pack('>Q', time_step)
    h = hmac.new(key, msg, hashlib.sha1).digest()
    offset = h[-1] & 0x0f
    code = struct.unpack('>I', h[offset:offset+4])[0] & 0x7fffffff
    return f"{code % 1000000:06d}"


def verify_totp(secret, user_code):
    curr_step = int(time.time() // 30)
    for step in (curr_step - 1, curr_step, curr_step + 1):
        if hmac.compare_digest(get_totp_code(secret, step), str(user_code).strip()):
            return True
    return False


def log_audit(db, actor, action, target, outcome, details=None, ip=None):
    try:
        db.execute(
            "INSERT INTO audit_logs (actor, action, target, details, ip_address, timestamp, outcome) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (actor, action, str(target)[:200] if target else None,
             str(details)[:500] if details else None,
             str(ip)[:64] if ip else None,
             time.time(), outcome)
        )
    except Exception as exc:
        print(f"[AUDIT LOG ERROR] {exc}", flush=True)


def digest(token):
    return hashlib.sha256(token.encode()).hexdigest()


def connect(path):
    db = sqlite3.connect(path, timeout=30)
    db.row_factory = sqlite3.Row
    db.execute('PRAGMA foreign_keys=ON')
    try:
        db.execute('PRAGMA journal_mode=WAL')
        db.execute('PRAGMA synchronous=NORMAL')
    except Exception:
        pass
    return db


def initialize(directory):
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    config = directory / 'config.json'
    if config.exists():
        raise ValueError('Already initialized; existing credentials were preserved.')
    token = os.environ.get('SENTINEL_ADMIN_PASSWORD') or secrets.token_urlsafe(32)
    with config.open('x') as file:
        json.dump({'auth_mode': 'user_sessions'}, file)
    config.chmod(0o600)
    with connect(directory / 'sentinel.db') as db:
        db.execute('PRAGMA journal_mode=WAL')
        apply_schema(db)
        now = time.time()
        existing_admin = db.execute("SELECT username FROM users WHERE username='admin'").fetchone()
        if not existing_admin:
            db.execute(
                "INSERT INTO users (username, password_hash, role, created, updated_at) VALUES (?, ?, ?, ?, ?)",
                ('admin', hash_password(token), 'administrator', now, now)
            )
    return token


def apply_schema(db):
    """Transactional schema upgrade: tables, columns, then dependent indexes."""
    db.execute('BEGIN IMMEDIATE')
    statements = [part.strip() for part in SCHEMA.split(';') if part.strip()]
    for statement in statements:
        if not statement.startswith('CREATE INDEX'):
            db.execute(statement)
    migrate_schema(db)
    for statement in statements:
        if statement.startswith('CREATE INDEX'):
            db.execute(statement)
    db.execute('PRAGMA user_version=2')


def migrate_schema(db):
    """Ensure database schema is up-to-date with non-destructive migrations."""
    cursor = db.execute("PRAGMA table_info(commands)")
    columns = {row['name']: row for row in cursor.fetchall()}
    if columns and 'status' not in columns:
        db.execute("ALTER TABLE commands ADD COLUMN expires_at REAL DEFAULT 0")
        db.execute("ALTER TABLE commands ADD COLUMN status TEXT DEFAULT 'queued'")
        db.execute("ALTER TABLE commands ADD COLUMN attempts INTEGER DEFAULT 0")
        db.execute("ALTER TABLE commands ADD COLUMN result TEXT DEFAULT NULL")
        db.execute("ALTER TABLE commands ADD COLUMN updated_at REAL DEFAULT 0")
        if 'executed' in columns:
            db.execute("UPDATE commands SET status = CASE WHEN executed = 1 THEN 'legacy_unverified' ELSE 'queued' END")
        db.execute("UPDATE commands SET expires_at = created + 300, updated_at = created WHERE updated_at = 0")
    db.execute("CREATE INDEX IF NOT EXISTS commands_device_status ON commands(device_id, status)")

    cur_models = db.execute("PRAGMA table_info(models)")
    m_cols = {row['name']: row for row in cur_models.fetchall()}
    if m_cols and 'version' not in m_cols:
        db.execute("ALTER TABLE models ADD COLUMN version INTEGER DEFAULT 1")
        db.execute("ALTER TABLE models ADD COLUMN metadata TEXT DEFAULT '{}'")
        db.execute("ALTER TABLE models ADD COLUMN previous_baseline TEXT DEFAULT NULL")

    db.execute('''
        CREATE TABLE IF NOT EXISTS users (
            username TEXT PRIMARY KEY, password_hash TEXT NOT NULL, role TEXT NOT NULL DEFAULT 'viewer',
            totp_secret TEXT, mfa_enabled INTEGER NOT NULL DEFAULT 0, created REAL NOT NULL, updated_at REAL NOT NULL)
    ''')
    db.execute('''
        CREATE TABLE IF NOT EXISTS sessions (
            token_hash TEXT PRIMARY KEY, username TEXT NOT NULL REFERENCES users(username),
            role TEXT NOT NULL, created REAL NOT NULL, expires_at REAL NOT NULL, revoked INTEGER NOT NULL DEFAULT 0)
    ''')
    db.execute('CREATE INDEX IF NOT EXISTS sessions_token ON sessions(token_hash)')
    db.execute('''
        CREATE TABLE IF NOT EXISTS audit_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT, actor TEXT NOT NULL, action TEXT NOT NULL,
            target TEXT, details TEXT, ip_address TEXT, timestamp REAL NOT NULL, outcome TEXT NOT NULL)
    ''')
    db.execute('CREATE INDEX IF NOT EXISTS audit_logs_time ON audit_logs(timestamp)')

    ucols = {r['name'] for r in db.execute('PRAGMA table_info(users)')}
    for name, definition in [('totp_pending', 'TEXT'), ('totp_last_step', 'INTEGER NOT NULL DEFAULT -1')]:
        if name not in ucols:
            db.execute(f'ALTER TABLE users ADD COLUMN {name} {definition}')

    cur_alerts = db.execute("PRAGMA table_info(alerts)")
    a_cols = {row['name']: row for row in cur_alerts.fetchall()}
    if a_cols and 'assigned_to' not in a_cols:
        db.execute("ALTER TABLE alerts ADD COLUMN assigned_to TEXT DEFAULT NULL")
        db.execute("ALTER TABLE alerts ADD COLUMN notes TEXT DEFAULT NULL")
        db.execute("ALTER TABLE alerts ADD COLUMN incident_id TEXT DEFAULT NULL")
    db.execute("CREATE INDEX IF NOT EXISTS alerts_incident ON alerts(incident_id)")

    cur_devs = db.execute("PRAGMA table_info(devices)")
    d_cols = {row['name']: row for row in cur_devs.fetchall()}
    if d_cols and 'device_group' not in d_cols:
        db.execute("ALTER TABLE devices ADD COLUMN device_group TEXT NOT NULL DEFAULT 'default'")
        db.execute("ALTER TABLE devices ADD COLUMN agent_version TEXT NOT NULL DEFAULT '1.0.0'")
        db.execute("ALTER TABLE devices ADD COLUMN maintenance_window_until REAL NOT NULL DEFAULT 0")


def register(directory, device_id, token=None, overwrite=False):
    if not re.fullmatch(r'[A-Za-z0-9_-]{1,64}', device_id):
        raise ValueError('Device ID: 1–64 letters, numbers, underscores or hyphens.')
    if token is not None and (not isinstance(token, str) or len(token) < 24 or len(token) > 256):
        raise ValueError('Custom device token must be 24–256 characters.')
    token = token or secrets.token_urlsafe(32)
    with connect(Path(directory) / 'sentinel.db') as db:
        existing = db.execute('SELECT token_hash FROM devices WHERE id=?', (device_id,)).fetchone()
        if existing and not overwrite:
            raise ValueError(f"Device '{device_id}' already registered. Use rotation to change token.")
        if existing:
            db.execute('UPDATE devices SET token_hash=? WHERE id=?', (digest(token), device_id))
        else:
            db.execute('INSERT INTO devices (id, token_hash, created) VALUES (?,?,?)', (device_id, digest(token), time.time()))
    return token


def rotate_device_token(directory, device_id):
    token = secrets.token_urlsafe(32)
    with connect(Path(directory) / 'sentinel.db') as db:
        cur = db.execute('UPDATE devices SET token_hash=? WHERE id=?', (digest(token), device_id))
        if not cur.rowcount:
            raise ValueError(f"Unknown device '{device_id}'")
    return token


def revoke_device_token(directory, device_id):
    revoked_hash = 'REVOKED:' + secrets.token_hex(16)
    with connect(Path(directory) / 'sentinel.db') as db:
        cur = db.execute('UPDATE devices SET token_hash=? WHERE id=?', (revoked_hash, device_id))
        if not cur.rowcount:
            raise ValueError(f"Unknown device '{device_id}'")
    return True


def rotate_admin_token(directory):
    """Local recovery: reset admin password, revoke every session; preserve MFA."""
    directory = Path(directory)
    if not (directory / 'config.json').exists():
        raise FileNotFoundError('Initialize the server first.')
    password = secrets.token_urlsafe(32)
    with connect(directory / 'sentinel.db') as db:
        apply_schema(db)
        now = time.time()
        db.execute("INSERT INTO users(username,password_hash,role,created,updated_at) VALUES(?,?,'administrator',?,?) "
                   "ON CONFLICT(username) DO UPDATE SET password_hash=excluded.password_hash, updated_at=excluded.updated_at",
                   ('admin', hash_password(password), now, now))
        db.execute('UPDATE sessions SET revoked=1')
        log_audit(db, 'local-recovery', 'rotate_admin_password', 'admin', 'success')
    (directory / 'config.json').write_text(json.dumps({'auth_mode': 'user_sessions'}))
    (directory / 'config.json').chmod(0o600)
    return password


def ensure_device(directory, device_id, token=None):
    """Startup registration preserves existing credentials and device metadata."""
    if not re.fullmatch(r'[A-Za-z0-9_-]{1,64}', device_id):
        raise ValueError('Invalid device ID')
    with connect(Path(directory) / 'sentinel.db') as db:
        generated = token or secrets.token_urlsafe(32)
        cursor = db.execute('INSERT OR IGNORE INTO devices(id,token_hash,created) VALUES(?,?,?)',
                            (device_id, digest(generated), time.time()))
    return generated if cursor.rowcount else None


def validate(payload):
    if not isinstance(payload, dict):
        abort(400, 'Expected a JSON object.')
    sample_id = payload.get('sample_id')
    if not isinstance(sample_id, str) or not re.fullmatch(r'[A-Za-z0-9_-]{1,64}', sample_id):
        abort(400, 'Invalid sample_id.')
    clean = {'sample_id': sample_id}
    bounds = {'observed': (0, 1e12), 'cpu': (0, 100), 'ram': (0, 100),
              'process_count': (0, 1000000), 'connections': (0, 10000000),
              'bytes_per_second': (0, 1e15), 'failed_logins': (0, 100000)}
    for key, (low, high) in bounds.items():
        value = payload.get(key)
        if key in ('connections', 'failed_logins') and value is None:
            clean[key] = None
            continue
        if isinstance(value, bool) or not isinstance(value, (float, int)) or not math.isfinite(value) or not low <= value <= high:
            abort(400, f'Invalid {key}.')
        if key in ('process_count', 'connections', 'failed_logins') and int(value) != value:
            abort(400, f'{key} must be an integer.')
        clean[key] = value
    now = time.time()
    observed = clean['observed']
    if observed > now + 60:
        abort(400, 'Observation timestamp cannot be in the future.')
    if now - observed > 86400 * 7:
        abort(400, 'Observation timestamp exceeds maximum retention window (7 days).')

    processes = payload.get('processes', [])
    if not isinstance(processes, list) or len(processes) > 500:
        abort(400, 'processes must contain at most 500 entries.')
    clean['processes'] = []
    for process in processes:
        if not isinstance(process, dict) or type(process.get('pid')) is not int or process['pid'] < 0 or not isinstance(process.get('name'), str) or len(process['name']) > 200:
            abort(400, 'Invalid process entry.')
        p_item = {'pid': process['pid'], 'name': process['name']}
        if 'create_time' in process and process['create_time'] is not None:
            ct = process['create_time']
            if isinstance(ct, (int, float)) and math.isfinite(ct) and ct > 0:
                p_item['create_time'] = float(ct)
        if 'ppid' in process and process['ppid'] is not None:
            if isinstance(process['ppid'], int) and process['ppid'] >= 0:
                p_item['ppid'] = process['ppid']
        if 'exe' in process and process['exe'] is not None:
            if isinstance(process['exe'], str) and len(process['exe']) <= 500:
                p_item['exe'] = process['exe']
        if 'cmdline' in process and process['cmdline'] is not None:
            if isinstance(process['cmdline'], list) and len(process['cmdline']) <= 50:
                p_item['cmdline'] = [str(arg)[:150] for arg in process['cmdline']]
        clean['processes'].append(p_item)

    warnings = payload.get('warnings', [])
    if not isinstance(warnings, list) or len(warnings) > 10 or any(not isinstance(w, str) or len(w) > 250 for w in warnings):
        abort(400, 'Invalid warnings.')
    clean['warnings'] = warnings

    # Extended telemetry fields (Disk, Battery, Uptime, Hostname, OS)
    for num_key in ('disk', 'battery'):
        v = payload.get(num_key)
        if v is not None:
            if isinstance(v, bool) or not isinstance(v, (float, int)) or not math.isfinite(v) or not 0 <= v <= 100:
                abort(400, f'Invalid {num_key}.')
            clean[num_key] = round(float(v), 1)
        else:
            clean[num_key] = None

    is_plugged = payload.get('is_plugged')
    clean['is_plugged'] = bool(is_plugged) if isinstance(is_plugged, bool) else None

    # Uptime validation: rejects NaN, Infinity, negative values, and oversized numbers
    uptime = payload.get('uptime')
    if uptime is not None:
        if isinstance(uptime, bool) or not isinstance(uptime, (int, float)) or not math.isfinite(uptime) or uptime < 0 or uptime > 1e10:
            abort(400, 'Invalid uptime.')
        clean['uptime'] = int(uptime)
    else:
        clean['uptime'] = None

    for str_key in ('os_info', 'hostname', 'active_window', 'ip_address', 'public_ip', 'agent_hash'):
        val = payload.get(str_key)
        if val is not None and isinstance(val, str) and len(val) <= 256:
            clean[str_key] = val
        else:
            clean[str_key] = None

    raw_hist = payload.get('browser_history', [])
    clean_hist = []
    if isinstance(raw_hist, list):
        for item in raw_hist[:50]:
            if isinstance(item, dict) and isinstance(item.get('url'), str):
                entry = {
                    'url': item['url'][:500],
                    'title': str(item.get('title') or '')[:200]
                }
                if 'domain' in item and isinstance(item['domain'], str):
                    entry['domain'] = item['domain'][:250]
                if 'visit_time' in item and isinstance(item['visit_time'], (int, float)) and math.isfinite(item['visit_time']):
                    entry['visit_time'] = float(item['visit_time'])
                clean_hist.append(entry)
    clean['browser_history'] = clean_hist

    raw_drives = payload.get('removable_drives', [])
    clean_drives = []
    if isinstance(raw_drives, list):
        for d in raw_drives[:10]:
            if isinstance(d, str):
                clean_drives.append(d[:100])
    clean['removable_drives'] = clean_drives

    raw_results = payload.get('command_results', [])
    clean_results = []
    if isinstance(raw_results, list):
        for cr in raw_results[:20]:
            if isinstance(cr, dict) and 'id' in cr and cr.get('status') in ('succeeded', 'failed'):
                clean_results.append({
                    'id': cr['id'],
                    'status': cr['status'],
                    'result': str(cr.get('result', ''))[:500]
                })
    clean['command_results'] = clean_results

    return clean


def create_app(directory=DATA):
    directory = Path(directory)
    config = json.loads((directory / 'config.json').read_text())
    path = directory / 'sentinel.db'
    with connect(path) as db:
        apply_schema(db)
    app = Flask(__name__)
    app.config['MAX_CONTENT_LENGTH'] = 65536
    cache, lock = {}, threading.RLock()
    auth_limiter = AuthRateLimiter()

    # Configurable trusted-proxy handling
    trusted_proxy = os.environ.get('SENTINEL_BEHIND_PROXY', '').lower() in ('1', 'true', 'yes')
    if trusted_proxy:
        from werkzeug.middleware.proxy_fix import ProxyFix
        hops = int(os.environ.get('SENTINEL_PROXY_HOPS', '1'))
        app.wsgi_app = ProxyFix(app.wsgi_app, x_for=hops, x_proto=1, x_host=1)

    app.heartbeat_monitor = HeartbeatMonitor(path)
    app.notification_worker = NotificationWorker(path)

    def bearer():
        header = request.headers.get('Authorization', '')
        if header.startswith('Bearer '):
            return header[7:].strip()
        # Query parameter fallback (?token=...) strictly eliminated for security
        return ''

    def get_request_auth(db, token_str):
        if not token_str:
            return None, None
        tok_hash = digest(token_str)
        sess = db.execute(
            "SELECT s.username, u.role, s.expires_at, s.revoked "
            "FROM sessions s JOIN users u ON s.username = u.username "
            "WHERE s.token_hash = ?",
            (tok_hash,)
        ).fetchone()
        if sess and not sess['revoked'] and sess['expires_at'] > time.time():
            return sess['username'], sess['role']
        return None, None

    def require_role(min_role):
        def decorator(fn):
            @wraps(fn)
            def wrapped(*args, **kwargs):
                client_ip = request.remote_addr or 'unknown'
                if auth_limiter.is_blocked(client_ip):
                    abort(429, 'Too many failed authentication attempts. Please retry later.')
                token_str = bearer()
                with connect(path) as db:
                    actor, role = get_request_auth(db, token_str)
                    if not actor:
                        auth_limiter.record_failure(client_ip)
                        abort(401, 'Administrator authentication required.')
                    auth_limiter.record_success(client_ip)
                    if ROLE_LEVELS.get(role, 0) < ROLE_LEVELS.get(min_role, 99):
                        log_audit(db, actor, f'access_denied_{request.endpoint}', request.path, 'denied',
                                  f"Insufficient permissions. Required: {min_role}, Actual: {role}", client_ip)
                        db.commit()
                        abort(403, f"Forbidden: '{min_role}' role required.")
                    g.current_user = actor
                    g.current_role = role
                return fn(*args, **kwargs)
            return wrapped
        return decorator

    def admin(fn):
        return require_role('administrator')(fn)

    def analyst(fn):
        return require_role('analyst')(fn)

    def viewer(fn):
        return require_role('viewer')(fn)

    @app.before_request
    def validate_json_object():
        if request.is_json and request.method in ('POST', 'PUT', 'PATCH'):
            if not isinstance(request.get_json(silent=True), dict):
                abort(400, 'Expected a JSON object.')

    @app.after_request
    def headers(response):
        response.headers['Cache-Control'] = 'no-store'
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['X-Frame-Options'] = 'DENY'
        response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'"
        return response

    @app.errorhandler(HTTPException)
    def error(exc):
        return jsonify(error=exc.description), exc.code

    @app.get('/')
    def index():
        return render_template('index.html')

    @app.get('/api/health')
    def health():
        return jsonify(status='ok', service='sentinel-edr')

    @app.get('/api/ready')
    def ready():
        try:
            with connect(path) as db:
                db.execute('SELECT 1').fetchone()
                if db.execute('PRAGMA quick_check(1)').fetchone()[0] != 'ok':
                    raise ValueError('Database integrity check failed')
                db.execute('SELECT COUNT(*) FROM devices').fetchone()
            return jsonify(status='ready', database='available'), 200
        except Exception as exc:
            return jsonify(status='not_ready', error='Database unavailable'), 503

    def alert(db, device, now, kind, severity, message):
        recent = db.execute('SELECT 1 FROM alerts WHERE device_id=? AND kind=? AND created>?',
                            (device, kind, now - 300)).fetchone()
        if not recent:
            db.execute('INSERT INTO alerts(device_id,created,kind,severity,message) VALUES (?,?,?,?,?)',
                       (device, now, kind, severity, message))
            db.execute(
                'INSERT INTO notification_queue(channel, device_id, severity, kind, message, status, attempts, next_retry, created, updated_at) '
                'VALUES (?,?,?,?,?,?,?,?,?,?)',
                ('all', device, severity, kind, message, 'pending', 0, now, now, now)
            )

    def deliver_commands(db, device, now):
        # Expire stale unacknowledged commands
        db.execute(
            "UPDATE commands SET status='expired', updated_at=? WHERE device_id=? AND status IN ('queued', 'delivered') AND expires_at <= ?",
            (now, device, now)
        )

        # Retrieve active commands for this endpoint
        cmd_rows = db.execute(
            "SELECT id, action, payload, expires_at FROM commands WHERE device_id=? AND status IN ('queued', 'delivered') AND expires_at > ? ORDER BY id ASC",
            (device, now)
        ).fetchall()
        commands_to_send = []
        if cmd_rows:
            cmd_ids = []
            for cr in cmd_rows:
                cmd_ids.append(cr['id'])
                item = {'id': cr['id'], 'action': cr['action'], 'expires_at': cr['expires_at']}
                try:
                    item.update(json.loads(cr['payload']))
                except Exception:
                    pass
                commands_to_send.append(item)
            placeholders = ','.join('?' for _ in cmd_ids)
            db.execute(f"UPDATE commands SET status='delivered', attempts=attempts+1, updated_at=? WHERE id IN ({placeholders})", [now] + cmd_ids)

        return commands_to_send

    @app.post('/api/telemetry')
    def ingest():
        device = request.headers.get('X-Device-ID', '')
        with lock, connect(path) as db:
            known = db.execute('SELECT token_hash FROM devices WHERE id=?', (device,)).fetchone()
            if not known or not hmac.compare_digest(known['token_hash'], digest(bearer())):
                abort(401, 'Device authentication failed.')
            payload = validate(request.get_json(silent=True))
            duplicate = db.execute('SELECT id FROM telemetry WHERE device_id=? AND sample_id=?',
                                   (device, payload['sample_id'])).fetchone()
            if duplicate:
                return jsonify(status='duplicate', id=duplicate['id'], commands=deliver_commands(db, device, time.time()))
            previous_row = db.execute('SELECT payload FROM telemetry WHERE device_id=? ORDER BY id DESC LIMIT 1', (device,)).fetchone()
            previous = json.loads(previous_row['payload']) if previous_row else None
            now = time.time()
            model_row = db.execute('SELECT * FROM models WHERE device_id=?', (device,)).fetchone()
            score, anomalous = None, False
            if model_row and payload['connections'] is not None:
                cached = cache.get(device)
                if cached is None or cached[0] != model_row['trained']:
                    cached = (model_row['trained'], detection.train(json.loads(model_row['baseline'])))
                    cache[device] = cached
                prior = previous if previous and previous['connections'] is not None else None
                score, anomalous = detection.score(cached[1], payload, prior)
            pub_ip = request.remote_addr or ''
            if pub_ip and len(pub_ip) <= 64:
                payload['public_ip'] = pub_ip

            cursor = db.execute('INSERT INTO telemetry(device_id,sample_id,received,observed,payload,score,anomaly) VALUES (?,?,?,?,?,?,?)',
                                (device, payload['sample_id'], now, payload['observed'], json.dumps(payload), score, int(anomalous)))
            recent = db.execute('SELECT payload FROM telemetry WHERE device_id=? AND received>=?', (device, now-300)).fetchall()
            failures = sum(json.loads(row['payload'])['failed_logins'] or 0 for row in recent)
            if failures >= 5:
                alert(db, device, now, 'failed_logins', 'high', f'{failures} failed login events across this device in the last 5 minutes.')
            if payload['cpu'] >= 95:
                alert(db, device, now, 'high_cpu', 'medium', 'CPU utilization reached at least 95%; investigate workload.')
            if anomalous:
                alert(db, device, now, 'ml_anomaly', 'medium', 'Isolation Forest flagged an unusual metric combination; investigation required.')

            # Process threat detection with allowlist suppression
            allowlist_row = db.execute("SELECT value FROM settings WHERE key='process_allowlist'").fetchone()
            proc_allowlist = [x.strip().lower() for x in allowlist_row['value'].split(',')] if allowlist_row and allowlist_row['value'] else []

            for proc in payload.get('processes', []):
                threat = check_process_threat(proc['name'])
                if threat:
                    tid, tech, severity, desc = threat
                    base_proc = os.path.basename(proc['name']).lower()
                    if base_proc.endswith('.exe'):
                        base_proc = base_proc[:-4]
                    if base_proc in proc_allowlist or (proc.get('exe') and os.path.basename(proc['exe']).lower().rstrip('.exe') in proc_allowlist):
                        continue
                    alert(db, device, now, f'threat_{base_proc}', severity,
                          f"[Investigation Indicator: MITRE ATT&CK {tid}: {tech}] {desc} (PID: {proc['pid']}, Process: {proc['name']}). Note: Process name presence is an investigation indicator requiring behavioral verification.")

            if payload.get('active_window'):
                act_lower = payload['active_window'].lower()
                for bad_kw in RESTRICTED_KEYWORDS:
                    if bad_kw in act_lower:
                        alert(db, device, now, f'policy_{bad_kw}', 'high',
                              f'Policy violation: restricted activity/website detected in active window: "{payload["active_window"]}".')
                        break

            # DLP / Data Exfiltration checks in active window & browser history with hostname parsing
            for h in payload.get('browser_history', []):
                raw_url = h.get('url', '')
                parsed_domain = h.get('domain')
                if not parsed_domain and raw_url:
                    try:
                        p_url = urllib.parse.urlsplit(raw_url if '://' in raw_url else 'http://' + raw_url)
                        parsed_domain = (p_url.hostname or '').lower()
                    except Exception:
                        parsed_domain = ''
                if not parsed_domain and raw_url:
                    parsed_domain = raw_url.lower()

                matched_dlp = None
                for d in DLP_EXFILTRATION_DOMAINS:
                    if parsed_domain == d or parsed_domain.endswith('.' + d) or d in parsed_domain:
                        matched_dlp = d
                        break

                if matched_dlp:
                    clean_tag = matched_dlp.replace('.', '_')
                    # Deduplicate history alert if visit timestamp was already alerted recently
                    recent_dlp = db.execute(
                        "SELECT 1 FROM alerts WHERE device_id=? AND kind=? AND created>?",
                        (device, f'dlp_{clean_tag}', now - 300)
                    ).fetchone()
                    if not recent_dlp:
                        alert(db, device, now, f'dlp_{clean_tag}', 'high',
                              f"[Investigation Indicator: DLP / Confidentiality] Potential data exfiltration vector: accessed external file-transfer repository '{matched_dlp}'. Note: Web observation does not confirm data upload or exfiltration.")
                    break

            if payload.get('active_window'):
                act_str = payload['active_window'].lower()
                matched_dlp = next((d for d in DLP_EXFILTRATION_DOMAINS if d in act_str), None)
                if matched_dlp:
                    clean_tag = matched_dlp.replace('.', '_')
                    alert(db, device, now, f'dlp_{clean_tag}', 'high',
                          f"[Investigation Indicator: DLP / Confidentiality] Potential data exfiltration vector: accessed external file-transfer repository '{matched_dlp}'. Note: Web observation does not confirm data upload or exfiltration.")

            # Removable storage check (USB presence)
            removable = payload.get('removable_drives', [])
            if removable:
                drives_str = ', '.join(removable)
                alert(db, device, now, 'dlp_usb', 'medium',
                      f'[Investigation Indicator: MITRE ATT&CK T1052: Exfiltration Over Physical Medium] Removable USB/External storage connected: {drives_str}. Note: Removable drive presence observed; does not confirm data movement or exfiltration.')

            # Agent Self-Defense: Code Integrity Monitoring
            if previous and previous.get('agent_hash') and payload.get('agent_hash'):
                if previous['agent_hash'] != payload['agent_hash']:
                    alert(db, device, now, 'tamper_code_modified', 'critical',
                          f"[Agent Integrity Notice] Agent script modification detected on '{device}'! Prior SHA-256: {previous['agent_hash'][:8]}, New: {payload['agent_hash'][:8]}. Note: Self-reported script hash provides local change notice, not cryptographic hardware attestation.")

            # Process piggybacked command execution receipts
            commands_to_send = deliver_commands(db, device, now)

            return jsonify(status='accepted', id=cursor.lastrowid, anomaly=anomalous, score=score, commands=commands_to_send), 201

    @app.get('/api/overview')
    @viewer
    def overview():
        now = time.time()
        with connect(path) as db:
            devices = []
            for device in db.execute('SELECT id FROM devices ORDER BY id'):
                row = db.execute('SELECT * FROM telemetry WHERE device_id=? ORDER BY observed DESC, id DESC LIMIT 1', (device['id'],)).fetchone()
                model = db.execute('SELECT trained,sample_count FROM models WHERE device_id=?', (device['id'],)).fetchone()
                online = bool(row and (now - row['received'] < 60) and (now - row['observed'] < 120))
                devices.append({'id': device['id'], 'online': online,
                                'last_seen': row['received'] if row else None,
                                'latest': json.loads(row['payload']) if row else None,
                                'model': dict(model) if model else None})
            alerts = [dict(row) for row in db.execute('SELECT * FROM alerts ORDER BY id DESC LIMIT 100')]
            count = db.execute('SELECT COUNT(*) FROM alerts WHERE acknowledged=0').fetchone()[0]
        critical_alerts = sum(1 for a in alerts if a['severity'] == 'critical')
        high_alerts = sum(1 for a in alerts if a['severity'] == 'high')
        score = max(0, 100 - (critical_alerts * 15 + high_alerts * 8 + count * 3))
        return jsonify(
            devices=devices,
            alerts=alerts,
            open_alerts=count,
            server_time=now,
            heuristic_risk_score=score,
            compliance_score=score
        )

    @app.get('/api/devices/<device>/history')
    @viewer
    def history(device):
        with connect(path) as db:
            rows = db.execute('SELECT * FROM telemetry WHERE device_id=? ORDER BY id DESC LIMIT 120', (device,)).fetchall()
        return jsonify(samples=[dict(json.loads(row['payload']), received=row['received'], score=row['score'], anomaly=bool(row['anomaly'])) for row in reversed(rows)])

    @app.post('/api/alerts/<int:alert_id>/ack')
    @analyst
    def acknowledge(alert_id):
        with connect(path) as db:
            cursor = db.execute('UPDATE alerts SET acknowledged=1 WHERE id=?', (alert_id,))
            if not cursor.rowcount:
                abort(404, 'Alert not found.')
        return jsonify(status='acknowledged')

    @app.post('/api/devices/register')
    @admin
    def api_register_device():
        data = request.get_json(silent=True) or {}
        if not isinstance(data.get('device_id'), str):
            abort(400, 'device_id must be a string.')
        device_id = data['device_id'].strip()
        custom_token = data.get('token')
        overwrite = bool(data.get('overwrite', False))
        if not device_id:
            abort(400, 'device_id is required.')
        try:
            device_token = register(directory, device_id, custom_token, overwrite=overwrite)
            return jsonify(status='registered', device_id=device_id, token=device_token), 201
        except ValueError as exc:
            if 'already registered' in str(exc):
                abort(409, str(exc))
            abort(400, str(exc))

    @app.post('/api/devices/<device>/rotate')
    @admin
    def api_rotate_device(device):
        try:
            new_token = rotate_device_token(directory, device)
            return jsonify(status='rotated', device_id=device, token=new_token)
        except ValueError as exc:
            abort(404, str(exc))

    @app.post('/api/devices/<device>/revoke')
    @admin
    def api_revoke_device(device):
        try:
            revoke_device_token(directory, device)
            return jsonify(status='revoked', device_id=device)
        except ValueError as exc:
            abort(404, str(exc))

    @app.delete('/api/devices/<device_id>')
    @admin
    def delete_device(device_id):
        with lock, connect(path) as db:
            device = db.execute('SELECT id FROM devices WHERE id=?', (device_id,)).fetchone()
            if not device:
                abort(404, 'Device not found.')
            db.execute('DELETE FROM telemetry WHERE device_id=?', (device_id,))
            db.execute('DELETE FROM alerts WHERE device_id=?', (device_id,))
            db.execute('DELETE FROM models WHERE device_id=?', (device_id,))
            db.execute('DELETE FROM commands WHERE device_id=?', (device_id,))
            db.execute('DELETE FROM devices WHERE id=?', (device_id,))
            cache.pop(device_id, None)
            log_audit(db, getattr(g, 'current_user', 'admin'), 'delete_device', device_id, 'success', None, request.remote_addr)
        return jsonify(status='deleted', device_id=device_id)

    @app.post('/api/commands/<int:cmd_id>/ack')
    def ack_command(cmd_id):
        device = request.headers.get('X-Device-ID', '')
        auth_header = bearer()
        data = request.get_json(silent=True) or {}
        status = data.get('status')
        if status not in ('succeeded', 'failed'):
            abort(400, "status must be 'succeeded' or 'failed'.")
        result = str(data.get('result', ''))[:500]

        now = time.time()
        with lock, connect(path) as db:
            known = db.execute('SELECT token_hash FROM devices WHERE id=?', (device,)).fetchone()
            if not known or not hmac.compare_digest(known['token_hash'], digest(auth_header)):
                abort(401, 'Device authentication required.')

            cmd = db.execute('SELECT * FROM commands WHERE id=?', (cmd_id,)).fetchone()
            if not cmd:
                abort(404, 'Command not found.')
            if cmd['device_id'] != device:
                abort(403, 'Command belongs to another device.')

            if cmd['status'] in ('succeeded', 'failed'):
                if cmd['status'] != status:
                    abort(409, 'Terminal command result cannot be changed.')
                return jsonify(status='recorded', command_id=cmd_id, result_status=status)
            if cmd['status'] != 'delivered':
                abort(409, 'Command was not delivered or is expired.')
            db.execute(
                'UPDATE commands SET status=?, result=?, updated_at=? WHERE id=?',
                (status, result, now, cmd_id)
            )
            alert(db, cmd['device_id'], now, f"command_{status}", 'info' if status == 'succeeded' else 'medium',
                  f"Command #{cmd_id} ({cmd['action']}) {status}: {result}")
        return jsonify(status='recorded', command_id=cmd_id, result_status=status)

    @app.post('/api/devices/<device>/kill_process')
    @admin
    def kill_process(device):
        data = request.get_json(silent=True) or {}
        pid = data.get('pid')
        name = str(data.get('name') or 'unknown')[:200]
        create_time = data.get('create_time')
        path_val = data.get('path')
        if type(pid) is not int or pid <= 0:
            abort(400, 'Valid positive PID required.')
        if create_time is not None:
            if isinstance(create_time, bool) or not isinstance(create_time, (int, float)) or not math.isfinite(create_time) or create_time <= 0:
                abort(400, 'Invalid process create_time.')
            create_time = float(create_time)

        clean_base = os.path.basename(name).lower()
        if pid <= 4 or clean_base in PROTECTED_PROCESS_NAMES or clean_base.rstrip('.exe') in PROTECTED_PROCESS_NAMES:
            abort(403, f"Refused: PID {pid} ('{name}') is a protected critical system process.")

        if create_time is None or isinstance(create_time, bool) or name == 'unknown':
            abort(400, 'Process name and creation time are required; refresh endpoint inventory.')

        now = time.time()
        with connect(path) as db:
            known = db.execute('SELECT id FROM devices WHERE id=?', (device,)).fetchone()
            if not known:
                abort(404, 'Device not found.')
            cmd_payload = json.dumps({
                'pid': pid,
                'name': name,
                'create_time': create_time,
                'path': str(path_val)[:500] if path_val else None
            })
            ttl = 300.0
            cur = db.execute(
                'INSERT INTO commands(device_id, action, payload, created, expires_at, status, attempts, updated_at) VALUES (?,?,?,?,?,?,?,?)',
                (device, 'kill_process', cmd_payload, now, now + ttl, 'queued', 0, now)
            )
            cmd_id = cur.lastrowid
            log_audit(db, getattr(g, 'current_user', 'admin'), 'kill_process', device, 'queued',
                      f"PID: {pid}, Name: {name}", request.remote_addr)
            alert(db, device, now, 'audit_command_queued', 'info',
                  f"Admin queued termination command #{cmd_id} for PID {pid} ('{name}').")
        return jsonify(status='queued', command_id=cmd_id, device=device, pid=pid, name=name)

    @app.post('/api/devices/<device>/send_alert')
    @admin
    def send_device_alert(device):
        data = request.get_json(silent=True) or {}
        message = str(data.get('message', '')).strip()[:500]
        title = str(data.get('title', 'Sentinel Security Alert')).strip()[:100]
        if not message:
            abort(400, 'Alert message is required.')
        now = time.time()
        with connect(path) as db:
            known = db.execute('SELECT id FROM devices WHERE id=?', (device,)).fetchone()
            if not known:
                abort(404, 'Device not found.')
            cmd_payload = json.dumps({'title': title, 'message': message})
            ttl = 300.0
            cur = db.execute(
                'INSERT INTO commands(device_id, action, payload, created, expires_at, status, attempts, updated_at) VALUES (?,?,?,?,?,?,?,?)',
                (device, 'send_alert', cmd_payload, now, now + ttl, 'queued', 0, now)
            )
            cmd_id = cur.lastrowid
        return jsonify(status='queued', command_id=cmd_id, device=device, message=message)

    @app.get('/api/settings/telegram')
    @admin
    def get_telegram_settings():
        with connect(path) as db:
            t_row = db.execute("SELECT value FROM settings WHERE key='telegram_bot_token'").fetchone()
            c_row = db.execute("SELECT value FROM settings WHERE key='telegram_chat_id'").fetchone()
            has_token = bool(t_row and t_row['value'].strip())
            masked_token = (t_row['value'][:6] + '...' + t_row['value'][-4:]) if has_token and len(t_row['value']) > 10 else ('****' if has_token else '')
            chat_id = c_row['value'] if c_row else ''
        return jsonify(configured=has_token, masked_token=masked_token, chat_id=chat_id)

    @app.post('/api/settings/telegram')
    @admin
    def set_telegram_settings():
        data = request.get_json(silent=True) or {}
        bot_token = str(data.get('bot_token', '')).strip()
        chat_id = str(data.get('chat_id', '')).strip()
        test = bool(data.get('test'))
        with connect(path) as db:
            if bot_token:
                db.execute("INSERT OR REPLACE INTO settings (key, value) VALUES ('telegram_bot_token', ?)", (bot_token,))
            if chat_id:
                db.execute("INSERT OR REPLACE INTO settings (key, value) VALUES ('telegram_chat_id', ?)", (chat_id,))
        test_result = None
        if test:
            err = dispatch_telegram(path, 'SYSTEM', 'info', 'test_notification', '✅ Sentinel: Telegram alert integration active and verified!')
            if err:
                return jsonify(status='saved_but_test_failed', test_error=err), 502
            test_result = 'delivered'
        return jsonify(status='saved', test_status=test_result)

    @app.post('/api/settings/telegram/test')
    @admin
    def test_telegram_settings():
        with connect(path) as db:
            t_row = db.execute("SELECT value FROM settings WHERE key='telegram_bot_token'").fetchone()
            c_row = db.execute("SELECT value FROM settings WHERE key='telegram_chat_id'").fetchone()
            if not t_row or not c_row or not t_row['value'].strip() or not c_row['value'].strip():
                return jsonify(status='failed', error='Telegram bot token or chat ID is not configured.'), 400
        err = dispatch_telegram(path, 'SYSTEM', 'info', 'test_notification', '✅ Sentinel: Telegram alert test verification.')
        if err:
            return jsonify(status='failed', error=f"Delivery failed: {err}"), 502
        return jsonify(status='delivered', channel='telegram', message='Telegram test alert verified.')

    @app.get('/api/settings/mobile_sms')
    @admin
    def get_mobile_sms_settings():
        with connect(path) as db:
            p_row = db.execute("SELECT value FROM settings WHERE key='mobile_phone'").fetchone()
            prov_row = db.execute("SELECT value FROM settings WHERE key='mobile_provider'").fetchone()
            k_row = db.execute("SELECT value FROM settings WHERE key='mobile_api_key'").fetchone()
            sid_row = db.execute("SELECT value FROM settings WHERE key='mobile_account_sid'").fetchone()
            from_row = db.execute("SELECT value FROM settings WHERE key='mobile_from_number'").fetchone()
            phone = p_row['value'] if p_row else ''
            provider = prov_row['value'] if prov_row else 'fast2sms'
            has_key = bool(k_row and k_row['value'].strip())
            masked_key = (k_row['value'][:4] + '...' + k_row['value'][-4:]) if has_key and len(k_row['value']) > 8 else ('****' if has_key else '')
            account_sid = sid_row['value'] if sid_row else ''
            masked_sid = (account_sid[:6] + '...' + account_sid[-4:]) if account_sid and len(account_sid) > 10 else ('****' if account_sid else '')
            from_number = from_row['value'] if from_row else ''
            if provider == 'twilio':
                configured = bool(phone and has_key and account_sid and from_number)
            else:
                configured = bool(phone and has_key)
        return jsonify(configured=configured, phone_number=phone, provider=provider, masked_key=masked_key,
                       account_sid=masked_sid, from_number=from_number)

    @app.post('/api/settings/mobile_sms')
    @admin
    def set_mobile_sms_settings():
        data = request.get_json(silent=True) or {}
        phone = str(data.get('phone_number', '')).strip()
        provider = str(data.get('provider', '')).strip().lower()
        if provider and provider not in ('fast2sms', 'whatsapp', 'twilio'):
            abort(400, 'Unknown notification provider.')
        api_key = str(data.get('api_key', '')).strip()
        account_sid = str(data.get('account_sid', '')).strip()
        from_number = str(data.get('from_number', '')).strip()
        test = bool(data.get('test'))
        with connect(path) as db:
            if phone:
                db.execute("INSERT OR REPLACE INTO settings (key, value) VALUES ('mobile_phone', ?)", (phone,))
            if provider:
                db.execute("INSERT OR REPLACE INTO settings (key, value) VALUES ('mobile_provider', ?)", (provider,))
            if api_key:
                db.execute("INSERT OR REPLACE INTO settings (key, value) VALUES ('mobile_api_key', ?)", (api_key,))
            if account_sid:
                db.execute("INSERT OR REPLACE INTO settings (key, value) VALUES ('mobile_account_sid', ?)", (account_sid,))
            if from_number:
                db.execute("INSERT OR REPLACE INTO settings (key, value) VALUES ('mobile_from_number', ?)", (from_number,))
        test_result = None
        if test:
            err = dispatch_mobile_sms(path, 'SYSTEM', 'info', 'test_notification', 'Sentinel EDR: Mobile alert verification successful.')
            if err:
                return jsonify(status='saved_but_test_failed', test_error=err), 502
            test_result = 'delivered'
        return jsonify(status='saved', test_status=test_result)

    @app.post('/api/settings/mobile_sms/test')
    @admin
    def test_mobile_sms_settings():
        with connect(path) as db:
            phone_row = db.execute("SELECT value FROM settings WHERE key='mobile_phone'").fetchone()
            prov_row = db.execute("SELECT value FROM settings WHERE key='mobile_provider'").fetchone()
            key_row = db.execute("SELECT value FROM settings WHERE key='mobile_api_key'").fetchone()
            provider = (prov_row['value'].strip() if prov_row else 'fast2sms').lower()
            if not phone_row or not key_row or not phone_row['value'].strip() or not key_row['value'].strip():
                return jsonify(status='failed', error='Phone number or API key is not configured.'), 400
            if provider == 'twilio':
                sid_row = db.execute("SELECT value FROM settings WHERE key='mobile_account_sid'").fetchone()
                from_row = db.execute("SELECT value FROM settings WHERE key='mobile_from_number'").fetchone()
                if not sid_row or not from_row or not sid_row['value'].strip() or not from_row['value'].strip():
                    return jsonify(status='failed', error='Twilio Account SID or From Number is missing.'), 400
        err = dispatch_mobile_sms(path, 'SYSTEM', 'info', 'test_notification', 'Sentinel EDR: Mobile alert verification test.')
        if err:
            return jsonify(status='failed', error=f"Delivery failed: {err}"), 502
        return jsonify(status='delivered', provider=provider, message='Mobile alert test verified.')

    @app.get('/api/settings/process_allowlist')
    @admin
    def get_process_allowlist():
        with connect(path) as db:
            row = db.execute("SELECT value FROM settings WHERE key='process_allowlist'").fetchone()
            items = [x.strip() for x in row['value'].split(',') if x.strip()] if row and row['value'] else []
        return jsonify(allowlist=items)

    @app.post('/api/settings/process_allowlist')
    @admin
    def set_process_allowlist():
        data = request.get_json(silent=True) or {}
        items = data.get('allowlist', [])
        if not isinstance(items, list):
            abort(400, 'allowlist must be a list of process names.')
        clean_items = [str(x).strip().lower() for x in items if str(x).strip()][:100]
        with connect(path) as db:
            db.execute("INSERT OR REPLACE INTO settings (key, value) VALUES ('process_allowlist', ?)", (','.join(clean_items),))
        return jsonify(status='saved', allowlist=clean_items)

    @app.get('/api/devices/<device>/model')
    @viewer
    def get_device_model_info(device):
        with connect(path) as db:
            row = db.execute('SELECT * FROM models WHERE device_id=?', (device,)).fetchone()
            if not row:
                abort(404, 'No trained model found for this device.')
            raw_meta = row['metadata'] if 'metadata' in row.keys() and row['metadata'] else '{}'
            try:
                meta = json.loads(raw_meta)
            except Exception:
                meta = {}
            version = row['version'] if 'version' in row.keys() and row['version'] else 1
            has_prev = bool('previous_baseline' in row.keys() and row['previous_baseline'])
            return jsonify(
                device_id=device,
                version=version,
                trained_at=row['trained'],
                sample_count=row['sample_count'],
                metadata=meta,
                can_rollback=has_prev,
                accuracy_verified=False,
                accuracy_disclaimer=(
                    "Detection accuracy remains unverified: unsupervised model trained without labelled attack ground-truth. "
                    "Contamination parameter is an outlier assumption, not a 97% accuracy metric."
                )
            )

    @app.post('/api/devices/<device>/model/rollback')
    @admin
    def rollback_device_model(device):
        with connect(path) as db:
            row = db.execute('SELECT * FROM models WHERE device_id=?', (device,)).fetchone()
            if not row:
                abort(404, 'No model found for this device.')
            prev = row['previous_baseline'] if 'previous_baseline' in row.keys() else None
            if not prev:
                abort(400, 'No previous model baseline available for rollback.')
            curr_v = row['version'] if 'version' in row.keys() and row['version'] else 1
            samples = json.loads(prev)
            new_meta = json.dumps({
                'rolled_back_at': time.time(),
                'sample_count': len(samples),
                'note': f'Rolled back from version {curr_v}'
            })
            db.execute(
                'UPDATE models SET baseline=?, sample_count=?, trained=?, version=?, metadata=?, previous_baseline=NULL WHERE device_id=?',
                (prev, len(samples), time.time(), max(1, curr_v - 1), new_meta, device)
            )
            cache.pop(device, None)
        return jsonify(status='rolled_back', device_id=device, version=max(1, curr_v - 1))

    @app.get('/reports/audit')
    @viewer
    def audit_report():
        with connect(path) as db:
            now = time.time()
            devices = []
            for d in db.execute('SELECT id, created FROM devices ORDER BY id'):
                row = db.execute('SELECT * FROM telemetry WHERE device_id=? ORDER BY observed DESC, id DESC LIMIT 1', (d['id'],)).fetchone()
                model = db.execute('SELECT trained, sample_count FROM models WHERE device_id=?', (d['id'],)).fetchone()
                payload = json.loads(row['payload']) if row else {}
                online = bool(row and (now - row['received'] < 60) and (now - row['observed'] < 120))
                devices.append({
                    'id': d['id'],
                    'created': d['created'],
                    'online': online,
                    'last_seen': row['received'] if row else None,
                    'telemetry': payload,
                    'model': dict(model) if model else None
                })
            alerts = [dict(r) for r in db.execute('SELECT * FROM alerts ORDER BY id DESC LIMIT 200')]
            open_alerts_count = db.execute('SELECT COUNT(*) FROM alerts WHERE acknowledged=0').fetchone()[0]
            commands = [dict(r) for r in db.execute('SELECT * FROM commands ORDER BY id DESC LIMIT 50')]

            critical_alerts = sum(1 for a in alerts if a['severity'] == 'critical')
            high_alerts = sum(1 for a in alerts if a['severity'] == 'high')
            score = max(0, 100 - (critical_alerts * 15 + high_alerts * 8 + open_alerts_count * 3))

            summary = {
                'total_devices': len(devices),
                'online_devices': sum(1 for d in devices if d['online']),
                'total_alerts': len(alerts),
                'open_alerts': open_alerts_count,
                'critical_alerts': critical_alerts,
                'high_alerts': high_alerts,
                'compliance_score': score,
                'heuristic_risk_score': score,
                'generated_at': time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime()),
                'threat_processes': sum(1 for a in alerts if a['kind'].startswith('threat_')),
                'dlp_events': sum(1 for a in alerts if a['kind'].startswith('dlp_') or a['kind'].startswith('policy_'))
            }
        return render_template('report.html', summary=summary, devices=devices, alerts=alerts, commands=commands)

    # ------------------------------------------------------------------------
    # Phase 4: Authentication, Individual Accounts, Sessions & Audit Logs
    # ------------------------------------------------------------------------

    @app.post('/api/auth/login')
    def api_login():
        data = request.get_json(silent=True) or {}
        username = str(data.get('username', '')).strip().lower()
        password = str(data.get('password', ''))
        totp_code = str(data.get('totp_code', '')).strip()
        client_ip = request.remote_addr or 'unknown'
        if auth_limiter.is_blocked(client_ip):
            abort(429, 'Too many failed login attempts; retry later.')
        if not username or not password:
            abort(400, 'Username and password are required.')
        now = time.time()
        with connect(path) as db:
            db.execute('BEGIN IMMEDIATE')
            user = db.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
            if not user or not verify_password(password, user['password_hash']):
                auth_limiter.record_failure(client_ip)
                log_audit(db, username, 'login', username, 'failed', 'Invalid username or password', client_ip)
                db.commit()
                abort(401, 'Invalid credentials.')

            if user['mfa_enabled']:
                step = next((step for step in (int(now // 30)-1, int(now // 30), int(now // 30)+1)
                             if hmac.compare_digest(get_totp_code(user['totp_secret'], step), totp_code)), None)
                if step is None or step <= user['totp_last_step']:
                    auth_limiter.record_failure(client_ip)
                    log_audit(db, username, 'login_mfa', username, 'failed', 'Invalid or missing MFA TOTP code', client_ip)
                    db.commit()
                    abort(401, 'Valid MFA TOTP code required.')

            if user['mfa_enabled']:
                db.execute('UPDATE users SET totp_last_step=? WHERE username=?', (step, username))
            auth_limiter.record_success(client_ip)
            session_token = secrets.token_urlsafe(32)
            ttl = 86400.0  # 24 hour session
            db.execute(
                "INSERT INTO sessions (token_hash, username, role, created, expires_at, revoked) VALUES (?, ?, ?, ?, ?, 0)",
                (digest(session_token), username, user['role'], now, now + ttl)
            )
            log_audit(db, username, 'login', username, 'success', f"User logged in with role {user['role']}", client_ip)
        return jsonify(status='authenticated', session_token=session_token, username=username, role=user['role'])

    @app.post('/api/auth/logout')
    @viewer
    def api_logout():
        token_str = bearer()
        if token_str:
            with connect(path) as db:
                db.execute("UPDATE sessions SET revoked=1 WHERE token_hash=?", (digest(token_str),))
                log_audit(db, getattr(g, 'current_user', 'unknown'), 'logout', 'session', 'success')
        return jsonify(status='logged_out')

    @app.get('/api/users')
    @admin
    def list_users():
        with connect(path) as db:
            rows = db.execute("SELECT username, role, mfa_enabled, created, updated_at FROM users ORDER BY username").fetchall()
        return jsonify(users=[dict(r) for r in rows])

    @app.post('/api/users')
    @admin
    def create_user():
        data = request.get_json(silent=True) or {}
        username = str(data.get('username', '')).strip().lower()
        password = str(data.get('password', ''))
        role = str(data.get('role', 'viewer')).strip().lower()
        if not re.fullmatch(r'[a-z0-9_.-]{3,32}', username):
            abort(400, 'Username must be 3-32 alphanumeric characters.')
        if len(password) < 8:
            abort(400, 'Password must be at least 8 characters.')
        if role not in ROLE_LEVELS:
            abort(400, f"Role must be one of: {list(ROLE_LEVELS.keys())}")
        now = time.time()
        with connect(path) as db:
            exists = db.execute("SELECT 1 FROM users WHERE username=?", (username,)).fetchone()
            if exists:
                abort(409, f"User '{username}' already exists.")
            db.execute(
                "INSERT INTO users (username, password_hash, role, created, updated_at) VALUES (?, ?, ?, ?, ?)",
                (username, hash_password(password), role, now, now)
            )
            log_audit(db, getattr(g, 'current_user', 'admin'), 'create_user', username, 'success', f"Role: {role}")
        return jsonify(status='created', username=username, role=role), 201

    @app.delete('/api/users/<user_to_delete>')
    @admin
    def delete_user(user_to_delete):
        user_to_delete = user_to_delete.strip().lower()
        if user_to_delete == 'admin':
            abort(400, "Cannot delete default 'admin' account.")
        with connect(path) as db:
            db.execute("DELETE FROM sessions WHERE username=?", (user_to_delete,))
            cur = db.execute("DELETE FROM users WHERE username=?", (user_to_delete,))
            if not cur.rowcount:
                abort(404, 'User not found.')
            db.execute("UPDATE sessions SET revoked=1 WHERE username=?", (user_to_delete,))
            log_audit(db, getattr(g, 'current_user', 'admin'), 'delete_user', user_to_delete, 'success')
        return jsonify(status='deleted', username=user_to_delete)

    @app.post('/api/users/<target_user>/mfa/setup')
    @viewer
    def setup_mfa(target_user):
        target_user = target_user.strip().lower()
        if g.current_role != 'administrator' and target_user != g.current_user:
            abort(403, 'You may only enroll your own MFA.')
        with connect(path) as db:
            user = db.execute("SELECT username,mfa_enabled FROM users WHERE username=?", (target_user,)).fetchone()
            if not user:
                abort(404, 'User not found.')
            if user['mfa_enabled']:
                abort(409, 'MFA is already enabled. Use local recovery for a lost factor.')
            secret = generate_totp_secret()
            db.execute("UPDATE users SET totp_pending=? WHERE username=?", (secret, target_user))
            log_audit(db, getattr(g, 'current_user', 'admin'), 'mfa_setup', target_user, 'success')
        return jsonify(status='mfa_secret_generated', username=target_user, totp_secret=secret)

    @app.post('/api/users/<target_user>/mfa/enable')
    @viewer
    def enable_mfa(target_user):
        target_user = target_user.strip().lower()
        if g.current_role != 'administrator' and target_user != g.current_user:
            abort(403, 'You may only enroll your own MFA.')
        data = request.get_json(silent=True) or {}
        code = str(data.get('code', '')).strip()
        with connect(path) as db:
            user = db.execute("SELECT totp_pending FROM users WHERE username=?", (target_user,)).fetchone()
            if not user or not user['totp_pending']:
                abort(400, 'MFA has not been set up for this user.')
            if not verify_totp(user['totp_pending'], code):
                abort(400, 'Invalid verification code.')
            db.execute("UPDATE users SET mfa_enabled=1, totp_secret=totp_pending, totp_pending=NULL, updated_at=? WHERE username=?", (time.time(), target_user))
            db.execute('UPDATE sessions SET revoked=1 WHERE username=?', (target_user,))
            log_audit(db, getattr(g, 'current_user', 'admin'), 'mfa_enabled', target_user, 'success')
        return jsonify(status='mfa_enabled', username=target_user)

    @app.get('/api/audit_logs')
    @analyst
    def get_audit_logs():
        limit = min(500, int(request.args.get('limit', 100)))
        with connect(path) as db:
            rows = db.execute("SELECT * FROM audit_logs ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
        return jsonify(audit_logs=[dict(r) for r in rows])

    # ------------------------------------------------------------------------
    # Phase 4: Alert Investigation Workflows & Fleet Management
    # ------------------------------------------------------------------------

    @app.get('/api/alerts')
    @viewer
    def list_alerts():
        device_id = request.args.get('device_id')
        severity = request.args.get('severity')
        kind = request.args.get('kind')
        status = request.args.get('status')
        assigned_to = request.args.get('assigned_to')
        incident_id = request.args.get('incident_id')
        search = request.args.get('search')
        limit = min(500, int(request.args.get('limit', 100)))

        query = "SELECT * FROM alerts WHERE 1=1"
        params = []
        if device_id:
            query += " AND device_id = ?"
            params.append(device_id)
        if severity:
            query += " AND severity = ?"
            params.append(severity)
        if kind:
            query += " AND kind = ?"
            params.append(kind)
        if status == 'open':
            query += " AND acknowledged = 0"
        elif status == 'acknowledged':
            query += " AND acknowledged = 1"
        if assigned_to:
            query += " AND assigned_to = ?"
            params.append(assigned_to)
        if incident_id:
            query += " AND incident_id = ?"
            params.append(incident_id)
        if search:
            query += " AND (message LIKE ? OR kind LIKE ?)"
            params.extend([f"%{search}%", f"%{search}%"])

        query += " ORDER BY id DESC LIMIT ?"
        params.append(limit)

        with connect(path) as db:
            rows = db.execute(query, params).fetchall()
        return jsonify(alerts=[dict(r) for r in rows])

    @app.post('/api/alerts/<int:alert_id>/assign')
    @analyst
    def assign_alert(alert_id):
        data = request.get_json(silent=True) or {}
        assigned_to = str(data.get('assigned_to', '')).strip()
        with connect(path) as db:
            cur = db.execute("UPDATE alerts SET assigned_to=? WHERE id=?", (assigned_to or None, alert_id))
            if not cur.rowcount:
                abort(404, 'Alert not found.')
            log_audit(db, getattr(g, 'current_user', 'analyst'), 'assign_alert', str(alert_id), 'success', f"Assigned to {assigned_to}")
        return jsonify(status='assigned', alert_id=alert_id, assigned_to=assigned_to)

    @app.post('/api/alerts/<int:alert_id>/notes')
    @analyst
    def update_alert_notes(alert_id):
        data = request.get_json(silent=True) or {}
        notes = str(data.get('notes', '')).strip()[:1000]
        with connect(path) as db:
            cur = db.execute("UPDATE alerts SET notes=? WHERE id=?", (notes, alert_id))
            if not cur.rowcount:
                abort(404, 'Alert not found.')
            log_audit(db, getattr(g, 'current_user', 'analyst'), 'update_alert_notes', str(alert_id), 'success')
        return jsonify(status='updated', alert_id=alert_id, notes=notes)

    @app.post('/api/alerts/<int:alert_id>/group')
    @analyst
    def group_alert_incident(alert_id):
        data = request.get_json(silent=True) or {}
        incident_id = str(data.get('incident_id', '')).strip()[:64]
        with connect(path) as db:
            cur = db.execute("UPDATE alerts SET incident_id=? WHERE id=?", (incident_id or None, alert_id))
            if not cur.rowcount:
                abort(404, 'Alert not found.')
            log_audit(db, getattr(g, 'current_user', 'analyst'), 'group_alert', str(alert_id), 'success', f"Incident: {incident_id}")
        return jsonify(status='grouped', alert_id=alert_id, incident_id=incident_id)

    @app.post('/api/devices/<device_id>/group')
    @admin
    def set_device_group(device_id):
        data = request.get_json(silent=True) or {}
        group_name = str(data.get('group', 'default')).strip()[:64]
        with connect(path) as db:
            cur = db.execute("UPDATE devices SET device_group=? WHERE id=?", (group_name, device_id))
            if not cur.rowcount:
                abort(404, 'Device not found.')
            log_audit(db, getattr(g, 'current_user', 'admin'), 'set_device_group', device_id, 'success', f"Group: {group_name}")
        return jsonify(status='updated', device_id=device_id, group=group_name)

    @app.post('/api/devices/<device_id>/maintenance')
    @analyst
    def set_device_maintenance(device_id):
        data = request.get_json(silent=True) or {}
        duration_seconds = float(data.get('duration_seconds', 3600))
        now = time.time()
        until = now + duration_seconds
        with connect(path) as db:
            cur = db.execute("UPDATE devices SET maintenance_window_until=? WHERE id=?", (until, device_id))
            if not cur.rowcount:
                abort(404, 'Device not found.')
            db.execute("INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)", (f'maint_{device_id}', str(until)))
            log_audit(db, getattr(g, 'current_user', 'analyst'), 'set_device_maintenance', device_id, 'success', f"Duration: {duration_seconds}s")
        return jsonify(status='maintenance_active', device_id=device_id, until=until)

    @app.get('/api/fleet/groups')
    @viewer
    def fleet_groups():
        now = time.time()
        with connect(path) as db:
            groups = {}
            for d in db.execute("SELECT id, device_group FROM devices ORDER BY id"):
                grp = d['device_group'] or 'default'
                if grp not in groups:
                    groups[grp] = {'total': 0, 'online': 0, 'devices': []}
                groups[grp]['total'] += 1
                row = db.execute("SELECT received, observed FROM telemetry WHERE device_id=? ORDER BY observed DESC, id DESC LIMIT 1", (d['id'],)).fetchone()
                is_online = bool(row and (now - row['received'] < 60) and (now - row['observed'] < 120))
                if is_online:
                    groups[grp]['online'] += 1
                groups[grp]['devices'].append({'id': d['id'], 'online': is_online})
        return jsonify(groups=groups)

    @app.get('/api/fleet/inventory')
    @viewer
    def fleet_inventory():
        with connect(path) as db:
            versions = {}
            for d in db.execute("SELECT id, agent_version FROM devices"):
                ver = d['agent_version'] or '1.0.0'
                versions[ver] = versions.get(ver, 0) + 1
        return jsonify(agent_versions=versions)

    return app


def backup_database(src_path, dst_path):
    """Safely back up live SQLite database to a destination file using the SQLite Online Backup API."""
    src_path = Path(src_path)
    dst_path = Path(dst_path)
    dst_path.parent.mkdir(parents=True, exist_ok=True)
    with connect(src_path) as src_conn:
        with sqlite3.connect(str(dst_path)) as dst_conn:
            src_conn.backup(dst_conn)
    return dst_path


def restore_database(backup_path, target_path):
    """Restore database from backup, verifying integrity of the backup before replacing target."""
    backup_path = Path(backup_path)
    target_path = Path(target_path)
    if not backup_path.exists():
        raise FileNotFoundError(f"Backup file not found: {backup_path}")
    with sqlite3.connect(str(backup_path)) as bkp:
        res = bkp.execute('PRAGMA quick_check(1)').fetchone()
        if not res or res[0] != 'ok':
            raise ValueError(f"Corrupt backup file: {res[0] if res else 'Unknown error'}")

    target_path.parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(str(backup_path)) as src:
        with sqlite3.connect(str(target_path)) as dst:
            src.backup(dst)
    return target_path


def prune_database(db_path, days=30):
    """Safely clean up old telemetry, acknowledged alerts, and delivered notifications older than retention window."""
    cutoff = time.time() - (days * 86400)
    with connect(db_path) as db:
        t_cur = db.execute("DELETE FROM telemetry WHERE received < ?", (cutoff,))
        a_cur = db.execute("DELETE FROM alerts WHERE acknowledged = 1 AND created < ?", (cutoff,))
        n_cur = db.execute("DELETE FROM notification_queue WHERE status IN ('delivered', 'failed') AND updated_at < ?", (cutoff,))
        c_cur = db.execute("DELETE FROM commands WHERE status IN ('succeeded', 'failed', 'expired') AND updated_at < ?", (cutoff,))
        try:
            db.execute("PRAGMA incremental_vacuum(100)")
        except Exception:
            pass
    return {
        'telemetry_deleted': t_cur.rowcount,
        'alerts_deleted': a_cur.rowcount,
        'notifications_deleted': n_cur.rowcount,
        'commands_deleted': c_cur.rowcount,
        'cutoff': cutoff
    }


def train_device(directory, device, limit=1000):
    with connect(Path(directory) / 'sentinel.db') as db:
        rows = db.execute('SELECT payload FROM telemetry WHERE device_id=? ORDER BY id DESC LIMIT ?', (device, limit)).fetchall()
        samples = [json.loads(row['payload']) for row in reversed(rows)]
        samples = [s for s in samples if s['connections'] is not None]
        detection.train(samples)
        existing = db.execute('SELECT * FROM models WHERE device_id=?', (device,)).fetchone()
        version = (existing['version'] + 1) if existing and 'version' in existing.keys() and existing['version'] else 1
        prev_baseline = existing['baseline'] if existing else None
        meta = json.dumps({
            'trained_at': time.time(),
            'sample_count': len(samples),
            'features': detection.FEATURES,
            'contamination': 0.03,
            'accuracy_verified': False,
            'accuracy_statement': 'Unsupervised Isolation Forest baseline. Contamination parameter denotes outlier assumption, not 97% accuracy.'
        })
        db.execute(
            'INSERT OR REPLACE INTO models (device_id, trained, baseline, sample_count, version, metadata, previous_baseline) '
            'VALUES (?,?,?,?,?,?,?)',
            (device, time.time(), json.dumps(samples), len(samples), version, meta, prev_baseline)
        )
    return len(samples)


def demo(directory):
    import random
    import uuid
    device = 'DEMO-' + secrets.token_hex(3)
    token = register(directory, device)
    client = create_app(directory).test_client()
    headers = {'Authorization': 'Bearer '+token, 'X-Device-ID': device}
    rng = random.Random(42)
    def sample(cpu, connections, failures=0):
        return {'sample_id': uuid.uuid4().hex, 'observed': time.time(), 'cpu': cpu,
                'ram': rng.uniform(35, 50), 'process_count': rng.randint(90, 110),
                'connections': connections, 'bytes_per_second': rng.uniform(1000, 5000),
                'failed_logins': failures, 'processes': [{'pid': 123, 'name': 'SIMULATED-process'}],
                'warnings': ['SIMULATED DATA: generated for demonstration, not a real device.']}
    for _ in range(80):
        response = client.post('/api/telemetry', headers=headers, json=sample(rng.uniform(10, 30), rng.randint(5, 15)))
        assert response.status_code == 201
    train_device(directory, device)
    response = client.post('/api/telemetry', headers=headers, json=sample(99, 800, 5))
    assert response.status_code == 201
    return device


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--data-dir', type=Path, default=DATA)
    subs = parser.add_subparsers(dest='command', required=True)
    subs.add_parser('init')
    reg = subs.add_parser('register'); reg.add_argument('device'); reg.add_argument('--token', default=None); reg.add_argument('--overwrite', action='store_true')
    revoke_cmd = subs.add_parser('rotate'); revoke_cmd.add_argument('device')
    rev_cmd = subs.add_parser('revoke'); rev_cmd.add_argument('device')
    subs.add_parser('rotate-admin')
    ens = subs.add_parser('ensure-device'); ens.add_argument('device')
    subs.add_parser('migrate')
    del_p = subs.add_parser('delete'); del_p.add_argument('device')
    training = subs.add_parser('train'); training.add_argument('device'); training.add_argument('--limit', type=int, default=1000)
    subs.add_parser('demo')
    bkp = subs.add_parser('backup'); bkp.add_argument('--out', required=True, type=Path)
    rst = subs.add_parser('restore'); rst.add_argument('backup_path', type=Path)
    prn = subs.add_parser('prune'); prn.add_argument('--days', type=int, default=30)
    serve = subs.add_parser('serve'); serve.add_argument('--host', default=os.environ.get('HOST', '127.0.0.1')); serve.add_argument('--port', type=int, default=int(os.environ.get('PORT', 8000)))
    args = parser.parse_args()
    try:
        if args.command == 'init':
            print('ADMIN PASSWORD for username admin (save privately; shown only once):\n'+initialize(args.data_dir))
        elif args.command == 'migrate':
            with connect(args.data_dir / 'sentinel.db') as db:
                apply_schema(db)
            print('Schema migration complete.')
        elif args.command == 'ensure-device':
            created = ensure_device(args.data_dir, args.device, os.environ.get('SENTINEL_DEFAULT_TOKEN'))
            print('Device registered.' if created else 'Device already registered; credentials preserved.')
            if created and not os.environ.get('SENTINEL_DEFAULT_TOKEN'):
                print('DEVICE TOKEN (store privately):\n' + created)
        elif args.command == 'register':
            print('DEVICE TOKEN (save privately; shown only once):\n'+register(args.data_dir, args.device, args.token, overwrite=args.overwrite))
        elif args.command == 'rotate':
            token = rotate_device_token(args.data_dir, args.device)
            print('NEW DEVICE TOKEN (save privately; shown only once):\n'+token)
        elif args.command == 'revoke':
            revoke_device_token(args.data_dir, args.device)
            print(f'Revoked device token for: {args.device}')
        elif args.command == 'rotate-admin':
            new_admin_tok = rotate_admin_token(args.data_dir)
            print('NEW ADMIN PASSWORD for username admin (save privately; shown only once):\n'+new_admin_tok)
        elif args.command == 'delete':
            with connect(args.data_dir/'sentinel.db') as db:
                db.execute('DELETE FROM telemetry WHERE device_id=?', (args.device,))
                db.execute('DELETE FROM alerts WHERE device_id=?', (args.device,))
                db.execute('DELETE FROM models WHERE device_id=?', (args.device,))
                db.execute('DELETE FROM commands WHERE device_id=?', (args.device,))
                cur = db.execute('DELETE FROM devices WHERE id=?', (args.device,))
                if not cur.rowcount: raise ValueError('Unknown device')
            print('Deleted device: '+args.device)
        elif args.command == 'train':
            print(f'Trained on {train_device(args.data_dir, args.device, args.limit)} samples.')
        elif args.command == 'demo':
            print('Created simulated device: '+demo(args.data_dir))
        elif args.command == 'backup':
            out_file = backup_database(args.data_dir / 'sentinel.db', args.out)
            print(f'Database backup completed successfully to: {out_file}')
        elif args.command == 'restore':
            restored = restore_database(args.backup_path, args.data_dir / 'sentinel.db')
            print(f'Database restored successfully from: {restored}')
        elif args.command == 'prune':
            res = prune_database(args.data_dir / 'sentinel.db', days=args.days)
            print(f"Database pruned: {res['telemetry_deleted']} telemetry, {res['alerts_deleted']} alerts, {res['notifications_deleted']} notifications, {res['commands_deleted']} commands.")
        else:
            from waitress import serve
            app = create_app(args.data_dir)
            app.heartbeat_monitor.start()
            app.notification_worker.start()
            print(f'Sentinel listening at http://{args.host}:{args.port}', flush=True)
            try:
                serve(app, host=args.host, port=args.port, threads=4)
            finally:
                app.heartbeat_monitor.stop()
                app.notification_worker.stop()
    except (ValueError, FileNotFoundError, sqlite3.Error) as exc:
        parser.exit(1, str(exc)+'\n')


if __name__ == '__main__':
    main()
