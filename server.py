"""Sentinel educational endpoint-monitoring backend. Run `python server.py --help`."""
import argparse
import hashlib
import hmac
import json
import math
import os
from pathlib import Path
import re
import secrets
import sqlite3
import threading
import time
from functools import wraps

from flask import Flask, abort, jsonify, request, render_template
from werkzeug.exceptions import HTTPException
import detection

BASE = Path(__file__).resolve().parent
DATA = Path(os.environ.get('SENTINEL_DATA', str(BASE / 'data')))
SCHEMA = '''
CREATE TABLE IF NOT EXISTS devices (
 id TEXT PRIMARY KEY, token_hash TEXT NOT NULL, created REAL NOT NULL);
CREATE TABLE IF NOT EXISTS telemetry (
 id INTEGER PRIMARY KEY AUTOINCREMENT, device_id TEXT NOT NULL REFERENCES devices(id),
 sample_id TEXT NOT NULL, received REAL NOT NULL, observed REAL NOT NULL,
 payload TEXT NOT NULL, score REAL, anomaly INTEGER NOT NULL DEFAULT 0,
 UNIQUE(device_id, sample_id));
CREATE INDEX IF NOT EXISTS telemetry_device_time ON telemetry(device_id, received);
CREATE TABLE IF NOT EXISTS alerts (
 id INTEGER PRIMARY KEY AUTOINCREMENT, device_id TEXT NOT NULL REFERENCES devices(id),
 created REAL NOT NULL, kind TEXT NOT NULL, severity TEXT NOT NULL,
 message TEXT NOT NULL, acknowledged INTEGER NOT NULL DEFAULT 0);
CREATE INDEX IF NOT EXISTS alerts_device_kind ON alerts(device_id, kind, created);
CREATE TABLE IF NOT EXISTS models (
 device_id TEXT PRIMARY KEY REFERENCES devices(id), trained REAL NOT NULL,
 baseline TEXT NOT NULL, sample_count INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS commands (
 id INTEGER PRIMARY KEY AUTOINCREMENT, device_id TEXT NOT NULL REFERENCES devices(id),
 action TEXT NOT NULL, payload TEXT NOT NULL, created REAL NOT NULL,
 executed INTEGER NOT NULL DEFAULT 0);
CREATE INDEX IF NOT EXISTS commands_device_exec ON commands(device_id, executed);
CREATE TABLE IF NOT EXISTS settings (
 key TEXT PRIMARY KEY, value TEXT NOT NULL);
'''


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


def check_process_threat(name):
    if not isinstance(name, str):
        return None
    base = os.path.basename(name).lower()
    if base.endswith('.exe'):
        base = base[:-4]
    return THREAT_SIGNATURES.get(base)


def send_telegram(db_path, device, severity, kind, message):
    def _worker():
        try:
            with connect(db_path) as db:
                token_row = db.execute("SELECT value FROM settings WHERE key='telegram_bot_token'").fetchone()
                chat_row = db.execute("SELECT value FROM settings WHERE key='telegram_chat_id'").fetchone()
                if not token_row or not chat_row:
                    return
                bot_token = token_row['value'].strip()
                chat_id = chat_row['value'].strip()
                if not bot_token or not chat_id:
                    return
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
        except Exception as exc:
            print(f"[TELEGRAM ALERT ERROR] {exc}", flush=True)

    threading.Thread(target=_worker, daemon=True).start()


def digest(token):
    return hashlib.sha256(token.encode()).hexdigest()


def connect(path):
    db = sqlite3.connect(path, timeout=30)
    db.row_factory = sqlite3.Row
    db.execute('PRAGMA foreign_keys=ON')
    return db


def initialize(directory):
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    config = directory / 'config.json'
    if config.exists():
        raise ValueError('Already initialized; existing credentials were preserved.')
    token = os.environ.get('SENTINEL_ADMIN_TOKEN') or secrets.token_urlsafe(32)
    with config.open('x') as file:
        json.dump({'admin_token_hash': digest(token)}, file)
    config.chmod(0o600)
    with connect(directory / 'sentinel.db') as db:
        db.execute('PRAGMA journal_mode=WAL')
        db.executescript(SCHEMA)
    return token


def register(directory, device_id, token=None):
    if not re.fullmatch(r'[A-Za-z0-9_-]{1,64}', device_id):
        raise ValueError('Device ID: 1–64 letters, numbers, underscores or hyphens.')
    token = token or secrets.token_urlsafe(32)
    with connect(Path(directory) / 'sentinel.db') as db:
        db.execute('INSERT OR REPLACE INTO devices VALUES (?,?,?)', (device_id, digest(token), time.time()))
    return token


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
    if abs(time.time() - clean['observed']) > 600:
        abort(400, 'Observation must be within 10 minutes of server time.')
    processes = payload.get('processes', [])
    if not isinstance(processes, list) or len(processes) > 100:
        abort(400, 'processes must contain at most 100 entries.')
    clean['processes'] = []
    for process in processes:
        if not isinstance(process, dict) or type(process.get('pid')) is not int or process['pid'] < 0 or not isinstance(process.get('name'), str) or len(process['name']) > 200:
            abort(400, 'Invalid process entry.')
        clean['processes'].append({'pid': process['pid'], 'name': process['name']})
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

    uptime = payload.get('uptime')
    if uptime is not None:
        if isinstance(uptime, bool) or not isinstance(uptime, (int, float)) or uptime < 0:
            abort(400, 'Invalid uptime.')
        clean['uptime'] = int(uptime)
    else:
        clean['uptime'] = None

    for str_key in ('os_info', 'hostname'):
        val = payload.get(str_key)
        if val is not None and isinstance(val, str) and len(val) <= 128:
            clean[str_key] = val
        else:
            clean[str_key] = None

    return clean


def create_app(directory=DATA):
    directory = Path(directory)
    config = json.loads((directory / 'config.json').read_text())
    path = directory / 'sentinel.db'
    with connect(path) as db:
        db.executescript(SCHEMA)
    app = Flask(__name__)
    app.config['MAX_CONTENT_LENGTH'] = 65536
    cache, lock = {}, threading.RLock()

    def bearer():
        header = request.headers.get('Authorization', '')
        if header.startswith('Bearer '):
            return header[7:]
        return request.args.get('token', '')

    def admin(fn):
        @wraps(fn)
        def wrapped(*args, **kwargs):
            if not hmac.compare_digest(digest(bearer()), config['admin_token_hash']):
                abort(401, 'Administrator authentication required.')
            return fn(*args, **kwargs)
        return wrapped

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
        return jsonify(status='ok')

    def alert(db, device, now, kind, severity, message):
        recent = db.execute('SELECT 1 FROM alerts WHERE device_id=? AND kind=? AND created>?',
                            (device, kind, now - 300)).fetchone()
        if not recent:
            db.execute('INSERT INTO alerts(device_id,created,kind,severity,message) VALUES (?,?,?,?,?)',
                       (device, now, kind, severity, message))
            send_telegram(path, device, severity, kind, message)

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
                return jsonify(status='duplicate', id=duplicate['id'])
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

            for proc in payload.get('processes', []):
                threat = check_process_threat(proc['name'])
                if threat:
                    tid, tech, severity, desc = threat
                    base_proc = os.path.basename(proc['name']).lower()
                    if base_proc.endswith('.exe'):
                        base_proc = base_proc[:-4]
                    alert(db, device, now, f'threat_{base_proc}', severity,
                          f"[MITRE ATT&CK {tid}: {tech}] {desc} (PID: {proc['pid']}, Process: {proc['name']})")

            cmd_rows = db.execute('SELECT id, action, payload FROM commands WHERE device_id=? AND executed=0 ORDER BY id ASC', (device,)).fetchall()
            commands_to_send = []
            if cmd_rows:
                cmd_ids = []
                for cr in cmd_rows:
                    cmd_ids.append(cr['id'])
                    item = {'id': cr['id'], 'action': cr['action']}
                    try:
                        item.update(json.loads(cr['payload']))
                    except Exception:
                        pass
                    commands_to_send.append(item)
                placeholders = ','.join('?' for _ in cmd_ids)
                db.execute(f'UPDATE commands SET executed=1 WHERE id IN ({placeholders})', cmd_ids)

            return jsonify(status='accepted', id=cursor.lastrowid, anomaly=anomalous, score=score, commands=commands_to_send), 201

    @app.get('/api/overview')
    @admin
    def overview():
        with connect(path) as db:
            devices = []
            for device in db.execute('SELECT id FROM devices ORDER BY id'):
                row = db.execute('SELECT * FROM telemetry WHERE device_id=? ORDER BY id DESC LIMIT 1', (device['id'],)).fetchone()
                model = db.execute('SELECT trained,sample_count FROM models WHERE device_id=?', (device['id'],)).fetchone()
                devices.append({'id': device['id'], 'online': bool(row and time.time()-row['received'] < 60),
                                'last_seen': row['received'] if row else None,
                                'latest': json.loads(row['payload']) if row else None,
                                'model': dict(model) if model else None})
            alerts = [dict(row) for row in db.execute('SELECT * FROM alerts ORDER BY id DESC LIMIT 100')]
            count = db.execute('SELECT COUNT(*) FROM alerts WHERE acknowledged=0').fetchone()[0]
        return jsonify(devices=devices, alerts=alerts, open_alerts=count, server_time=time.time())

    @app.get('/api/devices/<device>/history')
    @admin
    def history(device):
        with connect(path) as db:
            rows = db.execute('SELECT * FROM telemetry WHERE device_id=? ORDER BY id DESC LIMIT 120', (device,)).fetchall()
        return jsonify(samples=[dict(json.loads(row['payload']), received=row['received'], score=row['score'], anomaly=bool(row['anomaly'])) for row in reversed(rows)])

    @app.post('/api/alerts/<int:alert_id>/ack')
    @admin
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
        device_id = data.get('device_id', '').strip()
        custom_token = data.get('token')
        if not device_id:
            abort(400, 'device_id is required.')
        try:
            device_token = register(directory, device_id, custom_token)
            return jsonify(status='registered', device_id=device_id, token=device_token), 201
        except ValueError as exc:
            abort(400, str(exc))

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
        return jsonify(status='deleted', device_id=device_id)

    @app.post('/api/devices/<device>/kill_process')
    @admin
    def kill_process(device):
        data = request.get_json(silent=True) or {}
        pid = data.get('pid')
        name = str(data.get('name') or 'unknown')[:200]
        if not isinstance(pid, int) or pid <= 0:
            abort(400, 'Valid positive PID required.')
        with connect(path) as db:
            known = db.execute('SELECT id FROM devices WHERE id=?', (device,)).fetchone()
            if not known:
                abort(404, 'Device not found.')
            cmd_payload = json.dumps({'pid': pid, 'name': name})
            db.execute('INSERT INTO commands(device_id, action, payload, created, executed) VALUES (?,?,?,?,0)',
                       (device, 'kill_process', cmd_payload, time.time()))
        return jsonify(status='queued', device=device, pid=pid, name=name)

    @app.get('/api/settings/telegram')
    @admin
    def get_telegram_settings():
        with connect(path) as db:
            t_row = db.execute("SELECT value FROM settings WHERE key='telegram_bot_token'").fetchone()
            c_row = db.execute("SELECT value FROM settings WHERE key='telegram_chat_id'").fetchone()
            has_token = bool(t_row and t_row['value'].strip())
            masked_token = (t_row['value'][:6] + '...' + t_row['value'][-4:]) if has_token else ''
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
        if test:
            send_telegram(path, 'SYSTEM', 'info', 'test_notification', '✅ Sentinel: Telegram alert integration active and verified!')
        return jsonify(status='saved')

    @app.get('/reports/audit')
    @admin
    def audit_report():
        with connect(path) as db:
            devices = []
            for d in db.execute('SELECT id, created FROM devices ORDER BY id'):
                row = db.execute('SELECT * FROM telemetry WHERE device_id=? ORDER BY id DESC LIMIT 1', (d['id'],)).fetchone()
                model = db.execute('SELECT trained, sample_count FROM models WHERE device_id=?', (d['id'],)).fetchone()
                payload = json.loads(row['payload']) if row else {}
                online = bool(row and time.time() - row['received'] < 60)
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
                'generated_at': time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime()),
                'threat_processes': sum(1 for a in alerts if a['kind'].startswith('threat_'))
            }
        return render_template('report.html', summary=summary, devices=devices, alerts=alerts, commands=commands)

    return app


def train_device(directory, device, limit=1000):
    with connect(Path(directory) / 'sentinel.db') as db:
        rows = db.execute('SELECT payload FROM telemetry WHERE device_id=? ORDER BY id DESC LIMIT ?', (device, limit)).fetchall()
        samples = [json.loads(row['payload']) for row in reversed(rows)]
        samples = [s for s in samples if s['connections'] is not None]
        detection.train(samples)
        db.execute('INSERT OR REPLACE INTO models VALUES (?,?,?,?)', (device, time.time(), json.dumps(samples), len(samples)))
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
    reg = subs.add_parser('register'); reg.add_argument('device'); reg.add_argument('--token', default=None)
    revoke = subs.add_parser('rotate'); revoke.add_argument('device')
    del_p = subs.add_parser('delete'); del_p.add_argument('device')
    training = subs.add_parser('train'); training.add_argument('device'); training.add_argument('--limit', type=int, default=1000)
    subs.add_parser('demo')
    serve = subs.add_parser('serve'); serve.add_argument('--host', default=os.environ.get('HOST', '127.0.0.1')); serve.add_argument('--port', type=int, default=int(os.environ.get('PORT', 8000)))
    args = parser.parse_args()
    try:
        if args.command == 'init':
            print('ADMIN TOKEN (save privately; shown only once):\n'+initialize(args.data_dir))
        elif args.command == 'register':
            print('DEVICE TOKEN (save privately; shown only once):\n'+register(args.data_dir, args.device, args.token))
        elif args.command == 'rotate':
            token = secrets.token_urlsafe(32)
            with connect(args.data_dir/'sentinel.db') as db:
                cur = db.execute('UPDATE devices SET token_hash=? WHERE id=?', (digest(token), args.device))
                if not cur.rowcount: raise ValueError('Unknown device')
            print('NEW DEVICE TOKEN:\n'+token)
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
        else:
            from waitress import serve
            print(f'Sentinel listening at http://{args.host}:{args.port}', flush=True)
            serve(create_app(args.data_dir), host=args.host, port=args.port, threads=4)
    except (ValueError, FileNotFoundError, sqlite3.Error) as exc:
        parser.exit(1, str(exc)+'\n')


if __name__ == '__main__':
    main()
