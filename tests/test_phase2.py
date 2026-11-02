import json
import os
import sqlite3
import time
from unittest.mock import patch
import pytest

import server
from agent import TelemetryDiskQueue


@pytest.fixture
def phase2_env(tmp_path):
    data_dir = tmp_path / 'data'
    data_dir.mkdir(parents=True, exist_ok=True)
    admin_token = server.initialize(data_dir)
    app = server.create_app(data_dir)
    client = app.test_client()

    device_token = server.register(data_dir, 'DEV-PH2-01')

    session_token = client.post('/api/auth/login', json={'username':'admin','password':admin_token}).get_json()['session_token']
    admin_hdr = {'Authorization': f'Bearer {session_token}'}
    device_hdr = {'Authorization': f'Bearer {device_token}', 'X-Device-ID': 'DEV-PH2-01'}

    return data_dir, app, client, admin_token, device_token, admin_hdr, device_hdr


def make_payload(sample_id='SMPL-01', observed=None, **kwargs):
    p = {
        'sample_id': sample_id,
        'observed': observed if observed is not None else time.time(),
        'cpu': 20.0,
        'ram': 40.0,
        'process_count': 50,
        'connections': 10,
        'bytes_per_second': 1500.0,
        'failed_logins': 0,
        'processes': [{'pid': 1234, 'name': 'safeproc'}],
        'warnings': []
    }
    p.update(kwargs)
    return p


# ============================================================================
# 7. Durable Telemetry Buffering (Queue, Backoff, Delayed Ingest)
# ============================================================================

def test_telemetry_disk_queue_bounded_and_eviction(tmp_path):
    """Disk queue enforces max_samples limit by evicting oldest samples."""
    q_db = tmp_path / 'queue.db'
    queue = TelemetryDiskQueue(q_db, max_samples=3)

    for i in range(5):
        queue.push(make_payload(sample_id=f'S-{i}', cpu=10.0 + i))

    assert queue.size() == 3
    assert queue.stats['dropped_full'] == 2

    # Verify oldest two (S-0, S-1) were evicted, leaving S-2, S-3, S-4
    first = queue.peek()
    assert first['sample_id'] == 'S-2'


def test_telemetry_disk_queue_stale_dropping(tmp_path):
    """Disk queue automatically drops stale samples older than max_retention."""
    q_db = tmp_path / 'queue.db'
    queue = TelemetryDiskQueue(q_db, max_samples=10, max_retention=3600)  # 1 hour retention

    # Push old sample observed 2 hours ago
    queue.push(make_payload(sample_id='OLD-1', observed=time.time() - 7200))
    # Push fresh sample
    queue.push(make_payload(sample_id='FRESH-1', observed=time.time()))

    assert queue.size() == 1
    assert queue.stats['dropped_stale'] == 1
    peeked = queue.peek()
    assert peeked['sample_id'] == 'FRESH-1'


def test_telemetry_disk_queue_persistence_across_restart(tmp_path):
    """Buffered telemetry survives agent process restart."""
    q_db = tmp_path / 'queue.db'
    q1 = TelemetryDiskQueue(q_db, max_samples=10)
    q1.push(make_payload(sample_id='RESTART-01', cpu=45.0))
    q1.push(make_payload(sample_id='RESTART-02', cpu=55.0))

    # Simulate restart by destroying q1 and opening new instance on same file
    del q1
    q2 = TelemetryDiskQueue(q_db, max_samples=10)
    assert q2.size() == 2

    first = q2.peek()
    assert first['sample_id'] == 'RESTART-01'
    q2.pop('RESTART-01')
    assert q2.size() == 1

    second = q2.peek()
    assert second['sample_id'] == 'RESTART-02'


def test_telemetry_disk_queue_exponential_backoff_with_jitter(tmp_path):
    """Failures apply exponential backoff with randomized jitter."""
    q_db = tmp_path / 'queue.db'
    queue = TelemetryDiskQueue(q_db, max_samples=10)
    queue.push(make_payload(sample_id='FAIL-01'))

    now = time.time()
    queue.mark_failure('FAIL-01', error_str='Connection refused')

    with queue._connect() as db:
        row = db.execute('SELECT attempts, next_retry FROM queue WHERE sample_id="FAIL-01"').fetchone()
        assert row['attempts'] == 1
        # Base delay for attempt 1: 2.0 * 1.8^1 = 3.6s, jitter [0.8, 1.2] => [2.88, 4.32]
        delay = row['next_retry'] - now
        assert 2.5 <= delay <= 5.0

    # During backoff window, peek() returns None (not ready)
    assert queue.peek() is None


def test_offline_delayed_telemetry_acceptance_and_online_status(phase2_env):
    """Server accepts buffered telemetry up to 7 days old, but stale observation does not mark device online."""
    _, _, client, _, _, admin_hdr, device_hdr = phase2_env
    now = time.time()

    # 1. Telemetry observed 3 days ago is accepted (durable buffer delivery)
    three_days_ago = now - (3 * 86400)
    p_offline = make_payload(sample_id='OFFLINE-3D', observed=three_days_ago)
    res = client.post('/api/telemetry', headers=device_hdr, json=p_offline)
    assert res.status_code == 201
    assert res.get_json()['status'] == 'accepted'

    # 2. Delayed telemetry observation does not falsely mark device online in overview
    ov = client.get('/api/overview', headers=admin_hdr).get_json()
    dev = next(d for d in ov['devices'] if d['id'] == 'DEV-PH2-01')
    assert dev['online'] is False  # Because observation is 3 days old!

    # 3. Telemetry older than 7 days is rejected
    eight_days_ago = now - (8 * 86400)
    p_too_old = make_payload(sample_id='TOO-OLD', observed=eight_days_ago)
    res_too_old = client.post('/api/telemetry', headers=device_hdr, json=p_too_old)
    assert res_too_old.status_code == 400
    assert 'maximum retention window' in res_too_old.get_json()['error']

    # 4. Fresh telemetry (observed now) immediately marks device online
    p_live = make_payload(sample_id='LIVE-01', observed=now)
    res_live = client.post('/api/telemetry', headers=device_hdr, json=p_live)
    assert res_live.status_code == 201

    ov_live = client.get('/api/overview', headers=admin_hdr).get_json()
    dev_live = next(d for d in ov_live['devices'] if d['id'] == 'DEV-PH2-01')
    assert dev_live['online'] is True


# ============================================================================
# 8. Deployment Persistence, Backup, Restore, Health & Readiness
# ============================================================================

def test_database_backup_and_restore(phase2_env, tmp_path):
    """Database online backup and restore verify integrity and recover all tables and data."""
    data_dir, _, client, _, _, _, device_hdr = phase2_env

    # Ingest data
    client.post('/api/telemetry', headers=device_hdr, json=make_payload(sample_id='DATA-1'))

    backup_file = tmp_path / 'backup' / 'sentinel_bkp.db'
    server.backup_database(data_dir / 'sentinel.db', backup_file)
    assert backup_file.exists()

    # Verify backup with quick_check
    with sqlite3.connect(str(backup_file)) as bkp:
        assert bkp.execute('PRAGMA quick_check(1)').fetchone()[0] == 'ok'
        row = bkp.execute('SELECT COUNT(*) FROM telemetry').fetchone()
        assert row[0] >= 1

    # Restore to a new location and verify
    restore_target = tmp_path / 'restored' / 'sentinel.db'
    server.restore_database(backup_file, restore_target)
    assert restore_target.exists()

    with sqlite3.connect(str(restore_target)) as rst:
        assert rst.execute('PRAGMA quick_check(1)').fetchone()[0] == 'ok'
        assert rst.execute('SELECT COUNT(*) FROM telemetry').fetchone()[0] >= 1


def test_database_prune_retention(phase2_env):
    """Pruning removes old telemetry, acknowledged alerts, delivered notifications, and expired commands."""
    data_dir, _, client, _, _, _, device_hdr = phase2_env
    db_path = data_dir / 'sentinel.db'

    now = time.time()
    old_time = now - (40 * 86400)  # 40 days ago

    with server.connect(db_path) as db:
        # Insert old telemetry
        db.execute(
            'INSERT INTO telemetry(device_id, sample_id, received, observed, payload) VALUES (?,?,?,?,?)',
            ('DEV-PH2-01', 'OLD-TEL', old_time, old_time, json.dumps(make_payload()))
        )
        # Insert acknowledged old alert
        db.execute(
            'INSERT INTO alerts(device_id, created, kind, severity, message, acknowledged) VALUES (?,?,?,?,?,?)',
            ('DEV-PH2-01', old_time, 'test_alert', 'low', 'Old alert', 1)
        )
        # Insert delivered old notification
        db.execute(
            'INSERT INTO notification_queue(channel, device_id, severity, kind, message, status, attempts, next_retry, created, updated_at) '
            'VALUES (?,?,?,?,?,?,?,?,?,?)',
            ('all', 'DEV-PH2-01', 'low', 'test', 'msg', 'delivered', 1, old_time, old_time, old_time)
        )

    # Prune retention > 30 days
    result = server.prune_database(db_path, days=30)
    assert result['telemetry_deleted'] >= 1
    assert result['alerts_deleted'] >= 1
    assert result['notifications_deleted'] >= 1

    with server.connect(db_path) as db:
        assert db.execute('SELECT 1 FROM telemetry WHERE sample_id="OLD-TEL"').fetchone() is None


def test_health_and_readiness_endpoints(phase2_env):
    """GET /api/health and GET /api/ready return 200 when database is operational."""
    _, _, client, _, _, _, _ = phase2_env

    # Liveness check
    h_res = client.get('/api/health')
    assert h_res.status_code == 200
    assert h_res.get_json()['status'] == 'ok'

    # Readiness check
    r_res = client.get('/api/ready')
    assert r_res.status_code == 200
    assert r_res.get_json()['status'] == 'ready'
    assert r_res.get_json()['database'] == 'available'


# ============================================================================
# 9. Dependable Notifications (Worker, Retry, Twilio, Test Endpoints)
# ============================================================================

def test_notification_worker_delivery_success(phase2_env):
    """Alerts enqueue in notification_queue; NotificationWorker marks delivered on provider success."""
    data_dir, app, client, _, _, _, device_hdr = phase2_env
    db_path = data_dir / 'sentinel.db'

    # High CPU triggers alert and notification enqueue
    p = make_payload(sample_id='CPU-HIGH', cpu=98.0)
    client.post('/api/telemetry', headers=device_hdr, json=p)

    with server.connect(db_path) as db:
        queue_row = db.execute('SELECT * FROM notification_queue WHERE device_id="DEV-PH2-01"').fetchone()
        assert queue_row is not None
        assert queue_row['status'] == 'pending'

    # Mock dispatch_telegram and dispatch_mobile_sms to return None (success)
    with patch('server.dispatch_telegram', return_value=None), \
         patch('server.dispatch_mobile_sms', return_value=None):
        with server.connect(db_path) as db:
            app.notification_worker.process_queue(db, time.time())

    with server.connect(db_path) as db:
        updated_row = db.execute('SELECT * FROM notification_queue WHERE id=?', (queue_row['id'],)).fetchone()
        assert updated_row['status'] == 'delivered'
        assert updated_row['attempts'] == 1


def test_notification_worker_failure_and_retry_backoff(phase2_env):
    """Worker retries on failure with exponential backoff and caps at 5 attempts before marking failed."""
    data_dir, app, _, _, _, _, _ = phase2_env
    db_path = data_dir / 'sentinel.db'
    now = time.time()

    with server.connect(db_path) as db:
        db.execute(
            'INSERT INTO notification_queue(channel, device_id, severity, kind, message, status, attempts, next_retry, created, updated_at) '
            'VALUES (?,?,?,?,?,?,?,?,?,?)',
            ('all', 'DEV-PH2-01', 'high', 'test_fail', 'Error test', 'pending', 0, now, now, now)
        )
        notif_id = db.execute('SELECT last_insert_rowid()').fetchone()[0]

    # Process attempt 1 with error
    with patch('server.dispatch_telegram', return_value="HTTP 403 Forbidden"):
        with server.connect(db_path) as db:
            app.notification_worker.process_queue(db, now)

    with server.connect(db_path) as db:
        row = db.execute('SELECT attempts, status, next_retry, last_error FROM notification_queue WHERE id=?', (notif_id,)).fetchone()
        assert row['attempts'] == 1
        assert row['status'] == 'pending'
        assert 'HTTP 403' in row['last_error']
        assert row['next_retry'] > now  # Backoff delay scheduled

        # Advance attempts to 4
        db.execute('UPDATE notification_queue SET attempts=4, next_retry=? WHERE id=?', (now, notif_id))

    # Process attempt 5 (max) with error => transitions to 'failed'
    with patch('server.dispatch_telegram', return_value="HTTP 500 Internal Error"):
        with server.connect(db_path) as db:
            app.notification_worker.process_queue(db, now)

    with server.connect(db_path) as db:
        final_row = db.execute('SELECT attempts, status, last_error FROM notification_queue WHERE id=?', (notif_id,)).fetchone()
        assert final_row['attempts'] == 5
        assert final_row['status'] == 'failed'


def test_twilio_settings_completeness_and_masking(phase2_env):
    """Twilio requires account_sid and from_number; reports incomplete when missing."""
    _, _, client, _, _, admin_hdr, _ = phase2_env

    # 1. Initially unconfigured
    init_res = client.get('/api/settings/mobile_sms', headers=admin_hdr).get_json()
    assert init_res['configured'] is False

    # 2. Incomplete Twilio configuration (missing account_sid and from_number)
    client.post(
        '/api/settings/mobile_sms',
        headers=admin_hdr,
        json={'provider': 'twilio', 'phone_number': '+1234567890', 'api_key': 'secret_auth_token'}
    )
    incompl_res = client.get('/api/settings/mobile_sms', headers=admin_hdr).get_json()
    assert incompl_res['configured'] is False

    # 3. Complete Twilio configuration
    client.post(
        '/api/settings/mobile_sms',
        headers=admin_hdr,
        json={
            'provider': 'twilio',
            'phone_number': '+1234567890',
            'api_key': 'secret_auth_token',
            'account_sid': 'AC1234567890abcdef123456',
            'from_number': '+1987654321'
        }
    )
    compl_res = client.get('/api/settings/mobile_sms', headers=admin_hdr).get_json()
    assert compl_res['configured'] is True
    assert compl_res['from_number'] == '+1987654321'
    assert '...' in compl_res['account_sid']  # Account SID is masked


def test_notification_test_endpoints_verification(phase2_env):
    """Test notification buttons report verified delivery or pending/failed state, not unconditional success."""
    _, _, client, _, _, admin_hdr, _ = phase2_env

    # 1. Unconfigured test returns 400
    tg_unconf = client.post('/api/settings/telegram/test', headers=admin_hdr)
    assert tg_unconf.status_code == 400
    assert 'not configured' in tg_unconf.get_json()['error']

    # 2. Configure Telegram
    client.post(
        '/api/settings/telegram',
        headers=admin_hdr,
        json={'bot_token': '123456:ABC-DEF1234ghIkl-zyx57W2v1u123ew11', 'chat_id': '987654321'}
    )

    # 3. Provider failure reports 502 with error details
    with patch('server.dispatch_telegram', return_value="HTTP 401 Unauthorized: Invalid bot token"):
        fail_res = client.post('/api/settings/telegram/test', headers=admin_hdr)
        assert fail_res.status_code == 502
        assert 'Delivery failed' in fail_res.get_json()['error']

    # 4. Successful delivery returns 200 with status='delivered'
    with patch('server.dispatch_telegram', return_value=None):
        ok_res = client.post('/api/settings/telegram/test', headers=admin_hdr)
        assert ok_res.status_code == 200
        assert ok_res.get_json()['status'] == 'delivered'
