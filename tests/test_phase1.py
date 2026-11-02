"""Comprehensive regression tests for Phase 1 — Security and Correctness."""
import json
import math
import os
from pathlib import Path
import time
import uuid
import pytest

import server
from agent import (
    safe_terminate_process,
    CommandReceiptStore,
    trigger_popup,
    validate_url
)


@pytest.fixture
def phase1_env(tmp_path):
    admin_token = server.initialize(tmp_path)
    device_token = server.register(tmp_path, 'DEV-SEC-01')
    app = server.create_app(tmp_path)
    app.testing = True
    client = app.test_client()
    session_token = client.post('/api/auth/login', json={'username':'admin','password':admin_token}).get_json()['session_token']
    admin_hdr = {'Authorization': f'Bearer {session_token}'}
    device_hdr = {'Authorization': f'Bearer {device_token}', 'X-Device-ID': 'DEV-SEC-01'}
    return tmp_path, app, client, admin_token, device_token, admin_hdr, device_hdr


def make_payload(**kwargs):
    base = {
        'sample_id': uuid.uuid4().hex,
        'observed': time.time(),
        'cpu': 15.0,
        'ram': 35.0,
        'process_count': 50,
        'connections': 5,
        'bytes_per_second': 1200.0,
        'failed_logins': 0,
        'processes': [{'pid': 500, 'name': 'python', 'create_time': time.time() - 100}]
    }
    base.update(kwargs)
    return base


# ============================================================================
# 1. Credentials, Idempotent Registration, Rotation, Revocation
# ============================================================================

def test_registration_idempotency(phase1_env):
    """Existing devices must not have their tokens silently overwritten."""
    path, _, client, _, _, admin_hdr, _ = phase1_env

    # Direct registration attempt for existing device should fail with 409 Conflict
    res = client.post('/api/devices/register', headers=admin_hdr, json={'device_id': 'DEV-SEC-01'})
    assert res.status_code == 409
    assert 'already registered' in res.get_json()['error']

    # Server Python function must raise ValueError
    with pytest.raises(ValueError, match="already registered"):
        server.register(path, 'DEV-SEC-01')

    # Explicit overwrite flag allows updating credentials
    res_overwrite = client.post(
        '/api/devices/register',
        headers=admin_hdr,
        json={'device_id': 'DEV-SEC-01', 'overwrite': True}
    )
    assert res_overwrite.status_code == 201
    new_token = res_overwrite.get_json()['token']
    assert len(new_token) > 20


def test_device_token_rotation_and_revocation(phase1_env):
    """Explicit device token rotation and revocation endpoints bar old credentials."""
    path, _, client, _, old_dev_tok, admin_hdr, device_hdr = phase1_env

    # Old token works initially
    p = make_payload()
    res1 = client.post('/api/telemetry', headers=device_hdr, json=p)
    assert res1.status_code == 201

    # Rotate device token via API
    rot_res = client.post('/api/devices/DEV-SEC-01/rotate', headers=admin_hdr)
    assert rot_res.status_code == 200
    new_dev_tok = rot_res.get_json()['token']
    assert new_dev_tok != old_dev_tok

    # Old token is immediately rejected
    res_old = client.post('/api/telemetry', headers=device_hdr, json=make_payload())
    assert res_old.status_code == 401

    # New token works
    new_hdr = {'Authorization': f'Bearer {new_dev_tok}', 'X-Device-ID': 'DEV-SEC-01'}
    res_new = client.post('/api/telemetry', headers=new_hdr, json=make_payload())
    assert res_new.status_code == 201

    # Revoke device token via API
    rev_res = client.post('/api/devices/DEV-SEC-01/revoke', headers=admin_hdr)
    assert rev_res.status_code == 200

    # Revoked token is barred
    res_rev = client.post('/api/telemetry', headers=new_hdr, json=make_payload())
    assert res_rev.status_code == 401


def test_admin_token_rotation(phase1_env):
    """Admin token recovery/rotation updates config and invalidates old token."""
    path, _, client, old_admin_token, _, admin_hdr, _ = phase1_env

    new_admin = server.rotate_admin_token(path)
    assert new_admin != old_admin_token

    # Old admin token rejected
    assert client.get('/api/overview', headers=admin_hdr).status_code == 401

    # New admin token accepted
    new_session = client.post('/api/auth/login',json={'username':'admin','password':new_admin}).get_json()['session_token']
    new_admin_hdr = {'Authorization': f'Bearer {new_session}'}
    assert client.get('/api/overview', headers=new_admin_hdr).status_code == 200


# ============================================================================
# 2. Query String Credentials Rejected & Rate Limiting
# ============================================================================

def test_query_param_auth_rejected(phase1_env):
    """Token query param fallback ?token= must be strictly rejected."""
    _, _, client, admin_token, _, _, _ = phase1_env

    res = client.get(f'/api/overview?token={admin_token}')
    assert res.status_code == 401
    assert 'Administrator authentication required' in res.get_json()['error']

    res2 = client.get(f'/reports/audit?token={admin_token}')
    assert res2.status_code == 401


def test_auth_rate_limiting(phase1_env):
    """Repeated failed authentication attempts trigger HTTP 429 Too Many Requests."""
    _, _, client, _, _, _, _ = phase1_env
    bad_hdr = {'Authorization': 'Bearer WRONG_TOKEN'}

    for _ in range(10):
        r = client.get('/api/overview', headers=bad_hdr)
        assert r.status_code == 401

    # 11th attempt must be rate-limited
    r_limited = client.get('/api/overview', headers=bad_hdr)
    assert r_limited.status_code == 429
    assert 'Too many failed authentication attempts' in r_limited.get_json()['error']


# ============================================================================
# 3. Reliable Remote Commands (Lifecycle, States, Expiry, Acks)
# ============================================================================

def test_command_lifecycle_and_acks(phase1_env):
    """Verify queued -> delivered -> retried -> acknowledged lifecycle."""
    path, _, client, _, _, admin_hdr, device_hdr = phase1_env

    # 1. Admin queues a command
    q_res = client.post(
        '/api/devices/DEV-SEC-01/send_alert',
        headers=admin_hdr,
        json={'title': 'Drill', 'message': 'Safety drill notification.'}
    )
    assert q_res.status_code == 200
    cmd_id = q_res.get_json()['command_id']

    with server.connect(path / 'sentinel.db') as db:
        row = db.execute('SELECT status, attempts FROM commands WHERE id=?', (cmd_id,)).fetchone()
        assert row['status'] == 'queued'
        assert row['attempts'] == 0

    # 2. Ingest fetches command; status changes to 'delivered' with attempt incremented
    hb1 = client.post('/api/telemetry', headers=device_hdr, json=make_payload())
    assert hb1.status_code == 201
    cmds = hb1.get_json().get('commands', [])
    assert len(cmds) == 1 and cmds[0]['id'] == cmd_id

    with server.connect(path / 'sentinel.db') as db:
        row = db.execute('SELECT status, attempts FROM commands WHERE id=?', (cmd_id,)).fetchone()
        assert row['status'] == 'delivered'
        assert row['attempts'] == 1

    # 3. Duplicate telemetry without ack still retries pending command
    hb2 = client.post('/api/telemetry', headers=device_hdr, json=make_payload())
    assert len(hb2.get_json().get('commands', [])) == 1

    # 4. Device sends authenticated acknowledgement
    ack = client.post(
        f'/api/commands/{cmd_id}/ack',
        headers=device_hdr,
        json={'status': 'succeeded', 'result': 'Notification displayed'}
    )
    assert ack.status_code == 200
    assert ack.get_json()['status'] == 'recorded'

    with server.connect(path / 'sentinel.db') as db:
        row = db.execute('SELECT status, result FROM commands WHERE id=?', (cmd_id,)).fetchone()
        assert row['status'] == 'succeeded'
        assert 'Notification displayed' in row['result']

    # 5. Subsequent heartbeat has no pending commands
    hb3 = client.post('/api/telemetry', headers=device_hdr, json=make_payload())
    assert hb3.get_json().get('commands', []) == []


def test_command_expiration(phase1_env):
    """Overdue unacknowledged commands transition to expired."""
    path, _, client, _, _, admin_hdr, device_hdr = phase1_env

    q_res = client.post(
        '/api/devices/DEV-SEC-01/send_alert',
        headers=admin_hdr,
        json={'message': 'Urgent notice'}
    )
    cmd_id = q_res.get_json()['command_id']

    # Set expires_at to 10 seconds in the past
    with server.connect(path / 'sentinel.db') as db:
        db.execute('UPDATE commands SET expires_at=? WHERE id=?', (time.time() - 10, cmd_id))

    # Next telemetry expires the command and returns nothing
    hb = client.post('/api/telemetry', headers=device_hdr, json=make_payload())
    assert hb.status_code == 201
    assert hb.get_json().get('commands', []) == []

    with server.connect(path / 'sentinel.db') as db:
        row = db.execute('SELECT status FROM commands WHERE id=?', (cmd_id,)).fetchone()
        assert row['status'] == 'expired'


def test_agent_command_receipt_store(tmp_path):
    """CommandReceiptStore deduplicates duplicate delivery across restarts."""
    receipt_file = tmp_path / 'receipts.json'
    store1 = CommandReceiptStore(receipt_file)

    assert not store1.has(101)
    store1.record(101, 'succeeded', 'Process exited cleanly.')
    assert store1.has(101)
    unacked = store1.get_unacked()
    assert len(unacked) == 1 and unacked[0]['id'] == 101

    store1.mark_acked(101)
    assert len(store1.get_unacked()) == 0

    # Simulate restart by reading into new store instance
    store2 = CommandReceiptStore(receipt_file)
    assert store2.has(101)
    assert len(store2.get_unacked()) == 0


# ============================================================================
# 4. Safe Process Termination
# ============================================================================

def test_protected_process_refusal(phase1_env):
    """Refuse termination of protected system processes on server and agent."""
    _, _, client, _, _, admin_hdr, _ = phase1_env

    # Server refusal: PID 1 (init / launchd)
    r1 = client.post('/api/devices/DEV-SEC-01/kill_process', headers=admin_hdr, json={'pid': 1, 'name': 'launchd'})
    assert r1.status_code == 403
    assert 'protected critical system process' in r1.get_json()['error']

    # Server refusal: System PID 4
    r4 = client.post('/api/devices/DEV-SEC-01/kill_process', headers=admin_hdr, json={'pid': 4, 'name': 'system'})
    assert r4.status_code == 403

    # Server refusal: protected name 'csrss.exe'
    rcsrss = client.post('/api/devices/DEV-SEC-01/kill_process', headers=admin_hdr, json={'pid': 888, 'name': 'csrss.exe'})
    assert rcsrss.status_code == 403

    # Agent side refusal: PID 0 or PID 1
    ok1, msg1 = safe_terminate_process(1, 'launchd')
    assert not ok1 and 'protected process' in msg1


def test_safe_terminate_process_pid_reuse():
    """Agent detects PID reuse when process create_time mismatches target."""
    import psutil
    curr_proc = psutil.Process()
    curr_pid = curr_proc.pid
    real_create_time = curr_proc.create_time()

    # Mismatched create_time simulates PID reuse
    ok, msg = safe_terminate_process(
        target_pid=curr_pid,
        expected_name=curr_proc.name(),
        expected_create_time=real_create_time - 5000.0
    )
    assert not ok
    assert 'PID reuse detected' in msg or 'protected process' in msg


# ============================================================================
# 5. Offline Monitoring Decoupled from Dashboard
# ============================================================================

def test_offline_monitoring_independent_of_dashboard(phase1_env):
    """Heartbeat-loss detection runs without any dashboard /api/overview visits."""
    path, app, client, _, _, admin_hdr, device_hdr = phase1_env

    # Ingest one sample to establish heartbeat
    p = make_payload()
    client.post('/api/telemetry', headers=device_hdr, json=p)

    # Fast forward telemetry received timestamp by 120s
    with server.connect(path / 'sentinel.db') as db:
        db.execute('UPDATE telemetry SET received=? WHERE device_id=?', (time.time() - 120, 'DEV-SEC-01'))

    # Verify GET /api/overview remains read-only
    ro_overview = client.get('/api/overview', headers=admin_hdr).get_json()
    assert not any(a['kind'] == 'device_offline' for a in ro_overview['alerts'])

    # Scheduled worker executes independently
    with server.connect(path / 'sentinel.db') as db:
        app.heartbeat_monitor.check_devices(db, time.time())

    # Alert is now recorded in database
    overview = client.get('/api/overview', headers=admin_hdr).get_json()
    offline_alerts = [a for a in overview['alerts'] if a['kind'] == 'device_offline']
    assert len(offline_alerts) == 1
    assert "heartbeat lost" in offline_alerts[0]['message']


def test_offline_monitoring_maintenance_window(phase1_env):
    """Devices in active maintenance window do not generate offline alerts."""
    path, app, client, _, _, admin_hdr, device_hdr = phase1_env

    client.post('/api/telemetry', headers=device_hdr, json=make_payload())

    now = time.time()
    with server.connect(path / 'sentinel.db') as db:
        db.execute('UPDATE telemetry SET received=? WHERE device_id=?', (now - 120, 'DEV-SEC-01'))
        # Set maintenance window until 1 hour into future
        db.execute("INSERT OR REPLACE INTO settings (key, value) VALUES ('maintenance_window_until', ?)", (str(now + 3600),))
        app.heartbeat_monitor.check_devices(db, now)

    overview = client.get('/api/overview', headers=admin_hdr).get_json()
    offline_alerts = [a for a in overview['alerts'] if a['kind'] == 'device_offline']
    assert len(offline_alerts) == 0


# ============================================================================
# 6. Validation Hardening (NaN, Infinity, Uptime, AppleScript)
# ============================================================================

@pytest.mark.parametrize("bad_val", [float('inf'), float('-inf'), float('nan'), -5, 1e12])
def test_uptime_validation_rejection(phase1_env, bad_val):
    """Uptime=Infinity and invalid numeric values are rejected with 400."""
    _, _, client, _, _, _, device_hdr = phase1_env

    p = make_payload(uptime=bad_val)
    res = client.post('/api/telemetry', headers=device_hdr, json=p)
    assert res.status_code == 400
    assert 'Invalid uptime' in res.get_json()['error']


def test_applescript_safe_invocation():
    """trigger_popup does not crash or execute shell injection on titles with special characters."""
    from unittest.mock import patch
    weird_title = 'Alert "Quotes" & rm -rf / ; \\'
    weird_msg = 'Message with \' single and " double quotes'
    with patch('platform.system', return_value='Darwin'), patch('subprocess.run') as mock_run:
        trigger_popup(weird_title, weird_msg)
        assert mock_run.called
        call_args = mock_run.call_args[0][0]
        # Verify passed as separate list elements rather than shell interpolation
        assert call_args[0] == 'osascript'
        assert weird_title in call_args
        assert weird_msg in call_args
