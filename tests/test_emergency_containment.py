import json
import os
import time
from unittest.mock import Mock, patch

import pytest
import server
import agent


@pytest.fixture
def env(tmp_path):
    password = server.initialize(tmp_path)
    app = server.create_app(tmp_path)
    client = app.test_client()
    admin_session = client.post('/api/auth/login', json={'username': 'admin', 'password': password}).json['session_token']
    
    # Create an analyst user
    client.post('/api/users', headers={'Authorization': 'Bearer ' + admin_session},
                json={'username': 'sec_analyst', 'password': 'AnalystPassword123!', 'role': 'analyst'})
    analyst_session = client.post('/api/auth/login', json={'username': 'sec_analyst', 'password': 'AnalystPassword123!'}).json['session_token']

    # Create a viewer user
    client.post('/api/users', headers={'Authorization': 'Bearer ' + admin_session},
                json={'username': 'read_only_viewer', 'password': 'ViewerPassword123!', 'role': 'viewer'})
    viewer_session = client.post('/api/auth/login', json={'username': 'read_only_viewer', 'password': 'ViewerPassword123!'}).json['session_token']

    device_token = server.register(tmp_path, 'TEST-LAPTOP')
    return {
        'path': tmp_path,
        'client': client,
        'admin_auth': {'Authorization': 'Bearer ' + admin_session},
        'analyst_auth': {'Authorization': 'Bearer ' + analyst_session},
        'viewer_auth': {'Authorization': 'Bearer ' + viewer_session},
        'device_auth': {'Authorization': 'Bearer ' + device_token, 'X-Device-ID': 'TEST-LAPTOP'}
    }


def sample():
    return {
        'sample_id': 'sample-shutdown-1',
        'observed': time.time(),
        'cpu': 10,
        'ram': 20,
        'process_count': 1,
        'connections': 1,
        'bytes_per_second': 10,
        'failed_logins': 0
    }


def test_emergency_shutdown_role_restrictions(env):
    c = env['client']
    # 1. Unauthenticated request rejected
    res = c.post('/api/devices/TEST-LAPTOP/emergency_shutdown', json={'reason': 'Wiper detected'})
    assert res.status_code == 401

    # 2. Viewer role is forbidden
    res = c.post('/api/devices/TEST-LAPTOP/emergency_shutdown', headers=env['viewer_auth'], json={'reason': 'Wiper detected'})
    assert res.status_code == 403

    # 3. Non-existent device returns 404
    res = c.post('/api/devices/NON-EXISTENT-DEVICE/emergency_shutdown', headers=env['analyst_auth'], json={'reason': 'Wiper detected'})
    assert res.status_code == 404


def test_emergency_shutdown_queued_and_audited(env):
    c = env['client']
    reason_msg = 'Active ransomware wiper corrupting disk sectors'
    res = c.post('/api/devices/TEST-LAPTOP/emergency_shutdown', headers=env['analyst_auth'], json={'reason': reason_msg})
    assert res.status_code == 200
    data = res.json
    assert data['status'] == 'queued'
    assert data['action'] == 'emergency_shutdown'
    assert data['device'] == 'TEST-LAPTOP'
    cmd_id = data['command_id']

    # Verify command queue
    with server.connect(env['path'] / 'sentinel.db') as db:
        cmd_row = db.execute('SELECT action, payload, status FROM commands WHERE id=?', (cmd_id,)).fetchone()
        assert cmd_row['action'] == 'emergency_shutdown'
        assert cmd_row['status'] == 'queued'
        payload = json.loads(cmd_row['payload'])
        assert payload['reason'] == reason_msg
        assert payload['force'] is True

        # Verify critical alert logged
        alert_row = db.execute("SELECT kind, severity, message FROM alerts WHERE device_id='TEST-LAPTOP' AND kind='emergency_containment'").fetchone()
        assert alert_row is not None
        assert alert_row['severity'] == 'critical'
        assert reason_msg in alert_row['message']

        # Verify audit log entry
        audit_row = db.execute("SELECT actor, action, target, outcome FROM audit_logs WHERE action='emergency_shutdown'").fetchone()
        assert audit_row is not None
        assert audit_row['actor'] == 'sec_analyst'
        assert audit_row['target'] == 'TEST-LAPTOP'
        assert audit_row['outcome'] == 'queued'


def test_emergency_shutdown_delivered_and_acknowledged(env):
    c = env['client']
    # Queue emergency shutdown
    res = c.post('/api/devices/TEST-LAPTOP/emergency_shutdown', headers=env['admin_auth'], json={'reason': 'Active wiper containment'})
    cmd_id = res.json['command_id']

    # Endpoint heartbeats via telemetry
    hb = c.post('/api/telemetry', headers=env['device_auth'], json=sample())
    assert hb.status_code == 201
    cmds = hb.json.get('commands', [])
    assert len(cmds) == 1
    assert cmds[0]['id'] == cmd_id
    assert cmds[0]['action'] == 'emergency_shutdown'
    assert 'Active wiper containment' in cmds[0]['reason']

    # Device acknowledges receipt and execution
    ack = c.post(f'/api/commands/{cmd_id}/ack', headers=env['device_auth'],
                 json={'status': 'succeeded', 'result': 'Emergency shutdown initiated: Active wiper containment'})
    assert ack.status_code == 200

    # Verify command status in database
    with server.connect(env['path'] / 'sentinel.db') as db:
        row = db.execute('SELECT status, result FROM commands WHERE id=?', (cmd_id,)).fetchone()
        assert row['status'] == 'succeeded'
        assert 'Emergency shutdown initiated' in row['result']


@pytest.mark.parametrize('system,expected_cmd', [
    ('Windows', ['shutdown', '/s', '/f', '/t', '0']),
    ('Linux', ['shutdown', '-h', 'now']),
])
def test_execute_emergency_shutdown_platform_commands(system, expected_cmd):
    # Ensure SENTINEL_TESTING is unset for this unit test so we test the actual command dispatcher
    with patch.dict(os.environ, {}, clear=False), patch('agent.platform.system', return_value=system), patch('subprocess.run') as mock_run:
        os.environ.pop('SENTINEL_TESTING', None)
        ok, msg = agent.execute_emergency_shutdown('Ransomware panic test')
        assert ok is True
        assert mock_run.called
        assert mock_run.call_args[0][0] == expected_cmd


def test_execute_emergency_shutdown_darwin():
    with patch.dict(os.environ, {}, clear=False), patch('agent.platform.system', return_value='Darwin'), patch('subprocess.run') as mock_run:
        os.environ.pop('SENTINEL_TESTING', None)
        ok, msg = agent.execute_emergency_shutdown('Mac panic test')
        assert ok is True
        assert mock_run.called
        assert 'System Events' in mock_run.call_args[0][0][2]
