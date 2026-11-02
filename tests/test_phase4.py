import json
import time
import pytest

import server
from server import get_totp_code


@pytest.fixture
def phase4_env(tmp_path):
    data_dir = tmp_path / 'data'
    data_dir.mkdir(parents=True, exist_ok=True)
    admin_token = server.initialize(data_dir)
    app = server.create_app(data_dir)
    client = app.test_client()

    device_token = server.register(data_dir, 'DEV-PILOT-01')

    session_token = client.post('/api/auth/login', json={'username':'admin','password':admin_token}).get_json()['session_token']
    admin_hdr = {'Authorization': f'Bearer {session_token}'}
    device_hdr = {'Authorization': f'Bearer {device_token}', 'X-Device-ID': 'DEV-PILOT-01'}

    # Create users with different roles
    # 1. Viewer
    client.post('/api/users', headers=admin_hdr, json={'username': 'alice_viewer', 'password': 'Password123!', 'role': 'viewer'})
    # 2. Analyst
    client.post('/api/users', headers=admin_hdr, json={'username': 'bob_analyst', 'password': 'Password123!', 'role': 'analyst'})
    # 3. Administrator
    client.post('/api/users', headers=admin_hdr, json={'username': 'charlie_admin', 'password': 'Password123!', 'role': 'administrator'})

    # Log in each user to get session tokens
    v_login = client.post('/api/auth/login', json={'username': 'alice_viewer', 'password': 'Password123!'}).get_json()
    a_login = client.post('/api/auth/login', json={'username': 'bob_analyst', 'password': 'Password123!'}).get_json()
    adm_login = client.post('/api/auth/login', json={'username': 'charlie_admin', 'password': 'Password123!'}).get_json()

    viewer_hdr = {'Authorization': f"Bearer {v_login['session_token']}"}
    analyst_hdr = {'Authorization': f"Bearer {a_login['session_token']}"}
    user_admin_hdr = {'Authorization': f"Bearer {adm_login['session_token']}"}

    return {
        'data_dir': data_dir,
        'app': app,
        'client': client,
        'admin_token': admin_token,
        'device_token': device_token,
        'admin_hdr': admin_hdr,
        'device_hdr': device_hdr,
        'viewer_hdr': viewer_hdr,
        'analyst_hdr': analyst_hdr,
        'user_admin_hdr': user_admin_hdr,
    }


def make_payload(sample_id='SMPL-01', **kwargs):
    p = {
        'sample_id': sample_id,
        'observed': time.time(),
        'cpu': 20.0,
        'ram': 40.0,
        'process_count': 50,
        'connections': 10,
        'bytes_per_second': 1500.0,
        'failed_logins': 0,
        'processes': [{'pid': 1001, 'name': 'testproc', 'ppid': 1, 'exe': '/usr/bin/testproc'}],
        'warnings': []
    }
    p.update(kwargs)
    return p


# ============================================================================
# 14. Server-Enforced RBAC, Secure Sessions, MFA & Audit Logging
# ============================================================================

def test_user_session_login_and_logout(phase4_env):
    """Users authenticate with credentials to receive session tokens; logout revokes session."""
    client = phase4_env['client']

    # 1. Invalid login fails
    bad_res = client.post('/api/auth/login', json={'username': 'alice_viewer', 'password': 'WrongPassword!'})
    assert bad_res.status_code == 401

    # 2. Valid login creates session
    good_res = client.post('/api/auth/login', json={'username': 'alice_viewer', 'password': 'Password123!'})
    assert good_res.status_code == 200
    tok = good_res.get_json()['session_token']
    hdr = {'Authorization': f'Bearer {tok}'}

    # Session token works for overview
    ov = client.get('/api/overview', headers=hdr)
    assert ov.status_code == 200

    # 3. Logout revokes session
    logout_res = client.post('/api/auth/logout', headers=hdr)
    assert logout_res.status_code == 200

    # Revoked session is rejected
    after_ov = client.get('/api/overview', headers=hdr)
    assert after_ov.status_code == 401


def test_rbac_restrictions_process_kill_and_device_deletion(phase4_env):
    """Restricts process termination and device deletion to administrator role."""
    client = phase4_env['client']
    viewer_hdr = phase4_env['viewer_hdr']
    analyst_hdr = phase4_env['analyst_hdr']
    user_admin_hdr = phase4_env['user_admin_hdr']

    # 1. Viewer is forbidden (403) from kill_process and delete_device
    v_kill = client.post('/api/devices/DEV-PILOT-01/kill_process', headers=viewer_hdr, json={'pid': 5555, 'name': 'badproc', 'create_time':12345.0})
    assert v_kill.status_code == 403
    assert 'administrator' in v_kill.get_json()['error']

    v_del = client.delete('/api/devices/DEV-PILOT-01', headers=viewer_hdr)
    assert v_del.status_code == 403

    # 2. Analyst is also forbidden (403) from kill_process and delete_device
    a_kill = client.post('/api/devices/DEV-PILOT-01/kill_process', headers=analyst_hdr, json={'pid': 5555, 'name': 'badproc', 'create_time':12345.0})
    assert a_kill.status_code == 403

    a_del = client.delete('/api/devices/DEV-PILOT-01', headers=analyst_hdr)
    assert a_del.status_code == 403

    # 3. Administrator is allowed to kill process
    adm_kill = client.post('/api/devices/DEV-PILOT-01/kill_process', headers=user_admin_hdr, json={'pid': 5555, 'name': 'badproc', 'create_time':12345.0})
    assert adm_kill.status_code == 200
    assert adm_kill.get_json()['status'] == 'queued'


def test_rbac_alert_acknowledgement(phase4_env):
    """Viewer cannot acknowledge alerts; analyst and administrator can."""
    client = phase4_env['client']
    device_hdr = phase4_env['device_hdr']
    viewer_hdr = phase4_env['viewer_hdr']
    analyst_hdr = phase4_env['analyst_hdr']

    # Generate an alert via high CPU
    client.post('/api/telemetry', headers=device_hdr, json=make_payload(sample_id='CPU-ALRT', cpu=99.0))

    # Viewer tries to acknowledge alert -> 403 Forbidden
    v_ack = client.post('/api/alerts/1/ack', headers=viewer_hdr)
    assert v_ack.status_code == 403
    assert 'analyst' in v_ack.get_json()['error']

    # Analyst acknowledges alert -> 200 OK
    a_ack = client.post('/api/alerts/1/ack', headers=analyst_hdr)
    assert a_ack.status_code == 200
    assert a_ack.get_json()['status'] == 'acknowledged'


def test_mfa_setup_enable_and_login_flow(phase4_env):
    """MFA TOTP setup, verification and enforcement on subsequent logins."""
    client = phase4_env['client']
    admin_hdr = phase4_env['admin_hdr']

    # 1. Admin setups MFA for bob_analyst
    setup_res = client.post('/api/users/bob_analyst/mfa/setup', headers=admin_hdr)
    assert setup_res.status_code == 200
    secret = setup_res.get_json()['totp_secret']
    assert len(secret) >= 16

    # 2. Enable MFA with invalid code -> 400
    bad_enable = client.post('/api/users/bob_analyst/mfa/enable', headers=admin_hdr, json={'code': '000000'})
    assert bad_enable.status_code == 400

    # Enable MFA with valid code -> 200
    valid_code = get_totp_code(secret)
    good_enable = client.post('/api/users/bob_analyst/mfa/enable', headers=admin_hdr, json={'code': valid_code})
    assert good_enable.status_code == 200
    assert good_enable.get_json()['status'] == 'mfa_enabled'

    # 3. Subsequent login without TOTP fails
    no_totp = client.post('/api/auth/login', json={'username': 'bob_analyst', 'password': 'Password123!'})
    assert no_totp.status_code == 401
    assert 'MFA TOTP code required' in no_totp.get_json()['error']

    # Login with valid TOTP succeeds
    curr_code = get_totp_code(secret)
    mfa_login = client.post('/api/auth/login', json={'username': 'bob_analyst', 'password': 'Password123!', 'totp_code': curr_code})
    assert mfa_login.status_code == 200
    assert mfa_login.get_json()['status'] == 'authenticated'


def test_audit_logging_records_actions_without_secrets(phase4_env):
    """Audit logs record actor, action, target, timestamp, and outcome without logging passwords/tokens."""
    client = phase4_env['client']
    admin_hdr = phase4_env['admin_hdr']
    analyst_hdr = phase4_env['analyst_hdr']

    # Perform privileged action
    client.post('/api/devices/DEV-PILOT-01/kill_process', headers=admin_hdr, json={'pid': 8080, 'name': 'malproc', 'create_time':12345.0})

    # Inspect audit logs
    audit_res = client.get('/api/audit_logs', headers=analyst_hdr)
    assert audit_res.status_code == 200
    logs = audit_res.get_json()['audit_logs']

    assert len(logs) > 0
    kill_log = next(log for log in logs if log['action'] == 'kill_process')
    assert kill_log['actor'] == 'admin'
    assert kill_log['target'] == 'DEV-PILOT-01'
    assert kill_log['outcome'] == 'queued'
    assert 'PID: 8080' in kill_log['details']

    # Verify no raw passwords or auth tokens exist in audit logs
    for log in logs:
        details_str = str(log.get('details') or '')
        assert 'Password123' not in details_str


# ============================================================================
# 15. Alert Investigation Workflows & Fleet Management
# ============================================================================

def test_alert_filtering_assignment_and_notes(phase4_env):
    """Alerts can be searched, assigned to analysts, annotated with notes, and grouped into incidents."""
    client = phase4_env['client']
    device_hdr = phase4_env['device_hdr']
    analyst_hdr = phase4_env['analyst_hdr']
    viewer_hdr = phase4_env['viewer_hdr']

    # Generate 2 alerts
    client.post('/api/telemetry', headers=device_hdr, json=make_payload(sample_id='ALERT-1', cpu=99.0))
    client.post('/api/telemetry', headers=device_hdr, json=make_payload(sample_id='ALERT-2', processes=[{'pid': 909, 'name': 'wireshark'}]))

    # 1. Search and filter alerts
    alerts_all = client.get('/api/alerts', headers=viewer_hdr).get_json()['alerts']
    assert len(alerts_all) >= 2

    filtered = client.get('/api/alerts?kind=threat_wireshark', headers=viewer_hdr).get_json()['alerts']
    assert len(filtered) == 1
    target_alert_id = filtered[0]['id']

    # 2. Analyst assigns alert
    assign_res = client.post(f'/api/alerts/{target_alert_id}/assign', headers=analyst_hdr, json={'assigned_to': 'bob_analyst'})
    assert assign_res.status_code == 200
    assert assign_res.get_json()['assigned_to'] == 'bob_analyst'

    # 3. Analyst appends investigation notes
    notes_res = client.post(f'/api/alerts/{target_alert_id}/notes', headers=analyst_hdr, json={'notes': 'Confirmed authorized network testing by QA team.'})
    assert notes_res.status_code == 200

    # 4. Analyst groups alert into incident
    group_res = client.post(f'/api/alerts/{target_alert_id}/group', headers=analyst_hdr, json={'incident_id': 'INC-2026-001'})
    assert group_res.status_code == 200
    assert group_res.get_json()['incident_id'] == 'INC-2026-001'

    # 5. Verify fields updated in alert listing
    updated_alerts = client.get(f'/api/alerts?incident_id=INC-2026-001', headers=viewer_hdr).get_json()['alerts']
    assert len(updated_alerts) == 1
    assert updated_alerts[0]['assigned_to'] == 'bob_analyst'
    assert 'QA team' in updated_alerts[0]['notes']


def test_fleet_device_groups_and_maintenance(phase4_env):
    """Endpoints support device groups, maintenance window setting, and fleet inventory."""
    client = phase4_env['client']
    admin_hdr = phase4_env['admin_hdr']
    analyst_hdr = phase4_env['analyst_hdr']
    viewer_hdr = phase4_env['viewer_hdr']

    # 1. Admin assigns device to group 'Production-DB'
    grp_res = client.post('/api/devices/DEV-PILOT-01/group', headers=admin_hdr, json={'group': 'Production-DB'})
    assert grp_res.status_code == 200
    assert grp_res.get_json()['group'] == 'Production-DB'

    # 2. Analyst sets maintenance window for 2 hours
    maint_res = client.post('/api/devices/DEV-PILOT-01/maintenance', headers=analyst_hdr, json={'duration_seconds': 7200})
    assert maint_res.status_code == 200
    assert maint_res.get_json()['status'] == 'maintenance_active'

    # 3. Viewer inspects fleet groups
    fleet_res = client.get('/api/fleet/groups', headers=viewer_hdr).get_json()
    assert 'Production-DB' in fleet_res['groups']
    assert fleet_res['groups']['Production-DB']['total'] == 1

    # 4. Viewer inspects fleet version inventory
    inv_res = client.get('/api/fleet/inventory', headers=viewer_hdr).get_json()
    assert '1.0.0' in inv_res['agent_versions']
