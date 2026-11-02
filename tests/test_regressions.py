import json
import sqlite3
import time
from pathlib import Path
from unittest.mock import Mock, patch

import pytest
import server
import agent

@pytest.fixture
def env(tmp_path):
    password = server.initialize(tmp_path)
    client = server.create_app(tmp_path).test_client()
    session = client.post('/api/auth/login', json={'username':'admin','password':password}).json['session_token']
    device = server.register(tmp_path, 'TEST')
    return tmp_path, client, password, {'Authorization':'Bearer '+session}, {'Authorization':'Bearer '+device,'X-Device-ID':'TEST'}

def sample():
    return dict(sample_id='sample-one',observed=time.time(),cpu=10,ram=20,process_count=1,connections=1,bytes_per_second=10,failed_logins=0)

def test_rotation_revokes_password_sessions_and_master_bearer(env):
    path,c,old,a,_ = env
    new = server.rotate_admin_token(path)
    assert c.get('/api/overview',headers=a).status_code == 401
    assert c.post('/api/auth/login',json={'username':'admin','password':old}).status_code == 401
    for raw in (old,new):
        assert c.get('/api/overview',headers={'Authorization':'Bearer '+raw}).status_code == 401
    assert c.post('/api/auth/login',json={'username':'admin','password':new}).status_code == 200

def test_mfa_no_master_bypass_or_code_replay(env):
    _,c,pw,a,_=env
    secret=c.post('/api/users/admin/mfa/setup',headers=a).json['totp_secret']
    code=server.get_totp_code(secret)
    assert c.post('/api/users/admin/mfa/enable',headers=a,json={'code':code}).status_code==200
    assert c.get('/api/overview',headers=a).status_code==401
    assert c.get('/api/overview',headers={'Authorization':'Bearer '+pw}).status_code==401
    assert c.post('/api/auth/login',json={'username':'admin','password':pw}).status_code==401
    auth={'username':'admin','password':pw,'totp_code':code}
    assert c.post('/api/auth/login',json=auth).status_code==200
    assert c.post('/api/auth/login',json=auth).status_code==401

def test_login_rate_limit_and_failure_audit(env):
    path,c,_,_,_=env
    for _ in range(10):
        assert c.post('/api/auth/login',json={'username':'admin','password':'wrong'}).status_code==401
    assert c.post('/api/auth/login',json={'username':'admin','password':'wrong'}).status_code==429
    with server.connect(path/'sentinel.db') as db:
        assert db.execute("SELECT COUNT(*) FROM audit_logs WHERE outcome='failed'").fetchone()[0]==10

def test_legacy_upgrade_preserves_data_and_uncertain_command(tmp_path):
    (tmp_path/'config.json').write_text(json.dumps({'admin_token_hash':'legacy-hash'}))
    with sqlite3.connect(tmp_path/'sentinel.db') as db:
        db.executescript((Path(__file__).parent/'fixtures/legacy_schema.sql').read_text())
        db.execute('INSERT INTO devices VALUES(?,?,?)',('OLD','hash',1))
        db.execute("INSERT INTO commands(device_id,action,payload,created,executed) VALUES('OLD','send_alert','{}',1,1)")
    server.create_app(tmp_path)
    server.create_app(tmp_path)  # Repeat upgrade must be safe.
    with server.connect(tmp_path/'sentinel.db') as db:
        assert db.execute('SELECT status FROM commands').fetchone()[0]=='legacy_unverified'
        assert db.execute('SELECT id FROM devices').fetchone()[0]=='OLD'
    pw=server.rotate_admin_token(tmp_path)
    c=server.create_app(tmp_path).test_client()
    assert c.post('/api/auth/login',json={'username':'admin','password':pw}).status_code==200

def test_default_device_startup_does_not_overwrite_rotation(env):
    path,_,_,_,_=env
    rotated=server.rotate_device_token(path,'TEST')
    assert server.ensure_device(path,'TEST','replacement-test-token-12345') is None
    with server.connect(path/'sentinel.db') as db:
        assert db.execute("SELECT token_hash FROM devices WHERE id='TEST'").fetchone()[0]==server.digest(rotated)

def test_delete_user_removes_sessions(env):
    _,c,_,a,_=env
    c.post('/api/users',headers=a,json={'username':'temporary','password':'TestPassword123','role':'viewer'})
    tok=c.post('/api/auth/login',json={'username':'temporary','password':'TestPassword123'}).json['session_token']
    assert c.delete('/api/users/temporary',headers=a).status_code==200
    assert c.get('/api/overview',headers={'Authorization':'Bearer '+tok}).status_code==401

def test_process_identity_required_and_verified_without_termination(env):
    _,c,_,a,_=env
    assert c.post('/api/devices/TEST/kill_process',headers=a,json={'pid':99999,'name':'demo'}).status_code==400
    assert agent.safe_terminate_process(99999,expected_name='demo')[0] is False
    proc=Mock();proc.name.return_value='demo';proc.create_time.return_value=100.1;proc.exe.return_value='/different/path'
    with patch('agent.psutil.pid_exists',return_value=True),patch('agent.psutil.Process',return_value=proc):
        assert agent.safe_terminate_process(99999,'demo',100.0)[0] is False
        assert agent.safe_terminate_process(99999,'demo',100.1,'/expected/path')[0] is False
        proc.terminate.assert_not_called()

def test_command_retry_on_duplicate_and_immutable_ack(env):
    _,c,_,a,d=env
    r=c.post('/api/devices/TEST/kill_process',headers=a,json={'pid':99999,'name':'demo','create_time':123.0})
    cid=r.json['command_id'];s=sample()
    first=c.post('/api/telemetry',headers=d,json=s)
    second=c.post('/api/telemetry',headers=d,json=s)
    assert first.json['commands'][0]['id']==second.json['commands'][0]['id']==cid
    assert 'expires_at' in second.json['commands'][0]
    assert c.post(f'/api/commands/{cid}/ack',headers=a,json={'status':'succeeded'}).status_code==401
    assert c.post(f'/api/commands/{cid}/ack',headers=d,json={'status':'succeeded'}).status_code==200
    assert c.post(f'/api/commands/{cid}/ack',headers=d,json={'status':'failed'}).status_code==409
    assert c.post('/api/telemetry',headers=d,json=s).json['commands']==[]

def test_interrupted_journal_does_not_repeat_action(tmp_path):
    path=tmp_path/'receipts.json'
    journal=agent.CommandReceiptStore(path);journal.record(10,'executing','started')
    recovered=agent.CommandReceiptStore(path)
    assert recovered.has(10)
    assert recovered.get_unacked()[0]['status']=='failed'
    assert 'unknown' in recovered.get_unacked()[0]['result']
    path.write_text('corrupt')
    with pytest.raises(RuntimeError):agent.CommandReceiptStore(path)

def test_forwarding_header_not_trusted(env):
    _,c,_,_,d=env
    c.post('/api/telemetry',headers={**d,'X-Forwarded-For':'1.2.3.4'},json=sample())
    # Read stored payload; no public endpoint exposes device data.
    with server.connect(env[0]/'sentinel.db') as db:
        assert json.loads(db.execute('SELECT payload FROM telemetry').fetchone()[0])['public_ip']=='127.0.0.1'

def test_json_arrays_rejected(env):
    assert env[1].post('/api/auth/login',json=[]).status_code==400

@pytest.mark.parametrize('system,expected',[('Darwin','osascript'),('Linux','notify-send')])
def test_popup_arguments_are_data(system,expected):
    with patch('agent.platform.system',return_value=system),patch('subprocess.run') as run:
        assert agent.trigger_popup('Title "quoted"','Message') is True
        assert run.call_args.args[0][0]==expected
        assert run.call_args.kwargs['check'] is True

def test_weak_custom_device_token_rejected(env):
    _,c,_,a,_=env
    assert c.post('/api/devices/register',headers=a,json={'device_id':'WEAK','token':'short'}).status_code==400

def test_dashboard_auth_and_identity_contract(env):
    _,c,_,_,_=env
    page=c.get('/').data.decode()
    assert 'id="password"' in page and 'id="totp-code"' in page
    source=c.get('/static/app.js').data.decode()
    assert "'/api/auth/login'" in source and "'/api/auth/logout'" in source
    assert 'create_time:p.create_time' in source and 'path:p.exe' in source
    assert '?token=' not in source

def test_identity_types_rejected(env):
    _,c,_,a,_=env
    assert c.post('/api/devices/TEST/kill_process',headers=a,json={'pid':99,'name':'demo','create_time':True}).status_code==400
    assert c.post('/api/devices/register',headers=a,json={'device_id':42}).status_code==400
