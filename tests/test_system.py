import time
import uuid
import pytest
import server
from agent import AuthLog, Collector, validate_url

@pytest.fixture
def setup(tmp_path):
    admin=server.initialize(tmp_path)
    token=server.register(tmp_path,'LAPTOP-01')
    app=server.create_app(tmp_path);app.testing=True
    return tmp_path,app.test_client(),{'Authorization':'Bearer '+admin},{'Authorization':'Bearer '+token,'X-Device-ID':'LAPTOP-01'}

def sample(**changes):
    value={'sample_id':uuid.uuid4().hex,'observed':time.time(),'cpu':20,'ram':40,'process_count':100,'connections':10,'bytes_per_second':2500,'failed_logins':0,'processes':[]}
    value.update(changes);return value

def test_auth_and_roles(setup):
    _,c,a,d=setup
    assert c.get('/').status_code==200
    assert c.get('/api/overview').status_code==401
    assert c.get('/api/overview',headers=d).status_code==401
    assert c.post('/api/telemetry',headers=a,json=sample()).status_code==401
    assert c.post('/api/telemetry',headers={**d,'X-Device-ID':'another'},json=sample()).status_code==401
    assert c.get('/api/overview',headers=a).status_code==200

def test_rules_dedup_ack_persistence(setup):
    path,c,a,d=setup;p=sample(failed_logins=3)
    assert c.post('/api/telemetry',headers=d,json=p).status_code==201
    assert c.post('/api/telemetry',headers=d,json=p).json['status']=='duplicate'
    assert c.get('/api/overview',headers=a).json['open_alerts']==0
    c.post('/api/telemetry',headers=d,json=sample(failed_logins=2,cpu=98))
    data=c.get('/api/overview',headers=a).json
    assert {v['kind'] for v in data['alerts']}=={'failed_logins','high_cpu'}
    c.post('/api/telemetry',headers=d,json=sample(cpu=99))
    assert len(c.get('/api/overview',headers=a).json['alerts'])==2
    aid=data['alerts'][0]['id']
    assert c.post(f'/api/alerts/{aid}/ack').status_code==401
    assert c.post(f'/api/alerts/{aid}/ack',headers=a).status_code==200
    restarted=server.create_app(path).test_client()
    assert restarted.get('/api/overview',headers=a).json['open_alerts']==1
    assert len(restarted.get('/api/devices/LAPTOP-01/history',headers=a).json['samples'])==3

@pytest.mark.parametrize('changes',[{'cpu':101},{'ram':float('nan')},{'connections':-1},{'failed_logins':True},{'failed_logins':1.2},{'observed':1},{'processes':[{'pid':'1','name':'x'}]}])
def test_validation(setup,changes):
    _,c,_,d=setup
    assert c.post('/api/telemetry',headers=d,json=sample(**changes)).status_code==400

def test_missing_permissions(setup):
    _,c,a,d=setup
    r=c.post('/api/telemetry',headers=d,json=sample(connections=None,failed_logins=None))
    assert r.status_code==201 and r.json['score'] is None
    assert c.get('/api/overview',headers=a).json['devices'][0]['latest']['connections'] is None

def test_login_window(setup):
    path,c,a,d=setup
    c.post('/api/telemetry',headers=d,json=sample(failed_logins=4))
    with server.connect(path/'sentinel.db') as db:db.execute('UPDATE telemetry SET received=?',(time.time()-301,))
    c.post('/api/telemetry',headers=d,json=sample(failed_logins=1))
    assert c.get('/api/overview',headers=a).json['open_alerts']==0

def test_model_and_demo(setup):
    path,c,a,_=setup
    with pytest.raises(ValueError):server.train_device(path,'LAPTOP-01')
    name=server.demo(path)
    overview=server.create_app(path).test_client().get('/api/overview',headers=a).json
    assert {v['kind'] for v in overview['alerts'] if v['device_id']==name}=={'failed_logins','high_cpu','ml_anomaly'}
    assert next(d for d in overview['devices'] if d['id']==name)['model']['sample_count']==80

def test_log_tail(tmp_path):
    log=tmp_path/'auth.log';log.write_text('sshd[1]: Failed password for old\n');tail=AuthLog(log)
    assert tail.read()==(0,None)
    with log.open('a') as f:f.write('sshd[2]: Failed password for user\nsshd[2]: pam_unix authentication failure\nsshd[3]: Failed publickey')
    assert tail.read()==(1,None)
    with log.open('a') as f:f.write(' for user\n')
    assert tail.read()==(1,None)
    assert tail.read()==(0,None)
    log.rename(tmp_path/'auth.log.1');log.write_text('sshd[4]: Failed password for user\n')
    assert tail.read()==(1,None)
    log.write_text('');assert tail.read()==(0,None)
    assert AuthLog().read()[0] is None

@pytest.mark.parametrize('url,allowed',[('http://example.com',True),('http://127.0.0.1',False),('ftp://localhost',True),('https://user:pass@host',False)])
def test_unsafe_url(url,allowed):
    with pytest.raises(ValueError):validate_url(url,allowed)

def test_collector():
    validate_url('http://127.0.0.1:8000',True);validate_url('https://monitor.example.com',False)
    data=Collector().sample()
    assert 0<=data['cpu']<=100 and 0<=data['ram']<=100
    assert data['failed_logins'] is None and len(data['processes'])<=100

def test_device_api_registration(setup):
    _, c, a, d = setup
    assert c.post('/api/devices/register', json={'device_id': 'NEW-DEV'}).status_code == 401
    assert c.post('/api/devices/register', headers=d, json={'device_id': 'NEW-DEV'}).status_code == 401
    res = c.post('/api/devices/register', headers=a, json={'device_id': 'NEW-DEV'})
    assert res.status_code == 201
    data = res.get_json()
    assert data['device_id'] == 'NEW-DEV' and len(data['token']) > 20
    res2 = c.post('/api/devices/register', headers=a, json={'device_id': 'NEW-DEV-2', 'token': 'fixed-token-12345'})
    assert res2.status_code == 201
    assert res2.get_json()['token'] == 'fixed-token-12345'
