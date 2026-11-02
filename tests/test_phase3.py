import json
import os
import time
from unittest.mock import patch
import pytest

import detection
import server
from agent import Collector, redact_cmdline, extract_domain


@pytest.fixture
def phase3_env(tmp_path):
    data_dir = tmp_path / 'data'
    data_dir.mkdir(parents=True, exist_ok=True)
    admin_token = server.initialize(data_dir)
    app = server.create_app(data_dir)
    client = app.test_client()

    device_token = server.register(data_dir, 'DEV-PH3-01')

    session_token = client.post('/api/auth/login', json={'username':'admin','password':admin_token}).get_json()['session_token']
    admin_hdr = {'Authorization': f'Bearer {session_token}'}
    device_hdr = {'Authorization': f'Bearer {device_token}', 'X-Device-ID': 'DEV-PH3-01'}

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
        'processes': [{'pid': 1001, 'name': 'safeproc', 'ppid': 1, 'exe': '/usr/bin/safeproc'}],
        'warnings': []
    }
    p.update(kwargs)
    return p


# ============================================================================
# 10. Process Visibility, Metadata, Redaction & Suppression
# ============================================================================

def test_cmdline_argument_redaction():
    """redact_cmdline masks passwords, tokens, API keys, and bearer credentials."""
    raw_cmdline = [
        'python', 'worker.py',
        '--password=SuperSecretPassword123',
        '--token', 'abc-def-secret-token',
        '--api-key=xyz987654321',
        '--host=127.0.0.1',
        '--port=8080'
    ]
    redacted = redact_cmdline(raw_cmdline)

    assert 'python' in redacted
    assert '--host=127.0.0.1' in redacted
    assert '--port=8080' in redacted

    # Sensitive arguments must be masked
    assert any('--password=[REDACTED]' in arg or '[REDACTED' in arg for arg in redacted)
    assert not any('SuperSecretPassword123' in arg for arg in redacted)
    assert not any('xyz987654321' in arg for arg in redacted)


def test_process_threat_allowlist_suppression(phase3_env):
    """Allowlisted process names or executables suppress threat alerts."""
    _, _, client, _, _, admin_hdr, device_hdr = phase3_env

    # 1. Telemetry with wireshark triggers threat alert initially
    p1 = make_payload(
        sample_id='THREAT-1',
        processes=[{'pid': 7777, 'name': 'wireshark', 'ppid': 1, 'exe': '/usr/bin/wireshark'}]
    )
    client.post('/api/telemetry', headers=device_hdr, json=p1)

    ov1 = client.get('/api/overview', headers=admin_hdr).get_json()
    assert any(a['kind'] == 'threat_wireshark' for a in ov1['alerts'])

    # 2. Add wireshark to process allowlist
    set_al = client.post(
        '/api/settings/process_allowlist',
        headers=admin_hdr,
        json={'allowlist': ['wireshark']}
    )
    assert set_al.status_code == 200
    assert 'wireshark' in set_al.get_json()['allowlist']

    # 3. Subsequent telemetry with wireshark is suppressed (no new alert generated)
    client.post('/api/alerts/1/ack', headers=admin_hdr)  # acknowledge first alert
    p2 = make_payload(
        sample_id='THREAT-2',
        processes=[{'pid': 7778, 'name': 'wireshark', 'ppid': 1, 'exe': '/usr/bin/wireshark'}]
    )
    client.post('/api/telemetry', headers=device_hdr, json=p2)

    ov2 = client.get('/api/overview', headers=admin_hdr).get_json()
    open_alerts = [a for a in ov2['alerts'] if a['acknowledged'] == 0 and a['kind'] == 'threat_wireshark']
    assert len(open_alerts) == 0


def test_process_threat_explanation_in_alert(phase3_env):
    """Threat alerts include MITRE technique and investigation indicator disclaimer."""
    _, _, client, _, _, admin_hdr, device_hdr = phase3_env

    p = make_payload(
        sample_id='THREAT-NC',
        processes=[{'pid': 9898, 'name': 'nmap', 'ppid': 500, 'exe': '/usr/bin/nmap'}]
    )
    client.post('/api/telemetry', headers=device_hdr, json=p)

    ov = client.get('/api/overview', headers=admin_hdr).get_json()
    nmap_alert = next(a for a in ov['alerts'] if a['kind'] == 'threat_nmap')
    assert 'Investigation Indicator' in nmap_alert['message']
    assert 'MITRE ATT&CK T1046' in nmap_alert['message']
    assert 'behavioral verification' in nmap_alert['message']


# ============================================================================
# 11. Browser & DLP Privacy (Opt-in, Domain Parsing, Deduplication)
# ============================================================================

def test_collector_privacy_defaults():
    """Browser history and active window are disabled by default."""
    c_default = Collector()
    assert c_default.enable_browser_history is False
    assert c_default.enable_active_window is False
    assert c_default.domain_only_history is True

    sample = c_default.sample()
    assert sample['browser_history'] == []
    assert sample['active_window'] is None


def test_extract_domain():
    """Domain extraction accurately pulls hostnames from diverse URLs."""
    assert extract_domain('https://mega.nz/file/1234#key') == 'mega.nz'
    assert extract_domain('http://sub.domain.filetransfer.io/download?q=1') == 'sub.domain.filetransfer.io'
    assert extract_domain('pastebin.com/raw/secret') == 'pastebin.com'


def test_browser_history_hostname_matching_not_substring(phase3_env):
    """Server matches actual hostnames; does not match coincidental substring in path or title."""
    _, _, client, _, _, admin_hdr, device_hdr = phase3_env

    # URL has 'mega.nz' only inside search query parameter on google.com
    innocent_url = 'https://www.google.com/search?q=how+does+mega.nz+work'
    p = make_payload(
        sample_id='SAFE-WEB',
        browser_history=[{'url': innocent_url, 'domain': 'www.google.com', 'title': 'Search mega.nz'}]
    )
    client.post('/api/telemetry', headers=device_hdr, json=p)

    ov = client.get('/api/overview', headers=admin_hdr).get_json()
    dlp_alerts = [a for a in ov['alerts'] if a['kind'].startswith('dlp_mega')]
    assert len(dlp_alerts) == 0


def test_dlp_history_deduplication(phase3_env):
    """Repeated telemetry visits for the same domain do not spam duplicate DLP alerts."""
    _, _, client, _, _, admin_hdr, device_hdr = phase3_env

    dlp_payload = {
        'url': 'https://mega.nz/file/xyz',
        'domain': 'mega.nz',
        'title': 'Mega Storage',
        'visit_time': 1700000000.0
    }

    # First ingest
    p1 = make_payload(sample_id='DLP-1', browser_history=[dlp_payload])
    client.post('/api/telemetry', headers=device_hdr, json=p1)

    # Second ingest with same visit
    p2 = make_payload(sample_id='DLP-2', browser_history=[dlp_payload])
    client.post('/api/telemetry', headers=device_hdr, json=p2)

    ov = client.get('/api/overview', headers=admin_hdr).get_json()
    mega_alerts = [a for a in ov['alerts'] if a['kind'] == 'dlp_mega_nz']
    # Deduplication ensures only 1 alert generated
    assert len(mega_alerts) == 1


# ============================================================================
# 12. Correct Self-Defense & Compliance Claims
# ============================================================================

def test_heuristic_risk_score_and_compliance_renaming(phase3_env):
    """Overview and audit report include heuristic risk score without false compliance guarantees."""
    _, _, client, _, _, admin_hdr, _ = phase3_env

    ov = client.get('/api/overview', headers=admin_hdr).get_json()
    assert 'heuristic_risk_score' in ov
    assert isinstance(ov['heuristic_risk_score'], (int, float))

    rep = client.get('/reports/audit', headers=admin_hdr)
    assert rep.status_code == 200
    assert b'Heuristic Risk Indicator' in rep.data
    assert b'Fleet Connectivity' in rep.data


def test_agent_script_tamper_alert_wording(phase3_env):
    """Agent script change alert states it is a self-reported change notice, not hardware attestation."""
    _, _, client, _, _, admin_hdr, device_hdr = phase3_env

    client.post('/api/telemetry', headers=device_hdr, json=make_payload(sample_id='H1', agent_hash='orig1111'))
    client.post('/api/telemetry', headers=device_hdr, json=make_payload(sample_id='H2', agent_hash='tampered2222'))

    ov = client.get('/api/overview', headers=admin_hdr).get_json()
    tamper_alert = next(a for a in ov['alerts'] if a['kind'] == 'tamper_code_modified')
    assert 'Agent script modification detected' in tamper_alert['message']
    assert 'cryptographic hardware attestation' in tamper_alert['message']


# ============================================================================
# 13. ML Evaluation, Anomaly vs Attack Probability, Model Versioning & Rollback
# ============================================================================

def test_ml_unlabelled_evaluation_disclaimer():
    """Unlabelled evaluation reports accuracy unverified and clarifies contamination != accuracy."""
    samples = [{'cpu': 10.0 + i % 5, 'ram': 40.0, 'process_count': 50, 'connections': 10, 'bytes_per_second': 1000.0, 'observed': 1000.0 + i * 15} for i in range(40)]
    model = detection.train(samples, contamination=0.03)

    eval_result = detection.evaluate_model(model, samples)
    assert eval_result['accuracy_verified'] is False
    assert eval_result['evaluation_status'] == 'UNVERIFIED'
    assert 'NOT a 97% detection accuracy' in eval_result['accuracy_disclaimer']


def test_ml_labelled_evaluation_metrics():
    """Labelled evaluation calculates precision, recall, F1, and false alerts per device/day."""
    samples = [{'cpu': 10.0 + i % 5, 'ram': 40.0, 'process_count': 50, 'connections': 10, 'bytes_per_second': 1000.0, 'observed': 1000.0 + i * 15} for i in range(50)]
    # Add 2 obvious anomalies
    samples.append({'cpu': 99.9, 'ram': 99.0, 'process_count': 500, 'connections': 5000, 'bytes_per_second': 9e7, 'observed': 2000.0})
    samples.append({'cpu': 98.5, 'ram': 98.0, 'process_count': 450, 'connections': 4800, 'bytes_per_second': 8e7, 'observed': 2015.0})

    model = detection.train(samples[:45], contamination=0.05)

    labels = [0] * 50 + [1, 1]
    eval_result = detection.evaluate_model(model, samples, ground_truth_labels=labels)

    assert eval_result['accuracy_verified'] is True
    assert eval_result['evaluation_status'] == 'VERIFIED_LABELLED'
    assert 'precision' in eval_result
    assert 'recall' in eval_result
    assert 'f1_score' in eval_result
    assert 'estimated_false_alerts_per_device_day' in eval_result


def test_model_versioning_and_rollback(phase3_env):
    """Device models track versions and support rollback to previous baseline."""
    data_dir, _, client, _, _, admin_hdr, device_hdr = phase3_env

    # Ingest 35 telemetry samples
    for i in range(35):
        p = make_payload(sample_id=f'TR-{i}', cpu=15.0 + (i % 5), connections=10 + (i % 3))
        client.post('/api/telemetry', headers=device_hdr, json=p)

    # Train model v1
    server.train_device(data_dir, 'DEV-PH3-01', limit=35)

    m1 = client.get('/api/devices/DEV-PH3-01/model', headers=admin_hdr).get_json()
    assert m1['version'] == 1
    assert m1['can_rollback'] is False

    # Ingest more samples and train model v2
    for i in range(35, 70):
        p = make_payload(sample_id=f'TR-{i}', cpu=25.0 + (i % 5), connections=20 + (i % 3))
        client.post('/api/telemetry', headers=device_hdr, json=p)

    server.train_device(data_dir, 'DEV-PH3-01', limit=50)

    m2 = client.get('/api/devices/DEV-PH3-01/model', headers=admin_hdr).get_json()
    assert m2['version'] == 2
    assert m2['can_rollback'] is True

    # Roll back model to v1
    rb_res = client.post('/api/devices/DEV-PH3-01/model/rollback', headers=admin_hdr)
    assert rb_res.status_code == 200
    assert rb_res.get_json()['status'] == 'rolled_back'

    m_after = client.get('/api/devices/DEV-PH3-01/model', headers=admin_hdr).get_json()
    assert m_after['version'] == 1
    assert m_after['can_rollback'] is False
