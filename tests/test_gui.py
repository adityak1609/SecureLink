from http.client import HTTPConnection
import json
from pathlib import Path
import threading
import time
from urllib.parse import quote
import pytest

from securelink.gui import Application, LocalServer
from securelink.settings import ROOT
from securelink.storage import file_hash


@pytest.fixture
def gui(tmp_path):
    app = Application(tmp_path / 'gui')
    server = LocalServer(app)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield app, server
    server.shutdown()
    server.server_close()
    thread.join(timeout=3)
    app.close()


def http(gui, method, path, body=None, headers=None, authenticated=True):
    app, server = gui
    values = {'X-SecureLink-Token': app.token} if authenticated else {}
    values.update(headers or {})
    if isinstance(body, dict):
        body = json.dumps(body).encode()
        values['Content-Type'] = 'application/json'
    connection = HTTPConnection('127.0.0.1', server.server_port, timeout=25)
    try:
        connection.request(method, path, body=body, headers=values)
        response = connection.getresponse()
        return response.status, response.read()
    finally:
        connection.close()


def job(gui, path, body=None):
    status, data = http(gui, 'POST', path, body or {})
    assert status == 202, data
    job_id = json.loads(data)['job']
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        snapshot = gui[0].state()
        result = next(item for item in snapshot['jobs'] if item['id'] == job_id)
        if result['status'] in ('complete', 'failed'):
            return result
        time.sleep(.03)
    pytest.fail('GUI operation exceeded deadline')


def start(gui):
    result = job(gui, '/api/demo/start')
    assert result['status'] == 'complete', result


def test_gui_http_boundary_and_no_credential_disclosure(gui):
    assert http(gui, 'GET', '/api/state', authenticated=False)[0] == 401
    assert http(gui, 'POST', '/api/demo/start', {}, authenticated=False)[0] == 401
    assert http(gui, 'GET', '/api/state', headers={'Origin': 'https://evil.example'})[0] == 403
    assert http(gui, 'GET', '/api/state', headers={'Host': 'evil.example'})[0] == 403
    assert http(gui, 'GET', '/credentials/client.json')[0] == 404
    assert http(gui, 'GET', '/../../secrets/client.json')[0] == 404
    status, data = http(gui, 'GET', '/api/state')
    assert status == 200 and gui[0].config['secret'].encode() not in data
    assert gui[0].token.encode() not in data
    assert gui[0].signing_key.hex().encode() not in data
    assert json.loads(data)['mode'] == 'offline'
    assert http(gui,'GET','/api/evidence/'+'0'*32,authenticated=False)[0]==401
    assert http(gui,'GET','/api/logs/audit.jsonl',authenticated=False)[0]==401
    assert http(gui,'GET','/api/evidence/'+'0'*32)[0]==400
    assert http(gui,'GET','/api/logs/audit.jsonl')[0]==400


def test_gui_rejects_unsafe_uploads_before_reading_body(gui):
    for name in ('../secret.txt', 'malware.exe', 'video.mp4', 'folder\\note (1).txt', 'note:1.txt', 'note\r\n.txt', 'a' * 117 + '.txt'):
        # Withhold the declared body to prove validation happens before reading it.
        assert http(gui, 'POST', '/api/upload?name=' + quote(name, safe=''),
                    headers={'Content-Length': '1'})[0] == 400
    assert http(gui, 'POST', '/api/upload?name=note.txt', headers={'Content-Length': str(33*1024*1024)})[0] == 400
    assert http(gui, 'POST', '/api/upload?name=note.txt', b'')[0] == 400


def test_legacy_video_history_is_hidden_without_deleting_it(gui):
    app, _ = gui
    request = 'f' * 32
    app.history.append({'request': request, 'name': 'video.mp4', 'media': 'video',
                        'endpoint': app.endpoint()})
    assert all(row['request'] != request for row in app.state()['transfers'])
    with pytest.raises(ValueError, match='Transfer not found'):
        app.record(request)
    assert app.history[-1]['request'] == request


def test_gui_real_multimedia_roundtrips_audit_exports_and_restart(gui):
    app, _ = gui
    start(gui)
    topology = app.state()['topology']
    assert len(set(topology.values())) == 3
    for name in ('transaction.txt', 'identity.png', 'audio.wav'):
        sent = job(gui, '/api/sample', {'name': name})
        assert sent['status'] == 'complete', sent
        assert sent['done'] == sent['total'] > 0
        request = sent['result']['request']
        received = job(gui, '/api/download', {'request': request})
        assert received['status'] == 'complete', received
        assert received['done'] == received['total']
        row=next(row for row in app.state()['transfers'] if row['request']==request)
        assert row['crypto']['upload']['signature_verified']
        assert row['crypto']['download']['signature_verified']
        assert row['crypto']['upload']['client']['signing']['nanoseconds']>0
        status,evidence_data=http(gui,'GET','/api/evidence/'+request)
        assert status==200
        evidence=json.loads(evidence_data)
        transfer=evidence['transfer']
        assert transfer['received_sha256']==transfer['sha256']
        assert transfer['created']<=transfer['upload_started']<=transfer['upload_completed']<=transfer['download_started']<=transfer['download_verified']
        assert all(transfer[field].endswith('+00:00') for field in ('created','upload_completed','download_verified'))
        assert {event['event'] for event in evidence['client_events']}=={'upload_started','upload_completed','download_started','download_verified'}
        assert {'authentication','signature_verified','transfer_complete','download_complete'}<={event['event'] for event in evidence['server_events']}
        assert all(event['request']==request for event in evidence['server_events'] if event['event']!='authentication')
        assert 'source' not in transfer
        assert app.config['secret'].encode() not in evidence_data and app.signing_key.hex().encode() not in evidence_data
        for direction,kind in (('upload','chunk'),('download','data')):
            sample=transfer['crypto'][direction]['ciphertext_samples'][0]
            assert sample['request']==request and sample['kind']==kind
            assert 0<sample['prefix_bytes']<=64 and len(sample['gcm_tag_hex'])==32 and len(sample['nonce_hex'])==24
        if name.endswith('.png'):
            assert transfer['image_metrics']['mse']==0 and transfer['image_metrics']['pixels_equal']
            assert transfer['image_metrics']['source']['encoded_bytes']==transfer['size']
        status, data = http(gui, 'GET', '/api/file/' + request)
        assert status == 200 and data == (ROOT / 'sample_data/fixtures' / name).read_bytes()
    audit = job(gui, '/api/audit/verify')
    assert audit['status'] == 'complete' and audit['result']['verified']
    analysis = job(gui, '/api/analysis')
    assert analysis['status'] == 'complete' and analysis['result']['records'] > 0
    assert app.state()['analysis']['engine']=='PyShark + Wireshark/TShark'
    for name in ('pcap', 'sqlite', 'xml', 'json'):
        status, data = http(gui, 'GET', '/api/export/' + name)
        assert status == 200 and data
    status,csv=http(gui,'GET','/api/metrics/csv')
    assert status==200 and b'signature_verification' in csv and b'encryption' in csv
    assert app.signing_key.hex().encode() not in http(gui,'GET','/api/metrics/json')[1]
    assert len(app.history) == 3
    status,log_data=http(gui,'GET','/api/logs/audit.jsonl')
    assert status==200 and b'transfer_complete' in log_data
    start(gui)  # Retained transfers belong to the logical demo, not an ephemeral port.
    assert len(app.state()['transfers']) == 3
    received = job(gui, '/api/download', {'request': app.history[0]['request']})
    assert received['status'] == 'complete'
    source = app.root / app.history[0]['source']
    assert file_hash(source) == app.history[0]['sha256']


def test_gui_text_filepicker_resumption_and_invalid_content(gui):
    start(gui)
    sent = job(gui, '/api/text', {'text': 'Hello from the GUI — नमस्ते'})
    assert sent['status'] == 'complete'
    sent_id = sent['result']['request']
    resumed = job(gui, '/api/retry', {'request': sent_id})
    assert resumed['status'] == 'complete' and len(gui[0].history) == 1
    filename = 'WHEN_TO_USE_7_EDUSECURE_SCENARIOS (1).txt'
    content = b'Uploaded through the browser'
    status, data = http(gui, 'POST', '/api/upload?name=' + quote(filename, safe=''), content)
    assert status == 202
    deadline = time.monotonic() + 20
    while any(j['status'] in ('queued','running') for j in gui[0].state()['jobs']) and time.monotonic() < deadline:
        time.sleep(.03)
    assert gui[0].state()['jobs'][-1]['status'] == 'complete'
    uploaded = gui[0].state()['jobs'][-1]
    assert uploaded['id'] == json.loads(data)['job']
    request = uploaded['result']['request']
    row = next(row for row in gui[0].state()['transfers'] if row['request'] == request)
    assert row['name'] == filename and row['crypto']['upload']['signature_verified']
    received = job(gui, '/api/download', {'request': request})
    assert received['status'] == 'complete', received
    row = next(row for row in gui[0].state()['transfers'] if row['request'] == request)
    assert row['crypto']['download']['signature_verified']
    assert http(gui, 'GET', '/api/file/' + request) == (200, content)
    invalid = http(gui, 'POST', '/api/text', {'text': ''})
    assert invalid[0] == 400
    assert job(gui, '/api/download', {'request': '0'*32})['status'] == 'failed'


def test_gui_detects_audit_edit(gui):
    start(gui)
    assert job(gui, '/api/sample', {'name': 'transaction.txt'})['status'] == 'complete'
    assert job(gui, '/api/audit/verify')['status'] == 'complete'
    path = gui[0].root / 'audit.jsonl'
    original = path.read_bytes()
    path.write_bytes(original.replace(b'authentication', b'authenticatioX', 1))
    assert job(gui, '/api/audit/verify')['status'] == 'failed'
    assert gui[0].state()['audit']['verified'] is False
    path.write_bytes(original)


def test_gui_failed_remote_authentication_does_not_replace_local_demo(gui, lab):
    server, _, _, _ = lab
    start(gui)
    original = gui[0].target
    result = job(gui, '/api/connect', {'host': server.address[0], 'port': server.address[1]})
    assert result['status'] == 'failed'
    assert gui[0].mode == 'local' and gui[0].target == original
    assert job(gui, '/api/sample', {'name': 'identity.png'})['status'] == 'complete'
