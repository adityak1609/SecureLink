import json
import time

import pytest

from securelink import crypto_lab
from securelink.metrics import CryptoMetrics, operation_rate
from securelink.security_metrics import _block, difference, hash_resistance, text_security
from securelink.settings import ROOT
from tests.test_gui import gui, http, job


def upload_lab(gui, name, content):
    status, raw = http(gui, 'POST', '/api/lab/encrypt?name='+name, content)
    assert status == 202, raw
    job_id = json.loads(raw)['job']
    deadline = time.monotonic()+30
    while time.monotonic() < deadline:
        current = next(row for row in gui[0].state()['jobs'] if row['id']==job_id)
        if current['status'] in ('failed', 'complete'):
            return current
        time.sleep(.02)
    pytest.fail('Encryption demonstration did not finish')


def test_aes_sensitivity_uses_real_blocks_and_exact_change_counts(monkeypatch):
    key = bytes(range(32))
    block = bytes.fromhex('00112233445566778899aabbccddeeff')
    assert _block(key, block).hex() == '8ea2b7ca516745bfeafc49904b496089'
    monkeypatch.setattr('securelink.security_metrics.secrets.token_bytes', lambda size: key)
    report = text_security(block)
    assert report['baseline_ciphertext_hex'] == '8ea2b7ca516745bfeafc49904b496089'
    assert [row['trial_count'] for row in report['series']] == [128,256]
    original = bytes.fromhex(report['baseline_ciphertext_hex'])
    for series in report['series']:
        for trial in series['trials']:
            output = bytes.fromhex(trial['output_hex'])
            changed = sum(bin(a ^ b).count('1') for a,b in zip(original,output))
            assert trial['bit_percent'] == pytest.approx(changed/128*100)
            assert trial['character_percent'] == pytest.approx(sum(a!=b for a,b in zip(original,output))/16*100)
        assert series['mean_bit_percent'] == pytest.approx(sum(row['bit_percent'] for row in series['trials'])/series['trial_count'])
    exact = difference(b'\0\0', b'\1\0')
    assert exact['bit_percent']==6.25 and exact['character_percent']==50 and exact['hex_character_percent']==25
    assert text_security(b'hi')['zero_padding_bytes']==14


def test_hash_criteria_search_full_digests_and_report_real_matches():
    report = hash_resistance(b'abc', attempts=32)
    assert report['target_digest_hex']=='ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad'
    assert {row['criterion'] for row in report['criteria']}=={'preimage','second_preimage','collision'}
    assert all(row['attempts']==32 and not row['match_found'] and row['milliseconds']>=0 for row in report['criteria'])
    assert report['one_bit_changed_digest_hex'] != report['target_digest_hex']
    guessed = hash_resistance(b'SecureLink candidate 0', attempts=32)
    assert guessed['criteria'][0]['match_found'] and guessed['criteria'][0]['attempts']==1
    assert not guessed['criteria'][1]['match_found']
    with pytest.raises(ValueError):
        hash_resistance(b'abc', attempts=100000)


@pytest.mark.parametrize('name', ['transaction.txt','identity.png','identity.jpg'])
def test_lab_text_image_encrypt_decrypt_full_ciphertext_and_exports(gui, name):
    content=(ROOT/'sample_data/fixtures'/name).read_bytes()
    sent=upload_lab(gui,name,content)
    assert sent['status']=='complete', sent
    run_id=sent['result']['run_id']
    base='/api/lab/'+run_id
    status,raw=http(gui,'GET',base)
    report=json.loads(raw)
    assert status==200 and not report['decrypted']
    assert http(gui,'GET',base+'/recovered')[0]==400
    assert http(gui,'GET',base+'/source')==(200,content)
    encrypted=http(gui,'GET',base+'/ciphertext')[1]
    assert len(encrypted)==len(content)+16 and encrypted[:-16]!=content
    assert encrypted[-16:].hex()==report['tag_hex']
    collected=bytearray()
    offset=0
    while offset is not None:
        status,raw=http(gui,'GET',base+'/hex?offset='+str(offset))
        page=json.loads(raw)
        assert status==200 and page['offset']==len(collected)
        collected.extend(bytes.fromhex(page['hex']))
        offset=page['next_offset']
    assert bytes(collected)==encrypted[:-16]
    result=job(gui,'/api/lab/decrypt',{'id':run_id})
    assert result['status']=='complete',result
    report=json.loads(http(gui,'GET',base)[1])
    assert report['signature_verified'] and report['received_sha256']==report['metadata']['sha256']
    assert report['tampering']['rejected'] and report['tampering']['payload_difference']['changed_bits']==1
    assert http(gui,'GET',base+'/recovered')==(200,content)
    assert report['metrics']['signing']['nanoseconds']>0
    assert report['decryption_metrics']['signature_verification']['nanoseconds']>0
    assert report['metrics']['encryption']['throughput_mib_s']>0
    assert report['decryption_metrics']['decryption']['throughput_mib_s']>0
    for resource in ('report','signature','source','recovered','ciphertext','hex'):
        assert http(gui,'GET',base+'/'+resource)[0]==200
        assert http(gui,'GET',base+'/'+resource,authenticated=False)[0]==401
    assert http(gui,'GET',base+'/key.bin')[0]==400
    assert http(gui,'GET',base+'/hex?offset=-1')[0]==400
    assert http(gui,'GET',base+'/hex?offset='+str(len(content)))[0]==400
    private=(gui[0].lab_directory(run_id)/'key.bin').read_bytes()
    public_bytes=http(gui,'GET',base+'/report')[1]
    assert private.hex().encode() not in public_bytes and gui[0].signing_key.hex().encode() not in public_bytes
    if name.endswith('.txt'):
        assert report['text_security']['series'][0]['trial_count']==128
    else:
        assert report['image_metrics']['pixels_equal'] and report['image_metrics']['mse']==0


@pytest.mark.parametrize('change', ['ciphertext','signature','metadata'])
def test_lab_rejects_tampering_and_revokes_recovered_access(gui, change):
    sent=upload_lab(gui,'message.txt','A message नमस्ते'.encode('utf-8'))
    run_id=sent['result']['run_id']
    folder=gui[0].lab_directory(run_id)
    initial = job(gui,'/api/lab/decrypt',{'id':run_id})
    assert initial['status']=='complete', initial.get('error')
    if change=='ciphertext':
        data=bytearray((folder/'ciphertext.bin').read_bytes()); data[0]^=1
        (folder/'ciphertext.bin').write_bytes(data)
    else:
        report=json.loads((folder/'report.json').read_text())
        if change=='signature':
            report['signature']['signature']='00'*64
        else:
            report['metadata']['name']='altered.txt'
        crypto_lab.save_report(folder,report)
    assert job(gui,'/api/lab/decrypt',{'id':run_id})['status']=='failed'
    assert http(gui,'GET','/api/lab/'+run_id+'/recovered')[0]==400
    failed = json.loads(http(gui,'GET','/api/lab/'+run_id)[1])
    assert not failed['decrypted'] and 'decryption_metrics' not in failed and 'decrypted_at' not in failed


def test_lab_input_access_controls_and_saved_artifacts(gui):
    assert http(gui,'POST','/api/lab/encrypt?name=message.txt',b'secret',authenticated=False)[0]==401
    assert http(gui,'POST','/api/lab/encrypt?name=../escape.txt',b'x')[0]==400
    assert http(gui,'POST','/api/lab/encrypt?name=video.mp4',headers={'Content-Length':'1'})[0]==400
    assert http(gui,'POST','/api/lab/encrypt?name=empty.txt',b'')[0]==400
    assert upload_lab(gui,'fake.png',b'not an image')['status']=='failed'
    result=upload_lab(gui,'saved.txt',b'persistent example')
    run_id=result['result']['run_id']
    from securelink.gui import Application
    restarted=Application(gui[0].root)
    try:
        assert any(row['id']==run_id for row in restarted.lab_runs())
        assert restarted.lab_decrypt(run_id,{})['run_id']==run_id
    finally:
        restarted.close()


def test_crypto_speed_uses_processed_bytes_and_excludes_failures():
    assert operation_rate('encryption',{'bytes':1048576,'milliseconds':1000,'failures':0})==1
    assert operation_rate('decryption',{'bytes':1048576,'milliseconds':1000,'failures':1}) is None
    assert operation_rate('signing',{'bytes':1048576,'milliseconds':1000}) is None
    assert operation_rate('encryption',{'bytes':1,'milliseconds':0}) is None
    metrics=CryptoMetrics()
    with metrics.measure('encryption',1048576):
        pass
    assert metrics.snapshot()['encryption']['throughput_mib_s']>0
