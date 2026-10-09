import math
import secrets
import socket
import pytest
from PIL import Image
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from securelink.client import Client
from securelink.protocol import Session, send_packet
from securelink.image_metrics import image_metrics


def test_ciphertext_sample_is_the_actual_transmitted_and_verified_record():
    left,right=socket.socketpair()
    key,reverse=secrets.token_bytes(32),secrets.token_bytes(32)
    sender=Client(('127.0.0.1',1),'sender',key,collect_evidence=True)
    receiver=Client(('127.0.0.1',1),'receiver',key,collect_evidence=True)
    sending=Session(left,key,reverse,'session','receiver',record_observer=sender.observe_record)
    receiving=Session(right,reverse,key,'session','sender',record_observer=receiver.observe_record)
    payload=b'Actual media bytes'
    try:
        sending.send('chunk',payload,{'request':'a'*32,'offset':0})
        assert receiving.receive()[1]==payload
        sent=sender.ciphertext_samples[0]
        received=receiver.ciphertext_samples[0]
        for field in ('ciphertext_prefix_hex','gcm_tag_hex','nonce_hex','authenticated_header'):
            assert sent[field]==received[field]
        body=bytes.fromhex(sent['ciphertext_prefix_hex']+sent['gcm_tag_hex'])
        assert AESGCM(key).decrypt(bytes.fromhex(sent['nonce_hex']),body,sent['authenticated_header'].encode())==payload
        assert sent['ciphertext_bytes']==len(payload) and sent['direction']=='sent'
        assert received['direction']=='received'
        assert payload.hex()!=sent['ciphertext_prefix_hex']
        for offset in range(1,4):
            sending.send('chunk',b'x'*200,{'request':'a'*32,'offset':offset})
            receiving.receive()
        assert len(sender.ciphertext_samples)==len(receiver.ciphertext_samples)==1
        sender.ciphertext_samples=[]
        sending.send('chunk',b'y'*200,{'request':'b'*32,'offset':0})
        receiving.receive()
        assert sender.ciphertext_samples[0]['prefix_bytes']==64
        assert len(sender.ciphertext_samples[0]['ciphertext_prefix_hex'])==128
    finally:
        sending.close();receiving.close()


def test_invalid_ciphertext_is_not_reported_as_a_verified_received_sample():
    left,right=socket.socketpair()
    key=secrets.token_bytes(32)
    client=Client(('127.0.0.1',1),'receiver',key,collect_evidence=True)
    sending=Session(left,key,key,'session','receiver')
    receiving=Session(right,key,key,'session','sender',record_observer=client.observe_record)
    try:
        packet=sending.encode('data',b'media',{'request':'a'*32})
        send_packet(left,packet[:-1]+bytes([packet[-1]^1]))
        with pytest.raises(InvalidTag):
            receiving.receive()
        assert client.ciphertext_samples==[]
    finally:
        sending.close();receiving.close()


def test_image_metrics_measure_exact_pixels_and_detect_changed_pixels(tmp_path,monkeypatch):
    source=tmp_path/'original.png';received=tmp_path/'received.png'
    original=Image.new('RGBA',(2,2),(10,20,30,255))
    original.save(source);original.save(received)
    metrics=image_metrics(source,received)
    assert metrics['source']['width']==2 and metrics['source']['channels']==4
    assert metrics['pixels_equal'] and metrics['mse']==0 and metrics['psnr_db'] is None
    assert metrics['psnr']=='Infinity (identical pixels)'
    original.putpixel((0,0),(11,20,30,255));original.save(received)
    changed=image_metrics(source,received)
    assert not changed['pixels_equal'] and changed['mse']==1/16
    assert changed['psnr_db']==pytest.approx(10*math.log10(255**2/(1/16)))
    monkeypatch.setattr('securelink.image_metrics.MAX_METRIC_PIXELS',1)
    assert 'skipped' in image_metrics(source,received)['comparison']
    invalid=tmp_path/'invalid.png';invalid.write_bytes(b'not an image')
    assert image_metrics(invalid)['status']=='unavailable'
