import concurrent.futures
import hashlib
import json
import secrets
import socket
import struct
import threading
import time
import uuid
from pathlib import Path

import pytest
from cryptography.exceptions import InvalidTag
from securelink.audit import AuditLog
from securelink.client import Client
from securelink.protocol import (Session, ProtocolError, canonical, decode_json, send_packet,
    recv_packet, handshake_client, handshake_server)
from securelink.settings import MAX_FRAME, MAX_FILE, CHUNK_SIZE
from securelink.storage import metadata_for, file_hash

def client(lab):
    server,key,_,_ = lab
    return Client(server.address,'terminal-1',key,retry_delay=.01)

def paired():
    a,b=socket.socketpair()
    c2s,s2c=secrets.token_bytes(32),secrets.token_bytes(32)
    return Session(a,c2s,s2c,'test-session','server'),Session(b,s2c,c2s,'test-session','client')

def test_exact_record_replay_rejected():
    a,b=paired()
    try:
        packet=a.encode('chunk',b'secret',{'request':'x','offset':0})
        send_packet(a.sock,packet)
        assert b.receive()[1]==b'secret'
        send_packet(a.sock,packet)
        with pytest.raises(ProtocolError,match='replay'):
            b.receive()
    finally:
        a.close();b.close()

@pytest.mark.parametrize('target',['ciphertext','kind','offset','request'])
def test_tampering_rejected(target):
    a,b=paired()
    try:
        packet=a.encode('chunk',b'private content',{'offset':0,'request':'a'*32})
        n=struct.unpack('!H',packet[:2])[0]
        header=decode_json(packet[2:2+n]);body=packet[2+n:]
        if target=='ciphertext':
            body=body[:-1]+bytes([body[-1]^1])
        elif target=='kind':
            header['kind']='finish'
        else:
            header['meta'][target]=1 if target=='offset' else 'b'*32
        encoded=canonical(header)
        send_packet(a.sock,struct.pack('!H',len(encoded))+encoded+body)
        with pytest.raises(InvalidTag):
            b.receive()
    finally:
        a.close();b.close()

def test_wrong_secret_and_server_identity(lab):
    server,key,_,_=lab
    for secret,name in [(secrets.token_bytes(32),'bank-server'),(key,'impersonator')]:
        with socket.create_connection(server.address) as sock:
            with pytest.raises((ProtocolError,ConnectionError,OSError)):
                handshake_client(sock,'terminal-1',secret,name)

def test_fresh_sessions_and_direction_keys(lab):
    with client(lab) as first,client(lab) as second:
        first.connect();second.connect()
        assert first.session.sid!=second.session.sid
        assert first.session.send_key!=first.session.receive_key
        assert first.session.send_key!=second.session.send_key

def test_old_session_record_rejected(lab):
    with client(lab) as c:
        c.connect()
        packet=c.session.encode('status',metadata={'request':'a'*32})
        c.connect()
        send_packet(c.session.sock,packet)
        with pytest.raises((ConnectionError,OSError)):
            c.session.receive()

def test_oversized_frame_rejected_before_payload():
    a,b=socket.socketpair()
    try:
        a.sendall(struct.pack('!I',MAX_FRAME+1))
        with pytest.raises(ProtocolError,match='size'):
            recv_packet(b)
    finally:
        a.close();b.close()

def test_absolute_deadline():
    a,b=socket.socketpair()
    try:
        a.sendall(struct.pack('!I',10)+b'a')
        start=time.monotonic()
        with pytest.raises(TimeoutError):
            recv_packet(b,timeout=.08)
        assert time.monotonic()-start<.5
    finally:
        a.close();b.close()

@pytest.mark.parametrize('name',['transaction.txt','identity.png','identity.jpg','audio.wav','audio.mp3'])
def test_real_media_roundtrip(lab,tmp_path,name):
    source=Path('sample_data/fixtures')/name
    assert source.exists(),'Run generate_samples.py before tests'
    with client(lab) as c:
        result=c.upload(source)
        target=c.download(result['request'],tmp_path/name)
        assert file_hash(source)==file_hash(target)


def test_video_upload_is_not_supported(lab,tmp_path):
    source=tmp_path/'video.mp4'
    source.write_bytes(b'\0\0\0\x18ftypisom')
    with client(lab) as c:
        with pytest.raises(ProtocolError,match='Unsupported media format'):
            c.upload(source)

@pytest.mark.parametrize('failure',['chunk','finish'])
def test_lost_ack_recovery_and_idempotency(lab,tmp_path,failure):
    server,_,audit,_=lab
    dropped=[]
    def fault(kind,request,result):
        if kind==failure and not dropped:
            dropped.append(True)
            return True
        return False
    server.fault=fault
    source=tmp_path/'transaction.txt'
    source.write_text(json.dumps({'action':'transfer','source':'A','destination':'B','amount_paise':100}),encoding='utf-8')
    request=uuid.uuid4().hex
    with client(lab) as c:
        first=c.upload(source,request)
        assert c.retries==1
        assert first['complete']
        c.connect()
        assert c.upload(source,request)['complete']
    with server.store.connect() as db:
        assert db.execute('SELECT count(*) FROM transactions').fetchone()[0]==1
    assert audit.verify()[0]>0

def test_resume_across_new_client(lab,tmp_path):
    source=tmp_path/'large.txt'
    source.write_bytes(b'x'*(CHUNK_SIZE*3+123))
    request=uuid.uuid4().hex
    with client(lab) as c:
        c.connect();c.call('begin',canonical(metadata_for(source)),request=request)
        c.call('chunk',b'x'*CHUNK_SIZE,request=request,offset=0)
    with client(lab) as c:
        assert c.upload(source,request)['complete']
        assert file_hash(c.download(request,tmp_path/'copy.txt'))==file_hash(source)

def test_request_conflict_and_owner_isolation(lab,tmp_path):
    server,_,_,_=lab
    source=tmp_path/'test.txt';source.write_text('hello')
    request=uuid.uuid4().hex
    with client(lab) as c:
        c.upload(source,request)
        source.write_text('changed')
        with pytest.raises(ProtocolError,match='different'):
            c.upload(source,request)
    other=Client(server.address,'terminal-2',server.devices['terminal-2'])
    with other:
        other.connect()
        with pytest.raises(ProtocolError,match='Unknown'):
            other.call('status',request=request)

@pytest.mark.parametrize('case',['traversal','oversize','mismatch','reorder','incomplete'])
def test_invalid_transfer(lab,tmp_path,case):
    source=tmp_path/'test.txt';source.write_text('hello')
    meta=metadata_for(source);request=uuid.uuid4().hex
    with client(lab) as c:
        c.connect()
        if case=='traversal':meta['name']='../test.txt'
        if case=='oversize':meta['size']=MAX_FILE+1
        if case in ('traversal','oversize'):
            with pytest.raises(ProtocolError):c.call('begin',canonical(meta),request=request)
            return
        c.call('begin',canonical(meta),request=request)
        with pytest.raises(ProtocolError):
            if case=='reorder':c.call('chunk',b'hello',request=request,offset=1)
            else:
                if case=='mismatch':c.call('chunk',b'other',request=request,offset=0)
                c.call('finish',request=request)

@pytest.mark.parametrize('attack',['edit','truncate','rewrite','delete'])
def test_audit_attacks_detected(lab,attack):
    _,_,audit,_=lab
    audit.log('one');audit.log('two')
    entries=audit.entries()
    if attack=='edit':entries[0]['event']='forged'
    if attack=='truncate':entries=entries[:-1]
    if attack=='delete':entries=[]
    if attack=='rewrite':
        previous='0'*64
        for entry in entries:
            entry['event']='forged';entry['previous']=previous
            entry.pop('hash');entry['hash']=hashlib.sha256(canonical(entry)).hexdigest();previous=entry['hash']
    audit.path.write_bytes(b''.join(canonical(e)+b'\n' for e in entries))
    with pytest.raises(ProtocolError):audit.verify()

def test_concurrent_audit_writes(lab):
    _,_,audit,_=lab
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
        list(pool.map(lambda i:audit.log('event',details={'n':i}),range(12)))
    assert audit.verify()[0]==12

def test_connection_limit_recovers(lab,tmp_path):
    server,_,_,_=lab
    held=[socket.create_connection(server.address) for _ in range(8)]
    try:
        time.sleep(.15)
        with socket.create_connection(server.address) as excess:
            excess.settimeout(1)
            assert excess.recv(1)==b''
        assert server.rejected>=1
    finally:
        for sock in held:sock.close()
    deadline=time.monotonic()+3
    while time.monotonic()<deadline:
        with server.lock:
            if not server.connections:break
        time.sleep(.02)
    source=tmp_path/'ok.txt';source.write_text('legitimate')
    with client(lab) as c:assert c.upload(source)['complete']

def test_download_recovers_after_disconnect(lab,tmp_path):
    server,_,_,_=lab
    source=tmp_path/'source.txt';source.write_bytes(b'a'*(CHUNK_SIZE*3+15))
    dropped=[]
    def fault(kind,request,result):
        if kind=='read' and result['offset']>=CHUNK_SIZE and not dropped:
            dropped.append(True);return True
        return False
    with client(lab) as c:
        result=c.upload(source)
        server.fault=fault
        target=c.download(result['request'],tmp_path/'download.txt')
        assert c.retries==1 and file_hash(target)==file_hash(source)

def test_partial_and_completed_state_survive_store_restart(lab,tmp_path):
    from securelink.storage import TransferStore
    server,_,_,_=lab
    source=tmp_path/'source.txt';source.write_bytes(b'z'*(CHUNK_SIZE+10))
    request=uuid.uuid4().hex
    with client(lab) as c:
        c.connect();c.call('begin',canonical(metadata_for(source)),request=request)
        c.call('chunk',b'z'*CHUNK_SIZE,request=request,offset=0)
    server.store=TransferStore(server.store.root)
    with client(lab) as c:assert c.upload(source,request)['complete']
    server.store=TransferStore(server.store.root)
    with client(lab) as c:assert c.upload(source,request)['complete']

def test_witness_rejects_rollback_and_conflict(lab):
    _,_,audit,witness=lab
    first=audit.log('one');audit.log('two')
    for count,head,previous in [(1,first['hash'],'0'*64),(2,'a'*64,first['hash'])]:
        with pytest.raises((ProtocolError,ConnectionError,OSError)):
            witness.anchor(count,head,previous)

def test_audit_fails_closed_and_recovers_pending(lab,monkeypatch):
    _,_,audit,witness=lab
    original=witness.anchor
    def unavailable(*args):raise ConnectionError('Witness unavailable')
    monkeypatch.setattr(witness,'anchor',unavailable)
    with pytest.raises(ConnectionError):audit.log('unacknowledged')
    monkeypatch.setattr(witness,'anchor',original)
    audit.log('recovered')
    assert audit.verify()[0]==2 and witness.get()['count']==2

def test_legitimate_transfer_while_slow_peer_connected(lab,tmp_path):
    server,_,_,_=lab
    with socket.create_connection(server.address) as slow:
        slow.sendall(b'\x00')
        source=tmp_path/'legitimate.txt';source.write_text('available')
        with client(lab) as c:assert c.upload(source)['complete']

def test_file_quota_and_format_rejection(lab,tmp_path,monkeypatch):
    import securelink.storage as storage
    source=tmp_path/'fake.png';source.write_bytes(b'not an image')
    with client(lab) as c:
        with pytest.raises(ProtocolError,match='format'):c.upload(source)
    monkeypatch.setattr(storage,'MAX_STORAGE',1)
    source=tmp_path/'large.txt';source.write_text('too large')
    with client(lab) as c:
        with pytest.raises(ProtocolError,match='quota'):c.upload(source)

def test_duplicate_json_fields_rejected():
    with pytest.raises(ProtocolError):decode_json(b'{"seq":1,"seq":2}')

def test_plaintext_lab_cannot_bind_to_lan(tmp_path):
    from securelink.server import BankServer
    with pytest.raises(ValueError,match='loopback'):
        BankServer(tmp_path,{},None,plaintext_lab=True,host='0.0.0.0')

def test_expired_handshake_timestamp_rejected(lab):
    """Handshake with a timestamp far in the past or future must be rejected."""
    from securelink.settings import HANDSHAKE_CLOCK_SKEW
    server,key,_,_=lab
    for offset in [-(HANDSHAKE_CLOCK_SKEW+60), HANDSHAKE_CLOCK_SKEW+60]:
        with socket.create_connection(server.address) as sock:
            hello=canonical({'v':3,'client':'terminal-1','server':'bank-server',
                             'nc':secrets.token_hex(32),'time':int(time.time())+offset})
            send_packet(sock,hello,4096)
            with pytest.raises((ProtocolError,ConnectionError,OSError)):
                recv_packet(sock,4096)

def test_valid_timestamp_within_skew_accepted(lab):
    """Normal handshake with current timestamp must succeed."""
    with client(lab) as c:
        c.connect()
        assert c.session is not None and c.session.sid
