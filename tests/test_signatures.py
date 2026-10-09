import secrets
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
import pytest
from securelink.client import Client
from securelink.metrics import CryptoMetrics
from securelink.protocol import canonical, ProtocolError
from securelink.server import BankServer
from securelink.signatures import sign,verify
from securelink.storage import metadata_for,TransferStore


@pytest.fixture
def signed_lab(lab,tmp_path):
    _,secret,audit,_=lab
    key=Ed25519PrivateKey.generate()
    with BankServer(tmp_path/'signed',{'terminal-1':secret},audit,
                    signing_keys={'terminal-1':key.public_key().public_bytes_raw()},
                    attempts_per_minute=100000) as server:
        yield server,secret,key.private_bytes_raw()


def test_signed_transfer_metrics_and_persistence(signed_lab,tmp_path):
    server,secret,private=signed_lab
    source=tmp_path/'message.txt';source.write_text('Signed multimedia manifest',encoding='utf-8')
    with Client(server.address,'terminal-1',secret,signing_key=private) as client:
        result=client.upload(source)
        request=result['request']
        upload=client.metrics.snapshot()
        assert result['signature']['algorithm']=='Ed25519'
        assert len(result['signature']['signature'])==128
        assert client.server_metrics['signature_verification']['calls']==1
        assert client.server_metrics['hashing']['bytes']==source.stat().st_size
        assert all(value['nanoseconds']>0 and value['failures']==0 for value in upload.values())
        assert upload['hashing']['calls']==1 and upload['signing']['calls']==1
        assert upload['encryption']['calls']>=3 and upload['decryption']['calls']>=3
        client.download(request,tmp_path/'received.txt')
        received=client.metrics.snapshot()
        assert received['signature_verification']['calls']==1
        assert received['hashing']['bytes']==source.stat().st_size
        assert (tmp_path/'received.txt').read_bytes()==source.read_bytes()
    reopened=TransferStore(server.store.root)
    assert reopened.status('terminal-1',request)['signature']==result['signature']
    with Client(server.address,'terminal-1',secret,signing_key=private) as client:
        assert client.upload(source,request)['complete']


@pytest.mark.parametrize('changed',['hash','name','request','device'])
def test_signature_context_tampering_rejected(tmp_path,changed):
    key=Ed25519PrivateKey.generate()
    path=tmp_path/'note.txt';path.write_text('original')
    metadata=metadata_for(path);request=secrets.token_hex(16);device='terminal-1'
    proof=sign(key.private_bytes_raw(),device,request,metadata,CryptoMetrics())
    if changed=='hash':metadata['sha256']='0'*64
    elif changed=='name':metadata['name']='other.txt'
    elif changed=='request':request=secrets.token_hex(16)
    else:device='terminal-2'
    metrics=CryptoMetrics()
    with pytest.raises(ProtocolError,match='verification failed'):
        verify(proof,key.public_key().public_bytes_raw(),device,request,metadata,metrics)
    assert metrics.snapshot()['signature_verification']['failures']==1


@pytest.mark.parametrize('mode',['unsigned','wrong-key','corrupted-signature'])
def test_server_requires_pinned_signature(signed_lab,tmp_path,mode):
    server,secret,private=signed_lab
    source=tmp_path/'note.txt';source.write_text('Receiver must reject invalid signatures')
    if mode=='corrupted-signature':
        request=secrets.token_hex(16);metadata=metadata_for(source)
        proof=sign(private,'terminal-1',request,metadata,CryptoMetrics())
        proof['signature']=('00' if proof['signature'][:2]!='00' else '01')+proof['signature'][2:]
        with Client(server.address,'terminal-1',secret) as client:
            client.connect()
            with pytest.raises(ProtocolError,match='signature verification failed'):
                client.call('begin',canonical({'metadata':metadata,'signature':proof}),request=request)
    else:
        chosen=None if mode=='unsigned' else Ed25519PrivateKey.generate().private_bytes_raw()
        with Client(server.address,'terminal-1',secret,signing_key=chosen) as client:
            with pytest.raises(ProtocolError,match='signature'):
                client.upload(source)
    with server.store.connect() as db:
        assert db.execute('SELECT count(*) FROM transfers').fetchone()[0]==0


def test_download_rejects_changed_signed_manifest(signed_lab,tmp_path,monkeypatch):
    server,secret,private=signed_lab
    source=tmp_path/'note.txt';source.write_text('Original signed contents')
    with Client(server.address,'terminal-1',secret,signing_key=private) as client:
        request=client.upload(source)['request']
        original=client.call
        def changed(kind,*args,**kwargs):
            result=original(kind,*args,**kwargs)
            if kind=='status':result['metadata']['name']='forged.txt'
            return result
        monkeypatch.setattr(client,'call',changed)
        with pytest.raises(ProtocolError,match='signature verification failed'):
            client.download(request,tmp_path/'should_not_exist.txt')
        assert not (tmp_path/'should_not_exist.txt').exists()
