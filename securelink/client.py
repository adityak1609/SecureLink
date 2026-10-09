import os
from pathlib import Path
import random
import socket
import time
import uuid
from .protocol import canonical, decode_json, handshake_client, plain_session, ProtocolError
from .settings import CHUNK_SIZE
from .storage import metadata_for, validate_metadata, file_hash, TransferStore
from .metrics import CryptoMetrics
from .signatures import sign, verify
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

class CountingSocket:
    def __init__(self,sock):
        self.sock=sock
        self.sent_bytes=0
        self.received_bytes=0
    def sendall(self,data):
        self.sock.sendall(data)
        self.sent_bytes+=len(data)
    def recv(self,size):
        data=self.sock.recv(size)
        self.received_bytes+=len(data)
        return data
    def __getattr__(self,name):
        return getattr(self.sock,name)

class Client:
    def __init__(self, address, identity, secret, server='bank-server', attempts=4, retry_delay=.2, plaintext_lab=False, signing_key=None):
        if plaintext_lab and address[0] != '127.0.0.1':
            raise ValueError('Plaintext baseline is restricted to loopback')
        self.address, self.identity, self.secret, self.server = address, identity, secret, server
        self.attempts, self.retry_delay, self.plaintext_lab = attempts, retry_delay, plaintext_lab
        self.session = None
        self.retries = 0
        self.handshake_ms = 0
        self.sent_bytes = 0
        self.received_bytes = 0
        self.signing_key=signing_key
        self.metrics=CryptoMetrics()
        self.server_metrics={}
        self.last_signature=None

    def connect(self):
        self.close()
        sock = CountingSocket(socket.create_connection(self.address, timeout=3))
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        start = time.perf_counter()
        try:
            self.session = plain_session(sock, True) if self.plaintext_lab else handshake_client(sock, self.identity, self.secret, self.server)
            self.session.metrics=self.metrics
        except Exception:
            sock.close()
            raise
        self.handshake_ms += (time.perf_counter()-start)*1000

    def close(self):
        if self.session:
            self.sent_bytes += self.session.sock.sent_bytes
            self.received_bytes += self.session.sock.received_bytes
            self.session.close()
            self.session = None

    def call(self, kind, body=b'', **meta):
        self.session.send(kind, body, meta)
        result, data, response_meta = self.session.receive()
        if result == 'error':
            raise ProtocolError(decode_json(data)['error'])
        if result not in ('ok','data') or response_meta.get('request') != meta.get('request'):
            raise ProtocolError('Unexpected response')
        if kind == 'read':
            if result != 'data' or response_meta.get('offset') != meta.get('offset'):
                raise ProtocolError('Wrong download chunk')
            return data
        if result != 'ok':
            raise ProtocolError('Expected acknowledgement')
        response=decode_json(data)
        self.server_metrics=response.get('crypto_metrics',{})
        return response

    def _retry(self, operation):
        for attempt in range(self.attempts):
            try:
                if self.session is None:
                    self.connect()
                return operation()
            except (OSError, ConnectionError, TimeoutError):
                self.close()
                if attempt + 1 == self.attempts:
                    raise
                self.retries += 1
                time.sleep(min(2.0,self.retry_delay*2**attempt)+random.uniform(0,.02))

    def upload(self, path, request=None, progress=None):
        self.metrics=CryptoMetrics()
        self.server_metrics={}
        if self.session:
            self.session.metrics=self.metrics
        path = Path(path)
        request = request or uuid.uuid4().hex
        TransferStore.check_request(request)
        meta = metadata_for(path,self.metrics)
        validate_metadata(meta)
        self.last_signature=sign(self.signing_key,self.identity,request,meta,self.metrics) if self.signing_key else None
        begin={'metadata':meta,'signature':self.last_signature} if self.last_signature else meta
        def attempt():
            status = self.call('begin', canonical(begin), request=request)
            offset = status['offset']
            if type(offset) is not int or not 0<=offset<=meta['size']:
                raise ProtocolError('Invalid resume offset')
            if progress:
                progress(offset, meta['size'])
            if status['complete']:
                return self.call('finish', request=request)
            with path.open('rb') as stream:
                stream.seek(offset)
                while offset < meta['size']:
                    data = stream.read(min(CHUNK_SIZE,meta['size']-offset))
                    if not data:
                        raise ProtocolError('Source file changed during upload')
                    result = self.call('chunk', data, request=request, offset=offset)
                    if result['offset'] != offset + len(data):
                        raise ProtocolError('Incorrect chunk acknowledgement')
                    offset = result['offset']
                    if progress:
                        progress(offset, meta['size'])
            result = self.call('finish', request=request)
            if not result['complete'] or result['metadata'] != meta:
                raise ProtocolError('Incorrect completion acknowledgement')
            return result
        result=self._retry(attempt)
        if self.last_signature and result.get('signature')!=self.last_signature:
            raise ProtocolError('Server did not acknowledge the expected digital signature')
        return result

    def download(self, request, destination, progress=None):
        self.metrics=CryptoMetrics()
        self.server_metrics={}
        self.last_signature=None
        if self.session:
            self.session.metrics=self.metrics
        TransferStore.check_request(request)
        destination = Path(destination)
        destination.parent.mkdir(parents=True, exist_ok=True)
        partial = destination.with_name(destination.name+'.'+request+'.part')
        def attempt():
            status = self.call('status', request=request)
            if not status['complete']:
                raise ProtocolError('Transfer not complete')
            meta = status['metadata']
            validate_metadata(meta)
            proof=status.get('signature')
            if self.signing_key:
                public=Ed25519PrivateKey.from_private_bytes(self.signing_key).public_key().public_bytes_raw()
                verify(proof,public,self.identity,request,meta,self.metrics)
                self.last_signature=proof
            offset = partial.stat().st_size if partial.exists() else 0
            if offset > meta['size']:
                raise ProtocolError('Partial download exceeds expected length')
            if progress:
                progress(offset, meta['size'])
            with partial.open('ab') as stream:
                while offset < meta['size']:
                    data = self.call('read', request=request, offset=offset)
                    if not 0<len(data)<=min(CHUNK_SIZE,meta['size']-offset):
                        raise ProtocolError('Invalid download size')
                    stream.write(data)
                    stream.flush()
                    offset += len(data)
                    if progress:
                        progress(offset, meta['size'])
                os.fsync(stream.fileno())
            if file_hash(partial,self.metrics) != meta['sha256']:
                raise ProtocolError('Downloaded file hash mismatch')
            self.call('download_complete', request=request)
            os.replace(partial, destination)
            return destination
        return self._retry(attempt)

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()
