import time
from .protocol import canonical, decode_json, handshake_server, plain_session, ProtocolError
from .service import TCPService
from .storage import TransferStore

class BankServer(TCPService):
    def __init__(self, directory, devices, audit, plaintext_lab=False, fault=None, **kwargs):
        if plaintext_lab and kwargs.get('host', '127.0.0.1') != '127.0.0.1':
            raise ValueError('Plaintext baseline is restricted to IPv4 loopback')
        super().__init__(**kwargs)
        self.store = TransferStore(directory)
        self.devices, self.audit, self.plaintext_lab = devices, audit, plaintext_lab
        self.fault = fault

    def handle(self, conn, addr):
        try:
            session = plain_session(conn, False) if self.plaintext_lab else handshake_server(conn, self.devices)
        except Exception:
            self.audit.log('authentication', outcome='rejected', details={'address': addr[0]})
            raise
        self.audit.log('authentication', device=session.peer, session=session.sid)
        window, count = time.monotonic(), 0
        while True:
            try:
                kind, body, meta = session.receive()
            except ConnectionError:
                return
            except Exception:
                self.audit.log('record_rejected', device=session.peer, session=session.sid, outcome='rejected')
                raise
            if time.monotonic() - window >= 1:
                window, count = time.monotonic(), 0
            count += 1
            if count > 1000:
                raise ProtocolError('Record rate limit exceeded')
            request = meta.get('request', '')
            try:
                if kind == 'begin':
                    result = self.store.begin(session.peer, request, decode_json(body))
                    self.audit.log('transfer_begin', device=session.peer, session=session.sid, request=request)
                elif kind == 'chunk':
                    result = {'offset': self.store.chunk(session.peer, request, meta.get('offset'), body)}
                elif kind == 'finish':
                    self.audit.log('transfer_finalize_requested', device=session.peer, session=session.sid, request=request)
                    result = self.store.finish(session.peer, request)
                    self.audit.log('transfer_complete', device=session.peer, session=session.sid, request=request,
                                   details={'sha256': result['metadata']['sha256'], 'size': result['metadata']['size']})
                elif kind == 'status':
                    result = self.store.status(session.peer, request)
                elif kind == 'read':
                    data = self.store.read(session.peer, request, meta.get('offset'))
                    if self.fault and self.fault(kind, request, {'offset': meta['offset']}):
                        return
                    session.send('data', data, {'request': request, 'offset': meta['offset']})
                    continue
                elif kind == 'download_complete':
                    result = self.store.status(session.peer, request)
                    self.audit.log('download_complete', device=session.peer, session=session.sid, request=request)
                else:
                    raise ProtocolError('Unknown operation')
                if self.fault and self.fault(kind, request, result):
                    return
                session.send('ok', canonical(result), {'request': request})
            except (ProtocolError, UnicodeError) as exc:
                self.audit.log('request_rejected', device=session.peer, session=session.sid,
                               request=request if isinstance(request,str) and len(request)<=32 else '', outcome='rejected')
                session.send('error', canonical({'error': str(exc)}))
                return
