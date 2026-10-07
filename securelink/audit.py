"""Hash chain anchored to a separately operated authenticated witness.

The witness stores only counts and chain heads. It cannot attest to truth of
events, and compromise of both services is outside the security claim.
"""
import hashlib
import json
import os
from pathlib import Path
import socket
import sqlite3
import threading
from datetime import datetime, timezone
from contextlib import closing

from .protocol import canonical, decode_json, handshake_client, handshake_server, ProtocolError
from .service import TCPService

GENESIS = '0' * 64


class Witness(TCPService):
    def __init__(self, database, devices, **kwargs):
        super().__init__(**kwargs)
        self.database = str(database)
        Path(database).parent.mkdir(parents=True, exist_ok=True)
        self.devices = devices
        self.db_lock = threading.Lock()
        with closing(sqlite3.connect(self.database)) as db, db:
            db.execute('CREATE TABLE IF NOT EXISTS anchors (identity TEXT PRIMARY KEY, count INTEGER, head TEXT)')

    def handle(self, conn, addr):
        session = handshake_server(conn, self.devices, 'audit-witness')
        kind, body, _ = session.receive()
        with self.db_lock, closing(sqlite3.connect(self.database)) as db, db:
            row = db.execute('SELECT count, head FROM anchors WHERE identity=?', (session.peer,)).fetchone()
            current = {'count': row[0], 'head': row[1]} if row else {'count': 0, 'head': GENESIS}
            if kind == 'anchor':
                value = decode_json(body)
                if (not isinstance(value, dict) or set(value) != {'count', 'head', 'previous'} or
                        type(value['count']) is not int or not isinstance(value['head'], str) or
                        len(value['head']) != 64 or any(c not in '0123456789abcdef' for c in value['head'])):
                    raise ProtocolError('Invalid checkpoint')
                if value['count'] == current['count'] and value['head'] == current['head']:
                    pass  # Lost acknowledgement: idempotent checkpoint retry.
                elif value['count'] == current['count'] + 1 and value['previous'] == current['head']:
                    db.execute('INSERT OR REPLACE INTO anchors VALUES (?, ?, ?)',
                               (session.peer, value['count'], value['head']))
                    current = {'count': value['count'], 'head': value['head']}
                else:
                    raise ProtocolError('Checkpoint rollback or conflicting chain')
            elif kind != 'checkpoint':
                raise ProtocolError('Unsupported witness operation')
        session.send('checkpoint', canonical(current))


class WitnessClient:
    def __init__(self, address, identity, secret):
        self.address, self.identity, self.secret = address, identity, secret

    def call(self, kind, value=None):
        with socket.create_connection(self.address, timeout=3) as sock:
            session = handshake_client(sock, self.identity, self.secret, 'audit-witness')
            session.send(kind, canonical(value) if value else b'')
            result, body, _ = session.receive()
            if result != 'checkpoint':
                raise ProtocolError('Invalid witness response')
            return decode_json(body)

    def get(self):
        return self.call('checkpoint')

    def anchor(self, count, head, previous):
        return self.call('anchor', {'count': count, 'head': head, 'previous': previous})


class AuditLog:
    def __init__(self, path, witness):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.witness = witness
        self.lock = threading.Lock()
        self.count, self.head = self.verify()
        # A crash can leave fsynced entries after the latest witness checkpoint.
        self._anchor_pending()
        self.pending = None

    def entries(self):
        if not self.path.exists():
            return []
        with self.path.open(encoding='utf-8') as stream:
            return [json.loads(line) for line in stream if line.strip()]

    def verify(self):
        checkpoint = self.witness.get()
        head, count = GENESIS, 0
        anchored = checkpoint == {'count': 0, 'head': GENESIS}
        for entry in self.entries():
            fields = dict(entry)
            saved = fields.pop('hash')
            count += 1
            if fields['index'] != count or fields['previous'] != head:
                raise ProtocolError('Audit chain order invalid')
            head = hashlib.sha256(canonical(fields)).hexdigest()
            if saved != head:
                raise ProtocolError('Audit record modified')
            if count == checkpoint['count']:
                anchored = head == checkpoint['head']
        if count < checkpoint['count'] or not anchored:
            raise ProtocolError('Audit truncation or rewrite detected against witness')
        return count, head

    def _anchor_pending(self):
        checkpoint = self.witness.get()
        for entry in self.entries()[checkpoint['count']:]:
            self.witness.anchor(entry['index'], entry['hash'], entry['previous'])

    def log(self, event, device='', session='', request='', outcome='ok', details=None):
        with self.lock:
            if self.pending:
                self.witness.anchor(*self.pending)
                self.pending = None
            entry = {'index': self.count + 1, 'previous': self.head,
                     'timestamp': datetime.now(timezone.utc).isoformat(), 'event': event,
                     'device': device, 'session': session, 'request': request,
                     'outcome': outcome, 'details': details or {}}
            entry['hash'] = hashlib.sha256(canonical(entry)).hexdigest()
            with self.path.open('ab') as stream:
                stream.write(canonical(entry) + b'\n')
                stream.flush()
                os.fsync(stream.fileno())
            self.count, self.head = entry['index'], entry['hash']
            # Fail closed if the witness is unavailable; persisted entry is retried later.
            self.pending = (self.count, self.head, entry['previous'])
            self.witness.anchor(*self.pending)
            self.pending = None
            return entry
