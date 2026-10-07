"""Durable resumable transfers with owner-scoped idempotency."""
import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3
import threading
from contextlib import contextmanager
from .protocol import canonical, ProtocolError
from .settings import CHUNK_SIZE, MAX_FILE, MAX_STORAGE, MAX_TRANSFERS, EXTENSIONS

def file_hash(path):
    digest = hashlib.sha256()
    with open(path, 'rb') as stream:
        for block in iter(lambda: stream.read(CHUNK_SIZE), b''):
            digest.update(block)
    return digest.hexdigest()

def metadata_for(path):
    path = Path(path)
    return {'name': path.name, 'media': EXTENSIONS.get(path.suffix.lower()),
            'size': path.stat().st_size, 'sha256': file_hash(path)}

def validate_metadata(meta):
    if not isinstance(meta, dict) or set(meta) != {'name', 'media', 'size', 'sha256'}:
        raise ProtocolError('Invalid transfer metadata')
    name = meta['name']
    if (not isinstance(name, str) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_. -]{0,119}', name)
            or name.endswith(('.', ' '))):
        raise ProtocolError('Unsafe filename')
    if EXTENSIONS.get(Path(name).suffix.lower()) != meta['media'] or meta['media'] is None:
        raise ProtocolError('Unsupported media format')
    if type(meta['size']) is not int or not 0 < meta['size'] <= MAX_FILE:
        raise ProtocolError('File exceeds size limit or is empty')
    if not isinstance(meta['sha256'], str) or not re.fullmatch('[0-9a-f]{64}', meta['sha256']):
        raise ProtocolError('Invalid file digest')

def validate_content(path, meta):
    """Format consistency checks, not malware scanning or full decoding."""
    with open(path, 'rb') as stream:
        prefix = stream.read(32)
    ext = Path(meta['name']).suffix.lower()
    if ext == '.txt':
        import codecs
        decoder = codecs.getincrementaldecoder('utf-8')()
        with open(path, 'rb') as stream:
            for block in iter(lambda: stream.read(CHUNK_SIZE), b''):
                decoder.decode(block)
        decoder.decode(b'', final=True)
        return
    valid = {
        '.png': prefix.startswith(b'\x89PNG\r\n\x1a\n'),
        '.jpg': prefix.startswith(b'\xff\xd8\xff'), '.jpeg': prefix.startswith(b'\xff\xd8\xff'),
        '.wav': prefix.startswith(b'RIFF') and prefix[8:12] == b'WAVE',
        '.mp3': prefix.startswith(b'ID3') or (len(prefix)>1 and prefix[0]==255 and prefix[1]&224==224),
        '.mp4': prefix[4:8] == b'ftyp',
    }.get(ext, False)
    if not valid:
        raise ProtocolError('File contents do not match format')

class TransferStore:
    def __init__(self, directory):
        self.root = Path(directory)
        self.root.mkdir(parents=True, exist_ok=True)
        self.database = self.root / 'transfers.sqlite'
        self.lock = threading.RLock()
        with self.connect() as db:
            db.execute('CREATE TABLE IF NOT EXISTS transfers (device TEXT, request TEXT, metadata TEXT, offset INTEGER, complete INTEGER, path TEXT, PRIMARY KEY(device, request))')
            db.execute('CREATE TABLE IF NOT EXISTS transactions (device TEXT, request TEXT, source TEXT, destination TEXT, amount_paise INTEGER, PRIMARY KEY(device, request))')

    @contextmanager
    def connect(self):
        db = sqlite3.connect(self.database, timeout=10)
        db.row_factory = sqlite3.Row
        try:
            with db:
                yield db
        finally:
            db.close()

    @staticmethod
    def check_request(request):
        if not isinstance(request, str) or not re.fullmatch('[0-9a-f]{32}', request):
            raise ProtocolError('Request ID must be 32 lowercase hexadecimal characters')

    def _row(self, db, device, request):
        self.check_request(request)
        row = db.execute('SELECT * FROM transfers WHERE device=? AND request=?', (device, request)).fetchone()
        if not row:
            raise ProtocolError('Unknown transfer for this device')
        return row

    def _status(self, row):
        return {'request': row['request'], 'offset': row['offset'], 'complete': bool(row['complete']), 'metadata': json.loads(row['metadata'])}

    def begin(self, device, request, meta):
        self.check_request(request)
        validate_metadata(meta)
        encoded = canonical(meta).decode()
        with self.lock, self.connect() as db:
            row = db.execute('SELECT * FROM transfers WHERE device=? AND request=?', (device, request)).fetchone()
            if row:
                if row['metadata'] != encoded:
                    raise ProtocolError('Request ID reused with different content')
                path = self.root / row['path']
                if not path.exists() or path.stat().st_size < row['offset']:
                    raise ProtocolError('Stored transfer damaged')
                if row['complete']:
                    if file_hash(path) != meta['sha256']:
                        raise ProtocolError('Completed file damaged')
                else:
                    with path.open('r+b') as stream:
                        stream.truncate(row['offset'])
                return self._status(row)
            rows = db.execute('SELECT metadata FROM transfers').fetchall()
            if len(rows)>=MAX_TRANSFERS or sum(json.loads(r[0])['size'] for r in rows)+meta['size']>MAX_STORAGE:
                raise ProtocolError('Storage quota reached')
            filename = f'{device}_{request}_{meta["name"]}'
            with (self.root / filename).open('wb'):
                pass
            db.execute('INSERT INTO transfers VALUES (?, ?, ?, 0, 0, ?)', (device, request, encoded, filename))
            return self._status(self._row(db, device, request))

    def chunk(self, device, request, offset, data):
        with self.lock, self.connect() as db:
            row = self._row(db, device, request)
            meta = json.loads(row['metadata'])
            if (row['complete'] or type(offset) is not int or offset != row['offset'] or
                    not 0 < len(data) <= CHUNK_SIZE or offset + len(data) > meta['size']):
                raise ProtocolError('Invalid chunk offset or size')
            with (self.root / row['path']).open('r+b') as stream:
                stream.seek(offset)
                stream.write(data)
                stream.flush()
                os.fsync(stream.fileno())
            db.execute('UPDATE transfers SET offset=? WHERE device=? AND request=?', (offset+len(data), device, request))
            return offset + len(data)

    def finish(self, device, request):
        with self.lock, self.connect() as db:
            row = self._row(db, device, request)
            if row['complete']:
                return self._status(row)
            meta = json.loads(row['metadata'])
            path = self.root / row['path']
            if row['offset'] != meta['size'] or file_hash(path) != meta['sha256']:
                raise ProtocolError('Incomplete transfer or hash mismatch')
            validate_content(path, meta)
            if meta['media'] == 'text' and meta['size'] <= 4096:
                try:
                    value = json.loads(path.read_text(encoding='utf-8'))
                except ValueError:
                    value = None
                if isinstance(value, dict) and value.get('action') == 'transfer':
                    if (set(value) != {'action','source','destination','amount_paise'} or
                            type(value['amount_paise']) is not int or not 0<value['amount_paise']<=100000000 or
                            not all(isinstance(value[k], str) and re.fullmatch('[A-Za-z0-9_-]{1,32}',value[k]) for k in ('source','destination'))):
                        raise ProtocolError('Invalid simulated transaction')
                    db.execute('INSERT INTO transactions VALUES (?, ?, ?, ?, ?)',
                               (device, request, value['source'], value['destination'], value['amount_paise']))
            db.execute('UPDATE transfers SET complete=1 WHERE device=? AND request=?', (device, request))
            return self._status(self._row(db, device, request))

    def status(self, device, request):
        with self.lock, self.connect() as db:
            return self._status(self._row(db, device, request))

    def read(self, device, request, offset):
        with self.lock, self.connect() as db:
            row = self._row(db, device, request)
            if not row['complete'] or type(offset) is not int or not 0 <= offset < row['offset']:
                raise ProtocolError('File is unavailable or offset invalid')
            with (self.root / row['path']).open('rb') as stream:
                stream.seek(offset)
                return stream.read(CHUNK_SIZE)
