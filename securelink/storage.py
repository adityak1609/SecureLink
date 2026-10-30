"""Durable resumable transfers with owner-scoped idempotency."""
import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3
import threading
from contextlib import contextmanager, nullcontext
from .protocol import canonical, ProtocolError
from .settings import CHUNK_SIZE, MAX_FILE, MAX_STORAGE, MAX_TRANSFERS, EXTENSIONS

def file_hash(path, metrics=None):
    with metrics.measure('hashing',Path(path).stat().st_size) if metrics else nullcontext():
        digest = hashlib.sha256()
        with open(path, 'rb') as stream:
            for block in iter(lambda: stream.read(CHUNK_SIZE), b''):
                digest.update(block)
        return digest.hexdigest()

def metadata_for(path, metrics=None):
    path = Path(path)
    return {'name': path.name, 'media': EXTENSIONS.get(path.suffix.lower()),
            'size': path.stat().st_size, 'sha256': file_hash(path,metrics)}

def validate_metadata(meta):
    if not isinstance(meta, dict) or set(meta) != {'name', 'media', 'size', 'sha256'}:
        raise ProtocolError('Invalid transfer metadata')
    name = meta['name']
    if (not isinstance(name, str) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_. ()-]{0,119}', name)
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
            db.execute('CREATE TABLE IF NOT EXISTS signatures (device TEXT, request TEXT, proof TEXT, PRIMARY KEY(device, request))')

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

    def _status(self, row, db):
        result={'request': row['request'], 'offset': row['offset'], 'complete': bool(row['complete']), 'metadata': json.loads(row['metadata'])}
        proof=db.execute('SELECT proof FROM signatures WHERE device=? AND request=?',(row['device'],row['request'])).fetchone()
        if proof:
            result['signature']=json.loads(proof[0])
        return result

    def begin(self, device, request, meta, signature=None, metrics=None):
        self.check_request(request)
        validate_metadata(meta)
        encoded = canonical(meta).decode()
        with self.lock, self.connect() as db:
            row = db.execute('SELECT * FROM transfers WHERE device=? AND request=?', (device, request)).fetchone()
            if signature is not None:
                existing=db.execute('SELECT proof FROM signatures WHERE device=? AND request=?',(device,request)).fetchone()
                encoded_proof=canonical(signature).decode()
                if existing and existing[0]!=encoded_proof:
                    raise ProtocolError('Request ID reused with a different signature')
                db.execute('INSERT OR IGNORE INTO signatures VALUES (?,?,?)',(device,request,encoded_proof))
            if row:
                if row['metadata'] != encoded:
                    raise ProtocolError('Request ID reused with different content')
                path = self.root / row['path']
                if not path.exists() or path.stat().st_size < row['offset']:
                    raise ProtocolError('Stored transfer damaged')
                if row['complete']:
                    if file_hash(path,metrics) != meta['sha256']:
                        raise ProtocolError('Completed file damaged')
                else:
                    with path.open('r+b') as stream:
                        stream.truncate(row['offset'])
                return self._status(row,db)
            rows = db.execute('SELECT metadata FROM transfers').fetchall()
            if len(rows)>=MAX_TRANSFERS or sum(json.loads(r[0])['size'] for r in rows)+meta['size']>MAX_STORAGE:
                raise ProtocolError('Storage quota reached')
            filename = f'{device}_{request}_{meta["name"]}'
            with (self.root / filename).open('wb'):
                pass
            db.execute('INSERT INTO transfers VALUES (?, ?, ?, 0, 0, ?)', (device, request, encoded, filename))
            return self._status(self._row(db, device, request),db)

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

    def finish(self, device, request, metrics=None):
        with self.lock, self.connect() as db:
            row = self._row(db, device, request)
            if row['complete']:
                return self._status(row,db)
            meta = json.loads(row['metadata'])
            path = self.root / row['path']
            if row['offset'] != meta['size'] or file_hash(path,metrics) != meta['sha256']:
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
            return self._status(self._row(db, device, request),db)

    def status(self, device, request):
        with self.lock, self.connect() as db:
            return self._status(self._row(db, device, request),db)

    def read(self, device, request, offset):
        with self.lock, self.connect() as db:
            row = self._row(db, device, request)
            if not row['complete'] or type(offset) is not int or not 0 <= offset < row['offset']:
                raise ProtocolError('File is unavailable or offset invalid')
            with (self.root / row['path']).open('rb') as stream:
                stream.seek(offset)
                return stream.read(CHUNK_SIZE)
