"""Loopback-only graphical adapter to the real encrypted SecureLink endpoints.

The browser is a local user interface. Encryption applies to client/server TCP
traffic, not to the same-machine HTTP UI. No credentials are sent to JavaScript.
"""
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import csv
import io
import mimetypes
import os
from pathlib import Path
import re
import secrets
import shutil
import subprocess
import sys
import threading
import time
from urllib.parse import parse_qs, urlsplit
import webbrowser

from .analysis import analyze, wireshark_path
from .testing import REQUIREMENTS, parse_results
from .audit import AuditLog, WitnessClient
from .capture import StreamCapture
from .client import Client
from .credentials import load, provision, provision_signatures
from .settings import ROOT, MAX_FILE, EXTENSIONS
from .storage import metadata_for, validate_metadata, validate_content


def now():
    return datetime.now(timezone.utc).isoformat()


class Application:
    def __init__(self, directory):
        self.root = Path(directory).resolve()
        self.root.mkdir(parents=True, exist_ok=True)
        self.lock = threading.RLock()
        self.executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix='securelink-gui')
        self.token = secrets.token_urlsafe(32)
        self.target = None
        self.connected = False
        self.handshake_ms = None
        self.mode = 'offline'
        self.processes = []
        self.logs = []
        self.capture = None
        self.witness_address = None
        self.jobs = []
        self.audit_result = None
        self.analysis_result = None
        self.exports = {}
        self.closed = False
        self.test_result=None
        self.test_xml=None
        self.history_path = self.root / 'history.json'
        self.history = json.loads(self.history_path.read_text()) if self.history_path.exists() else []
        # Provision isolated GUI keys once; existing CLI credentials are unaffected.
        self.credentials = self.root / 'credentials'
        if not any((self.credentials / name).exists() for name in ('client.json', 'server.json', 'witness.json')):
            provision(self.credentials)
        self.config = load(self.credentials / 'client.json')
        self.signing_key=provision_signatures(self.credentials,self.config['device'])

    def save(self):
        temporary = self.history_path.with_suffix('.tmp')
        temporary.write_text(json.dumps(self.history, indent=2), encoding='utf-8')
        os.replace(temporary, self.history_path)

    def submit(self, label, operation):
        with self.lock:
            if self.closed:
                raise ValueError('Application is closing')
            if any(job['status'] in ('queued', 'running') for job in self.jobs):
                raise ValueError('Please wait for the current operation to finish')
            job = {'id': secrets.token_hex(16), 'label': label, 'status': 'queued',
                   'done': 0, 'total': 0, 'created': now(), 'error': None}
            self.jobs = self.jobs[-29:] + [job]

        def worker():
            start = time.perf_counter()
            with self.lock:
                job['status'] = 'running'
            try:
                result = operation(job)
                with self.lock:
                    job['result'] = result
                    job['status'] = 'complete'
            except Exception as exc:
                with self.lock:
                    job['status'] = 'failed'
                    job['error'] = str(exc)[:300]
                    if isinstance(exc, (OSError, ConnectionError, TimeoutError)):
                        self.connected = False
            finally:
                with self.lock:
                    job['elapsed_ms'] = round((time.perf_counter() - start) * 1000, 2)
                    job['finished'] = now()
        self.executor.submit(worker)
        return {'job': job['id']}

    def client(self, address=None):
        address = address or self.target
        if not address:
            raise ValueError('Start the local demo or connect a device first')
        return Client(tuple(address), self.config['device'], bytes.fromhex(self.config['secret']), self.config['server'],signing_key=self.signing_key)

    def spawn(self, script, arguments, name):
        ready = self.root / (name + '.ready.json')
        ready.unlink(missing_ok=True)
        output = (self.root / (name + '.console.log')).open('a', encoding='utf-8')
        self.logs.append(output)
        process = subprocess.Popen(
            [sys.executable, '-u', str(ROOT / script), *map(str, arguments), '--ready-file', str(ready)],
            cwd=ROOT, stdout=output, stderr=subprocess.STDOUT,
            creationflags=subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0,
        )
        self.processes.append(process)
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            if process.poll() is not None:
                raise RuntimeError(f'{name.title()} service could not start. See its local console log.')
            if ready.exists():
                try:
                    return tuple(json.loads(ready.read_text(encoding='utf-8')))
                except ValueError:
                    pass
            time.sleep(.05)
        raise TimeoutError(f'{name.title()} service startup timed out')

    def stop_services(self):
        if self.capture:
            self.capture.stop()
            self.capture = None
        for process in reversed(self.processes):
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()
        self.processes.clear()
        for stream in self.logs:
            stream.close()
        self.logs.clear()
        with self.lock:
            self.connected = False
            self.target = None
            self.witness_address = None
            self.mode = 'offline'
            self.audit_result = None

    def start_demo(self, job):
        self.stop_services()
        self.analysis_result = None
        self.exports = {}
        try:
            self.witness_address = self.spawn('witness_server.py', [
                '--port', 0, '--credentials', self.credentials / 'witness.json',
                '--database', self.root / 'witness.sqlite'], 'witness')
            bank_address = self.spawn('bank_server.py', [
                '--port', 0, '--credentials', self.credentials / 'server.json',
                '--state', self.root / 'bank', '--audit-log', self.root / 'audit.jsonl',
                '--signing-keys',self.credentials/'signing_public.json',
                '--witness-port', self.witness_address[1]], 'bank')
            self.capture_path = self.root / ('capture_' + secrets.token_hex(8) + '.pcap')
            self.capture = StreamCapture(bank_address, self.capture_path).start()
            # Persist the logical server identity, not a dynamic capture port.
            self.bank_address = bank_address
            with self.client(self.capture.address) as client:
                client.connect()
                handshake_ms = client.handshake_ms
            with self.lock:
                self.target = self.capture.address
                self.mode = 'local'
                self.connected = True
                self.handshake_ms = round(handshake_ms, 2)
            return {'message': 'Client, server and audit witness ready'}
        except Exception:
            self.stop_services()
            raise

    def connect_remote(self, values, job):
        host, port = values.get('host', ''), values.get('port')
        if not isinstance(host, str) or not re.fullmatch(r'[A-Za-z0-9.:-]{1,253}', host):
            raise ValueError('Enter a valid server hostname or IP address')
        if type(port) is not int or not 1 <= port <= 65535:
            raise ValueError('Port must be between 1 and 65535')
        with self.client((host, port)) as client:
            client.connect()
            handshake_ms = client.handshake_ms
        self.stop_services()
        with self.lock:
            self.target = (host, port)
            self.mode = 'remote'
            self.connected = True
            self.handshake_ms = round(handshake_ms, 2)
            self.analysis_result = None
            self.exports = {}
        return {'message': 'Device authenticated'}

    def endpoint(self):
        return 'local-demo' if self.mode == 'local' else ':'.join(map(str, self.target or ()))

    def progress(self, job):
        def update(done, total):
            with self.lock:
                job.update(done=done, total=total)
        return update

    @staticmethod
    def safe_name(name):
        if not isinstance(name, str) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_. -]{0,119}', name) or name.endswith(('.', ' ')):
            raise ValueError('Use a filename containing letters, numbers, spaces, dots, dashes or underscores (up to 120 characters)')
        if Path(name).suffix.lower() not in EXTENSIONS:
            raise ValueError('Supported formats: TXT, PNG, JPG, WAV, MP3 and MP4')
        return name

    def upload(self, source, job, request=None):
        meta = metadata_for(source)
        validate_metadata(meta)
        validate_content(source, meta)
        endpoint = self.endpoint()
        request = request or secrets.token_hex(16)
        with self.lock:
            record = next((row for row in self.history if row['request'] == request), None)
            if record is None:
                if len(self.history) >= 1024:
                    raise ValueError('The local transfer history is full')
                record = {'request': request, **meta, 'endpoint': endpoint, 'created': now(),
                          'source': str(source.relative_to(self.root)), 'status': 'sending', 'downloaded': False}
                self.history.insert(0, record)
            record.update(status='sending', error=None)
            self.save()
        started = time.perf_counter()
        try:
            with self.client() as client:
                result = client.upload(source, request, progress=self.progress(job))
            with self.lock:
                record.update(status='complete', elapsed_ms=round((time.perf_counter() - started)*1000, 2),
                              retries=client.retries, wire_bytes=client.sent_bytes + client.received_bytes)
                record['signature']=client.last_signature
                record.setdefault('crypto',{})['upload']=self.crypto_result(client,'upload')
                self.connected = True
                self.audit_result = None
                self.save()
            return {'request': result['request'], 'message': 'Encrypted transfer acknowledged by server'}
        except Exception as exc:
            with self.lock:
                record.update(status='failed', error=str(exc)[:300])
                self.save()
            raise

    def record(self, request):
        with self.lock:
            row = next((row for row in self.history if row['request'] == request and row['endpoint'] == self.endpoint()), None)
            if row is None:
                raise ValueError('Transfer not found for the selected server')
            return row

    def download(self, request, job):
        row = self.record(request)
        destination = self.root / 'downloads' / request / row['name']
        with self.client() as client:
            client.download(request, destination, progress=self.progress(job))
        with self.lock:
            row['downloaded'] = True
            row['download_verified'] = now()
            row.setdefault('crypto',{})['download']=self.crypto_result(client,'download')
            self.connected = True
            self.audit_result = None
            self.save()
        return {'request': request, 'message': 'Received copy verified with SHA-256; ready to preview or save'}

    @staticmethod
    def crypto_result(client,direction):
        values=client.server_metrics if direction=='upload' else client.metrics.snapshot()
        verification=values.get('signature_verification',{})
        return {'client':client.metrics.snapshot(),'server':client.server_metrics,
                'signature_verified':bool(client.last_signature and verification.get('calls',0)>0 and verification.get('failures',0)==0), 'algorithm':'Ed25519' if client.last_signature else None,
                'handshake_ms':client.handshake_ms,'direction':direction,
                'scope':'Client operation includes retries. Server metrics cover its final connection up to response encoding; final acknowledgement encryption is excluded. Hashing includes file reads.'}

    def retry(self, request, job):
        row = self.record(request)
        source = self.root / row['source']
        return self.upload(source, job, request=request)

    def sample(self, name, job):
        allowed = {'transaction.txt', 'identity.png', 'audio.wav', 'audio.mp3', 'video.mp4'}
        if name not in allowed:
            raise ValueError('Unknown sample')
        self.check_outbox((ROOT / 'sample_data' / 'fixtures' / name).stat().st_size)
        folder = self.root / 'outbox' / secrets.token_hex(16)
        folder.mkdir(parents=True)
        source = folder / name
        shutil.copyfile(ROOT / 'sample_data' / 'fixtures' / name, source)
        return self.upload(source, job)

    def check_outbox(self, additional):
        stored = sum(p.stat().st_size for p in (self.root / 'outbox').glob('*/*') if p.is_file())
        if stored + additional > 256 * 1024 * 1024:
            raise ValueError('Local upload quota reached (256 MiB)')

    def verify_audit(self, job):
        if self.mode != 'local' or not self.witness_address:
            raise ValueError('Local audit verification requires the local device simulation')
        config = load(self.credentials / 'server.json')
        audit = AuditLog.__new__(AuditLog)
        audit.path = self.root / 'audit.jsonl'
        audit.witness = WitnessClient(self.witness_address, config['audit_identity'], bytes.fromhex(config['audit_secret']))
        try:
            count, head = audit.verify()
            checkpoint = audit.witness.get()
            if checkpoint != {'count': count, 'head': head}:
                raise ValueError('Audit chain has entries awaiting a witness checkpoint; retry after the transfer')
            result = {'verified': True, 'count': count, 'head': head, 'verified_at': now()}
        except Exception:
            with self.lock:
                self.audit_result = {'verified': False, 'verified_at': now()}
            raise
        with self.lock:
            self.audit_result = result
        return result

    def analyze_capture(self, job):
        if self.mode != 'local' or not self.capture:
            raise ValueError('Traffic capture is available in local demo mode')
        directory = self.root / 'analysis' / secrets.token_hex(8)
        directory.mkdir(parents=True)
        snapshot = directory / 'session_stream.pcap'
        with self.capture.write_lock:
            self.capture.output.flush()
            shutil.copyfile(self.capture_path, snapshot)
        with self.lock:
            self.analysis_result=None
            self.exports={}
        result = analyze(snapshot, directory,backend='pyshark')
        with self.lock:
            self.analysis_result = result
            self.exports = {'pcap': snapshot, 'sqlite': directory / 'packets.sqlite', 'xml': directory / 'packets.xml',
                            'json': directory / 'summary.json'}
        return {'message': 'Decoded with PyShark + Wireshark/TShark; SQLite/XML counts match', 'records': result['records']}

    def open_wireshark(self,job):
        path=self.exports.get('pcap')
        if not path:
            raise ValueError('Analyze a capture first')
        executable=wireshark_path()
        if not executable:
            raise RuntimeError('Install Wireshark to open the capture viewer')
        subprocess.Popen([executable,'-X','lua_script:'+str(ROOT/'tools/securelink_user0.lua'),'-r',str(path)],
                         cwd=ROOT,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,
                         creationflags=subprocess.CREATE_NO_WINDOW if os.name=='nt' else 0)
        return {'message':'Opened the analyzed capture in Wireshark'}

    def run_tests(self,job):
        directory=self.root/'testing'/secrets.token_hex(8)
        directory.mkdir(parents=True)
        xml=directory/'results.xml'
        completed=subprocess.run([sys.executable,'-m','pytest','tests','-q','-p','no:cacheprovider',
                                  '--junitxml='+str(xml)],cwd=ROOT,capture_output=True,text=True,
                                 timeout=300,creationflags=subprocess.CREATE_NO_WINDOW if os.name=='nt' else 0)
        (directory/'console.log').write_text(completed.stdout+completed.stderr,encoding='utf-8')
        result=parse_results(xml,completed.returncode)
        result['finished_at']=now()
        with self.lock:
            self.test_result=result
            self.test_xml=xml
        return {'message':f"Tests finished: {result['passed']} passed, {result['failed']} failed, {result['skipped']} skipped"}

    def metrics_export(self,format):
        records=self.state()['transfers']
        if format=='json':
            return json.dumps(records,indent=2).encode()
        stream=io.StringIO(newline='')
        writer=csv.writer(stream)
        writer.writerow(['request','file','media','file_bytes','direction','endpoint','operation','calls','milliseconds','bytes_processed','failures'])
        for record in records:
            for direction,metrics in record.get('crypto',{}).items():
                for endpoint in ('client','server'):
                    for operation,value in metrics[endpoint].items():
                        writer.writerow([record['request'],record['name'],record['media'],record['size'],direction,endpoint,
                                         operation,value['calls'],value['milliseconds'],value['bytes'],value['failures']])
        return stream.getvalue().encode('utf-8')

    def state(self):
        with self.lock:
            live = self.mode == 'remote' or (self.mode == 'local' and all(p.poll() is None for p in self.processes))
            rows = [dict(row) for row in self.history if row['endpoint'] == self.endpoint()]
            for row in rows:
                row.pop('source', None)
            events = []
            if self.mode == 'local' and (self.root / 'audit.jsonl').exists():
                # A concurrent append can leave a final incomplete line in a read.
                for line in (self.root / 'audit.jsonl').read_text(encoding='utf-8').splitlines()[-30:]:
                    try:
                        events.append(json.loads(line))
                    except ValueError:
                        pass
            return {'mode': self.mode, 'connected': self.connected and live, 'target': self.target,
                    'identity': self.config['device'], 'handshake_ms': self.handshake_ms,
                    'jobs': [dict(job) for job in self.jobs], 'transfers': rows, 'events': events,
                    'audit': self.audit_result, 'analysis': self.analysis_result,
                    'topology': {'client': os.getpid(), 'server': self.processes[1].pid if len(self.processes)>1 else None,
                                 'witness': self.processes[0].pid if self.processes else None},
                    'max_file': MAX_FILE, 'exports': list(self.exports),
                    'tests':self.test_result,'test_requirements':REQUIREMENTS,'wireshark_available':bool(wireshark_path())}

    def close(self):
        with self.lock:
            self.closed = True
        self.executor.shutdown(wait=True, cancel_futures=True)
        self.stop_services()


class LocalServer(ThreadingHTTPServer):
    daemon_threads = True
    def __init__(self, app, port=0):
        self.app = app
        self.upload_slots = threading.BoundedSemaphore(1)
        super().__init__(('127.0.0.1', port), Handler)
        self.origin = f'http://127.0.0.1:{self.server_port}'


class Handler(BaseHTTPRequestHandler):
    server_version = 'SecureLink'
    def setup(self):
        super().setup()
        self.connection.settimeout(20)

    def log_message(self, *args):
        pass  # Do not log tokens, user text or file names.

    def headers_for(self, status, kind, size, filename=None):
        self.send_response(status)
        self.send_header('Content-Type', kind)
        self.send_header('Content-Length', str(size))
        self.send_header('Cache-Control', 'no-store')
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('Referrer-Policy', 'no-referrer')
        self.send_header('Content-Security-Policy', "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' blob:; media-src 'self' blob:; connect-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'none'")
        if filename:
            self.send_header('Content-Disposition', f'attachment; filename="{filename}"')
        self.end_headers()

    def respond(self, value, status=200):
        body = json.dumps(value).encode()
        self.headers_for(status, 'application/json', len(body))
        self.wfile.write(body)

    def file(self, path, attachment=False):
        if not path.is_file():
            raise ValueError('File is not available')
        kind = mimetypes.guess_type(path.name)[0] or 'application/octet-stream'
        self.headers_for(200, kind, path.stat().st_size, path.name if attachment else None)
        with path.open('rb') as source:
            shutil.copyfileobj(source, self.wfile)

    def authorized(self):
        # Host check blocks DNS rebinding; origin + unguessable header blocks CSRF.
        if self.headers.get('Host') != f'127.0.0.1:{self.server.server_port}':
            self.respond({'error': 'Invalid application host'}, 403)
            return False
        if self.headers.get('Origin') not in (None, self.server.origin):
            self.respond({'error': 'Cross-origin access is not allowed'}, 403)
            return False
        if not secrets.compare_digest(self.headers.get('X-SecureLink-Token', ''), self.server.app.token):
            self.respond({'error': 'Open the application using its desktop launcher'}, 401)
            return False
        return True

    def do_GET(self):
        parsed = urlsplit(self.path)
        assets = {'/': 'index.html', '/app.js': 'app.js', '/style.css': 'style.css'}
        try:
            if parsed.path in assets:
                self.file(ROOT / 'frontend' / assets[parsed.path])
                return
            if not self.authorized():
                return
            app = self.server.app
            if parsed.path == '/api/state':
                self.respond(app.state())
            elif parsed.path in ('/api/metrics/csv','/api/metrics/json'):
                format=parsed.path.rsplit('/',1)[-1]
                body=app.metrics_export(format)
                self.headers_for(200,'text/csv' if format=='csv' else 'application/json',len(body),'crypto_metrics.'+format)
                self.wfile.write(body)
            elif parsed.path=='/api/tests/export/json':
                if app.test_result is None:
                    raise ValueError('Run the tests first')
                body=json.dumps(app.test_result,indent=2).encode()
                self.headers_for(200,'application/json',len(body),'test_results.json')
                self.wfile.write(body)
            elif parsed.path=='/api/tests/export/xml':
                if app.test_xml is None:
                    raise ValueError('Run the tests first')
                self.file(app.test_xml,attachment=True)
            elif parsed.path.startswith('/api/file/'):
                request = parsed.path.rsplit('/', 1)[-1]
                row = app.record(request)
                if not row['downloaded']:
                    raise ValueError('Receive and verify this file first')
                self.file(app.root / 'downloads' / request / row['name'], attachment=True)
            elif parsed.path.startswith('/api/export/'):
                path = app.exports.get(parsed.path.rsplit('/', 1)[-1])
                if path is None:
                    raise ValueError('Run traffic analysis first')
                self.file(path, attachment=True)
            elif parsed.path.startswith('/api/report/'):
                name = parsed.path.rsplit('/', 1)[-1]
                if name not in ('SYNOPSIS.html', 'EVALUATION.html', 'PROTOCOL.md','GUI.md','TESTING.md'):
                    raise ValueError('Unknown report')
                self.file(ROOT / 'docs' / name, attachment=True)
            else:
                self.respond({'error': 'Not found'}, 404)
        except ConnectionError:
            return
        except (ValueError, OSError) as exc:
            self.respond({'error': str(exc)[:300]}, 400)

    def length(self, maximum):
        if self.headers.get('Transfer-Encoding'):
            raise ValueError('Chunked browser requests are unsupported')
        value = self.headers.get('Content-Length', '')
        if not value.isdigit() or not 0 < int(value) <= maximum:
            raise ValueError('Invalid request size')
        return int(value)

    def do_POST(self):
        if not self.authorized():
            return
        parsed = urlsplit(self.path)
        app = self.server.app
        try:
            if parsed.path == '/api/upload':
                if not self.server.upload_slots.acquire(blocking=False):
                    raise ValueError('Too many browser uploads; please wait')
                try:
                    name = app.safe_name(parse_qs(parsed.query).get('name', [''])[0])
                    size = self.length(MAX_FILE)
                    with app.lock:
                        if not app.connected:
                            raise ValueError('Connect a device first')
                        if any(j['status'] in ('running', 'queued') for j in app.jobs):
                            raise ValueError('Please wait for the current operation')
                        app.check_outbox(size)
                    folder = app.root / 'outbox' / secrets.token_hex(16)
                    folder.mkdir(parents=True)
                    source = folder / name
                    remaining = size
                    with source.open('xb') as output:
                        while remaining:
                            block = self.rfile.read(min(65536, remaining))
                            if not block:
                                raise ValueError('Browser upload interrupted')
                            output.write(block)
                            remaining -= len(block)
                    self.respond(app.submit('Send ' + name, lambda job: app.upload(source, job)), 202)
                finally:
                    self.server.upload_slots.release()
                return
            size = self.length(2 * 1024 * 1024)
            raw = self.rfile.read(size)
            if len(raw) != size:
                raise ValueError('Request interrupted')
            values = json.loads(raw)
            if not isinstance(values, dict):
                raise ValueError('Expected a JSON object')
            if parsed.path == '/api/demo/start':
                result = app.submit('Start local devices', app.start_demo)
            elif parsed.path == '/api/connect':
                result = app.submit('Authenticate device', lambda job: app.connect_remote(values, job))
            elif parsed.path == '/api/disconnect':
                result = app.submit('Disconnect devices', lambda job: app.stop_services())
            elif parsed.path == '/api/text':
                text = values.get('text')
                if not isinstance(text, str) or not text.strip():
                    raise ValueError('Write a message first')
                def send_text(job):
                    app.check_outbox(len(text.encode('utf-8')))
                    folder = app.root / 'outbox' / secrets.token_hex(16)
                    folder.mkdir(parents=True)
                    source = folder / ('message_' + time.strftime('%H%M%S') + '.txt')
                    source.write_bytes(text.encode('utf-8'))
                    return app.upload(source, job)
                result = app.submit('Send text message', send_text)
            elif parsed.path == '/api/sample':
                result = app.submit('Send demo sample', lambda job: app.sample(values.get('name'), job))
            elif parsed.path == '/api/download':
                result = app.submit('Receive verified copy', lambda job: app.download(values.get('request'), job))
            elif parsed.path == '/api/retry':
                result = app.submit('Resume transfer', lambda job: app.retry(values.get('request'), job))
            elif parsed.path == '/api/audit/verify':
                result = app.submit('Verify audit chain', app.verify_audit)
            elif parsed.path == '/api/analysis':
                result = app.submit('Analyze captured traffic', app.analyze_capture)
            elif parsed.path=='/api/wireshark/open':
                result=app.submit('Open in Wireshark',app.open_wireshark)
            elif parsed.path=='/api/tests/run':
                result=app.submit('Run isolated security and regression tests',app.run_tests)
            elif parsed.path == '/api/shutdown':
                with app.lock:
                    if any(j['status'] in ('running', 'queued') for j in app.jobs):
                        raise ValueError('Please wait for the current operation before closing')
                self.respond({'message': 'Application closed'})
                threading.Thread(target=self.server.shutdown, daemon=True).start()
                return
            else:
                self.respond({'error': 'Not found'}, 404)
                return
            self.respond(result, 202)
        except ConnectionError:
            return
        except (ValueError, OSError) as exc:
            self.respond({'error': str(exc)[:300]}, 400)


def run(port=8765, directory='runtime/gui', open_browser=True, ready_file=None):
    directory = Path(directory).resolve()
    directory.mkdir(parents=True, exist_ok=True)
    lock_file = (directory / 'application.lock').open('a+b')
    if lock_file.seek(0, 2) == 0:
        lock_file.write(b'0')
        lock_file.flush()
    lock_file.seek(0)
    try:
        if os.name == 'nt':
            import msvcrt
            msvcrt.locking(lock_file.fileno(), msvcrt.LK_NBLCK, 1)
        else:
            import fcntl
            fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        lock_file.close()
        existing = directory / 'application.json'
        if open_browser and existing.exists():
            info = json.loads(existing.read_text(encoding='utf-8'))
            if re.fullmatch(r'http://127\.0\.0\.1:[0-9]{1,5}', info['url']):
                webbrowser.open(info['url'] + '/#token=' + info['token'])
        return
    try:
        _run(port, directory, open_browser, ready_file)
    finally:
        lock_file.close()  # Kernel releases the single-instance lock even on a crash.


def _run(port, directory, open_browser, ready_file):
    app = Application(directory)
    try:
        try:
            server = LocalServer(app, port)
        except OSError:
            server = LocalServer(app, 0)
        url = server.origin + '/#token=' + app.token
        session_file = app.root / 'application.json'
        session_file.write_text(json.dumps({'url': server.origin, 'token': app.token}), encoding='utf-8')
        if ready_file:
            path = Path(ready_file).resolve()
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(json.dumps({'url': server.origin, 'token': app.token}), encoding='utf-8')
        if open_browser:
            webbrowser.open(url)
        try:
            server.serve_forever(poll_interval=.2)
        except KeyboardInterrupt:
            pass
        finally:
            server.server_close()
            session_file.unlink(missing_ok=True)
    finally:
        app.close()
