"""Repeated performance measurements for SecureLink's three crypto algorithms."""
import csv
import hashlib
import json
import math
import os
import platform
import secrets
import statistics
import time
from datetime import datetime, timezone
from pathlib import Path

from cryptography import __version__ as cryptography_version
from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .settings import CHUNK_SIZE, MAX_FILE

SIZES = (1024, 65536, 1048576, 8388608, MAX_FILE)
ALGORITHMS = {
    'aead': ('AES-256-GCM',),
    'hash': ('SHA-256',),
    'signature': ('Ed25519',),
}
FIELDS = ('category', 'algorithm', 'operation', 'sample', 'size_bytes', 'iteration',
          'milliseconds', 'throughput_mib_s', 'success')
MEASURES = FIELDS[6:-1]


class Cancelled(Exception):
    pass


def validate(value):
    if not isinstance(value, dict) or set(value) - {'category', 'algorithms', 'sizes', 'iterations', 'dataset'}:
        raise ValueError('Unknown experiment setting')
    category = value.get('category')
    if not isinstance(category,str) or category not in ALGORITHMS:
        raise ValueError('Choose an experiment category')
    algorithms = value.get('algorithms')
    if (not isinstance(algorithms, list) or not algorithms or
            any(not isinstance(name,str) for name in algorithms) or
            len(set(algorithms)) != len(algorithms)
            or any(name not in ALGORITHMS[category] for name in algorithms)):
        raise ValueError('Choose supported algorithms without duplicates')
    dataset = value.get('dataset', 'sizes')
    if dataset != 'sizes':
        raise ValueError('Benchmarks use controlled text sizes')
    sizes = value.get('sizes')
    if (not isinstance(sizes, list) or not sizes
          or any(type(size) is not int or size not in SIZES for size in sizes)
          or len(set(sizes)) != len(sizes)):
        raise ValueError('Choose supported payload sizes without duplicates')
    iterations = value.get('iterations')
    if type(iterations) is not int or not 2 <= iterations <= 50:
        raise ValueError('Choose 2 to 50 measured repetitions')
    return {'category': category, 'algorithms': algorithms, 'sizes': sorted(sizes),
            'iterations': iterations, 'dataset': dataset}


def expected_cases(config):
    return config['iterations']*len(config['sizes'])


def _row(category, algorithm, operation, sample, size, iteration, elapsed, **values):
    row = dict.fromkeys(FIELDS)
    row.update(category=category, algorithm=algorithm, operation=operation,
               sample=sample, size_bytes=size, iteration=iteration,
               milliseconds=elapsed, success=True)
    row.update(values)
    return row


def _timed(callback):
    start = time.perf_counter_ns()
    result = callback()
    return result, max(0, time.perf_counter_ns()-start)/1_000_000


def _rate(size, elapsed):
    return size / 1048576 / (elapsed/1000) if elapsed else None


def _check(checks, name, result):
    if not result:
        raise AssertionError(name + ' failed')
    checks[name] = checks.get(name, 0) + 1


def _rejected(callback, exception):
    try:
        callback()
    except exception:
        return True
    return False


def _aead(rows, checks, names, data, iteration, counters):
    size = len(data)
    aad = b'SecureLink comparison authenticated header v1'
    for name in names:
        cipher = AESGCM(secrets.token_bytes(32))
        counters[name] += 1
        nonce = counters[name].to_bytes(12, 'big')
        ciphertext, encrypted_ms = _timed(lambda: cipher.encrypt(nonce, data, aad))
        recovered, decrypted_ms = _timed(lambda: cipher.decrypt(nonce, ciphertext, aad))
        _check(checks, 'round trip bytes match', recovered == data)
        altered = bytearray(ciphertext)
        altered[0] ^= 1
        _check(checks, 'changed ciphertext rejected',
               _rejected(lambda: cipher.decrypt(nonce, bytes(altered), aad), InvalidTag))
        _check(checks, 'changed header rejected',
               _rejected(lambda: cipher.decrypt(nonce, ciphertext, aad + b'!'), InvalidTag))
        rows.extend((_row('aead', name, 'encrypt', '', size, iteration, encrypted_ms,
                          throughput_mib_s=_rate(size, encrypted_ms)),
                     _row('aead', name, 'decrypt', '', size, iteration, decrypted_ms,
                          throughput_mib_s=_rate(size, decrypted_ms))))


def _hash(rows, checks, names, data, iteration):
    for name in names:
        factory = hashlib.sha256
        digest, elapsed = _timed(lambda: factory(data).digest())
        stream = factory()
        for offset in range(0, len(data), CHUNK_SIZE):
            stream.update(data[offset:offset+CHUNK_SIZE])
        _check(checks, 'incremental digest matches', digest == stream.digest())
        changed = bytearray(data)
        changed[0] ^= 1
        _check(checks, 'changed input differs', digest != factory(changed).digest())
        rows.append(_row('hash', name, 'hash', '', len(data), iteration, elapsed))


def _signature(rows, checks, names, data, iteration):
    manifest = b'SecureLink benchmark manifest v1\0' + len(data).to_bytes(8, 'big') + hashlib.sha256(data).digest()
    changed = manifest[:-1] + bytes([manifest[-1] ^ 1])
    for name in names:
        key = ed25519.Ed25519PrivateKey.generate()
        public = key.public_key()
        signed, signing_ms = _timed(lambda: key.sign(manifest))
        _, verify_ms = _timed(lambda: public.verify(signed, manifest))
        _check(checks, 'valid signature accepted', True)
        _check(checks, 'changed manifest rejected',
               _rejected(lambda: public.verify(signed, changed), InvalidSignature))
        wrong = bytearray(signed)
        wrong[0] ^= 1
        _check(checks, 'changed signature rejected',
               _rejected(lambda: public.verify(bytes(wrong), manifest), InvalidSignature))
        rows.extend((_row('signature', name, 'sign', '', len(data), iteration, signing_ms),
                     _row('signature', name, 'verify', '', len(data), iteration, verify_ms)))


def _p95(values):
    ordered = sorted(values)
    return ordered[math.ceil(.95*len(ordered))-1]


def summarize(rows):
    groups = {}
    for row in rows:
        key = (row['algorithm'], row['operation'], row['sample'], row['size_bytes'])
        groups.setdefault(key, []).append(row)
    summary = []
    for (algorithm, operation, sample, size), group in sorted(groups.items()):
        metrics = {}
        for field in MEASURES:
            values = [row[field] for row in group if row[field] is not None]
            if values:
                metrics[field] = {'median': statistics.median(values), 'p95': _p95(values),
                                  'min': min(values), 'max': max(values),
                                  'mean': statistics.mean(values),
                                  'stdev': statistics.stdev(values) if len(values)>1 else 0}
        summary.append({'algorithm': algorithm, 'operation': operation, 'sample': sample,
                        'size_bytes': size, 'n': len(group),
                        'success_rate': sum(bool(row['success']) for row in group)/len(group),
                        'metrics': metrics})
    return summary


def plot(report, path):
    os.environ.setdefault('MPLCONFIGDIR', str((path.parent/'matplotlib').resolve()))
    import matplotlib
    matplotlib.use('Agg')
    import matplotlib.pyplot as plt
    operations = [name for name in ('encrypt', 'hash', 'sign', 'decrypt', 'verify')
                  if any(row['operation'] == name for row in report['summary'])][:2]
    fig, axes = plt.subplots(1, len(operations), figsize=(11,4.5), layout='constrained')
    if len(operations) == 1:
        axes = [axes]
    for axis, operation in zip(axes, operations):
        for algorithm in report['config']['algorithms']:
            points = sorted((row for row in report['summary'] if row['algorithm'] == algorithm
                             and row['operation'] == operation and row['size_bytes']),
                            key=lambda row: row['size_bytes'])
            if points:
                axis.plot([row['size_bytes']/1048576 for row in points],
                          [row['metrics']['milliseconds']['median'] for row in points],
                          marker='o', label=algorithm)
        axis.set_xlabel('Payload size (MiB)')
        axis.set_ylabel('Median time (ms)')
        axis.set_title(operation.title())
        axis.grid(alpha=.25)
        axis.legend(fontsize=8)
    fig.suptitle('SecureLink performance benchmark · ' + report['config']['category'])
    fig.savefig(path, dpi=160)
    plt.close(fig)


def run(directory, request, progress=None, cancelled=None):
    config = validate(request)
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=False)
    rows, checks = [], {}
    total = expected_cases(config)
    done = 0
    counters = dict.fromkeys(ALGORITHMS['aead'], 0)
    started = datetime.now(timezone.utc).isoformat()
    seed = b'SecureLink controlled benchmark data 0123456789 ABCDEFGHIJKLMNOPQRSTUVWXYZ\n'
    for iteration in range(-1, config['iterations']):
        sizes = config['sizes'] if iteration % 2 else list(reversed(config['sizes']))
        for size in sizes:
            if cancelled and cancelled.is_set():
                raise Cancelled('Benchmark cancelled after its current trial')
            data = (seed * (size // len(seed) + 1))[:size]
            current, verified = [], {}
            if config['category'] == 'aead':
                _aead(current, verified, config['algorithms'], data, iteration, counters)
            elif config['category'] == 'hash':
                _hash(current, verified, config['algorithms'], data, iteration)
            else:
                _signature(current, verified, config['algorithms'], data, iteration)
            if iteration >= 0:
                rows.extend(current)
                for check, count in verified.items():
                    checks[check] = checks.get(check, 0) + count
                done += 1
                if progress:
                    progress(done, total, f'{size} bytes · repetition {iteration + 1}/{config["iterations"]}')
    report = {'schema_version': 2, 'started_at': started,
              'finished_at': datetime.now(timezone.utc).isoformat(), 'config': config,
              'environment': {'platform': platform.platform(), 'python': platform.python_version(),
                              'cryptography': cryptography_version},
              'method': 'One discarded warmup per size. Size order alternates between repetitions. '
                        'Timings surround the cryptographic library calls; correctness checks run outside timed blocks.',
              'limits': ['Timings use in-memory controlled text bytes and exclude file I/O and transport.',
                         'Encryption speed is plaintext bytes divided by the measured encryption or decryption time.',
                         'Key generation and manifest preparation are excluded from signing and verification timings.',
                         'Signatures cover a fixed-size digest manifest for each input file size.',
                         'p95 is a descriptive nearest-rank statistic; small repetition counts are unstable.'],
              'checks': [{'name': name, 'passed': count} for name, count in sorted(checks.items())],
              'observations': len(rows), 'summary': summarize(rows)}
    (directory / 'report.json').write_text(json.dumps(report, indent=2), encoding='utf-8')
    with (directory / 'observations.csv').open('w', newline='', encoding='utf-8') as output:
        writer = csv.DictWriter(output, fieldnames=FIELDS)
        writer.writeheader()
        writer.writerows(rows)
    plot(report, directory / 'comparison.png')
    return report
