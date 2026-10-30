"""Local text/image encryption artifacts with explicit decrypt and inspection."""
import json
import os
import secrets
from datetime import datetime, timezone
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .image_metrics import image_metrics
from .metrics import CryptoMetrics
from .protocol import canonical
from .security_metrics import difference, hash_resistance, text_security
from .signatures import sign, verify
from .storage import file_hash, metadata_for, validate_content, validate_metadata


def save_report(folder, report):
    temporary = folder/'report.tmp'
    temporary.write_text(json.dumps(report, indent=2), encoding='utf-8')
    os.replace(temporary, folder/'report.json')


def encrypt(folder, name, signing_key, identity):
    folder = Path(folder)
    source = folder/'source'/name
    metrics = CryptoMetrics()
    meta = metadata_for(source, metrics)
    validate_metadata(meta)
    if meta['media'] not in ('text', 'image'):
        raise ValueError('Choose UTF-8 text, PNG or JPEG')
    validate_content(source, meta)
    data = source.read_bytes()
    key, nonce = secrets.token_bytes(32), secrets.token_bytes(12)
    header = canonical(meta)
    with metrics.measure('encryption', len(data)):
        encrypted = AESGCM(key).encrypt(nonce, data, header)
    proof = sign(signing_key, identity, folder.name, meta, metrics)
    (folder/'signature.json').write_text(json.dumps({'device': identity, 'request': folder.name,
                                                    'metadata': meta, 'proof': proof}, indent=2), encoding='utf-8')
    # Secret key stays local and is never included in API responses or exports.
    (folder/'key.bin').write_bytes(key)
    (folder/'ciphertext.bin').write_bytes(encrypted)
    altered = bytearray(encrypted)
    altered[0] ^= 1
    try:
        AESGCM(key).decrypt(nonce, bytes(altered), header)
    except InvalidTag:
        rejected = True
    else:
        raise ValueError('Modified ciphertext was not rejected')
    report = {'id': folder.name, 'created': datetime.now(timezone.utc).isoformat(),
              'metadata': meta, 'identity': identity, 'nonce_hex': nonce.hex(),
              'tag_hex': encrypted[-16:].hex(), 'authenticated_header': header.decode('ascii'),
              'ciphertext_bytes': len(encrypted)-16, 'package_bytes': len(encrypted),
              'signature': proof, 'metrics': metrics.snapshot(), 'decrypted': False,
              'tampering': {'rejected': rejected, 'scope': 'First up to 16 ciphertext bytes; one bit flipped and original tag retained',
                            'payload_difference': difference(encrypted[:min(16, len(data))], bytes(altered[:min(16, len(data))]))},
              'hash_resistance': hash_resistance(data),
              'text_security': text_security(data) if meta['media'] == 'text' else None,
              'scope': 'Standalone local AES-256-GCM demonstration, separate from TCP transfers. '
                       'Binary export contains complete ciphertext followed by its 16-byte tag. '
                       'Nonce and authenticated header are in this report. Keys remain on this computer.',
              'timing_scope': 'Crypto calls are timed; hashing includes source file reads. '
                              'Key generation, disk writes and security experiments are outside encryption/signing timings.'}
    save_report(folder, report)
    return report


def decrypt(folder, signing_key):
    folder = Path(folder)
    report = json.loads((folder/'report.json').read_text(encoding='utf-8'))
    # Reverification failures must revoke access to any previously recovered file.
    report['decrypted'] = False
    for field in ('received_sha256', 'signature_verified', 'decryption_metrics', 'decrypted_at', 'image_metrics'):
        report.pop(field, None)
    save_report(folder, report)
    metrics = CryptoMetrics()
    public = Ed25519PrivateKey.from_private_bytes(signing_key).public_key().public_bytes_raw()
    verify(report['signature'], public, report['identity'], folder.name, report['metadata'], metrics)
    encrypted = (folder/'ciphertext.bin').read_bytes()
    key = (folder/'key.bin').read_bytes()
    try:
        with metrics.measure('decryption', max(0, len(encrypted)-16)):
            data = AESGCM(key).decrypt(bytes.fromhex(report['nonce_hex']), encrypted,
                                       canonical(report['metadata']))
    except InvalidTag as exc:
        raise ValueError('Ciphertext authentication failed') from exc
    destination = folder/'recovered'/report['metadata']['name']
    destination.parent.mkdir(exist_ok=True)
    destination.write_bytes(data)
    received_hash = file_hash(destination, metrics)
    if received_hash != report['metadata']['sha256']:
        raise ValueError('Recovered file hash mismatch')
    report.update(decrypted=True, received_sha256=received_hash, signature_verified=True,
                  decrypted_at=datetime.now(timezone.utc).isoformat(), decryption_metrics=metrics.snapshot())
    if report['metadata']['media'] == 'image':
        report['image_metrics'] = image_metrics(folder/'source'/report['metadata']['name'], destination)
    save_report(folder, report)
    return report
