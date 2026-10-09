import json
import os
from pathlib import Path
import secrets

from .protocol import valid_identity


def provision(directory):
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    paths = [directory / name for name in ('client.json', 'server.json', 'witness.json')]
    if any(path.exists() for path in paths):
        raise FileExistsError('Credentials already exist; refusing to overwrite')
    device_key, audit_key = secrets.token_hex(32), secrets.token_hex(32)
    values = [
        {'device': 'terminal-1', 'secret': device_key, 'server': 'bank-server'},
        {'devices': {'terminal-1': device_key}, 'audit_identity': 'bank-audit', 'audit_secret': audit_key},
        {'devices': {'bank-audit': audit_key}},
    ]
    for path, value in zip(paths, values):
        with path.open('x', encoding='utf-8') as stream:
            json.dump(value, stream, indent=2)
        os.chmod(path, 0o600)
    return paths


def load(path):
    with open(path, encoding='utf-8') as stream:
        return json.load(stream)


def devices(config):
    result = {}
    for name, value in config['devices'].items():
        key = bytes.fromhex(value)
        if not valid_identity(name) or len(key) != 32:
            raise ValueError('Invalid device credential')
        result[name] = key
    return result


def provision_signatures(directory, identity):
    """Add a separate signing pair without replacing existing transport keys."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    directory=Path(directory)
    private_path=directory/'signing_private.json'
    public_path=directory/'signing_public.json'
    if private_path.exists():
        value=load(private_path)
        if value['device']!=identity:
            raise ValueError('Signing identity does not match client credentials')
        private=bytes.fromhex(value['private_key'])
        key=Ed25519PrivateKey.from_private_bytes(private)
    else:
        if public_path.exists():
            raise ValueError('Signing private key missing; refusing to replace the pinned public key')
        key=Ed25519PrivateKey.generate()
        private=key.private_bytes_raw()
        with private_path.open('x',encoding='utf-8') as output:
            json.dump({'device':identity,'private_key':private.hex()},output,indent=2)
        os.chmod(private_path,0o600)
    public=key.public_key().public_bytes_raw()
    if public_path.exists():
        if devices(load(public_path)).get(identity)!=public:
            raise ValueError('Signing public key does not match the existing private key')
    else:
        with public_path.open('x',encoding='utf-8') as output:
            json.dump({'devices':{identity:public.hex()}},output,indent=2)
    return private
