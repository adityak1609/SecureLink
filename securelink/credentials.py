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
