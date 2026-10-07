import secrets
from pathlib import Path
import uuid
import pytest
from securelink.audit import AuditLog, Witness, WitnessClient
from securelink.server import BankServer


def pytest_configure(config):
    # A fresh directory avoids collisions and Windows ACLs from older runs.
    # Respect explicit --basetemp arguments used by callers.
    if config.option.basetemp is None:
        runs = Path(__file__).resolve().parents[1] / 'runtime' / 'pytest_runs'
        runs.mkdir(parents=True, exist_ok=True)
        config.option.basetemp = str(runs / uuid.uuid4().hex)

@pytest.fixture
def lab(tmp_path):
    key, audit_key = secrets.token_bytes(32), secrets.token_bytes(32)
    with Witness(tmp_path/'witness.sqlite', {'bank-audit':audit_key}, attempts_per_minute=100000) as witness:
        remote = WitnessClient(witness.address,'bank-audit',audit_key)
        audit = AuditLog(tmp_path/'audit.jsonl',remote)
        with BankServer(tmp_path/'files',{'terminal-1':key,'terminal-2':secrets.token_bytes(32)},audit,
                        attempts_per_minute=100000) as server:
            yield server,key,audit,remote
