from contextlib import contextmanager
from pathlib import Path
import secrets
from .audit import AuditLog, Witness, WitnessClient
from .server import BankServer

@contextmanager
def local_lab(directory, plaintext=False, fault=None):
    """Isolated simulated endpoints; high connection limit for repeatable experiments."""
    root=Path(directory);root.mkdir(parents=True,exist_ok=True)
    key,audit_key=secrets.token_bytes(32),secrets.token_bytes(32)
    with Witness(root/'witness.sqlite',{'bank-audit':audit_key},attempts_per_minute=100000) as witness:
        remote=WitnessClient(witness.address,'bank-audit',audit_key)
        audit=AuditLog(root/'audit.jsonl',remote)
        with BankServer(root/'bank',{'terminal-1':key},audit,plaintext_lab=plaintext,fault=fault,
                        attempts_per_minute=100000) as server:
            yield server,key,audit,remote
