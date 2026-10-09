"""Bounded framing, transcript-bound PSK authentication and AEAD records.

Educational protocol, not a replacement for TLS. PSK compromise reveals past
sessions; authenticated ephemeral key agreement is deliberately out of scope.
"""
import hashlib
import hmac
import json
import secrets
import socket
import struct
import time
from dataclasses import dataclass, field
from .metrics import CryptoMetrics

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from .settings import VERSION, MAX_FRAME, MAX_HEADER, IO_TIMEOUT, HANDSHAKE_TIMEOUT, HANDSHAKE_CLOCK_SKEW


class ProtocolError(ValueError):
    pass


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'),
                      ensure_ascii=True, allow_nan=False).encode('ascii')


def decode_json(data):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ProtocolError('Duplicate JSON field')
            result[key] = value
        return result
    try:
        return json.loads(data, object_pairs_hook=unique)
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise ProtocolError('Invalid JSON') from exc


def recv_exact(sock, size, deadline):
    data = bytearray()
    while len(data) < size:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError('Record deadline exceeded')
        sock.settimeout(remaining)
        chunk = sock.recv(min(size - len(data), 65536))
        if not chunk:
            raise ConnectionError('Peer disconnected')
        data.extend(chunk)
    return bytes(data)


def send_packet(sock, data, limit=MAX_FRAME, timeout=IO_TIMEOUT):
    if not 0 < len(data) <= limit:
        raise ProtocolError('Frame size outside limit')
    sock.settimeout(timeout)
    sock.sendall(struct.pack('!I', len(data)) + data)


def recv_packet(sock, limit=MAX_FRAME, timeout=IO_TIMEOUT, deadline=None):
    deadline = deadline if deadline is not None else time.monotonic() + timeout
    size = struct.unpack('!I', recv_exact(sock, 4, deadline))[0]
    if not 0 < size <= limit:
        raise ProtocolError('Frame size outside limit')
    return recv_exact(sock, size, deadline)


def proof(secret, role, transcript):
    return hmac.new(secret, b'SecureLink-v3/' + role + b'\0' + transcript,
                    hashlib.sha256).hexdigest()


def valid_identity(value):
    return isinstance(value, str) and 1 <= len(value) <= 64 and all(
        c.isascii() and (c.isalnum() or c in '-_') for c in value)


def nonce_valid(value):
    return isinstance(value, str) and len(value) == 64 and all(c in '0123456789abcdef' for c in value)


@dataclass
class Session:
    sock: socket.socket
    send_key: bytes
    receive_key: bytes
    sid: str
    peer: str
    secure: bool = True
    send_seq: int = 0
    receive_seq: int = 0
    sent_bytes: int = 0
    received_bytes: int = 0
    metrics: CryptoMetrics = field(default_factory=CryptoMetrics)

    def encode(self, kind, payload=b'', metadata=None):
        if self.send_seq >= 2**64:
            raise ProtocolError('Session exhausted')
        header = canonical({'v': VERSION, 'sid': self.sid, 'seq': self.send_seq,
                            'kind': kind, 'meta': metadata or {}})
        if len(header) > MAX_HEADER:
            raise ProtocolError('Header too large')
        nonce = b'\0' * 4 + self.send_seq.to_bytes(8, 'big')
        if self.secure:
            with self.metrics.measure('encryption',len(payload)):
                body = AESGCM(self.send_key).encrypt(nonce, payload, header)
        else:
            body=payload
        packet = struct.pack('!H', len(header)) + header + body
        if len(packet) > MAX_FRAME:
            raise ProtocolError('Frame too large')
        self.send_seq += 1
        return packet

    def send(self, kind, payload=b'', metadata=None):
        packet = self.encode(kind, payload, metadata)
        send_packet(self.sock, packet)
        self.sent_bytes += 4 + len(packet)

    def receive(self):
        packet = recv_packet(self.sock)
        self.received_bytes += 4 + len(packet)
        if len(packet) < 2:
            raise ProtocolError('Missing header')
        length = struct.unpack('!H', packet[:2])[0]
        if not 0 < length <= MAX_HEADER or 2 + length > len(packet):
            raise ProtocolError('Invalid header length')
        header = packet[2:2 + length]
        value = decode_json(header)
        if not isinstance(value, dict) or set(value) != {'v', 'sid', 'seq', 'kind', 'meta'}:
            raise ProtocolError('Invalid header fields')
        if (value['v'] != VERSION or value['sid'] != self.sid or
                type(value['seq']) is not int or value['seq'] != self.receive_seq):
            raise ProtocolError('Wrong session, replay or out-of-order record')
        if not isinstance(value['kind'], str) or not isinstance(value['meta'], dict):
            raise ProtocolError('Invalid message metadata')
        nonce = b'\0' * 4 + self.receive_seq.to_bytes(8, 'big')
        ciphertext = packet[2 + length:]
        if self.secure:
            with self.metrics.measure('decryption',max(0,len(ciphertext)-16)):
                body=AESGCM(self.receive_key).decrypt(nonce,ciphertext,header)
        else:
            body=ciphertext
        self.receive_seq += 1
        return value['kind'], body, value['meta']

    def close(self):
        self.sock.close()


def derive_session(sock, secret, transcript, client, peer):
    material = HKDF(algorithm=hashes.SHA256(), length=64,
                    salt=hashlib.sha256(transcript).digest(),
                    info=b'SecureLink-v2/client-to-server|server-to-client').derive(secret)
    c2s, s2c = material[:32], material[32:]
    return Session(sock, c2s if client else s2c, s2c if client else c2s,
                   hashlib.sha256(transcript).hexdigest(), peer)


def handshake_client(sock, identity, secret, server='bank-server'):
    if not valid_identity(identity) or len(secret) != 32:
        raise ProtocolError('Invalid credentials')
    deadline = time.monotonic() + HANDSHAKE_TIMEOUT
    hello = {'v': VERSION, 'client': identity, 'server': server, 'nc': secrets.token_hex(32),
             'time': int(time.time())}
    send_packet(sock, canonical(hello), 4096, HANDSHAKE_TIMEOUT)
    response = decode_json(recv_packet(sock, 4096, deadline=deadline))
    if not isinstance(response, dict) or set(response) != {'ns', 'proof'} or not nonce_valid(response['ns']):
        raise ProtocolError('Invalid server hello')
    transcript = canonical({**hello, 'ns': response['ns']})
    if not isinstance(response['proof'], str) or not hmac.compare_digest(
            proof(secret, b'server', transcript), response['proof']):
        raise ProtocolError('Server authentication failed')
    send_packet(sock, canonical({'proof': proof(secret, b'client', transcript)}), 4096)
    finished = decode_json(recv_packet(sock, 4096, deadline=deadline))
    if (not isinstance(finished, dict) or set(finished) != {'proof'} or
            not isinstance(finished['proof'], str) or
            not hmac.compare_digest(finished['proof'], proof(secret, b'finished', transcript))):
        raise ProtocolError('Server confirmation failed')
    return derive_session(sock, secret, transcript, True, server)


def handshake_server(sock, devices, server='bank-server'):
    deadline = time.monotonic() + HANDSHAKE_TIMEOUT
    hello = decode_json(recv_packet(sock, 4096, deadline=deadline))
    if not isinstance(hello, dict) or set(hello) != {'v', 'client', 'server', 'nc', 'time'}:
        raise ProtocolError('Invalid client hello')
    if (hello['v'] != VERSION or hello['server'] != server or
            not valid_identity(hello['client']) or not nonce_valid(hello['nc'])):
        raise ProtocolError('Invalid handshake context')
    if type(hello['time']) is not int or abs(hello['time'] - int(time.time())) > HANDSHAKE_CLOCK_SKEW:
        raise ProtocolError('Handshake timestamp outside acceptable window')
    secret = devices.get(hello['client'])
    if secret is None or len(secret) != 32:
        raise ProtocolError('Unknown device')
    ns = secrets.token_hex(32)
    transcript = canonical({**hello, 'ns': ns})
    send_packet(sock, canonical({'ns': ns, 'proof': proof(secret, b'server', transcript)}), 4096)
    response = decode_json(recv_packet(sock, 4096, deadline=deadline))
    expected = proof(secret, b'client', transcript)
    if (not isinstance(response, dict) or set(response) != {'proof'} or
            not isinstance(response['proof'], str) or not hmac.compare_digest(expected, response['proof'])):
        raise ProtocolError('Client authentication failed')
    send_packet(sock, canonical({'proof': proof(secret, b'finished', transcript)}), 4096)
    return derive_session(sock, secret, transcript, False, hello['client'])


def plain_session(sock, client):
    """Deliberately unsecured baseline, allowed only by explicit loopback lab mode."""
    return Session(sock, b'', b'', 'plaintext-lab', 'lab-client' if not client else 'bank-server', False)
