"""Bounded, reproducible demonstrations; observations are not security proofs."""
import hashlib
import secrets
import statistics
import time

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


def difference(left, right):
    if not left or len(left) != len(right):
        raise ValueError('Compare nonempty outputs of equal length')
    bits = sum((a ^ b).bit_count() for a, b in zip(left, right))
    characters = sum(a != b for a, b in zip(left, right))
    hex_characters = sum(a != b for a, b in zip(left.hex(), right.hex()))
    return {'changed_bits': bits, 'total_bits': len(left)*8,
            'bit_percent': bits / (len(left)*8)*100,
            'changed_characters': characters, 'total_characters': len(left),
            'character_percent': characters / len(left)*100,
            'hex_character_percent': hex_characters / (len(left)*2)*100}


def _block(key, data):
    # One AES block only, for the sensitivity experiment. File encryption uses GCM.
    encryptor = Cipher(algorithms.AES(key), modes.ECB()).encryptor()
    return encryptor.update(data) + encryptor.finalize()


def text_security(data):
    if not data:
        raise ValueError('Text must not be empty')
    block = data[:16].ljust(16, b'\0')
    key = secrets.token_bytes(32)
    original = _block(key, block)
    series = []
    for kind, source in (('diffusion', block), ('confusion', key)):
        trials = []
        for bit in range(len(source)*8):
            changed = bytearray(source)
            changed[bit//8] ^= 1 << (bit % 8)
            output = _block(key, bytes(changed)) if kind == 'diffusion' else _block(bytes(changed), block)
            trials.append({'input_bit': bit, **difference(original, output),
                           'output_hex': output.hex()})
        series.append({'kind': kind, 'trials': trials, 'trial_count': len(trials),
                       'mean_bit_percent': statistics.mean(t['bit_percent'] for t in trials),
                       'min_bit_percent': min(t['bit_percent'] for t in trials),
                       'max_bit_percent': max(t['bit_percent'] for t in trials),
                       'mean_character_percent': statistics.mean(t['character_percent'] for t in trials),
                       'mean_hex_character_percent': statistics.mean(t['hex_character_percent'] for t in trials)})
    return {'algorithm': 'AES-256 block transformation', 'block_hex': block.hex(),
            'baseline_ciphertext_hex': original.hex(), 'input_bytes_used': min(16, len(data)),
            'zero_padding_bytes': max(0, 16-len(data)), 'series': series,
            'bit_target_percent': 50, 'character_target_percent': 100,
            'independent_byte_expected_percent': 100*(255/256),
            'scope': 'First 16 UTF-8 bytes, zero padded if shorter. Diffusion flips each of 128 input bits; '
                     'confusion uses each of 256 key-bit flips as a key-sensitivity demonstration. '
                     'Avalanche is the measured output change, not a proof of confusion or security.',
            'character_definition': 'One ciphertext byte is one character position. Hexadecimal character '
                                    'changes are reported separately; ciphertext is not Unicode text.',
            'target_scope': '50% is the expected bit-change rate. 100% byte-character change is the requested '
                            'reference maximum, not a guaranteed result. Independent random bytes differ '
                            'with probability 255/256 (99.609375%); hex digits differ with probability 15/16.',
            'gcm_scope': 'GCM uses counter mode for the payload. A one-bit ciphertext change is a tampering '
                         'attempt rejected by its authentication tag. AES-core avalanche is measured '
                         'separately; fresh-nonce ciphertext comparisons do not isolate plaintext sensitivity.'}


def hash_resistance(data, attempts=2048):
    if not data or type(attempts) is not int or not 1 <= attempts <= 4096:
        raise ValueError('Use nonempty input and 1–4096 candidates')
    target = hashlib.sha256(data).digest()
    definitions = {
        'preimage': 'Given a digest, find an input producing that digest.',
        'second_preimage': 'Given an input, find a different input with the same digest.',
        'collision': 'Find any two distinct inputs with the same digest.',
    }
    results = []
    for kind in definitions:
        started = time.perf_counter_ns()
        found = None
        seen = {}
        prefix = hashlib.sha256(data) if kind == 'second_preimage' else None
        for index in range(attempts):
            candidate = f'SecureLink candidate {index}'.encode('ascii')
            if prefix is not None:
                hashed = prefix.copy()
                hashed.update(candidate)  # Original input with a nonempty suffix is distinct.
                digest = hashed.digest()
            else:
                digest = hashlib.sha256(candidate).digest()
            if kind == 'collision':
                if digest in seen:
                    found = {'first_candidate': seen[digest], 'second_candidate': index,
                             'digest_hex': digest.hex()}
                seen[digest] = index
            elif digest == target:
                found = {'candidate_index': index, 'candidate_suffix_hex': candidate.hex(),
                         'digest_hex': digest.hex()}
            if found is not None:
                break
        elapsed = (time.perf_counter_ns()-started)/1_000_000
        results.append({'criterion': kind, 'definition': definitions[kind], 'attempts': index+1,
                        'milliseconds': elapsed, 'match_found': found is not None, 'match': found,
                        'candidate_scope': 'Original bytes plus the ASCII suffix SecureLink candidate N' if prefix
                        else 'Distinct ASCII strings SecureLink candidate N, starting at N=0',
                        'outcome': 'Match found in this candidate set' if found else 'No match in the bounded candidate set'})
    changed = bytearray(data)
    changed[0] ^= 1
    altered_digest = hashlib.sha256(changed).digest()
    return {'algorithm': 'SHA-256', 'target_digest_hex': target.hex(), 'criteria': results,
            'one_bit_changed_digest_hex': altered_digest.hex(), 'digest_avalanche': difference(target, altered_digest),
            'scope': 'All searches compare full 256-bit SHA-256 digests. These bounded searches illustrate '
                     'the three attack goals; failure to find a match does not prove resistance. '
                     'Predictable inputs may be recovered by guessing even when the hash is secure.',
            'reference': 'https://csrc.nist.gov/projects/hash-functions'}
