"""Ed25519 signatures binding the file hash, device and request identity."""
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from .protocol import canonical, ProtocolError


def manifest(device, request, metadata):
    return b'SecureLink/file-signature/Ed25519/v1\0' + canonical(
        {'device':device,'request':request,'metadata':metadata})


def sign(private_bytes, device, request, metadata, metrics):
    key = Ed25519PrivateKey.from_private_bytes(private_bytes)
    message = manifest(device, request, metadata)
    with metrics.measure('signing', len(message)):
        signature = key.sign(message)
    return {'algorithm':'Ed25519','public_key':key.public_key().public_bytes_raw().hex(),
            'signature':signature.hex()}


def verify(proof, public_bytes, device, request, metadata, metrics):
    if (not isinstance(proof,dict) or set(proof)!={'algorithm','public_key','signature'} or
            proof['algorithm']!='Ed25519' or proof['public_key']!=public_bytes.hex() or
            not isinstance(proof['signature'],str) or len(proof['signature'])!=128):
        raise ProtocolError('Invalid or untrusted digital signature')
    try:
        signature=bytes.fromhex(proof['signature'])
    except ValueError as exc:
        raise ProtocolError('Invalid digital signature encoding') from exc
    key=Ed25519PublicKey.from_public_bytes(public_bytes)
    message=manifest(device,request,metadata)
    try:
        with metrics.measure('signature_verification',len(message)):
            key.verify(signature,message)
    except InvalidSignature as exc:
        raise ProtocolError('Digital signature verification failed') from exc
