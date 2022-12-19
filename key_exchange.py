from __future__ import annotations

from struct import pack, unpack
from socket import socket
from dataclasses import dataclass

from utils import load_ECDSA_cert, verify_sig, load_raw_X25519_pubkey, generate_sig

from cryptography.hazmat.primitives.asymmetric import ec, x25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, serialization

import logging

SALT = b"\x10V\xe9C\x0c\x15w\x03vO\x82o\x90\x96!\xaf"
MAX_MODE = 3
# X25519 pubkey length
XCHG_PUBKEY_LEN = 32
SIG_LEN = 72
# mode || sig_len || cert_len || xchg_key || sig || cert
PACKET_PREFIX_LEN = 2 + 2 + 4 + XCHG_PUBKEY_LEN

FMT = f"<HHI{XCHG_PUBKEY_LEN}s"

@dataclass
class KeyExchangeSpec:
    mode: int
    uid: str | None
    xchg_pubkey: x25519.X25519PublicKey

def recv_exchange_packet(s: socket, verify: bool) -> KeyExchangeSpec:
    # recv necessary data
    _blocking = s.getblocking()
    s.setblocking(True)
    data = s.recv(PACKET_PREFIX_LEN)
    s.setblocking(_blocking)
    # extract
    mode, sig_length, cert_length, xchg_pubkey= unpack(FMT, data)
    sig = s.recv(sig_length)
    cert = s.recv(cert_length)
    uid = None
    if verify:
        pubkey, uid = load_ECDSA_cert(cert.decode())
        # remove sig_len
        raw = data[:2] + data[4:] + cert
        verify_sig(raw, sig, pubkey)
    return KeyExchangeSpec(mode, uid, load_raw_X25519_pubkey(xchg_pubkey))

# if sig is not necessary, you should let privkey = None
def generate_exchange_packet(
    mode: int, cert: str = "",
    privkey: ec.EllipticCurvePrivateKey | None = None
) -> tuple[x25519.X25519PrivateKey, bytes]:
    xchg_privkey = x25519.X25519PrivateKey.generate()
    raw = pack(FMT, mode, 0, len(cert),
        xchg_privkey.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
    )
    if privkey is not None:
        sig = generate_sig(raw[:2] + raw[4:] + cert.encode(), privkey)
    else:
        sig = b""
    return (xchg_privkey, raw[:2] + pack("<H", len(sig)) + raw[4:] + sig + cert.encode())

# return IV and key for AES-GCM
def generate_shared_key(
    spec: KeyExchangeSpec,
    xchg_privkey: x25519.X25519PrivateKey
) -> tuple[int, int, bytes]:
    shared_key = xchg_privkey.exchange(spec.xchg_pubkey)
    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=(128 + 96) // 8,
        salt=SALT,
        info=b'AES-GCM IV and key',
    ).derive(shared_key)
    return (
        int.from_bytes(derived_key[:96//8], "little"),
        int.from_bytes(derived_key[96//8:96//8*2], "little"),
        derived_key[-128//8:])

