
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, x25519
from cryptography.x509.oid import NameOID

from base64 import b64decode

import global_var

import requests
import json
import time
import logging

TOLERATE_TIME = 30

class AppException(Exception):
    pass


def load_ECDSA_pubkey(pubkey: str | bytes) -> ec.EllipticCurvePublicKey:
    try:
        if isinstance(pubkey, bytes):
            user_pubkey = serialization.load_pem_public_key(pubkey)
        else:
            user_pubkey = serialization.load_pem_public_key(pubkey.encode())
    except ValueError:
        raise AppException("pubkey load failed.")

    if not isinstance(user_pubkey, ec.EllipticCurvePublicKey):
        raise AppException("pubkey should be ECDSA.")
    return user_pubkey

def load_ECDSA_privkey(privkey: str | bytes) -> ec.EllipticCurvePrivateKey:
    try:
        if isinstance(privkey, bytes):
            user_privkey = serialization.load_pem_private_key(privkey, None)
        else:
            user_privkey = serialization.load_pem_private_key(privkey.encode(), None)
    except ValueError:
        raise AppException("privkey load failed.")

    if not isinstance(user_privkey, ec.EllipticCurvePrivateKey):
        raise AppException("privkey should be ECDSA.")
    return user_privkey

def load_raw_X25519_pubkey(pubkey: bytes) -> x25519.X25519PublicKey:
    try:
        user_pubkey = x25519.X25519PublicKey.from_public_bytes(pubkey)
    except ValueError:
        raise AppException("pubkey load failed.")
    return user_pubkey

def generate_sig(data: bytes, privkey: ec.EllipticCurvePrivateKey) -> bytes:
    return privkey.sign(data, ec.ECDSA(hashes.SHA256()))

def verify_sig(data: bytes, sig: bytes, pubkey: ec.EllipticCurvePublicKey):
    pubkey.verify(sig, data, ec.ECDSA(hashes.SHA256()))

def verify_json_sig(data: dict, pubkey: ec.EllipticCurvePublicKey):
    if abs(time.time() - data["data"]["timestamp"]) > TOLERATE_TIME:
        raise AppException("sig time limit exceeded.")
    sig = b64decode(data["sig"])
    raw = json.dumps(data["data"], sort_keys=True).encode()
    verify_sig(raw, sig, pubkey)
    return data["data"]

# load and verify, return pubkey and uid
def load_ECDSA_cert(cert: str) -> tuple[ec.EllipticCurvePublicKey, str]:
    c = x509.load_pem_x509_certificate(cert.encode())
    # first verify whether it is sign by CA
    verify_sig(c.tbs_certificate_bytes, c.signature, global_var.ca_pubkey)

    # then check revoke list
    result = requests.get(
        f"{global_var.ca_url}/revoke/check",
        params={"digest":c.fingerprint(hashes.SHA256()).hex()}
    ).json()
    # verify ca response
    result = verify_json_sig(result, global_var.ca_pubkey)
    if result["result"] == 0:
        raise AppException("cert is in revoke list.")

    common_name = c.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
    if isinstance(common_name, bytes):
        common_name = common_name.decode()
    pubkey = c.public_key()
    assert isinstance(pubkey, ec.EllipticCurvePublicKey)
    return pubkey, common_name

def to_bytes(v: int, bits: int) -> bytes:
    return v.to_bytes(bits//8, "little")
