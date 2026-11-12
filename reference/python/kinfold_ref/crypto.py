# SPDX-License-Identifier: Apache-2.0
"""Primitives for suite 0x0001 (PROTOCOL.md section 3).

H, Sign and KDF are domain-separated by ASCII labels "kinfold/v0/<purpose>".
HPKE is RFC 9180 base mode with DHKEM(X25519, HKDF-SHA256), HKDF-SHA256 and
AES-256-GCM, implemented here from the RFC and checked against its vectors.
"""
import hashlib
import hmac

from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .encoding import u8, u16, vec16

LABEL_PREFIX = "kinfold/v0/"   # rename the project -> change this and regenerate the vectors
VERSION = 0
SUITE = 0x0001

_RAW = dict(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw)


def label(purpose: str) -> bytes:
    return (LABEL_PREFIX + purpose).encode("ascii")


def H(purpose: str, data: bytes) -> bytes:
    """H(label, data) = SHA-256(vec16(label) || data)."""
    return hashlib.sha256(vec16(label(purpose)) + data).digest()


# --- Ed25519 -----------------------------------------------------------------

def ed25519_public(seed: bytes) -> bytes:
    return Ed25519PrivateKey.from_private_bytes(seed).public_key().public_bytes(**_RAW)


def sign(seed: bytes, purpose: str, data: bytes) -> bytes:
    """Sign(sk, label, data) = Ed25519(sk, vec16(label) || data)."""
    return Ed25519PrivateKey.from_private_bytes(seed).sign(vec16(label(purpose)) + data)


ED25519_L = 2**252 + 27742317777372353535851937790883648493      # order of the base point
P25519 = 2**255 - 19
ED25519_SMALL_ORDER_Y = frozenset(bytes.fromhex(h) for h in (       # y of the 8 small-order points
    "0000000000000000000000000000000000000000000000000000000000000000",
    "0100000000000000000000000000000000000000000000000000000000000000",
    "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
    "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
    "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"))


def ed25519_point_rejected(enc: bytes) -> bool:
    """Checks 2 and 3 of section 3.3 on a public key or on R: true when the
    encoding is non-canonical (y >= p) or names a small-order point."""
    if len(enc) != 32:
        return True
    y = bytes(enc[:31]) + bytes([enc[31] & 0x7F])       # clear the sign bit
    return int.from_bytes(y, "little") >= P25519 or y in ED25519_SMALL_ORDER_Y


def ed25519_key_invalid(pub: bytes) -> bool:
    """An "invalid key" in the sense of section 3.3."""
    return ed25519_point_rejected(pub)


def verify_raw(pub: bytes, msg: bytes, sig: bytes) -> bool:
    """Strict Ed25519 verification (section 3.3): the byte checks first, then the
    library's single-signature, cofactorless check."""
    if len(sig) != 64 or int.from_bytes(sig[32:], "little") >= ED25519_L:
        return False
    if ed25519_point_rejected(pub) or ed25519_point_rejected(sig[:32]):
        return False
    try:
        Ed25519PublicKey.from_public_bytes(pub).verify(sig, msg)
        return True
    except (InvalidSignature, ValueError):
        return False


def verify(pub: bytes, purpose: str, data: bytes, sig: bytes) -> bool:
    return verify_raw(pub, vec16(label(purpose)) + data, sig)


# --- X25519, HKDF, AES-GCM -----------------------------------------------------

X25519_LOW_ORDER = frozenset(bytes.fromhex(h) for h in (
    "0000000000000000000000000000000000000000000000000000000000000000",
    "0100000000000000000000000000000000000000000000000000000000000000",
    "e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800",
    "5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157",
    "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"))


def x25519_key_invalid(pub: bytes) -> bool:
    """An "invalid key" in the sense of section 3.5: top bit set, not below p, or low order."""
    return (len(pub) != 32 or pub[31] & 0x80 != 0 or int.from_bytes(pub, "little") >= P25519
            or bytes(pub) in X25519_LOW_ORDER)


def x25519_public(sk: bytes) -> bytes:
    return X25519PrivateKey.from_private_bytes(sk).public_key().public_bytes(**_RAW)


def hkdf_extract(salt: bytes, ikm: bytes) -> bytes:
    return hmac.new(salt if salt else bytes(32), ikm, hashlib.sha256).digest()


def hkdf_expand(prk: bytes, info: bytes, length: int) -> bytes:
    out, block, i = b"", b"", 1
    while len(out) < length:
        block = hmac.new(prk, block + info + bytes([i]), hashlib.sha256).digest()
        out += block
        i += 1
    return out[:length]


def kdf(ikm: bytes, purpose: str, length: int) -> bytes:
    """KDF(ikm, label, L) = HKDF-Expand(HKDF-Extract(zeros, ikm), vec16(label), L)."""
    return hkdf_expand(hkdf_extract(b"", ikm), vec16(label(purpose)), length)


def aead_seal(key: bytes, nonce: bytes, pt: bytes, aad: bytes) -> bytes:
    return AESGCM(key).encrypt(nonce, pt, aad)


def aead_open(key: bytes, nonce: bytes, ct: bytes, aad: bytes):
    """Returns the plaintext, or None if authentication fails."""
    try:
        return AESGCM(key).decrypt(nonce, ct, aad)
    except InvalidTag:
        return None


# --- HPKE (RFC 9180), base mode, single-shot ------------------------------------

KEM_ID, KDF_ID, AEAD_ID = 0x0020, 0x0001, 0x0002
_KEM = b"KEM" + u16(KEM_ID)
_HPKE = b"HPKE" + u16(KEM_ID) + u16(KDF_ID) + u16(AEAD_ID)


def _lx(salt, sid, lab, ikm):
    return hkdf_extract(salt, b"HPKE-v1" + sid + lab + ikm)


def _le(prk, sid, lab, info, length):
    return hkdf_expand(prk, u16(length) + b"HPKE-v1" + sid + lab + info, length)


def hpke_derive_key_pair(ikm: bytes):
    sk = _le(_lx(b"", _KEM, b"dkp_prk", ikm), _KEM, b"sk", b"", 32)
    return sk, x25519_public(sk)


def _dh(sk: bytes, pk: bytes) -> bytes:
    # cryptography raises ValueError when the shared secret is all zeros (RFC 9180 7.1.4)
    return X25519PrivateKey.from_private_bytes(sk).exchange(X25519PublicKey.from_public_bytes(pk))


def _shared_secret(dh: bytes, enc: bytes, pk_r: bytes) -> bytes:
    return _le(_lx(b"", _KEM, b"eae_prk", dh), _KEM, b"shared_secret", enc + pk_r, 32)


def hpke_key_schedule(shared_secret: bytes, info: bytes):
    ctx = u8(0) + _lx(b"", _HPKE, b"psk_id_hash", b"") + _lx(b"", _HPKE, b"info_hash", info)
    secret = _lx(shared_secret, _HPKE, b"secret", b"")
    return _le(secret, _HPKE, b"key", ctx, 32), _le(secret, _HPKE, b"base_nonce", ctx, 12)


def hpke_setup_sender(pk_r: bytes, info: bytes, ikm_e: bytes):
    """Returns (enc, shared_secret, key, base_nonce). ikm_e must be 32 fresh random
    bytes in production; test vectors fix it so the output is reproducible."""
    sk_e, pk_e = hpke_derive_key_pair(ikm_e)
    ss = _shared_secret(_dh(sk_e, pk_r), pk_e, pk_r)
    key, base_nonce = hpke_key_schedule(ss, info)
    return pk_e, ss, key, base_nonce


def hpke_seal(pk_r: bytes, info: bytes, aad: bytes, pt: bytes, ikm_e: bytes):
    enc, _, key, nonce = hpke_setup_sender(pk_r, info, ikm_e)
    return enc, aead_seal(key, nonce, pt, aad)


def hpke_open(enc: bytes, sk_r: bytes, info: bytes, aad: bytes, ct: bytes):
    """Returns the plaintext, or None on any failure."""
    try:
        dh = _dh(sk_r, enc)
    except ValueError:
        return None
    ss = _shared_secret(dh, enc, x25519_public(sk_r))
    key, nonce = hpke_key_schedule(ss, info)
    return aead_open(key, nonce, ct, aad)
