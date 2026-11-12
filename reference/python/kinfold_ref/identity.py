# SPDX-License-Identifier: Apache-2.0
"""Accounts, devices, certificates, key bundles, wraps (PROTOCOL.md section 4),
safety codes (section 11), server identity and login (section 13)."""
import hashlib
from dataclasses import dataclass

from .crypto import SUITE, VERSION, H, ed25519_public, hpke_open, hpke_seal, label, sign, verify
from .encoding import DecodeError, Reader, b64u, u8, u16, u64, vec16

DEVICE_KINDS = {1: "phone", 2: "tablet", 3: "web", 4: "home-assistant"}
CERT_TBS_LEN, CERT_LEN = 60, 156
BUNDLE_TBS_LEN, BUNDLE_LEN = 83, 147
WRAP_LEN = 104
DAY_MS = 86_400_000
MAX_BUNDLE_WINDOW_MS = 35 * DAY_MS


def account_id(ik_pub: bytes) -> bytes:
    return H("account-id", ik_pub)[:16]


def device_id(dsk_pub: bytes) -> bytes:
    return H("device-id", dsk_pub)[:16]


def key_id(dek_pub: bytes) -> bytes:
    return H("key-id", dek_pub)[:8]


# --- device certificate ------------------------------------------------------

@dataclass(frozen=True)
class Cert:
    raw: bytes
    version: int
    suite: int
    account_id: bytes
    dsk_pub: bytes
    kind: int
    issued_at: int
    ik_pub: bytes
    sig: bytes

    @property
    def device_id(self) -> bytes:
        return device_id(self.dsk_pub)

    @property
    def tbs(self) -> bytes:
        return self.raw[:CERT_TBS_LEN]


def make_cert(ik_seed: bytes, dsk_pub: bytes, kind: int, issued_at: int) -> bytes:
    ik_pub = ed25519_public(ik_seed)
    tbs = u8(VERSION) + u16(SUITE) + account_id(ik_pub) + dsk_pub + u8(kind) + u64(issued_at)
    return tbs + ik_pub + sign(ik_seed, "device-cert", tbs)


def read_cert(r: Reader) -> Cert:
    start = r.pos
    version, suite = r.u8(), r.u16()
    acc, dsk, kind, issued = r.take(16), r.take(32), r.u8(), r.u64()
    ik, sig = r.take(32), r.take(64)
    return Cert(r.data[start:r.pos], version, suite, acc, dsk, kind, issued, ik, sig)


def cert_ok(c: Cert) -> bool:
    return (c.version == VERSION and c.suite == SUITE and c.kind in DEVICE_KINDS
            and c.account_id == account_id(c.ik_pub)
            and verify(c.ik_pub, "device-cert", c.tbs, c.sig))


# --- key bundle ----------------------------------------------------------------

@dataclass(frozen=True)
class Bundle:
    raw: bytes
    version: int
    suite: int
    account_id: bytes
    device_id: bytes
    dek_pub: bytes
    not_before: int
    not_after: int
    sig: bytes

    @property
    def key_id(self) -> bytes:
        return key_id(self.dek_pub)

    @property
    def tbs(self) -> bytes:
        return self.raw[:BUNDLE_TBS_LEN]


def make_bundle(dsk_seed: bytes, acc_id: bytes, dek_pub: bytes, not_before: int, not_after: int) -> bytes:
    tbs = (u8(VERSION) + u16(SUITE) + acc_id + device_id(ed25519_public(dsk_seed)) + dek_pub
           + u64(not_before) + u64(not_after))
    return tbs + sign(dsk_seed, "key-bundle", tbs)


def read_bundle(r: Reader) -> Bundle:
    start = r.pos
    version, suite = r.u8(), r.u16()
    acc, dev, dek = r.take(16), r.take(16), r.take(32)
    nb, na, sig = r.u64(), r.u64(), r.take(64)
    return Bundle(r.data[start:r.pos], version, suite, acc, dev, dek, nb, na, sig)


def bundle_ok(b: Bundle, dsk_pub: bytes, acc_id: bytes) -> bool:
    return (b.version == VERSION and b.suite == SUITE
            and b.device_id == device_id(dsk_pub) and b.account_id == acc_id
            and b.not_before < b.not_after <= b.not_before + MAX_BUNDLE_WINDOW_MS
            and verify(dsk_pub, "key-bundle", b.tbs, b.sig))


# --- wraps: a 32-byte secret sealed to each recipient device --------------------

def make_wraps(recipients, info_fn, secret: bytes, ikm_fn) -> bytes:
    """recipients: iterable of (device_id, dek_pub). Output is sorted by device ID."""
    out = []
    for rid, pub in sorted(recipients):
        kid = key_id(pub)
        enc, ct = hpke_seal(pub, info_fn(rid, kid), b"", secret, ikm_fn(rid))
        out.append(rid + kid + enc + ct)
    return b"".join(out)


def parse_wraps(blob: bytes) -> list:
    if len(blob) % WRAP_LEN:
        raise DecodeError("wrap list length")
    return [(blob[i:i + 16], blob[i + 16:i + 24], blob[i + 24:i + 56], blob[i + 56:i + 104])
            for i in range(0, len(blob), WRAP_LEN)]


def strictly_ascending(ids) -> bool:
    return all(ids[i] < ids[i + 1] for i in range(len(ids) - 1))


def open_wrap(wraps: list, me: bytes, my_keys: dict, info_fn):
    """Returns (secret or None, reason or None)."""
    mine = [w for w in wraps if w[0] == me]
    if not mine:
        return None, "not_a_recipient"
    rid, kid, enc, ct = mine[0]
    sk = my_keys.get(kid)
    if sk is None:
        return None, "unknown_key"
    secret = hpke_open(enc, sk, info_fn(rid, kid), b"", ct)
    if secret is None or len(secret) != 32:
        return None, "bad_wrap"
    return secret, None


# --- safety codes (section 11) ---------------------------------------------------

SAFETY_ITERATIONS = 5200


def safety_half(ik_pub: bytes) -> str:
    h = vec16(label("safety")) + ik_pub
    for _ in range(SAFETY_ITERATIONS):
        h = hashlib.sha512(h + ik_pub).digest()
    return "".join(f"{int.from_bytes(h[i:i + 5], 'big') % 100000:05d}" for i in (0, 5, 10))


def safety_code(ik_a: bytes, ik_b: bytes) -> str:
    lo, hi = sorted((ik_a, ik_b))
    digits = safety_half(lo) + safety_half(hi)
    return " ".join(digits[i:i + 5] for i in range(0, 30, 5))


def safety_qr(ik_a: bytes, ik_b: bytes) -> str:
    lo, hi = sorted((ik_a, ik_b))
    return "kinfold://verify/" + b64u(u8(VERSION) + lo + hi)


# --- server identity and login (section 13) -------------------------------------------

def make_server_info(server_seed: bytes, url: str, issued_at: int, expires_at: int) -> bytes:
    tbs = (u8(VERSION) + vec16(url.encode("utf-8")) + ed25519_public(server_seed)
           + u64(issued_at) + u64(expires_at))
    return tbs + sign(server_seed, "server-info", tbs)


def parse_server_info(raw: bytes) -> dict:
    r = Reader(raw)
    version = r.u8()
    url = r.vec16().decode("utf-8")
    key, issued, expires = r.take(32), r.u64(), r.u64()
    tbs_len = r.pos
    sig = r.take(64)
    r.end()
    ok = version == VERSION and verify(key, "server-info", raw[:tbs_len], sig)
    return dict(version=version, url=url, server_key=key, issued_at=issued, expires_at=expires, sig_ok=ok)


def challenge_sig(server_seed: bytes, challenge: bytes, dev_id: bytes, expires_at: int) -> bytes:
    return sign(server_seed, "auth-challenge", challenge + dev_id + u64(expires_at))


def auth_sig(dsk_seed: bytes, server_key: bytes, challenge: bytes, dev_id: bytes) -> bytes:
    return sign(dsk_seed, "auth", server_key + challenge + dev_id)
