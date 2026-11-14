# SPDX-License-Identifier: Apache-2.0
"""Accounts, devices, certificates, identity chains, key bundles, wraps
(PROTOCOL.md section 4), safety codes (section 11), server identity, setup
codes, login and server moves (section 13)."""
import hashlib
from dataclasses import dataclass

from .crypto import (SUITE, VERSION, H, ed25519_key_invalid, ed25519_public, hpke_open, hpke_seal, label, sign,
                     verify, x25519_key_invalid)
from .encoding import DecodeError, Reader, b64u, u8, u16, u32, u64, unb64u, utf8, vec16

DEVICE_KINDS = {1: "phone", 2: "tablet", 3: "web", 4: "home-assistant", 5: "recovery"}
PHONE, TABLET, WEB, HOME_ASSISTANT, RECOVERY = 1, 2, 3, 4, 5
RECEIVING_KINDS = (PHONE, TABLET, WEB, HOME_ASSISTANT)
CERT_TBS_LEN, CERT_LEN = 60, 156
BUNDLE_TBS_LEN, BUNDLE_LEN = 88, 152
LINK_LEN, MAX_CHAIN_LINKS = 192, 8
WRAP_LEN = 104
DAY_MS = 86_400_000
MAX_BUNDLE_WINDOW_MS = 35 * DAY_MS
BUNDLE_EARLY_MS = 600_000            # a bundle may start up to 10 minutes after the entry that carries it


def account_id(first_ik_pub: bytes) -> bytes:
    """Of the account's first identity key; it never changes afterwards (4.2)."""
    return H("account-id", first_ik_pub)[:16]


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


def make_cert(ik_seed: bytes, dsk_pub: bytes, kind: int, issued_at: int, acc_id: bytes = None) -> bytes:
    """acc_id defaults to the ID of an account whose identity key never rotated."""
    ik_pub = ed25519_public(ik_seed)
    tbs = (u8(VERSION) + u16(SUITE) + (acc_id or account_id(ik_pub)) + dsk_pub + u8(kind) + u64(issued_at))
    return tbs + ik_pub + sign(ik_seed, "device-cert", tbs)


def read_cert(r: Reader) -> Cert:
    start = r.pos
    version, suite = r.u8(), r.u16()
    acc, dsk, kind, issued = r.take(16), r.take(32), r.u8(), r.u64()
    ik, sig = r.take(32), r.take(64)
    return Cert(r.data[start:r.pos], version, suite, acc, dsk, kind, issued, ik, sig)


def cert_wellformed(c: Cert) -> bool:
    """Section 4.3. Says nothing about whether account_id belongs to ik_pub: see chain_proves."""
    return (c.version == VERSION and c.suite == SUITE and c.kind in DEVICE_KINDS
            and not ed25519_key_invalid(c.ik_pub) and not ed25519_key_invalid(c.dsk_pub)
            and verify(c.ik_pub, "device-cert", c.tbs, c.sig))


# --- identity chain (section 4.3) ------------------------------------------------

def _link_tbs(acc_id: bytes, old_pub: bytes, new_pub: bytes) -> bytes:
    return acc_id + old_pub + new_pub


def make_identity_link(acc_id: bytes, old_ik_seed: bytes, new_ik_seed: bytes) -> bytes:
    old_pub, new_pub = ed25519_public(old_ik_seed), ed25519_public(new_ik_seed)
    tbs = _link_tbs(acc_id, old_pub, new_pub)
    return old_pub + new_pub + sign(old_ik_seed, "identity-rotate", tbs) + sign(new_ik_seed, "identity-rotate", tbs)


def split_link(raw: bytes):
    """(old_ik_pub, new_ik_pub, old_sig, new_sig)"""
    if len(raw) != LINK_LEN:
        raise DecodeError("identity link length")
    return raw[:32], raw[32:64], raw[64:128], raw[128:192]


def link_ok(acc_id: bytes, raw: bytes) -> bool:
    """Both keys usable, and both signatures verify for this account."""
    old_pub, new_pub, old_sig, new_sig = split_link(raw)
    tbs = _link_tbs(acc_id, old_pub, new_pub)
    return (not ed25519_key_invalid(old_pub) and not ed25519_key_invalid(new_pub)
            and verify(old_pub, "identity-rotate", tbs, old_sig)
            and verify(new_pub, "identity-rotate", tbs, new_sig))


def parse_chain(blob: bytes) -> list:
    """The contents of a `vec16 chain`: 0 to 8 links."""
    if len(blob) % LINK_LEN or len(blob) > LINK_LEN * MAX_CHAIN_LINKS:
        raise DecodeError("identity chain length")
    return [blob[i:i + LINK_LEN] for i in range(0, len(blob), LINK_LEN)]


def chain_proves(c: Cert, links: list) -> bool:
    """Whether the chain proves that c.ik_pub is the current identity key of c.account_id."""
    if not links:
        return c.account_id == account_id(c.ik_pub)
    key = None
    for raw in links:
        old_pub, new_pub, _, _ = split_link(raw)
        if key is None:
            if account_id(old_pub) != c.account_id:
                return False
        elif old_pub != key:
            return False
        if not link_ok(c.account_id, raw):
            return False
        key = new_pub
    return key == c.ik_pub


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
    proto_max: int
    features: int
    sig: bytes

    @property
    def key_id(self) -> bytes:
        return key_id(self.dek_pub)

    @property
    def tbs(self) -> bytes:
        return self.raw[:BUNDLE_TBS_LEN]


def make_bundle(dsk_seed: bytes, acc_id: bytes, dek_pub: bytes, not_before: int, not_after: int,
                proto_max: int = 0, features: int = 0) -> bytes:
    tbs = (u8(VERSION) + u16(SUITE) + acc_id + device_id(ed25519_public(dsk_seed)) + dek_pub
           + u64(not_before) + u64(not_after) + u8(proto_max) + u32(features))
    return tbs + sign(dsk_seed, "key-bundle", tbs)


def read_bundle(r: Reader) -> Bundle:
    start = r.pos
    version, suite = r.u8(), r.u16()
    acc, dev, dek = r.take(16), r.take(16), r.take(32)
    nb, na, pm, feat, sig = r.u64(), r.u64(), r.u8(), r.u32(), r.take(64)
    return Bundle(r.data[start:r.pos], version, suite, acc, dev, dek, nb, na, pm, feat, sig)


def bundle_ok(b: Bundle, dsk_pub: bytes, acc_id: bytes) -> bool:
    """"Valid for" a device (4.4). proto_max and features never affect validity."""
    return (b.version == VERSION and b.suite == SUITE
            and b.device_id == device_id(dsk_pub) and b.account_id == acc_id
            and not x25519_key_invalid(b.dek_pub)
            and b.not_before < b.not_after <= b.not_before + MAX_BUNDLE_WINDOW_MS
            and verify(dsk_pub, "key-bundle", b.tbs, b.sig))


def bundle_current(b: Bundle, t: int) -> bool:
    """"Current at" t (4.4): what a bundle must be when it enters the log."""
    return b.not_before <= t + BUNDLE_EARLY_MS and t < b.not_after


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


def _digits(purpose: str, key: bytes) -> str:
    """30 digits from a public key: SHA-512 iterated under a label, as sections 11 and 13.1 do."""
    h = vec16(label(purpose)) + key
    for _ in range(SAFETY_ITERATIONS):
        h = hashlib.sha512(h + key).digest()
    return "".join(f"{int.from_bytes(h[i:i + 5], 'big') % 100000:05d}" for i in range(0, 30, 5))


def safety_half(ik_pub: bytes) -> str:
    """30 digits for one person's current identity key."""
    return _digits("safety", ik_pub)


def safety_code(ik_a: bytes, ik_b: bytes) -> str:
    """60 digits in twelve groups of five; the same whichever key is "a"."""
    lo, hi = sorted((ik_a, ik_b))
    digits = safety_half(lo) + safety_half(hi)
    return " ".join(digits[i:i + 5] for i in range(0, 60, 5))


def safety_qr(ik_a: bytes, ik_b: bytes) -> str:
    lo, hi = sorted((ik_a, ik_b))
    return "KFV0" + b64u(u8(VERSION) + lo + hi)


# --- server identity, setup codes and login (section 13) -------------------------------

def server_fingerprint(server_key: bytes) -> str:
    """The server key's 30 digits, in six groups of five (13.1)."""
    digits = _digits("server-fingerprint", server_key)
    return " ".join(digits[i:i + 5] for i in range(0, 30, 5))


def make_server_info(server_seed: bytes, url: str, issued_at: int, expires_at: int) -> bytes:
    tbs = (u8(VERSION) + vec16(url.encode("utf-8")) + ed25519_public(server_seed)
           + u64(issued_at) + u64(expires_at))
    return tbs + sign(server_seed, "server-info", tbs)


def parse_server_info(raw: bytes) -> dict:
    r = Reader(raw)
    version = r.u8()
    url = utf8(r.vec16())
    key, issued, expires = r.take(32), r.u64(), r.u64()
    tbs_len = r.pos
    sig = r.take(64)
    r.end()
    ok = version == VERSION and verify(key, "server-info", raw[:tbs_len], sig)
    return dict(version=version, url=url, server_key=key, issued_at=issued, expires_at=expires, sig_ok=ok)


def make_setup(url: str, server_key: bytes, reg_token: bytes, expires_at: int) -> bytes:
    return u8(VERSION) + vec16(url.encode("utf-8")) + server_key + vec16(reg_token) + u64(expires_at)


def setup_code(setup: bytes) -> str:
    return "KFS0" + b64u(setup)


def parse_setup(raw: bytes) -> dict:
    r = Reader(raw)
    d = dict(version=r.u8(), server_url=utf8(r.vec16()), server_key=r.take(32), reg_token=r.vec16(),
             expires_at=r.u64())
    r.end()
    if d["version"] != VERSION:
        raise DecodeError("setup version")
    return d


def read_code(prefix: str, text: str) -> bytes:
    """The bytes inside a scanned code such as "KFS0..." (section 2)."""
    if not text.startswith(prefix):
        raise DecodeError("wrong code prefix")
    return unb64u(text[len(prefix):])


def challenge_sig(server_seed: bytes, challenge: bytes, dev_id: bytes, expires_at: int) -> bytes:
    return sign(server_seed, "auth-challenge", challenge + dev_id + u64(expires_at))


def auth_sig(dsk_seed: bytes, server_key: bytes, challenge: bytes, dev_id: bytes) -> bytes:
    return sign(dsk_seed, "auth", server_key + challenge + dev_id)


def make_server_move(old_seed: bytes, old_url: str, new_url: str, new_key: bytes, issued_at: int) -> bytes:
    tbs = (u8(VERSION) + vec16(old_url.encode("utf-8")) + ed25519_public(old_seed)
           + vec16(new_url.encode("utf-8")) + new_key + u64(issued_at))
    return tbs + sign(old_seed, "server-move", tbs)


def parse_server_move(raw: bytes) -> dict:
    """sig_ok says the notice was signed by the old key it names; the caller checks
    that old_url and old_key are the ones it trusts (13.3)."""
    r = Reader(raw)
    version = r.u8()
    old_url, old_key = utf8(r.vec16()), r.take(32)
    new_url, new_key, issued = utf8(r.vec16()), r.take(32), r.u64()
    tbs_len = r.pos
    sig = r.take(64)
    r.end()
    ok = version == VERSION and verify(old_key, "server-move", raw[:tbs_len], sig)
    return dict(version=version, old_url=old_url, old_key=old_key, new_url=new_url, new_key=new_key,
                issued_at=issued, sig_ok=ok)
