# SPDX-License-Identifier: Apache-2.0
"""Envelopes (PROTOCOL.md section 7) and payload helpers (section 8)."""
import json

from .crypto import SUITE, VERSION, H, aead_open, aead_seal, kdf, sign, verify
from .encoding import DecodeError, Reader, u8, u16, u32, u64, vec32
from .identity import make_wraps, open_wrap, parse_wraps, strictly_ascending

CIRCLE, DIRECT = 1, 2
ENV_HEADER_LEN = 88
BUCKETS = (256, 512, 1024, 2048, 4096, 8192, 16384, 65536)
MAX_PAYLOAD = 65535


class EnvelopeError(Exception):
    def __init__(self, reason):
        super().__init__(reason)
        self.reason = reason


# --- padding (section 7.4) -------------------------------------------------------------

def pad(p: bytes) -> bytes:
    if len(p) > MAX_PAYLOAD:
        raise ValueError("payload too large")
    n = len(p) + 1
    size = next(b for b in BUCKETS if b >= n)
    return p + b"\x80" + bytes(size - n)


def unpad(x: bytes):
    if len(x) not in BUCKETS:
        return None
    y = x.rstrip(b"\x00")
    if not y or y[-1] != 0x80:
        return None
    return y[:-1]


# --- building ------------------------------------------------------------------------

def env_header(kind, circle_id, sender, seq, sent_at, ttl_s, log_head) -> bytes:
    return (u8(VERSION) + u16(SUITE) + u8(kind) + circle_id + sender + u64(seq) + u64(sent_at)
            + u32(ttl_s) + log_head)


def wrap_info(hdr: bytes, rid: bytes, kid: bytes) -> bytes:
    return H("wrap", hdr + rid + kid)


def payload_keys(message_secret: bytes):
    return kdf(message_secret, "payload-key", 32), kdf(message_secret, "payload-nonce", 12)


def seal_wraps(hdr, recipients, message_secret, ikm_fn) -> bytes:
    return make_wraps(recipients, lambda rid, kid: wrap_info(hdr, rid, kid), message_secret, ikm_fn)


def seal_payload(hdr: bytes, wraps: bytes, padded: bytes, message_secret: bytes) -> bytes:
    key, nonce = payload_keys(message_secret)
    return aead_seal(key, nonce, padded, H("env-aad", hdr + vec32(wraps)))


def assemble(sender_dsk_seed: bytes, hdr: bytes, wraps: bytes, ct: bytes) -> bytes:
    body = hdr + vec32(wraps) + vec32(ct)
    return body + sign(sender_dsk_seed, "envelope", body)


def build_envelope(sender_dsk_seed, hdr, recipients, payload: bytes, message_secret, ikm_fn) -> bytes:
    wraps = seal_wraps(hdr, recipients, message_secret, ikm_fn)
    return assemble(sender_dsk_seed, hdr, wraps, seal_payload(hdr, wraps, pad(payload), message_secret))


# --- receiving (section 7.6) ---------------------------------------------------------------

def parse_envelope(raw: bytes) -> dict:
    r = Reader(raw)
    version, suite, kind = r.u8(), r.u16(), r.u8()
    cid, sender, seq, sent_at, ttl, head = r.take(16), r.take(16), r.u64(), r.u64(), r.u32(), r.take(32)
    wraps_blob = r.vec32()
    wraps_end = r.pos
    ct, sig = r.vec32(), r.take(64)
    r.end()
    return dict(version=version, suite=suite, kind=kind, circle_id=cid, sender=sender, seq=seq,
                sent_at=sent_at, ttl_s=ttl, log_head=head, header=raw[:ENV_HEADER_LEN],
                wraps=parse_wraps(wraps_blob), wraps_part=raw[:wraps_end], ct=ct, sig=sig)


MAX_AGE_MS = 31 * 86_400_000         # 30-day maximum TTL plus a day of clock skew
MAX_AHEAD_MS = 86_400_000            # sent_at at most a day ahead of the receiver's clock
TTL_MIN, TTL_MAX = 60, 2_592_000


def _common_checks(raw: bytes, state, now: int, seen: set) -> dict:
    """Section 7.6 steps 1-10, shared by receivers and servers."""
    try:
        env = parse_envelope(raw)
    except DecodeError:
        raise EnvelopeError("malformed")
    if env["version"] != VERSION or env["suite"] != SUITE:
        raise EnvelopeError("bad_version")
    if env["kind"] not in (CIRCLE, DIRECT):
        raise EnvelopeError("bad_kind")
    if env["circle_id"] != state.circle_id:
        raise EnvelopeError("wrong_circle")
    if env["log_head"] not in state.hashes:
        raise EnvelopeError("unknown_log_head")
    dev = state.device(env["sender"])
    if dev is None:
        raise EnvelopeError("sender_not_active")
    if not verify(dev.dsk_pub, "envelope", raw[:-64], env["sig"]):
        raise EnvelopeError("bad_signature")
    if env["sent_at"] + MAX_AGE_MS < now:
        raise EnvelopeError("expired")
    if env["sent_at"] > now + MAX_AHEAD_MS:
        raise EnvelopeError("bad_time")
    if (env["sender"], env["seq"]) in seen:
        raise EnvelopeError("replay")
    wraps = env["wraps"]
    if not wraps or not strictly_ascending([w[0] for w in wraps]):
        raise EnvelopeError("bad_wraps")
    return env


def open_envelope(raw: bytes, state, me: bytes, my_keys: dict, seen: set, now: int) -> dict:
    """Validate and decrypt an envelope for device `me` (section 7.6).

    state: the receiver's log State; my_keys: key_id -> X25519 private key;
    seen: (sender_device_id, seq) pairs already accepted, updated on success;
    now: the receiver's clock (ms). Returns the payload; raises EnvelopeError.
    """
    env = _common_checks(raw, state, now, seen)
    hdr = env["header"]
    secret, why = open_wrap(env["wraps"], me, my_keys, lambda rid, kid: wrap_info(hdr, rid, kid))
    if secret is None:
        raise EnvelopeError(why)
    key, nonce = payload_keys(secret)
    padded = aead_open(key, nonce, env["ct"], H("env-aad", env["wraps_part"]))
    if padded is None:
        raise EnvelopeError("bad_ciphertext")
    payload = unpad(padded)
    if payload is None:
        raise EnvelopeError("bad_padding")
    try:
        obj = json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        raise EnvelopeError("bad_payload")
    if not isinstance(obj, dict) or not isinstance(obj.get("t"), str):
        raise EnvelopeError("bad_payload")
    seen.add((env["sender"], env["seq"]))
    return obj


def server_check(raw: bytes, state, now: int, seen: set) -> None:
    """What a server checks before storing an envelope (section 7.5)."""
    env = _common_checks(raw, state, now, seen)
    if any(state.device(w[0]) is None for w in env["wraps"]):
        raise EnvelopeError("bad_wraps")
    if not TTL_MIN <= env["ttl_s"] <= TTL_MAX:
        raise EnvelopeError("bad_ttl")
    seen.add((env["sender"], env["seq"]))


# --- payload helpers (section 8) -------------------------------------------------------------

def payload_bytes(obj: dict) -> bytes:
    """Compact JSON, UTF-8, keys in insertion order (any order is valid on receipt)."""
    return json.dumps(obj, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


APPROX_CELL_E7 = 200_000            # 0.02 degrees
APPROX_MIN_ACCURACY_M = 2000


def approx_e7(lat_e7: int, lon_e7: int):
    """Snap a position to the centre of its 0.02-degree grid cell (section 8.3)."""
    lat = min(lat_e7, 899_999_999)
    lon = lon_e7 - 3_600_000_000 if lon_e7 >= 1_800_000_000 else lon_e7
    c = APPROX_CELL_E7
    return (lat // c) * c + c // 2, (lon // c) * c + c // 2
