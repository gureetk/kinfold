# SPDX-License-Identifier: Apache-2.0
"""Envelopes (PROTOCOL.md section 7) and payloads (section 8)."""
import hashlib
import json

from .crypto import SUITE, VERSION, H, aead_open, aead_seal, ed25519_public, kdf, sign, verify
from .encoding import BUCKETS, MAX_PAYLOAD, DecodeError, Reader, pad, u8, u16, u32, u64, unb64u, unpad, vec32
from .identity import HOME_ASSISTANT, RECEIVING_KINDS, WEB, make_wraps, open_wrap, parse_wraps, strictly_ascending
from .log import TEEN
from .push import GRANT_LEN, parse_watch_grant

CIRCLE, DIRECT = 1, 2
ENV_HEADER_LEN = 88
MAX_WRAPS = 255
__all__ = ["BUCKETS", "MAX_PAYLOAD", "pad", "unpad"]      # re-exported: section 7.4 lives in encoding.py


class EnvelopeError(Exception):
    def __init__(self, reason):
        super().__init__(reason)
        self.reason = reason


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


def _common_checks(raw: bytes, state, now: int, seen) -> dict:
    """Section 7.6 steps 1-10, shared by receivers and servers."""
    try:
        env = parse_envelope(raw)                                         # 1
    except DecodeError:
        raise EnvelopeError("malformed")
    if env["version"] != VERSION or env["suite"] != SUITE:                # 2
        raise EnvelopeError("bad_version")
    if env["kind"] not in (CIRCLE, DIRECT):                               # 3
        raise EnvelopeError("bad_kind")
    if env["circle_id"] != state.circle_id:                               # 4
        raise EnvelopeError("wrong_circle")
    dev = state.device(env["sender"])                                     # 5
    if dev is None or dev.kind not in RECEIVING_KINDS:
        raise EnvelopeError("sender_not_active")
    if not verify(dev.dsk_pub, "envelope", raw[:-64], env["sig"]):        # 6
        raise EnvelopeError("bad_signature")
    if env["log_head"] not in state.hashes:                               # 7
        raise EnvelopeError("unknown_log_head")
    if env["sent_at"] + MAX_AGE_MS < now:                                 # 8
        raise EnvelopeError("expired")
    if env["sent_at"] > now + MAX_AHEAD_MS:
        raise EnvelopeError("bad_time")
    if (env["sender"], env["seq"]) in seen:                               # 9
        raise EnvelopeError("replay")
    wraps = env["wraps"]                                                  # 10
    if not 1 <= len(wraps) <= MAX_WRAPS or not strictly_ascending([w[0] for w in wraps]):
        raise EnvelopeError("bad_wraps")
    env["sender_device"] = dev
    return env


def open_envelope(raw: bytes, state, me: bytes, my_keys: dict, seen: set, now: int) -> dict:
    """Validate and decrypt an envelope for device `me` (section 7.6).

    state: the receiver's log State (with its private fields); my_keys: key_id ->
    X25519 private key; seen: (sender_device_id, seq) pairs already accepted, updated
    on success; now: the receiver's clock (ms). Returns the payload; raises EnvelopeError,
    or Held when the payload has to wait for this device's private state (6.5).
    """
    env = _common_checks(raw, state, now, seen)
    hdr = env["header"]
    secret, why = open_wrap(env["wraps"], me, my_keys, lambda rid, kid: wrap_info(hdr, rid, kid))   # 11
    if secret is None:
        raise EnvelopeError(why)
    key, nonce = payload_keys(secret)
    padded = aead_open(key, nonce, env["ct"], H("env-aad", env["wraps_part"]))                      # 12
    if padded is None:
        raise EnvelopeError("bad_ciphertext")
    payload = unpad(padded)                                                                         # 13
    if payload is None:
        raise EnvelopeError("bad_padding")
    obj = parse_payload(payload)                                                                    # 14
    if not sender_may_send(obj, env["kind"], env["sender_device"], state, me):                      # 15 (may raise Held)
        raise EnvelopeError("not_allowed")
    seen.add((env["sender"], env["seq"]))
    return obj


def server_check(raw: bytes, state, now: int, seen: dict) -> str:
    """What a server checks before storing an envelope (section 7.5).

    seen: (sender_device_id, seq) -> SHA-256 of the stored envelope. Returns "stored",
    or "duplicate" when exactly these bytes were stored before; raises EnvelopeError.
    """
    digest = hashlib.sha256(raw).digest()
    try:
        env = _common_checks(raw, state, now, seen)
    except EnvelopeError as e:
        if e.reason == "replay":
            p = parse_envelope(raw)
            if seen[(p["sender"], p["seq"])] == digest:
                return "duplicate"                # posting is idempotent
        raise
    receiving = {d.device_id for d in state.receiving_devices()}
    named = [w[0] for w in env["wraps"]]
    if any(rid not in receiving for rid in named):
        raise EnvelopeError("bad_wraps")
    if not TTL_MIN <= env["ttl_s"] <= TTL_MAX:
        raise EnvelopeError("bad_ttl")
    if env["kind"] == CIRCLE:
        if state.hashes.index(env["log_head"]) < state.receiving_changed_seq:
            raise EnvelopeError("stale_head")
        if set(named) != receiving - {env["sender"]}:
            raise EnvelopeError("bad_wraps")      # a circle envelope names every receiving device
    seen[(env["sender"], env["seq"])] = digest
    return "stored"


# --- payloads (section 8) -------------------------------------------------------------------

MAX_DEPTH, MAX_STRING, MAX_AVATAR, MAX_ARRAY, MAX_INT = 8, 4096, 43_700, 256, 2**53 - 1
CIRCLE_TYPES = frozenset(("loc", "hb", "evt", "checkin", "sos", "place", "profile", "chat", "pause_req",
                          "pause_deny", "watch_grant", "refresh_req", "refresh"))
DIRECT_TYPES = frozenset(("sig", "welcome", "ik"))
KIND_MAY_SEND = {WEB: frozenset(("sig", "refresh_req")), HOME_ASSISTANT: frozenset(("refresh_req",))}
ROLE_RULES = frozenset(("pause_req", "pause_deny", "place"))        # types whose sender rule needs roles


class Held(Exception):
    """Step 15 needs roles this device doesn't know: its private state is frozen (6.5, 7.6).
    The envelope is neither accepted nor refused; the caller keeps it and opens it again
    once the device has caught up."""


def payload_bytes(obj: dict) -> bytes:
    """Compact JSON, UTF-8, keys in insertion order (any order is valid on receipt)."""
    return json.dumps(obj, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _bad_constant(_):
    raise ValueError("NaN and Infinity are not JSON")


def _within_limits(v, depth: int, avatar: bool = False):
    """Returns v with whole floats turned into ints; raises ValueError outside the limits of 8.1."""
    if isinstance(v, bool) or v is None:
        return v
    if isinstance(v, str):
        # encode() raises ValueError on an unpaired surrogate, which JSON's \u escapes can smuggle in
        if len(v.encode("utf-8")) > (MAX_AVATAR if avatar else MAX_STRING):
            raise ValueError("string too long")
        return v
    if isinstance(v, (int, float)):
        if isinstance(v, float):
            if v != v or v in (float("inf"), float("-inf")) or v != int(v):
                raise ValueError("not a whole number")
            v = int(v)
        if abs(v) > MAX_INT:
            raise ValueError("number out of range")
        return v
    if depth > MAX_DEPTH:
        raise ValueError("nested too deeply")
    if isinstance(v, list):
        if len(v) > MAX_ARRAY:
            raise ValueError("array too long")
        return [_within_limits(x, depth + 1) for x in v]
    out = {}
    for k, x in v.items():
        if len(k.encode("utf-8")) > MAX_STRING:
            raise ValueError("key too long")
        out[k] = _within_limits(x, depth + 1, avatar=(depth == 1 and k == "avatar"))
    return out


def parse_payload(raw: bytes) -> dict:
    """Step 14: UTF-8 JSON, an object with a string "t", within the limits of section 8.1."""
    try:
        obj = json.loads(raw.decode("utf-8"), parse_constant=_bad_constant)
        if not isinstance(obj, dict) or not isinstance(obj.get("t"), str):
            raise ValueError("not an object with a type")
        return _within_limits(obj, 1)
    except (UnicodeDecodeError, ValueError, RecursionError):
        raise EnvelopeError("bad_payload")


def _b64_field(obj: dict, name: str, size: int):
    v = obj.get(name)
    if not isinstance(v, str):
        return None
    try:
        b = unb64u(v)
    except DecodeError:
        return None
    return b if len(b) == size else None


def sender_may_send(obj: dict, kind: int, sender, state, me: bytes) -> bool:
    """Step 15: the Kind and Sent by columns of section 8.2 and the rules under the table.
    sender: the sending Device; me: the receiving device's ID. Raises Held when the rule
    needs roles and this device's private state is frozen."""
    t = obj["t"]
    if sender.kind in KIND_MAY_SEND and t not in KIND_MAY_SEND[sender.kind]:
        return False
    if (t in CIRCLE_TYPES and kind != CIRCLE) or (t in DIRECT_TYPES and kind != DIRECT):
        return False
    if t in ROLE_RULES and state.private_unknown_from is not None:
        raise Held()
    member = state.members[sender.account_id]
    if t == "pause_req":
        return member.role == TEEN
    if t == "pause_deny":
        teen = state.members.get(_b64_field(obj, "teen", 16))
        return teen is not None and teen.role == TEEN and sender.account_id in teen.guardians
    if t == "welcome":
        mine = state.device(me)
        return mine is not None and mine.added_by == sender.account_id
    if t == "watch_grant":
        raw = _b64_field(obj, "grant", GRANT_LEN)
        return raw is not None and parse_watch_grant(raw)["watched_device_id"] == sender.device_id
    if t == "ik":
        mine, seed = state.device(me), _b64_field(obj, "ik", 32)
        return (mine is not None and seed is not None and mine.account_id == sender.account_id
                and ed25519_public(seed) == member.ik_pub)
    if t == "place":
        creator, n, pid = _b64_field(obj, "creator", 16), _b64_field(obj, "n", 8), _b64_field(obj, "id", 8)
        if creator is None or n is None or pid != place_id(creator, n):
            return False
        return member.role != TEEN or creator == sender.account_id
    return True


def place_id(creator: bytes, n: bytes) -> bytes:
    return H("place-id", creator + n)[:8]


APPROX_CELL_E7 = 200_000            # 0.02 degrees
APPROX_MIN_ACCURACY_M = 2000


def approx_e7(lat_e7: int, lon_e7: int):
    """Snap a position to the centre of its 0.02-degree grid cell (section 8.3)."""
    lat = min(lat_e7, 899_999_999)
    lon = lon_e7 - 3_600_000_000 if lon_e7 >= 1_800_000_000 else lon_e7
    c = APPROX_CELL_E7
    return (lat // c) * c + c // 2, (lon // c) * c + c // 2
