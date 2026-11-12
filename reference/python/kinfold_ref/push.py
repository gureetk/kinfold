# SPDX-License-Identifier: Apache-2.0
"""Silence-watch grants, push messages and the relay signature (PROTOCOL.md section 14)."""
from .crypto import VERSION, H, hpke_open, hpke_seal, sign, verify
from .encoding import DecodeError, Reader, pad_to, u8, u16, u32, u64, unpad, vec16
from .identity import DAY_MS, PHONE, TABLET, key_id

GRANT_TBS_LEN, GRANT_LEN = 59, 123
GRANT_MAX_MS = 35 * DAY_MS
AFTER_MIN_RANGE = (15, 1440)
WAKE, RECORDS, SILENCE = 1, 2, 3
PUSH_PLAIN, PUSH_SEALED, PUSH_BODY_MAX = 2560, 2616, 2483
PUSH_SKEW_MS = 600_000
DELIVERY = {"alert": 1, "background": 2, "location": 3}


# --- watch grants (14.1) ---------------------------------------------------------------------

def make_watch_grant(dsk_seed: bytes, circle_id: bytes, watched_device_id: bytes, watcher_account_id: bytes,
                     after_min: int, not_after: int) -> bytes:
    tbs = u8(VERSION) + circle_id + watched_device_id + watcher_account_id + u16(after_min) + u64(not_after)
    return tbs + sign(dsk_seed, "watch-grant", tbs)


def parse_watch_grant(raw: bytes) -> dict:
    r = Reader(raw)
    d = dict(version=r.u8(), circle_id=r.take(16), watched_device_id=r.take(16), watcher_account_id=r.take(16),
             after_min=r.u16(), not_after=r.u64(), sig=r.take(64))
    r.end()
    return d


def watch_grant_ok(raw: bytes, state, now: int) -> bool:
    """Whether a server may register the watch at time `now`, given the circle's log."""
    try:
        g = parse_watch_grant(raw)
    except DecodeError:
        return False
    dev = state.device(g["watched_device_id"])
    return (g["version"] == VERSION and g["circle_id"] == state.circle_id
            and dev is not None and dev.kind in (PHONE, TABLET)
            and g["watcher_account_id"] in state.members
            and AFTER_MIN_RANGE[0] <= g["after_min"] <= AFTER_MIN_RANGE[1]
            and now < g["not_after"] <= now + GRANT_MAX_MS
            and verify(dev.dsk_pub, "watch-grant", raw[:GRANT_TBS_LEN], g["sig"]))


# --- push messages (14.2) ---------------------------------------------------------------------

class PushError(Exception):
    """A push that a device drops. The reason is for logs only; section 14 defines no codes."""

    def __init__(self, reason):
        super().__init__(reason)
        self.reason = reason


def make_push(server_seed: bytes, recipient_device_id: bytes, ptype: int, sent_at: int, body: bytes) -> bytes:
    if len(body) > PUSH_BODY_MAX:
        raise ValueError("push body too long")
    tbs = u8(VERSION) + u8(ptype) + u64(sent_at) + vec16(body)
    return tbs + sign(server_seed, "push-sig", recipient_device_id + tbs)


def push_info(device_id: bytes, kid: bytes) -> bytes:
    return H("push", device_id + kid)


def seal_push(push: bytes, device_id: bytes, dek_pub: bytes, ikm_e: bytes) -> bytes:
    """Always 2,616 bytes: key_id || enc || ciphertext of the push padded to 2,560."""
    kid = key_id(dek_pub)
    enc, ct = hpke_seal(dek_pub, push_info(device_id, kid), b"", pad_to(push, PUSH_PLAIN), ikm_e)
    return kid + enc + ct


def records_body(records) -> bytes:
    """records: iterable of (received_at, envelope bytes)."""
    return b"".join(u32(8 + len(env)) + u64(at) + env for at, env in records)


def silence_body(circle_id: bytes, watched_device_id: bytes, last_seen_at: int) -> bytes:
    return circle_id + watched_device_id + u64(last_seen_at)


def open_push(sealed: bytes, device_id: bytes, my_keys: dict, server_key: bytes, now: int) -> dict:
    """What a device does with a push. now: its trusted time (8.4). Raises PushError."""
    if len(sealed) != PUSH_SEALED:
        raise PushError("malformed")
    kid, enc, ct = sealed[:8], sealed[8:40], sealed[40:]
    sk = my_keys.get(kid)
    if sk is None:
        raise PushError("unknown_key")
    padded = hpke_open(enc, sk, push_info(device_id, kid), b"", ct)
    if padded is None:
        raise PushError("bad_ciphertext")
    push = unpad(padded, (PUSH_PLAIN,))
    if push is None:
        raise PushError("bad_padding")
    try:
        r = Reader(push)
        version, ptype, sent_at, body = r.u8(), r.u8(), r.u64(), r.vec16()
        tbs_len = r.pos
        sig = r.take(64)
        r.end()
    except DecodeError:
        raise PushError("malformed")
    if version != VERSION:
        raise PushError("bad_version")
    if not verify(server_key, "push-sig", device_id + push[:tbs_len], sig):
        raise PushError("bad_signature")
    if abs(sent_at - now) > PUSH_SKEW_MS:
        raise PushError("bad_time")
    out = dict(type=ptype, sent_at=sent_at)
    try:
        if ptype == WAKE:
            if body:
                raise DecodeError("wake body")
        elif ptype == RECORDS:
            r, recs = Reader(body), []
            while r.pos < len(body):
                rec = Reader(r.vec32())
                recs.append((rec.u64(), rec.take(len(rec.data) - 8)))
            if not recs:
                raise DecodeError("no records")
            out["records"] = recs
        elif ptype == SILENCE:
            r = Reader(body)
            out.update(circle_id=r.take(16), watched_device_id=r.take(16), last_seen_at=r.u64())
            r.end()
        else:
            raise PushError("unknown_type")
    except DecodeError:
        raise PushError("malformed")
    return out


# --- the iOS relay (14.4) ---------------------------------------------------------------------

def relay_tbs(capability: bytes, sealed: bytes, sent_at: int, delivery: int) -> bytes:
    return capability + sealed + u64(sent_at) + u8(delivery)


def relay_sig(server_seed: bytes, capability: bytes, sealed: bytes, sent_at: int, delivery: int) -> bytes:
    return sign(server_seed, "relay-push", relay_tbs(capability, sealed, sent_at, delivery))


def relay_sig_ok(server_key: bytes, capability: bytes, sealed: bytes, sent_at: int, delivery: int,
                 sig: bytes) -> bool:
    return (len(sealed) == PUSH_SEALED and delivery in DELIVERY.values()
            and verify(server_key, "relay-push", relay_tbs(capability, sealed, sent_at, delivery), sig))
