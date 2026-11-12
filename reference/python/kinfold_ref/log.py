# SPDX-License-Identifier: Apache-2.0
"""The circle member log: entries (PROTOCOL.md section 5) and validation (section 6).

apply() is the whole rule set. With secrets=None it runs in "public" mode, which
is what a server can check; with the circle's epoch secrets it runs the full
client rules, including encrypted roles, guardians, teen rules and pauses.
"""
import copy
from dataclasses import dataclass, field

from .crypto import SUITE, VERSION, H, aead_open, aead_seal, kdf, sign, verify
from .encoding import DecodeError, Reader, u8, u16, u32, u64, utf8, vec16, vec32
from .identity import (DAY_MS, Bundle, bundle_ok, cert_ok, parse_wraps, read_bundle, read_cert,
                       strictly_ascending)

GENESIS, ADD_MEMBER, REMOVE_MEMBER, ADD_DEVICE, REMOVE_DEVICE, UPDATE_KEY, POLICY, REKEY, SET_ADMIN = range(1, 10)
ENTRY_NAMES = {GENESIS: "GENESIS", ADD_MEMBER: "ADD_MEMBER", REMOVE_MEMBER: "REMOVE_MEMBER",
               ADD_DEVICE: "ADD_DEVICE", REMOVE_DEVICE: "REMOVE_DEVICE", UPDATE_KEY: "UPDATE_KEY",
               POLICY: "POLICY", REKEY: "REKEY", SET_ADMIN: "SET_ADMIN"}
SET_RULES, SET_GUARDIANS, GRANT_PAUSE, REVOKE_PAUSE, END_TEEN, SET_CIRCLE_NAME = range(1, 7)
POLICY_NAMES = {SET_RULES: "SET_RULES", SET_GUARDIANS: "SET_GUARDIANS", GRANT_PAUSE: "GRANT_PAUSE",
                REVOKE_PAUSE: "REVOKE_PAUSE", END_TEEN: "END_TEEN", SET_CIRCLE_NAME: "SET_CIRCLE_NAME"}
ADULT, TEEN = 1, 2
HEADER_LEN = 88
MIN_DETAILS = 12 + 16            # nonce + GCM tag
ZERO16, ZERO32 = bytes(16), bytes(32)
DEFAULT_RULES = dict(pause_mode=1, approx_mode=1, speed_alert_kmh=0, phone_use_alerts=0,
                     history_days=7, silence_alert_min=60, schedule=[])


class Fatal(Exception):
    """The log is broken at this entry. Servers refuse it; clients stop here."""

    def __init__(self, reason):
        super().__init__(reason)
        self.reason = reason


class Rejected(Exception):
    """A POLICY entry whose private rules fail. It stays in the chain as a no-op."""

    def __init__(self, reason):
        super().__init__(reason)
        self.reason = reason


# --- encoding helpers ------------------------------------------------------------

def header(entry_type, circle_id, seq, prev_hash, created_at, author, epoch) -> bytes:
    return (u8(VERSION) + u16(SUITE) + u8(entry_type) + circle_id + u64(seq) + prev_hash
            + u64(created_at) + author + u32(epoch))


def build_entry(dsk_seed: bytes, hdr: bytes, body: bytes) -> bytes:
    tbs = hdr + vec32(body)
    return tbs + sign(dsk_seed, "log-entry", tbs)


def entry_hash(raw: bytes) -> bytes:
    return H("log-hash", raw)


def circle_id_of(genesis_raw: bytes) -> bytes:
    return H("circle-id", genesis_raw)[:16]


def log_key(epoch_secret: bytes) -> bytes:
    return kdf(epoch_secret, "log-key", 32)


def epoch_commit(epoch: int, secret: bytes) -> bytes:
    return H("epoch-commit", u32(epoch) + secret)


def seal_details(epoch_secret: bytes, hdr: bytes, pt: bytes, nonce: bytes) -> bytes:
    return nonce + aead_seal(log_key(epoch_secret), nonce, pt, hdr)


def open_details(epoch_secret: bytes, hdr: bytes, blob: bytes):
    return aead_open(log_key(epoch_secret), blob[:12], blob[12:], hdr)


def epoch_wrap_info(circle_id, seq, prev_hash, new_epoch, rid, kid) -> bytes:
    return H("epoch-wrap", circle_id + u64(seq) + prev_hash + u32(new_epoch) + rid + kid)


# --- private structures (inside encrypted details) -----------------------------------

def enc_rules(r: dict) -> bytes:
    sched = b"".join(u8(w["kind"]) + u8(w["days"]) + u16(w["start_min"]) + u16(w["end_min"])
                     for w in r["schedule"])
    return (u8(r["pause_mode"]) + u8(r["approx_mode"]) + u16(r["speed_alert_kmh"])
            + u8(r["phone_use_alerts"]) + u8(r["history_days"]) + u16(r["silence_alert_min"])
            + vec16(sched))


def read_rules(rd: Reader) -> dict:
    r = dict(pause_mode=rd.u8(), approx_mode=rd.u8(), speed_alert_kmh=rd.u16(),
             phone_use_alerts=rd.u8(), history_days=rd.u8(), silence_alert_min=rd.u16())
    blob = rd.vec16()
    if len(blob) % 6:
        raise DecodeError("schedule length")
    sr = Reader(blob)
    r["schedule"] = [dict(kind=sr.u8(), days=sr.u8(), start_min=sr.u16(), end_min=sr.u16())
                     for _ in range(len(blob) // 6)]
    return r


def rules_ok(r: dict) -> bool:
    return (r["pause_mode"] <= 2 and r["approx_mode"] <= 2 and r["speed_alert_kmh"] <= 300
            and r["phone_use_alerts"] <= 1 and 1 <= r["history_days"] <= 30
            and r["silence_alert_min"] <= 1440 and len(r["schedule"]) <= 32
            and all(w["kind"] in (1, 2) and 1 <= w["days"] <= 127
                    and w["start_min"] < w["end_min"] <= 1440 for w in r["schedule"]))


def enc_member_details(role, teen_until, guardians, rules) -> bytes:
    return u8(role) + u64(teen_until) + vec16(b"".join(guardians)) + enc_rules(rules)


def dec_member_details(pt: bytes):
    rd = Reader(pt)
    role, teen_until, guardians, rules = rd.u8(), rd.u64(), rd.ids(), read_rules(rd)
    rd.end()
    return role, teen_until, guardians, rules


def enc_genesis_details(name: str) -> bytes:
    return vec16(name.encode("utf-8"))


def name_ok(name_bytes: bytes):
    """Returns the decoded name, or None if not 1..128 bytes of valid UTF-8."""
    if not 1 <= len(name_bytes) <= 128:
        return None
    try:
        return name_bytes.decode("utf-8")
    except UnicodeDecodeError:
        return None


def enc_policy(subtype: int, target: bytes = b"", **f) -> bytes:
    if subtype == SET_CIRCLE_NAME:
        return u8(subtype) + vec16(f["name"].encode("utf-8"))
    out = u8(subtype) + target
    if subtype == SET_RULES:
        out += enc_rules(f["rules"])
    elif subtype == SET_GUARDIANS:
        out += vec16(b"".join(f["guardians"]))
    elif subtype == GRANT_PAUSE:
        out += f["pause_id"] + u8(f["kind"]) + u64(f["start"]) + u64(f["end"])
    elif subtype == REVOKE_PAUSE:
        out += f["pause_id"]
    return out + f.get("extra", b"")


def dec_policy(pt: bytes) -> dict:
    rd = Reader(pt)
    st = rd.u8()
    if st not in POLICY_NAMES:
        return dict(subtype=st, unknown=True)
    if st == SET_CIRCLE_NAME:
        p = dict(subtype=st, name_bytes=rd.vec16())
    else:
        p = dict(subtype=st, target=rd.take(16))
        if st == SET_RULES:
            p["rules"] = read_rules(rd)
        elif st == SET_GUARDIANS:
            p["guardians"] = rd.ids()
        elif st == GRANT_PAUSE:
            p.update(pause_id=rd.take(8), kind=rd.u8(), start=rd.u64(), end=rd.u64())
        elif st == REVOKE_PAUSE:
            p["pause_id"] = rd.take(8)
    rd.end()
    return p


# --- entry framing and bodies --------------------------------------------------------

@dataclass
class Entry:
    raw: bytes
    header: bytes
    version: int
    suite: int
    type: int
    circle_id: bytes
    seq: int
    prev_hash: bytes
    created_at: int
    author: bytes
    epoch: int
    body_bytes: bytes
    sig: bytes

    @property
    def tbs(self) -> bytes:
        return self.raw[:-64]


def parse_entry(raw: bytes) -> Entry:
    r = Reader(raw)
    version, suite, t = r.u8(), r.u16(), r.u8()
    cid, seq, prev, created = r.take(16), r.u64(), r.take(32), r.u64()
    author, epoch = r.take(16), r.u32()
    body, sig = r.vec32(), r.take(64)
    r.end()
    return Entry(raw, raw[:HEADER_LEN], version, suite, t, cid, seq, prev, created, author, epoch, body, sig)


def parse_body(t: int, b: bytes) -> dict:
    r = Reader(b)
    d = {}
    if t in (GENESIS, ADD_MEMBER, ADD_DEVICE):
        d["cert"], d["bundle"] = read_cert(r), read_bundle(r)
    if t == GENESIS:
        d["commit"], d["details"] = r.take(32), r.vec32()
    elif t == ADD_MEMBER:
        d["invite_id"], d["consent"], d["admin"], d["details"] = r.take(16), r.take(64), r.flag(), r.vec32()
    elif t in (REMOVE_MEMBER, REMOVE_DEVICE):
        d["target"], d["commit"], d["wraps"] = r.take(16), r.take(32), parse_wraps(r.vec32())
    elif t == UPDATE_KEY:
        d["bundle"] = read_bundle(r)
    elif t == POLICY:
        d["details"] = r.vec32()
    elif t == REKEY:
        d["commit"], d["wraps"] = r.take(32), parse_wraps(r.vec32())
    elif t == SET_ADMIN:
        d["target"], d["admin"] = r.take(16), r.flag()
    r.end()
    if "details" in d and len(d["details"]) < MIN_DETAILS:
        raise DecodeError("details too short")
    return d


# --- state -------------------------------------------------------------------------

@dataclass
class Device:
    device_id: bytes
    account_id: bytes
    dsk_pub: bytes
    kind: int
    bundle: Bundle


@dataclass
class Member:
    account_id: bytes
    ik_pub: bytes
    admin: bool
    devices: dict = field(default_factory=dict)      # device_id -> Device
    role: int = ADULT                                # private
    teen_until: int = 0                              # private
    guardians: list = field(default_factory=list)    # private
    rules: dict = None                               # private (teens only)
    pauses: dict = field(default_factory=dict)       # private: pause_id -> (kind, start, end)


@dataclass
class State:
    circle_id: bytes = None
    seq: int = -1
    head: bytes = ZERO32
    epoch: int = 0
    commits: dict = field(default_factory=dict)      # epoch -> commitment
    name: str = ""
    members: dict = field(default_factory=dict)      # account_id -> Member
    hashes: list = field(default_factory=list)       # every entry hash, in order
    flags: list = field(default_factory=list)        # (seq, reason) for rejected or bad_details

    def device(self, did):
        for m in self.members.values():
            if did in m.devices:
                return m.devices[did]
        return None

    def active_devices(self) -> list:
        return sorted((d for m in self.members.values() for d in m.devices.values()),
                      key=lambda d: d.device_id)

    def admins(self) -> list:
        return sorted(a for a, m in self.members.items() if m.admin)


# --- validation (section 6) ---------------------------------------------------------------

def apply(st: State, raw: bytes, secrets=None):
    """Validate one entry against state st.

    secrets: None for public (server) mode, else {epoch: epoch_secret} covering at
    least every epoch up to and including this entry's.
    Returns (new_state, result, reason); result is "accepted" or "rejected".
    Raises Fatal(reason). st itself is never modified.
    """
    try:
        e = parse_entry(raw)
    except DecodeError:
        raise Fatal("malformed")
    if e.version != VERSION or e.suite != SUITE:
        raise Fatal("bad_version")
    if e.type not in ENTRY_NAMES:
        raise Fatal("unknown_entry_type")
    try:
        body = parse_body(e.type, e.body_bytes)
    except DecodeError:
        raise Fatal("malformed")

    if st.circle_id is None:
        if e.type != GENESIS or e.seq != 0:
            raise Fatal("bad_seq")
        if e.prev_hash != ZERO32:
            raise Fatal("bad_prev_hash")
        if e.circle_id != ZERO16:
            raise Fatal("bad_circle_id")
        if e.epoch != 0:
            raise Fatal("bad_epoch")
    else:
        if e.type == GENESIS:
            raise Fatal("unexpected_genesis")
        if e.seq != st.seq + 1:
            raise Fatal("bad_seq")
        if e.prev_hash != st.head:
            raise Fatal("bad_prev_hash")
        if e.circle_id != st.circle_id:
            raise Fatal("bad_circle_id")
        if e.epoch != st.epoch:
            raise Fatal("bad_epoch")

    if e.type == GENESIS:
        if e.author != body["cert"].device_id:
            raise Fatal("bad_author")
        author_pub, author_acc = body["cert"].dsk_pub, body["cert"].account_id
    else:
        dev = st.device(e.author)
        if dev is None:
            raise Fatal("author_not_active")
        author_pub, author_acc = dev.dsk_pub, dev.account_id
    if not verify(author_pub, "log-entry", e.tbs, e.sig):
        raise Fatal("bad_signature")

    s = copy.deepcopy(st)
    s.seq, s.head = e.seq, entry_hash(raw)
    s.hashes.append(s.head)
    result, reason = "accepted", None
    try:
        _HANDLERS[e.type](s, e, body, author_acc, secrets)
    except Rejected as rj:
        result, reason = "rejected", rj.reason
        s.flags.append((e.seq, rj.reason))
    if secrets is not None:
        _repair_guardians(s)
        if result == "accepted":
            reason = next((r for q, r in s.flags if q == e.seq), None)   # accepted but flagged: bad_details
    return s, result, reason


def _secret(secrets, epoch):
    sec = secrets.get(epoch)
    if sec is None:
        raise KeyError(f"missing epoch secret {epoch}")
    return sec


def _check_wraps(e, body, devices):
    wraps = body["wraps"]
    ids = [w[0] for w in wraps]
    expected = {d.device_id: d.bundle.key_id for d in devices}
    if (not strictly_ascending(ids) or len(ids) != len(expected)
            or any(expected.get(rid) != kid for rid, kid, _, _ in wraps)):
        raise Fatal("bad_wraps")


def _new_epoch(s, body, secrets):
    s.epoch += 1
    s.commits[s.epoch] = body["commit"]
    if secrets is not None and s.epoch in secrets and epoch_commit(s.epoch, secrets[s.epoch]) != body["commit"]:
        raise ValueError(f"supplied secret for epoch {s.epoch} does not match the log's commitment")


def _new_device(cert, bundle) -> Device:
    return Device(cert.device_id, cert.account_id, cert.dsk_pub, cert.kind, bundle)


def _genesis(s, e, b, author_acc, secrets):
    c, bu = b["cert"], b["bundle"]
    if not cert_ok(c):
        raise Fatal("bad_cert")
    if not bundle_ok(bu, c.dsk_pub, c.account_id):
        raise Fatal("bad_bundle")
    s.circle_id = circle_id_of(e.raw)
    s.commits = {0: b["commit"]}
    m = Member(c.account_id, c.ik_pub, admin=True)
    m.devices[c.device_id] = _new_device(c, bu)
    s.members[c.account_id] = m
    if secrets is None:
        return
    sec = _secret(secrets, 0)
    if epoch_commit(0, sec) != b["commit"]:
        raise ValueError("supplied secret for epoch 0 does not match the log's commitment")
    name = None
    pt = open_details(sec, e.header, b["details"])
    if pt is not None:
        try:
            rd = Reader(pt)
            nb = rd.vec16()
            rd.end()
            name = name_ok(nb)
        except DecodeError:
            name = None
    if name is None:
        s.flags.append((e.seq, "bad_details"))
    s.name = name or ""


def _add_member(s, e, b, author_acc, secrets):
    if not s.members[author_acc].admin:
        raise Fatal("not_admin")
    c, bu = b["cert"], b["bundle"]
    if not cert_ok(c):
        raise Fatal("bad_cert")
    if not bundle_ok(bu, c.dsk_pub, c.account_id):
        raise Fatal("bad_bundle")
    if c.account_id in s.members:
        raise Fatal("already_member")
    if s.device(c.device_id) is not None:
        raise Fatal("device_active")
    if not verify(c.ik_pub, "join-consent", s.circle_id + b["invite_id"] + c.raw + bu.raw, b["consent"]):
        raise Fatal("bad_consent")
    m = Member(c.account_id, c.ik_pub, admin=b["admin"])
    m.devices[c.device_id] = _new_device(c, bu)
    if secrets is not None:
        ok = False
        pt = open_details(_secret(secrets, s.epoch), e.header, b["details"])
        if pt is not None:
            try:
                role, tu, g, rules = dec_member_details(pt)
                if role == ADULT and tu == 0 and not g and rules_ok(rules):
                    ok = True
                elif (role == TEEN and tu > e.created_at and g and rules_ok(rules)
                      and all(x in s.members and s.members[x].role == ADULT for x in g)):
                    m.role, m.teen_until, m.guardians, m.rules = TEEN, tu, list(g), rules
                    ok = True
            except DecodeError:
                ok = False
        if not ok:
            s.flags.append((e.seq, "bad_details"))
    s.members[c.account_id] = m


def _remove_member(s, e, b, author_acc, secrets):
    target = b["target"]
    if target not in s.members:
        raise Fatal("not_member")
    if not (s.members[author_acc].admin or author_acc == target):
        raise Fatal("not_admin")
    if s.members[target].admin and len(s.admins()) == 1 and len(s.members) > 1:
        raise Fatal("last_admin")
    _check_wraps(e, b, [d for d in s.active_devices() if d.account_id != target])
    del s.members[target]
    _new_epoch(s, b, secrets)


def _add_device(s, e, b, author_acc, secrets):
    c, bu = b["cert"], b["bundle"]
    if not cert_ok(c):
        raise Fatal("bad_cert")
    if c.account_id != author_acc or c.ik_pub != s.members[author_acc].ik_pub:
        raise Fatal("wrong_account")
    if not bundle_ok(bu, c.dsk_pub, c.account_id):
        raise Fatal("bad_bundle")
    if s.device(c.device_id) is not None:
        raise Fatal("device_active")
    s.members[author_acc].devices[c.device_id] = _new_device(c, bu)


def _remove_device(s, e, b, author_acc, secrets):
    target = s.device(b["target"])
    if target is None:
        raise Fatal("unknown_device")
    if not (target.account_id == author_acc or s.members[author_acc].admin):
        raise Fatal("not_admin")
    if len(s.members[target.account_id].devices) == 1:
        raise Fatal("last_device")
    _check_wraps(e, b, [d for d in s.active_devices() if d.device_id != target.device_id])
    del s.members[target.account_id].devices[target.device_id]
    _new_epoch(s, b, secrets)


def _update_key(s, e, b, author_acc, secrets):
    dev = s.device(e.author)
    bu = b["bundle"]
    if not bundle_ok(bu, dev.dsk_pub, dev.account_id) or bu.key_id == dev.bundle.key_id:
        raise Fatal("bad_bundle")
    dev.bundle = bu


def _rekey(s, e, b, author_acc, secrets):
    _check_wraps(e, b, s.active_devices())
    _new_epoch(s, b, secrets)


def _set_admin(s, e, b, author_acc, secrets):
    if not s.members[author_acc].admin:
        raise Fatal("not_admin")
    target = b["target"]
    if target not in s.members:
        raise Fatal("not_member")
    if not b["admin"] and s.members[target].admin and len(s.admins()) == 1:
        raise Fatal("last_admin")
    s.members[target].admin = b["admin"]


def _policy(s, e, b, author_acc, secrets):
    if secrets is None:
        return                                   # opaque to servers
    pt = open_details(_secret(secrets, s.epoch), e.header, b["details"])
    if pt is None:
        raise Rejected("bad_details")
    try:
        p = dec_policy(pt)
    except DecodeError:
        raise Rejected("bad_details")
    if p.get("unknown"):
        raise Rejected("unknown_policy")
    if p["subtype"] == SET_CIRCLE_NAME:
        if not s.members[author_acc].admin:
            raise Rejected("not_admin")
        name = name_ok(p["name_bytes"])
        if name is None:
            raise Rejected("bad_details")
        s.name = name
        return
    t = p["target"]
    if t not in s.members:
        raise Rejected("not_member")
    tm = s.members[t]
    if tm.role != TEEN:
        raise Rejected("not_teen")
    is_guardian = author_acc in tm.guardians
    st = p["subtype"]
    if st == END_TEEN:
        if not is_guardian:
            if author_acc != t:
                raise Rejected("not_guardian")
            if e.created_at < tm.teen_until:
                raise Rejected("teen_until_not_reached")
        _end_teen(tm)
        return
    if not is_guardian:
        raise Rejected("not_guardian")
    if st == SET_RULES:
        if not rules_ok(p["rules"]):
            raise Rejected("bad_rules")
        tm.rules = p["rules"]
    elif st == SET_GUARDIANS:
        g = p["guardians"]
        if not g or any(x not in s.members or s.members[x].role != ADULT for x in g):
            raise Rejected("bad_guardians")
        tm.guardians = list(g)
    elif st == GRANT_PAUSE:
        if (p["kind"] not in (1, 2) or not p["start"] < p["end"] <= p["start"] + DAY_MS
                or p["pause_id"] in tm.pauses):
            raise Rejected("bad_pause")
        tm.pauses[p["pause_id"]] = (p["kind"], p["start"], p["end"])
    elif st == REVOKE_PAUSE:
        if p["pause_id"] not in tm.pauses:
            raise Rejected("unknown_pause")
        del tm.pauses[p["pause_id"]]


def _end_teen(m: Member):
    m.role, m.teen_until, m.guardians, m.rules, m.pauses = ADULT, 0, [], None, {}


def _repair_guardians(s: State):
    """Section 6.6: every teen keeps at least one adult guardian."""
    for acc in sorted(s.members):
        m = s.members[acc]
        if m.role != TEEN:
            continue
        g = [x for x in m.guardians if x in s.members and s.members[x].role == ADULT]
        if not g:
            g = sorted(x for x, o in s.members.items() if o.role == ADULT and o.admin)
        if not g:
            g = sorted(x for x, o in s.members.items() if o.role == ADULT)
        if g:
            m.guardians = g
        else:
            _end_teen(m)


_HANDLERS = {GENESIS: _genesis, ADD_MEMBER: _add_member, REMOVE_MEMBER: _remove_member,
             ADD_DEVICE: _add_device, REMOVE_DEVICE: _remove_device, UPDATE_KEY: _update_key,
             POLICY: _policy, REKEY: _rekey, SET_ADMIN: _set_admin}


def replay(entries, secrets=None, upto=None):
    """Apply a list of raw entries from an empty state; returns (state, results)."""
    s, results = State(), []
    for i, raw in enumerate(entries):
        if upto is not None and i > upto:
            break
        s, res, why = apply(s, raw, secrets)
        results.append((res, why))
    return s, results


# --- canonical JSON view of the state (used by the test vectors) ------------------------------

def rules_json(r):
    return None if r is None else {**{k: r[k] for k in DEFAULT_RULES if k != "schedule"},
                                   "schedule": [dict(w) for w in r["schedule"]]}


def state_json(s: State, private: bool = True) -> dict:
    members = []
    for acc in sorted(s.members):
        m = s.members[acc]
        d = dict(account_id=acc.hex(), admin=m.admin,
                 devices=[dict(device_id=dv.device_id.hex(), kind=dv.kind, key_id=dv.bundle.key_id.hex())
                          for dv in sorted(m.devices.values(), key=lambda x: x.device_id)])
        if private:
            d.update(role="teen" if m.role == TEEN else "adult", teen_until=m.teen_until,
                     guardians=[g.hex() for g in m.guardians], rules=rules_json(m.rules),
                     pauses=[dict(id=pid.hex(), kind=k, start=a, end=z)
                             for pid, (k, a, z) in sorted(m.pauses.items())])
        members.append(d)
    out = dict(circle_id=s.circle_id.hex() if s.circle_id else None, seq=s.seq, head=s.head.hex(),
               epoch=s.epoch, members=members)
    if private:
        out["name"] = s.name
        out["flags"] = [dict(seq=q, reason=r) for q, r in s.flags]
    return out
