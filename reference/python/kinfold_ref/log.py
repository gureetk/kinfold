# SPDX-License-Identifier: Apache-2.0
"""The circle member log: entries (PROTOCOL.md section 5) and validation (section 6).

apply() is the whole rule set. With secrets=None it runs in "public" mode, which
is what a server can check; with the circle's epoch secrets it runs the full
client rules, including encrypted roles, guardians, teen rules and pauses.
"""
import copy
from dataclasses import dataclass, field

from .crypto import SUITE, VERSION, H, aead_open, aead_seal, ed25519_key_invalid, kdf, sign, verify
from .encoding import DecodeError, Reader, pad_to, u8, u16, u32, u64, unpad, vec16, vec32
from .identity import (DAY_MS, HOME_ASSISTANT, LINK_LEN, PHONE, RECEIVING_KINDS, RECOVERY, TABLET, WEB, Bundle,
                       bundle_current, bundle_ok, cert_wellformed, chain_proves, link_ok, parse_chain, parse_wraps,
                       read_bundle, read_cert, split_link, strictly_ascending)

(GENESIS, ADD_MEMBER, REMOVE_MEMBER, ADD_DEVICE, REMOVE_DEVICE, UPDATE_KEY, POLICY, REKEY, SET_ADMIN,
 ADD_RECOVERY, SET_OPTIONS, ROTATE_IDENTITY) = range(1, 13)
ENTRY_NAMES = {GENESIS: "GENESIS", ADD_MEMBER: "ADD_MEMBER", REMOVE_MEMBER: "REMOVE_MEMBER",
               ADD_DEVICE: "ADD_DEVICE", REMOVE_DEVICE: "REMOVE_DEVICE", UPDATE_KEY: "UPDATE_KEY",
               POLICY: "POLICY", REKEY: "REKEY", SET_ADMIN: "SET_ADMIN", ADD_RECOVERY: "ADD_RECOVERY",
               SET_OPTIONS: "SET_OPTIONS", ROTATE_IDENTITY: "ROTATE_IDENTITY"}
SET_RULES, SET_GUARDIANS, GRANT_PAUSE, REVOKE_PAUSE, END_TEEN, SET_CIRCLE_NAME = range(1, 7)
POLICY_NAMES = {SET_RULES: "SET_RULES", SET_GUARDIANS: "SET_GUARDIANS", GRANT_PAUSE: "GRANT_PAUSE",
                REVOKE_PAUSE: "REVOKE_PAUSE", END_TEEN: "END_TEEN", SET_CIRCLE_NAME: "SET_CIRCLE_NAME"}
ADULT, TEEN = 1, 2
HEADER_LEN = 88
MAX_ENTRY = 65_536                     # section 16.6
DETAILS_PLAIN, DETAILS_LEN = 512, 540  # every details field: 12-byte nonce, 512 padded bytes, 16-byte tag
MAX_MEMBERS, MAX_DEVICES, MAX_GUARDIANS, MAX_PAUSES = 32, 8, 8, 16
OPT_WEB, OPT_HOME_ASSISTANT = 1, 2     # circle options (section 16.7)
OPTIONS_DEFINED = OPT_WEB | OPT_HOME_ASSISTANT
ZERO16, ZERO32 = bytes(16), bytes(32)
DEFAULT_RULES = dict(pause_mode=1, approx_mode=1, speed_alert_kmh=0, phone_use_alerts=0,
                     history_days=7, silence_alert_min=60, tz="", schedule=[])
TZ_CHARS = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789/_-+")


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
    """Always 540 bytes, whatever the plaintext (5.4)."""
    return nonce + aead_seal(log_key(epoch_secret), nonce, pad_to(pt, DETAILS_PLAIN), hdr)


def open_details(epoch_secret: bytes, hdr: bytes, blob: bytes):
    """The plaintext, or None if the ciphertext or its padding is bad."""
    padded = aead_open(log_key(epoch_secret), blob[:12], blob[12:], hdr)
    return None if padded is None else unpad(padded, (DETAILS_PLAIN,))


def epoch_wrap_info(circle_id, seq, prev_hash, new_epoch, rid, kid) -> bytes:
    return H("epoch-wrap", circle_id + u64(seq) + prev_hash + u32(new_epoch) + rid + kid)


# --- private structures (inside encrypted details) -----------------------------------

def enc_rules(r: dict) -> bytes:
    sched = b"".join(u8(w["kind"]) + u8(w["days"]) + u16(w["start_min"]) + u16(w["end_min"])
                     for w in r["schedule"])
    return (u8(r["pause_mode"]) + u8(r["approx_mode"]) + u16(r["speed_alert_kmh"])
            + u8(r["phone_use_alerts"]) + u8(r["history_days"]) + u16(r["silence_alert_min"])
            + vec16(r["tz"].encode("latin-1")) + vec16(sched))


def read_rules(rd: Reader) -> dict:
    r = dict(pause_mode=rd.u8(), approx_mode=rd.u8(), speed_alert_kmh=rd.u16(),
             phone_use_alerts=rd.u8(), history_days=rd.u8(), silence_alert_min=rd.u16())
    r["tz"] = rd.vec16().decode("latin-1")      # one character per byte; rules_ok checks which are allowed
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
            and (r["silence_alert_min"] == 0 or 15 <= r["silence_alert_min"] <= 1440)
            and len(r["tz"]) <= 64 and set(r["tz"]) <= TZ_CHARS
            and len(r["schedule"]) <= 32 and (r["tz"] != "" or not r["schedule"])
            and all(w["kind"] in (1, 2) and 1 <= w["days"] <= 127
                    and w["start_min"] < w["end_min"] <= 1440 for w in r["schedule"]))


def enc_terms(role, teen_until, guardians, rules) -> bytes:
    """MemberTerms: what a new member is asked to accept (5.5, 9)."""
    return u8(role) + u64(teen_until) + vec16(b"".join(guardians)) + enc_rules(rules)


def read_terms(rd: Reader) -> dict:
    return dict(role=rd.u8(), teen_until=rd.u64(), guardians=rd.ids(), rules=read_rules(rd))


def terms_commit(terms_salt: bytes, terms: bytes) -> bytes:
    return H("member-terms", terms_salt + terms)


def enc_member_details(terms_salt: bytes, terms: bytes) -> bytes:
    return terms_salt + terms


def dec_member_details(pt: bytes):
    """(terms_salt, parsed terms, the terms' bytes)"""
    rd = Reader(pt)
    salt = rd.take(16)
    terms = read_terms(rd)
    rd.end()
    return salt, terms, pt[16:]


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
    if t in (GENESIS, ADD_MEMBER):
        d["cert"], d["chain"], d["bundle"] = read_cert(r), parse_chain(r.vec16()), read_bundle(r)
    if t == GENESIS:
        d["commit"], d["details"] = r.take(32), r.take(DETAILS_LEN)
    elif t == ADD_MEMBER:
        d["invite_id"], d["terms_commit"], d["consent"] = r.take(16), r.take(32), r.take(64)
        d["admin"], d["details"] = r.flag(), r.take(DETAILS_LEN)
    elif t in (REMOVE_MEMBER, REMOVE_DEVICE):
        d["target"], d["commit"], d["wraps"] = r.take(16), r.take(32), parse_wraps(r.vec32())
    elif t == ADD_DEVICE:
        d["cert"], d["bundle"] = read_cert(r), read_bundle(r)
    elif t == UPDATE_KEY:
        d["bundle"] = read_bundle(r)
    elif t == POLICY:
        d["details"] = r.take(DETAILS_LEN)
    elif t == REKEY:
        d["commit"], d["wraps"] = r.take(32), parse_wraps(r.vec32())
    elif t == SET_ADMIN:
        d["target"], d["admin"] = r.take(16), r.flag()
    elif t == ADD_RECOVERY:
        d["cert"] = read_cert(r)
    elif t == SET_OPTIONS:
        d["options"] = r.u32()
    elif t == ROTATE_IDENTITY:
        d["link"] = r.take(LINK_LEN)
    r.end()
    return d


# --- state -------------------------------------------------------------------------

@dataclass
class Device:
    device_id: bytes
    account_id: bytes
    dsk_pub: bytes
    kind: int
    bundle: Bundle                 # None for a recovery device
    added_by: bytes = None         # account that authored the entry adding this device (for `welcome`, 8.2)


@dataclass
class Member:
    account_id: bytes
    ik_pub: bytes                                    # the current identity key
    admin: bool
    devices: dict = field(default_factory=dict)      # device_id -> Device
    role: int = ADULT                                # private
    teen_until: int = 0                              # private
    guardians: list = field(default_factory=list)    # private
    rules: dict = None                               # private (teens only)
    pauses: dict = field(default_factory=dict)       # private: pause_id -> (kind, start, end); at most 16


@dataclass
class State:
    circle_id: bytes = None
    seq: int = -1
    head: bytes = ZERO32
    epoch: int = 0
    commits: dict = field(default_factory=dict)      # epoch -> commitment
    name: str = ""
    members: dict = field(default_factory=dict)      # account_id -> Member
    hashes: list = field(default_factory=list)       # every entry hash, in order: hashes[seq]
    flags: list = field(default_factory=list)        # (seq, reason) for rejected or bad_details
    rekey_pending: bool = False                      # a removal that could not start a new epoch (6.4)
    private_unknown_from: int = None                 # seq where a missing epoch secret froze private state (6.5)
    options: int = 0                                 # public circle options (16.7)
    used_invites: set = field(default_factory=set)   # invite IDs already spent (6.4)
    receiving_changed_seq: int = -1                  # last entry that changed the set of receiving devices (7.5)

    def device(self, did):
        for m in self.members.values():
            if did in m.devices:
                return m.devices[did]
        return None

    def active_devices(self) -> list:
        return sorted((d for m in self.members.values() for d in m.devices.values()),
                      key=lambda d: d.device_id)

    def receiving_devices(self) -> list:
        return [d for d in self.active_devices() if d.kind in RECEIVING_KINDS]

    def admins(self) -> list:
        return sorted(a for a, m in self.members.items() if m.admin)


# --- validation (section 6) ---------------------------------------------------------------

def _kind_may_author(st: State, e: Entry, body: dict, kind: int, author_acc: bytes) -> bool:
    """The table in section 6.3: what a device may write depends on its kind."""
    if kind in (PHONE, TABLET):
        return True
    if kind in (WEB, HOME_ASSISTANT):
        return e.type == UPDATE_KEY or (e.type == REMOVE_DEVICE and body["target"] == e.author)
    if kind == RECOVERY:
        if e.type == ADD_DEVICE:
            return True
        if e.type == REMOVE_DEVICE:
            target = st.device(body["target"])
            return target is not None and target.account_id == author_acc
    return False


def apply(st: State, raw: bytes, secrets=None):
    """Validate one entry against state st (section 6.3).

    secrets: None for public (server) mode, else {epoch: epoch_secret} with whatever
    secrets the client holds. One that doesn't match the log's commitment is discarded,
    and an entry whose details need a secret the client lacks is deferred (6.5).
    Returns (new_state, result, reason); result is "accepted", "rejected" or "deferred".
    Raises Fatal(reason). st itself is never modified.
    """
    if len(raw) > MAX_ENTRY:                                              # step 1
        raise Fatal("too_large")
    try:
        e = parse_entry(raw)
    except DecodeError:
        raise Fatal("malformed")
    if e.version != VERSION or e.suite != SUITE:                          # step 2
        raise Fatal("bad_version")
    if e.type not in ENTRY_NAMES:                                         # step 3
        raise Fatal("unknown_entry_type")
    try:
        body = parse_body(e.type, e.body_bytes)                           # step 4
    except DecodeError:
        raise Fatal("malformed")

    if st.circle_id is None:                                              # step 5
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

    if e.type == GENESIS:                                                 # step 6
        c = body["cert"]
        if e.author != c.device_id:
            raise Fatal("bad_author")
        author_pub, author_acc, author_kind = c.dsk_pub, c.account_id, c.kind
    else:
        dev = st.device(e.author)
        if dev is None:
            raise Fatal("author_not_active")
        author_pub, author_acc, author_kind = dev.dsk_pub, dev.account_id, dev.kind
    if not verify(author_pub, "log-entry", e.tbs, e.sig):                 # step 7
        raise Fatal("bad_signature")
    if not _kind_may_author(st, e, body, author_kind, author_acc):        # step 8
        raise Fatal("kind_not_allowed")

    s = copy.deepcopy(st)
    s.seq, s.head = e.seq, entry_hash(raw)
    s.hashes.append(s.head)
    private = secrets is not None and s.private_unknown_from is None
    if private and e.type in (GENESIS, ADD_MEMBER, POLICY) and not _has_secret(st, e, body, secrets):
        s.private_unknown_from = e.seq            # 6.5: freeze private state until the secret arrives
        private = False
    result, reason = "accepted", None
    before = {d.device_id for d in st.receiving_devices()}
    try:
        _HANDLERS[e.type](s, e, body, author_acc, secrets if private else None)   # steps 9 to 11
    except Rejected as rj:
        result, reason = "rejected", rj.reason
        s.flags.append((e.seq, rj.reason))
    if e.type == GENESIS or before != {d.device_id for d in s.receiving_devices()}:
        s.receiving_changed_seq = e.seq
    if private:
        _repair_guardians(s)
        if result == "accepted":
            reason = next((r for q, r in s.flags if q == e.seq), None)   # accepted but flagged: bad_details
    elif secrets is not None:
        result = "deferred"
    return s, result, reason


def _has_secret(st, e, body, secrets) -> bool:
    """6.5: a secret counts only if it matches the log's commitment for its epoch."""
    sec = secrets.get(e.epoch)
    commit = body["commit"] if e.type == GENESIS else st.commits.get(e.epoch)
    return sec is not None and commit is not None and epoch_commit(e.epoch, sec) == commit


def _secret(secrets, epoch):
    """The epoch's secret. apply() has already checked it against the commitment."""
    return secrets[epoch]


def _check_wraps(body, devices):
    """Wrap coverage (6.4): exactly one wrap per device in the set, in order, to its current key."""
    wraps = body["wraps"]
    ids = [w[0] for w in wraps]
    expected = {d.device_id: d.bundle.key_id for d in devices}
    if (not strictly_ascending(ids) or len(ids) != len(expected)
            or any(expected.get(rid) != kid for rid, kid, _, _ in wraps)):
        raise Fatal("bad_wraps")


def _no_epoch(body):
    if body["commit"] != ZERO32 or body["wraps"]:
        raise Fatal("bad_wraps")


def _epoch_body(body, devices, fresh):
    """A removal by a remaining admin starts a new epoch; any other removal carries no secret (6.4)."""
    if fresh:
        _check_wraps(body, devices)
    else:
        _no_epoch(body)


def _advance(s, body, secrets, fresh):
    if fresh:
        _new_epoch(s, body, secrets)
        s.rekey_pending = False
    else:
        s.rekey_pending = True


def _new_epoch(s, body, secrets):
    s.epoch += 1
    s.commits[s.epoch] = body["commit"]


def _new_device(cert, bundle, added_by) -> Device:
    return Device(cert.device_id, cert.account_id, cert.dsk_pub, cert.kind, bundle, added_by)


def _genesis(s, e, b, author_acc, secrets):
    c, bu = b["cert"], b["bundle"]
    if not cert_wellformed(c) or not chain_proves(c, b["chain"]):
        raise Fatal("bad_cert")
    if not bundle_ok(bu, c.dsk_pub, c.account_id) or not bundle_current(bu, e.created_at):
        raise Fatal("bad_bundle")
    s.circle_id = circle_id_of(e.raw)
    s.commits = {0: b["commit"]}
    m = Member(c.account_id, c.ik_pub, admin=True)
    m.devices[c.device_id] = _new_device(c, bu, c.account_id)
    s.members[c.account_id] = m
    if secrets is None:
        return
    sec = _secret(secrets, 0)
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
    if s.rekey_pending:
        raise Fatal("rekey_pending")
    if len(s.members) >= MAX_MEMBERS:
        raise Fatal("too_many_members")
    c, bu = b["cert"], b["bundle"]
    if not cert_wellformed(c) or not chain_proves(c, b["chain"]):
        raise Fatal("bad_cert")
    if c.kind not in (PHONE, TABLET):
        raise Fatal("kind_not_allowed")
    if not bundle_ok(bu, c.dsk_pub, c.account_id) or not bundle_current(bu, e.created_at):
        raise Fatal("bad_bundle")
    if c.account_id in s.members or any(m.ik_pub == c.ik_pub for m in s.members.values()):
        raise Fatal("already_member")
    if s.device(c.device_id) is not None:
        raise Fatal("device_active")
    if b["invite_id"] in s.used_invites:
        raise Fatal("invite_reused")
    signed = s.circle_id + b["invite_id"] + c.raw + bu.raw + b["terms_commit"]
    if not verify(c.ik_pub, "join-consent", signed, b["consent"]):
        raise Fatal("bad_consent")
    m = Member(c.account_id, c.ik_pub, admin=b["admin"])
    m.devices[c.device_id] = _new_device(c, bu, author_acc)
    s.used_invites.add(b["invite_id"])
    if secrets is not None:
        ok = False
        pt = open_details(_secret(secrets, s.epoch), e.header, b["details"])
        if pt is not None:
            try:
                salt, t, terms = dec_member_details(pt)
                g, rules = t["guardians"], t["rules"]
                if terms_commit(salt, terms) != b["terms_commit"]:
                    ok = False                    # not the terms the new member signed (9)
                elif t["role"] == ADULT and t["teen_until"] == 0 and not g and rules_ok(rules):
                    ok = True
                elif (t["role"] == TEEN and t["teen_until"] > e.created_at and 1 <= len(g) <= MAX_GUARDIANS
                      and rules_ok(rules) and all(x in s.members and s.members[x].role == ADULT for x in g)):
                    m.role, m.teen_until, m.guardians, m.rules = TEEN, t["teen_until"], list(g), rules
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
    fresh = s.members[author_acc].admin and author_acc != target
    _epoch_body(b, [d for d in s.receiving_devices() if d.account_id != target], fresh)
    del s.members[target]
    _advance(s, b, secrets, fresh)


def _own_cert(s, c, author_acc):
    if not cert_wellformed(c):
        raise Fatal("bad_cert")
    if c.account_id != author_acc or c.ik_pub != s.members[author_acc].ik_pub:
        raise Fatal("wrong_account")


def _add_device(s, e, b, author_acc, secrets):
    c, bu = b["cert"], b["bundle"]
    _own_cert(s, c, author_acc)
    if (c.kind not in RECEIVING_KINDS or (c.kind == WEB and not s.options & OPT_WEB)
            or (c.kind == HOME_ASSISTANT and not s.options & OPT_HOME_ASSISTANT)):
        raise Fatal("kind_not_allowed")
    if len(s.members[author_acc].devices) >= MAX_DEVICES:
        raise Fatal("too_many_devices")
    if not bundle_ok(bu, c.dsk_pub, c.account_id) or not bundle_current(bu, e.created_at):
        raise Fatal("bad_bundle")
    if s.device(c.device_id) is not None:
        raise Fatal("device_active")
    s.members[author_acc].devices[c.device_id] = _new_device(c, bu, author_acc)


def _add_recovery(s, e, b, author_acc, secrets):
    c = b["cert"]
    _own_cert(s, c, author_acc)
    if c.kind != RECOVERY:
        raise Fatal("kind_not_allowed")
    devices = s.members[author_acc].devices
    if any(d.kind == RECOVERY for d in devices.values()) or len(devices) >= MAX_DEVICES:
        raise Fatal("too_many_devices")
    if s.device(c.device_id) is not None:
        raise Fatal("device_active")
    devices[c.device_id] = _new_device(c, None, author_acc)


def _remove_device(s, e, b, author_acc, secrets):
    target = s.device(b["target"])
    if target is None:
        raise Fatal("unknown_device")
    if not (target.account_id == author_acc or s.members[author_acc].admin):
        raise Fatal("not_admin")
    if len(s.members[target.account_id].devices) == 1:
        raise Fatal("last_device")
    if target.kind == RECOVERY:
        _no_epoch(b)                              # it never held an epoch secret, so nothing else changes
        del s.members[target.account_id].devices[target.device_id]
        return
    fresh = s.members[author_acc].admin and e.author != target.device_id
    _epoch_body(b, [d for d in s.receiving_devices() if d.device_id != target.device_id], fresh)
    del s.members[target.account_id].devices[target.device_id]
    _advance(s, b, secrets, fresh)


def _update_key(s, e, b, author_acc, secrets):
    dev = s.device(e.author)
    bu = b["bundle"]
    if (not bundle_ok(bu, dev.dsk_pub, dev.account_id) or not bundle_current(bu, e.created_at)
            or bu.key_id == dev.bundle.key_id):
        raise Fatal("bad_bundle")
    dev.bundle = bu


def _rekey(s, e, b, author_acc, secrets):
    if not s.members[author_acc].admin:
        raise Fatal("not_admin")
    _check_wraps(b, s.receiving_devices())
    _new_epoch(s, b, secrets)
    s.rekey_pending = False


def _set_admin(s, e, b, author_acc, secrets):
    if not s.members[author_acc].admin:
        raise Fatal("not_admin")
    target = b["target"]
    if target not in s.members:
        raise Fatal("not_member")
    if not b["admin"] and s.members[target].admin and len(s.admins()) == 1:
        raise Fatal("last_admin")
    s.members[target].admin = b["admin"]


def _set_options(s, e, b, author_acc, secrets):
    if not s.members[author_acc].admin:
        raise Fatal("not_admin")
    if b["options"] & ~OPTIONS_DEFINED:
        raise Fatal("bad_options")
    s.options = b["options"]


def _rotate_identity(s, e, b, author_acc, secrets):
    old_pub, new_pub, _, _ = split_link(b["link"])
    m = s.members[author_acc]
    if (old_pub != m.ik_pub or ed25519_key_invalid(new_pub) or new_pub == old_pub
            or any(o.ik_pub == new_pub for o in s.members.values())
            or not link_ok(author_acc, b["link"])):
        raise Fatal("bad_rotation")
    m.ik_pub = new_pub


def _policy(s, e, b, author_acc, secrets):
    if s.rekey_pending:
        raise Fatal("rekey_pending")
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
        if not 1 <= len(g) <= MAX_GUARDIANS or any(x not in s.members or s.members[x].role != ADULT for x in g):
            raise Rejected("bad_guardians")
        tm.guardians = list(g)
    elif st == GRANT_PAUSE:
        if (p["kind"] not in (1, 2) or not p["start"] < p["end"] <= p["start"] + DAY_MS
                or p["pause_id"] in tm.pauses):
            raise Rejected("bad_pause")
        if len(tm.pauses) >= MAX_PAUSES:         # keep 16: drop the one that ends earliest
            del tm.pauses[min(tm.pauses, key=lambda pid: (tm.pauses[pid][2], pid))]
        tm.pauses[p["pause_id"]] = (p["kind"], p["start"], p["end"])
    elif st == REVOKE_PAUSE:
        if p["pause_id"] not in tm.pauses:
            raise Rejected("unknown_pause")
        del tm.pauses[p["pause_id"]]


def _end_teen(m: Member):
    m.role, m.teen_until, m.guardians, m.rules, m.pauses = ADULT, 0, [], None, {}


def _repair_guardians(s: State):
    """Section 6.6: every teen keeps at least one adult guardian. Every teen is judged
    against the same snapshot, so one teen never becomes another's guardian here."""
    adults = sorted(a for a, m in s.members.items() if m.role == ADULT)
    admins = [a for a in adults if s.members[a].admin]
    ending = []
    for m in s.members.values():
        if m.role != TEEN:
            continue
        g = [x for x in m.guardians if x in adults] or admins[:MAX_GUARDIANS] or adults[:MAX_GUARDIANS]
        if g:
            m.guardians = g
        else:
            ending.append(m)
    for m in ending:
        _end_teen(m)


_HANDLERS = {GENESIS: _genesis, ADD_MEMBER: _add_member, REMOVE_MEMBER: _remove_member,
             ADD_DEVICE: _add_device, REMOVE_DEVICE: _remove_device, UPDATE_KEY: _update_key,
             POLICY: _policy, REKEY: _rekey, SET_ADMIN: _set_admin, ADD_RECOVERY: _add_recovery,
             SET_OPTIONS: _set_options, ROTATE_IDENTITY: _rotate_identity}


def replay(entries, secrets=None, upto=None):
    """Apply a list of raw entries from an empty state; returns (state, results)."""
    s, results = State(), []
    for i, raw in enumerate(entries):
        if upto is not None and i > upto:
            break
        s, res, why = apply(s, raw, secrets)
        results.append((res, why))
    return s, results


# --- state hash (section 6.9) -----------------------------------------------------------------

def state_bytes(s: State) -> bytes:
    out = (s.circle_id + u64(s.seq) + s.head + u32(s.epoch) + u8(s.rekey_pending) + u32(s.options)
           + vec16(s.name.encode("utf-8")) + u16(len(s.members)))
    for acc in sorted(s.members):
        m = s.members[acc]
        out += (acc + m.ik_pub + u8(m.admin) + u8(m.role) + u64(m.teen_until) + vec16(b"".join(m.guardians))
                + vec16(enc_rules(m.rules) if m.role == TEEN else b"") + u16(len(m.pauses)))
        for pid, (kind, start, end) in sorted(m.pauses.items()):
            out += pid + u8(kind) + u64(start) + u64(end)
        out += u16(len(m.devices))
        for dv in sorted(m.devices.values(), key=lambda d: d.device_id):
            out += dv.device_id + u8(dv.kind) + (dv.bundle.key_id if dv.bundle else bytes(8))
    return out


def state_hash(s: State):
    """8 bytes, or None while this client's private state is frozen."""
    return None if s.private_unknown_from is not None else H("state-hash", state_bytes(s))[:8]


# --- canonical JSON view of the state (used by the test vectors) ------------------------------

def rules_json(r):
    return None if r is None else {**{k: r[k] for k in DEFAULT_RULES if k != "schedule"},
                                   "schedule": [dict(w) for w in r["schedule"]]}


def state_json(s: State, private: bool = True) -> dict:
    members = []
    for acc in sorted(s.members):
        m = s.members[acc]
        d = dict(account_id=acc.hex(), ik_pub=m.ik_pub.hex(), admin=m.admin,
                 devices=[dict(device_id=dv.device_id.hex(), kind=dv.kind,
                               key_id=dv.bundle.key_id.hex() if dv.bundle else None)
                          for dv in sorted(m.devices.values(), key=lambda x: x.device_id)])
        if private:
            d.update(role="teen" if m.role == TEEN else "adult", teen_until=m.teen_until,
                     guardians=[g.hex() for g in m.guardians], rules=rules_json(m.rules),
                     pauses=[dict(id=pid.hex(), kind=k, start=a, end=z)
                             for pid, (k, a, z) in sorted(m.pauses.items())])
        members.append(d)
    out = dict(circle_id=s.circle_id.hex() if s.circle_id else None, seq=s.seq, head=s.head.hex(),
               epoch=s.epoch, rekey_pending=s.rekey_pending, options=s.options,
               used_invites=sorted(i.hex() for i in s.used_invites), members=members)
    if private:
        out["name"] = s.name
        out["flags"] = [dict(seq=q, reason=r) for q, r in s.flags]
        out["private_unknown_from"] = s.private_unknown_from
        h = state_hash(s) if s.circle_id else None
        out["state_hash"] = h.hex() if h else None
    return out
