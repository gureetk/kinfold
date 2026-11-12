#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Generate the protocol test vectors (spec/vectors/kinfold-v0.json).

Deterministic: every key, nonce and secret comes from rnd(tag), so running this
twice gives identical output. Each expected outcome is asserted here, so the
vectors record intended behaviour rather than whatever the code happened to do.

Usage: gen_vectors.py OUT.json RFC9180_TEST_VECTORS.json
"""
import copy
import hashlib
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from kinfold_ref import envelope as ev  # noqa: E402
from kinfold_ref import identity as idn  # noqa: E402
from kinfold_ref import log as lg  # noqa: E402
from kinfold_ref import rendezvous as rv  # noqa: E402
from kinfold_ref.crypto import (H, LABEL_PREFIX, aead_seal, ed25519_public, hpke_key_schedule,  # noqa: E402
                                hpke_open, hpke_setup_sender, kdf, sign, x25519_public)
from kinfold_ref.encoding import b64u, u8, u16, u64, vec16, vec32  # noqa: E402


def rnd(tag: str, n: int = 32) -> bytes:
    """Deterministic test bytes: SHA-256("kinfold-test-vector/" || tag), extended with "/1", "/2"... past 32."""
    out, i = b"", 0
    while len(out) < n:
        out += hashlib.sha256(b"kinfold-test-vector/" + tag.encode() + (f"/{i}".encode() if i else b"")).digest()
        i += 1
    return out[:n]


T0 = 1_793_635_200_000          # 2026-11-02T16:00:00Z
MIN, HOUR, DAY = 60_000, 3_600_000, 86_400_000
TEEN_UNTIL = 1_939_248_000_000  # 2031-06-15T00:00:00Z
SERVER_URL = "https://family.example"
SERVER_SEED = rnd("server/key")
SERVER_KEY = ed25519_public(SERVER_SEED)


class Device:
    def __init__(self, person, name, kind):
        self.person, self.name, self.kind = person, name, kind
        self.label = f"{person.name}/{name}"
        self.dsk = rnd(f"{self.label}/dsk")
        self.dsk_pub = ed25519_public(self.dsk)
        self.id = idn.device_id(self.dsk_pub)
        self.cert = idn.make_cert(person.ik, self.dsk_pub, kind, T0 - DAY)
        self.deks, self.bundles = [], []
        self.new_key(T0 - DAY)

    def new_key(self, not_before):
        sk = rnd(f"{self.label}/dek/{len(self.deks)}")
        self.deks.append((sk, x25519_public(sk)))
        b = idn.make_bundle(self.dsk, self.person.acc, self.deks[-1][1], not_before, not_before + 14 * DAY)
        self.bundles.append(b)
        return b

    @property
    def bundle(self):
        return self.bundles[-1]

    @property
    def dek_pub(self):
        return self.deks[-1][1]

    def keys(self, index=-1) -> dict:
        sk, pub = self.deks[index]
        return {idn.key_id(pub).hex(): sk.hex()}

    def json(self):
        return dict(label=self.label, kind=self.kind, dsk_seed=self.dsk.hex(), dsk_pub=self.dsk_pub.hex(),
                    device_id=self.id.hex(), cert=self.cert.hex(),
                    deks=[dict(sk=sk.hex(), pub=pub.hex(), key_id=idn.key_id(pub).hex()) for sk, pub in self.deks],
                    bundles=[b.hex() for b in self.bundles])


class Person:
    def __init__(self, name, devices):
        self.name = name
        self.ik = rnd(f"{name}/ik")
        self.ik_pub = ed25519_public(self.ik)
        self.acc = idn.account_id(self.ik_pub)
        self.dev = {}
        for n, k in devices:
            self.dev[n] = Device(self, n, k)

    def json(self):
        return dict(ik_seed=self.ik.hex(), ik_pub=self.ik_pub.hex(), account_id=self.acc.hex(),
                    devices={n: d.json() for n, d in self.dev.items()})


J = Person("jordan", [("phone", 1), ("tablet", 2), ("web", 3)])
A = Person("alex", [("phone", 1), ("tablet", 2)])
M = Person("maya", [("phone", 1)])
S = Person("sam", [("phone", 1)])
jp, jt, jw, ap, mp, sp = J.dev["phone"], J.dev["tablet"], J.dev["web"], A.dev["phone"], M.dev["phone"], S.dev["phone"]
at = A.dev["tablet"]


class LogBuilder:
    def __init__(self):
        self.state, self.pstate = lg.State(), lg.State()
        self.secrets = {0: rnd("circle/epoch/0")}
        self.records, self.raws = [], []
        self.clock = T0 - 10 * MIN
        self.withheld = set()

    def fork(self):
        b = LogBuilder()
        b.state, b.pstate, b.secrets = copy.deepcopy(self.state), copy.deepcopy(self.pstate), dict(self.secrets)
        b.clock = self.clock
        b.withheld = set(self.withheld)
        return b

    def head(self, t, author, created_at=None, **over):
        s = self.state
        self.clock = created_at if created_at is not None else self.clock + 10 * MIN
        created_at = self.clock
        f = dict(t=t, circle_id=s.circle_id or lg.ZERO16, seq=s.seq + 1, prev_hash=s.head,
                 created_at=created_at, author=author.id, epoch=s.epoch, version=0)
        f.update(over)
        hdr = lg.header(f["t"], f["circle_id"], f["seq"], f["prev_hash"], f["created_at"], f["author"], f["epoch"])
        if f["version"]:
            hdr = u8(f["version"]) + hdr[1:]
        return hdr, f

    def details(self, hdr, f, pt, secret=None):
        sec = secret or self.secrets[f["epoch"]]
        return vec32(lg.seal_details(sec, hdr, pt, rnd(f"log/{f['seq']}/{f['t']}/details-nonce", 12)))

    def wraps(self, f, devices, secret, new_epoch, tag=""):
        info = lambda rid, kid: lg.epoch_wrap_info(f["circle_id"], f["seq"], f["prev_hash"], new_epoch, rid, kid)
        ikm = lambda rid: rnd(f"log/{f['seq']}{tag}/wrap/{rid.hex()}")
        recips = [(d.id, d.dek_pub) for d in devices]
        return idn.make_wraps(recips, info, secret, ikm), {d.id.hex(): ikm(d.id).hex() for d in devices}

    def commit(self, desc, author, raw, expect, reason=None, details_pt=None, extra=None, public=None):
        try:
            new, res, why = lg.apply(self.state, raw, {k: v for k, v in self.secrets.items() if k not in self.withheld})
        except lg.Fatal as e:
            new, res, why = None, "fatal", e.reason
        try:
            pnew, pres, pwhy = lg.apply(self.pstate, raw, None)
        except lg.Fatal as e:
            pnew, pres, pwhy = None, "fatal", e.reason
        assert (res, why) == (expect, reason), (desc, res, why)
        assert (pres, pwhy) == (("accepted", None) if expect != "fatal" else ("fatal", reason)), (desc, pres, pwhy)
        rec = dict(seq=int.from_bytes(raw[20:28], "big"), author=author.label,
                   description=desc, raw=raw.hex(), hash=lg.entry_hash(raw).hex(),
                   result=res, reason=why, public_result=pres, public_reason=pwhy)
        if details_pt is not None:
            rec["details_plaintext"] = details_pt.hex()
        if extra:
            rec.update(extra)
        if new is not None:
            rec["state_after"] = lg.state_json(new)
            self.state, self.pstate = new, pnew
            self.raws.append(raw)
        self.records.append(rec)
        return rec


def policy(b, author, desc, pt, expect="accepted", reason=None, created_at=None, secret=None, **over):
    hdr, f = b.head(lg.POLICY, author, created_at, **over)
    raw = lg.build_entry(author.dsk, hdr, b.details(hdr, f, pt, secret))
    return b.commit(desc, author, raw, expect, reason, details_pt=pt)


def add_member(b, author, new_dev, invite_secret, admin, details_pt, desc, expect="accepted", reason=None,
               consent_circle=None, created_at=None, details_secret=None):
    hdr, f = b.head(lg.ADD_MEMBER, author, created_at)
    iid = rv.invite_id(invite_secret)
    consent = rv.consent_sig(new_dev.person.ik, consent_circle or b.state.circle_id, iid, new_dev.cert, new_dev.bundle)
    body = new_dev.cert + new_dev.bundle + iid + consent + u8(admin) + b.details(hdr, f, details_pt, details_secret)
    raw = lg.build_entry(author.dsk, hdr, body)
    return b.commit(desc, author, raw, expect, reason, details_pt=details_pt,
                    extra=dict(invite_secret=invite_secret.hex(), invite_id=iid.hex()))


def epoch_entry(b, t, author, desc, target, devices, expect="accepted", reason=None, tag="", **over):
    new_epoch = b.state.epoch + 1
    secret = rnd(f"circle/epoch/{new_epoch}{tag}")
    hdr, f = b.head(t, author, **over)
    wraps, ikms = b.wraps(f, devices, secret, new_epoch, tag)
    body = (target or b"") + lg.epoch_commit(new_epoch, secret) + vec32(wraps)
    raw = lg.build_entry(author.dsk, hdr, body)
    b.secrets[new_epoch] = secret
    return b.commit(desc, author, raw, expect, reason,
                    extra=dict(new_epoch=new_epoch, new_epoch_secret=secret.hex(), wrap_ikm=ikms))


def pending_removal(b, t, author, desc, target, expect="accepted", reason=None):
    """A removal not authored by a remaining admin carries no new secret and sets rekey_pending (6.4)."""
    hdr, f = b.head(t, author)
    raw = lg.build_entry(author.dsk, hdr, target + lg.ZERO32 + vec32(b""))
    return b.commit(desc, author, raw, expect, reason)


# ======================= the main log ==========================================
B = LogBuilder()
RULES = dict(pause_mode=2, approx_mode=1, speed_alert_kmh=110, phone_use_alerts=1, history_days=14,
             silence_alert_min=60, schedule=[dict(kind=1, days=0b0011111, start_min=930, end_min=1020)])
PAUSE1 = rnd("pause/1", 8)
INVITE_ALEX, INVITE_MAYA = rnd("invite/alex", 16), rnd("invite/maya", 16)

hdr, f = B.head(lg.GENESIS, jp, T0)
pt = lg.enc_genesis_details("Family")
raw = lg.build_entry(jp.dsk, hdr, jp.cert + jp.bundle + lg.epoch_commit(0, B.secrets[0]) + B.details(hdr, f, pt))
B.commit("Jordan creates the circle \"Family\" (epoch 0)", jp, raw, "accepted", details_pt=pt)
CID = B.state.circle_id

add_member(B, jp, ap, INVITE_ALEX, 1, lg.enc_member_details(lg.ADULT, 0, [], lg.DEFAULT_RULES),
           "Jordan adds Alex as an adult admin")
add_member(B, ap, mp, INVITE_MAYA, 0,
           lg.enc_member_details(lg.TEEN, TEEN_UNTIL, sorted([J.acc, A.acc]), lg.DEFAULT_RULES),
           "Alex adds Maya as a teen; guardians Jordan and Alex")
policy(B, jp, "Jordan sets Maya's rules", lg.enc_policy(lg.SET_RULES, M.acc, rules=RULES))
policy(B, ap, "Alex grants Maya a 2-hour pause",
       lg.enc_policy(lg.GRANT_PAUSE, M.acc, pause_id=PAUSE1, kind=1, start=T0 + 2 * HOUR, end=T0 + 4 * HOUR))
hdr, f = B.head(lg.ADD_DEVICE, jp)
B.commit("Jordan adds a tablet", jp, lg.build_entry(jp.dsk, hdr, jt.cert + jt.bundle), "accepted")
mp.new_key(T0 + DAY)
hdr, f = B.head(lg.UPDATE_KEY, mp, T0 + DAY)
B.commit("Maya's phone rotates its encryption key", mp, lg.build_entry(mp.dsk, hdr, mp.bundle), "accepted")
epoch_entry(B, lg.REMOVE_DEVICE, jp, "Jordan removes the tablet (epoch 1)", jt.id, [jp, ap, mp])
hdr, f = B.head(lg.SET_ADMIN, jp)
B.commit("Jordan makes Alex a non-admin", jp, lg.build_entry(jp.dsk, hdr, A.acc + u8(0)), "accepted")
policy(B, jp, "Jordan renames the circle", lg.enc_policy(lg.SET_CIRCLE_NAME, name="Rivera family"))
epoch_entry(B, lg.REKEY, jp, "Jordan's phone starts a new epoch (epoch 2)", None, [jp, ap, mp])
policy(B, jp, "Jordan revokes Maya's pause", lg.enc_policy(lg.REVOKE_PAUSE, M.acc, pause_id=PAUSE1))
policy(B, mp, "Maya tries to grant herself a pause: rejected, stays in the chain as a no-op",
       lg.enc_policy(lg.GRANT_PAUSE, M.acc, pause_id=rnd("pause/self", 8), kind=1, start=T0 + 3 * HOUR,
                     end=T0 + 5 * HOUR), expect="rejected", reason="not_guardian")
policy(B, ap, "Alex hands guardianship of Maya to Jordan alone",
       lg.enc_policy(lg.SET_GUARDIANS, M.acc, guardians=[J.acc]))
FINAL = B.state.seq
assert FINAL == 13 and lg.state_json(B.state)["members"][0]

# ======================= cases on top of the main log =============================
cases = []


def case(name, desc, fn, empty=False):
    b = LogBuilder() if empty else B.fork()
    fn(b)
    rec = dict(name=name, description=desc, base_seq=-1 if empty else FINAL, entries=b.records)
    if b.withheld:
        rec["withheld_epochs"] = sorted(b.withheld)
    last = b.records[-1]
    if "state_after" in last:
        rec["state_after"] = last["state_after"]
    added = {str(k): v.hex() for k, v in b.secrets.items() if k not in B.secrets and k <= b.state.epoch}
    if added:
        rec["new_epoch_secrets"] = added
    cases.append(rec)


def fatal_policy(b, reason, desc, **over):
    hdr, f = b.head(lg.POLICY, jp, **over)
    pt = lg.enc_policy(lg.SET_CIRCLE_NAME, name="Never applied")
    raw = lg.build_entry(jp.dsk, hdr, b.details(hdr, f, pt, b.secrets[b.state.epoch]))
    return hdr, f, raw


def c_prev(b):
    _, _, raw = fatal_policy(b, "bad_prev_hash", "", prev_hash=lg.ZERO32)
    b.commit("prev_hash does not match the head", jp, raw, "fatal", "bad_prev_hash")


def c_seq(b):
    _, _, raw = fatal_policy(b, "bad_seq", "", seq=FINAL + 2)
    b.commit("seq skips one", jp, raw, "fatal", "bad_seq")


def c_sig(b):
    _, _, raw = fatal_policy(b, "", "")
    b.commit("last signature byte flipped", jp, raw[:-1] + bytes([raw[-1] ^ 1]), "fatal", "bad_signature")


def c_epoch(b):
    _, _, raw = fatal_policy(b, "", "", epoch=1)
    b.commit("epoch is behind the circle's", jp, raw, "fatal", "bad_epoch")


def c_cid(b):
    _, _, raw = fatal_policy(b, "", "", circle_id=rnd("other-circle", 16))
    b.commit("circle_id of another circle", jp, raw, "fatal", "bad_circle_id")


def c_version(b):
    _, _, raw = fatal_policy(b, "", "", version=1)
    b.commit("version 1", jp, raw, "fatal", "bad_version")


def c_trunc(b):
    _, _, raw = fatal_policy(b, "", "")
    b.commit("entry cut short by 10 bytes", jp, raw[:-10], "fatal", "malformed")


def c_unknown_type(b):
    hdr, f = b.head(0x0A, jp)
    b.commit("entry type 0x0A", jp, lg.build_entry(jp.dsk, hdr, b""), "fatal", "unknown_entry_type")


def c_genesis(b):
    hdr, f = b.head(lg.GENESIS, sp)
    pt = lg.enc_genesis_details("Elsewhere")
    body = sp.cert + sp.bundle + lg.epoch_commit(0, rnd("x")) + b.details(hdr, f, pt, rnd("x"))
    b.commit("a second GENESIS", sp, lg.build_entry(sp.dsk, hdr, body), "fatal", "unexpected_genesis")


def c_removed_author(b):
    hdr, f = b.head(lg.SET_ADMIN, jt)
    b.commit("signed by the removed tablet", jt, lg.build_entry(jt.dsk, hdr, J.acc + u8(1)), "fatal",
             "author_not_active")


def c_not_admin_add(b):
    add_member(b, ap, sp, rnd("invite/sam", 16), 0, lg.enc_member_details(lg.ADULT, 0, [], lg.DEFAULT_RULES),
               "Alex (no longer an admin) adds Sam", "fatal", "not_admin")


def c_bad_consent(b):
    add_member(b, jp, sp, rnd("invite/sam", 16), 0, lg.enc_member_details(lg.ADULT, 0, [], lg.DEFAULT_RULES),
               "Sam's consent was signed for a different circle", "fatal", "bad_consent",
               consent_circle=rnd("other-circle", 16))


def c_already(b):
    add_member(b, jp, ap, rnd("invite/alex2", 16), 0, lg.enc_member_details(lg.ADULT, 0, [], lg.DEFAULT_RULES),
               "Alex added a second time", "fatal", "already_member")


def c_bad_cert(b):
    dsk = rnd("forged/dsk")
    tbs = u8(0) + u16(1) + A.acc + ed25519_public(dsk) + u8(1) + u64(T0)
    cert = tbs + J.ik_pub + sign(J.ik, "device-cert", tbs)       # claims Alex's account, signed by Jordan
    bundle = idn.make_bundle(dsk, A.acc, x25519_public(rnd("forged/dek")), T0, T0 + DAY)
    hdr, f = b.head(lg.ADD_DEVICE, ap)
    b.commit("certificate claims Alex's account but is signed by Jordan's identity key", ap,
             lg.build_entry(ap.dsk, hdr, cert + bundle), "fatal", "bad_cert")


def c_wrong_account(b):
    hdr, f = b.head(lg.ADD_DEVICE, ap)
    b.commit("Alex's phone posts a valid certificate for one of Jordan's devices", ap,
             lg.build_entry(ap.dsk, hdr, jw.cert + jw.bundle), "fatal", "wrong_account")


def c_bad_bundle(b):
    dek = x25519_public(rnd("alex/phone/dek/long"))
    bundle = idn.make_bundle(ap.dsk, A.acc, dek, T0, T0 + 40 * DAY)
    hdr, f = b.head(lg.UPDATE_KEY, ap)
    b.commit("key bundle valid for 40 days (limit 35)", ap, lg.build_entry(ap.dsk, hdr, bundle), "fatal",
             "bad_bundle")


def c_bad_wraps(b):
    epoch_entry(b, lg.REKEY, jp, "REKEY without a wrap for Maya's phone", None, [jp, ap], "fatal", "bad_wraps")


def c_last_admin(b):
    epoch_entry(b, lg.REMOVE_MEMBER, jp, "Jordan, the only admin, tries to leave while others remain",
                J.acc, [ap, mp], "fatal", "last_admin")


def c_last_device(b):
    epoch_entry(b, lg.REMOVE_DEVICE, ap, "Alex removes his only device", ap.id, [jp, mp], "fatal", "last_device")


def c_unknown_device(b):
    epoch_entry(b, lg.REMOVE_DEVICE, jp, "removing a device that is not in the circle", rnd("nobody", 16),
                [jp, ap, mp], "fatal", "unknown_device")


def c_not_member_admin(b):
    hdr, f = b.head(lg.SET_ADMIN, jp)
    b.commit("SET_ADMIN for someone outside the circle", jp, lg.build_entry(jp.dsk, hdr, S.acc + u8(1)), "fatal",
             "not_member")


# rejected POLICY entries: servers accept them, clients treat them as no-ops
def rj(subtype_pt, author, reason, desc, **kw):
    return lambda b: policy(b, author, desc, subtype_pt, expect="rejected", reason=reason, **kw)


def c_bad_details(b):
    policy(b, jp, "details encrypted under the wrong key", lg.enc_policy(lg.REVOKE_PAUSE, M.acc, pause_id=PAUSE1),
           expect="rejected", reason="bad_details", secret=rnd("wrong-key"))


# accepted edge cases
def c_teen_leaves(b):
    pending_removal(b, lg.REMOVE_MEMBER, mp, "Maya leaves on her own: valid, and everyone is alerted; she would know any "
                    "key she made, so the epoch stays and a rekey is pending", M.acc)


def c_add_bad_details(b):
    add_member(b, jp, sp, rnd("invite/sam", 16), 0,
               lg.enc_member_details(lg.TEEN, TEEN_UNTIL, [J.acc], lg.DEFAULT_RULES),
               "Sam is added with details that do not decrypt: added as an adult and flagged",
               reason="bad_details", details_secret=rnd("wrong-key"))
    assert b.state.flags[-1] == (FINAL + 1, "bad_details")


def c_end_teen_teen(b):
    policy(b, mp, "Maya ends her own teen settings once teen_until has passed",
           lg.enc_policy(lg.END_TEEN, M.acc), created_at=TEEN_UNTIL)


def c_end_teen_guardian(b):
    policy(b, jp, "Jordan, her guardian, ends Maya's teen settings early", lg.enc_policy(lg.END_TEEN, M.acc))


def c_repair(b):
    hdr, f = b.head(lg.SET_ADMIN, jp)
    b.commit("Jordan makes Alex an admin again", jp, lg.build_entry(jp.dsk, hdr, A.acc + u8(1)), "accepted")
    pending_removal(b, lg.REMOVE_MEMBER, jp, "Jordan leaves; Maya's only guardian is gone, so guardianship passes to "
                    "the remaining adult admin, Alex", J.acc)
    assert maya(b)["guardians"] == [A.acc.hex()]


def genesis_entry(b, author, cert, bundle, signer, details_secret=None, **over):
    hdr, f = b.head(lg.GENESIS, author, **over)
    pt = lg.enc_genesis_details("Family")
    body = cert + bundle + lg.epoch_commit(0, b.secrets[0]) + b.details(hdr, f, pt, details_secret or b.secrets[0])
    return lg.build_entry(signer, hdr, body), pt


def c_first_not_genesis(b):
    hdr, f = b.head(lg.SET_ADMIN, jp)
    b.commit("the first entry is not GENESIS", jp, lg.build_entry(jp.dsk, hdr, J.acc + u8(1)), "fatal", "bad_seq")


def c_genesis_author(b):
    raw, _ = genesis_entry(b, ap, jp.cert, jp.bundles[0], ap.dsk)
    b.commit("GENESIS whose author is not the founder's device", ap, raw, "fatal", "bad_author")


def c_genesis_prev(b):
    raw, _ = genesis_entry(b, jp, jp.cert, jp.bundles[0], jp.dsk, prev_hash=rnd("prev"))
    b.commit("GENESIS with a non-zero prev_hash", jp, raw, "fatal", "bad_prev_hash")


class Forged:
    dsk = rnd("forged/dsk")
    dsk_pub = ed25519_public(dsk)
    id = idn.device_id(dsk_pub)
    label = "forged/device"


def c_genesis_cert(b):
    tbs = u8(0) + u16(1) + A.acc + Forged.dsk_pub + u8(1) + u64(T0)
    cert = tbs + J.ik_pub + sign(J.ik, "device-cert", tbs)
    bundle = idn.make_bundle(Forged.dsk, A.acc, x25519_public(rnd("forged/dek")), T0, T0 + DAY)
    raw, _ = genesis_entry(b, Forged, cert, bundle, Forged.dsk)
    b.commit("GENESIS whose certificate claims Alex's account but is signed by Jordan's key", Forged, raw, "fatal",
             "bad_cert")


def c_genesis_details(b):
    raw, pt = genesis_entry(b, jp, jp.cert, jp.bundles[0], jp.dsk, details_secret=rnd("wrong-key"))
    b.commit("GENESIS whose details don't decrypt: accepted with no name, and flagged", jp, raw, "accepted",
             "bad_details", details_pt=pt)


def c_device_active_member(b):
    cert = idn.make_cert(S.ik, ap.dsk_pub, 1, T0)
    bundle = idn.make_bundle(ap.dsk, S.acc, x25519_public(rnd("sam/alex-device/dek")), T0, T0 + DAY)
    iid = rv.invite_id(rnd("invite/sam", 16))
    hdr, f = b.head(lg.ADD_MEMBER, jp)
    pt = lg.enc_member_details(lg.ADULT, 0, [], lg.DEFAULT_RULES)
    body = cert + bundle + iid + rv.consent_sig(S.ik, CID, iid, cert, bundle) + u8(0) + b.details(hdr, f, pt)
    b.commit("Sam joins with a certificate for Alex's phone, which is already in the circle", jp,
             lg.build_entry(jp.dsk, hdr, body), "fatal", "device_active")


def c_device_active_device(b):
    hdr, f = b.head(lg.ADD_DEVICE, jp)
    b.commit("Jordan adds his phone a second time", jp, lg.build_entry(jp.dsk, hdr, jp.cert + jp.bundles[0]),
             "fatal", "device_active")


def c_last_admin_flag(b):
    hdr, f = b.head(lg.SET_ADMIN, jp)
    b.commit("Jordan, the only admin, drops his own admin flag", jp, lg.build_entry(jp.dsk, hdr, J.acc + u8(0)),
             "fatal", "last_admin")


def c_same_key(b):
    bundle = idn.make_bundle(ap.dsk, A.acc, ap.dek_pub, T0 + DAY, T0 + 2 * DAY)
    hdr, f = b.head(lg.UPDATE_KEY, ap)
    b.commit("UPDATE_KEY that republishes the current key", ap, lg.build_entry(ap.dsk, hdr, bundle), "fatal",
             "bad_bundle")


def maya(b):
    st = lg.state_json(b.state)
    return next(m for m in st["members"] if m["account_id"] == M.acc.hex())


def c_repair_adults(b):
    hdr, f = b.head(lg.SET_ADMIN, jp)
    b.commit("Jordan makes Maya an admin", jp, lg.build_entry(jp.dsk, hdr, M.acc + u8(1)), "accepted")
    pending_removal(b, lg.REMOVE_MEMBER, jp, "Jordan leaves; no adult admin remains, so guardianship passes to every "
                    "adult member: Alex", J.acc)
    assert maya(b)["guardians"] == [A.acc.hex()]


def c_repair_none(b):
    hdr, f = b.head(lg.SET_ADMIN, jp)
    b.commit("Jordan makes Maya an admin", jp, lg.build_entry(jp.dsk, hdr, M.acc + u8(1)), "accepted")
    epoch_entry(b, lg.REMOVE_MEMBER, jp, "Jordan removes Alex (epoch 3)", A.acc, [jp, mp])
    pending_removal(b, lg.REMOVE_MEMBER, jp, "Jordan leaves; no adult remains, so Maya's teen settings end", J.acc)
    assert maya(b)["role"] == "adult" and maya(b)["rules"] is None


def c_removal_clears_pending(b):
    leave_maya(b)
    epoch_entry(b, lg.REMOVE_MEMBER, jp, "Jordan removes Alex (epoch 3), which also clears the pending rekey", A.acc,
                [jp])
    assert lg.state_json(b.state)["rekey_pending"] is False


def c_admin_device_removes_itself(b):
    hdr, f = b.head(lg.ADD_DEVICE, jp)
    b.commit("Jordan adds his tablet back", jp, lg.build_entry(jp.dsk, hdr, jt.cert + jt.bundle), "accepted")
    pending_removal(b, lg.REMOVE_DEVICE, jt, "The tablet removes itself: Jordan is an admin, but this device is "
                    "leaving, so a rekey is pending", jt.id)


def c_pending_with_commit(b):
    hdr, f = b.head(lg.REMOVE_MEMBER, mp)
    raw = lg.build_entry(mp.dsk, hdr, M.acc + rnd("leaver-commit") + vec32(b""))
    b.commit("Maya leaves with a commitment but no wraps", mp, raw, "fatal", "bad_wraps")


def c_rekey_not_admin(b):
    epoch_entry(b, lg.REKEY, mp, "Maya (not an admin) starts a new epoch", None, [jp, ap, mp], "fatal", "not_admin")


def c_self_leave_with_key(b):
    epoch_entry(b, lg.REMOVE_MEMBER, mp, "Maya leaves and hands out a new key she would know", M.acc, [jp, ap],
                "fatal", "bad_wraps")


def leave_maya(b):
    pending_removal(b, lg.REMOVE_MEMBER, mp, "Maya leaves; a rekey is now pending", M.acc)


def c_pending_policy(b):
    leave_maya(b)
    policy(b, jp, "Jordan renames the circle before anyone rekeys", lg.enc_policy(lg.SET_CIRCLE_NAME, name="Riveras"),
           expect="fatal", reason="rekey_pending")


def c_pending_add(b):
    leave_maya(b)
    add_member(b, jp, sp, rnd("invite/sam", 16), 0, lg.enc_member_details(lg.ADULT, 0, [], lg.DEFAULT_RULES),
               "Jordan adds Sam before anyone rekeys", "fatal", "rekey_pending")


def c_pending_cleared(b):
    leave_maya(b)
    epoch_entry(b, lg.REKEY, jp, "Jordan rekeys (epoch 3), which clears the pending flag", None, [jp, ap])
    policy(b, jp, "Jordan renames the circle in the new epoch", lg.enc_policy(lg.SET_CIRCLE_NAME, name="Riveras"))


def c_own_device(b):
    hdr, f = b.head(lg.ADD_DEVICE, ap)
    b.commit("Alex adds a tablet", ap, lg.build_entry(ap.dsk, hdr, at.cert + at.bundle), "accepted")
    pending_removal(b, lg.REMOVE_DEVICE, ap, "Alex (not an admin) removes his tablet: no new key; a rekey is pending",
                    at.id)


def c_last_member(b):
    epoch_entry(b, lg.REMOVE_MEMBER, jp, "Jordan removes Alex (epoch 3)", A.acc, [jp, mp])
    epoch_entry(b, lg.REMOVE_MEMBER, jp, "Jordan removes Maya (epoch 4)", M.acc, [jp])
    pending_removal(b, lg.REMOVE_MEMBER, jp, "Jordan, the last member, leaves: the circle is closed", J.acc)


def c_details_unsorted(b):
    policy(b, jp, "SET_GUARDIANS whose list is out of order",
           lg.enc_policy(lg.SET_GUARDIANS, M.acc, guardians=sorted([J.acc, A.acc], reverse=True)),
           expect="rejected", reason="bad_details")


def c_details_schedule(b):
    pt = lg.enc_policy(lg.SET_RULES, M.acc, rules={**RULES, "schedule": []})
    pt = pt[:-2] + vec16(bytes([1, 31, 3, 162, 4]))
    policy(b, jp, "SET_RULES whose schedule is 5 bytes long", pt, expect="rejected", reason="bad_details")


def c_add_unsorted(b):
    add_member(b, jp, sp, rnd("invite/sam", 16), 0,
               lg.enc_member_details(lg.TEEN, TEEN_UNTIL, sorted([J.acc, A.acc], reverse=True), lg.DEFAULT_RULES),
               "Sam is added as a teen with guardians out of order: added as an adult and flagged",
               reason="bad_details")


def c_repair_admin_only(b):
    hdr, f = b.head(lg.SET_ADMIN, jp)
    b.commit("Jordan makes Alex an admin again", jp, lg.build_entry(jp.dsk, hdr, A.acc + u8(1)), "accepted")
    add_member(b, jp, sp, rnd("invite/sam", 16), 0, lg.enc_member_details(lg.ADULT, 0, [], lg.DEFAULT_RULES),
               "Jordan adds Sam as an adult who isn't an admin")
    pending_removal(b, lg.REMOVE_MEMBER, jp, "Jordan leaves; guardianship passes to the adult admins (Alex), not to "
                    "every adult", J.acc)
    assert maya(b)["guardians"] == [A.acc.hex()]


def c_deferred(b):
    b.withheld = {3}
    epoch_entry(b, lg.REKEY, jp, "Jordan rekeys (epoch 3); this device never receives the new secret", None,
                [jp, ap, mp])
    hdr, f = b.head(lg.SET_ADMIN, jp)
    b.commit("Jordan makes Alex an admin in epoch 3: no details, so this device still applies it in full", jp,
             lg.build_entry(jp.dsk, hdr, A.acc + u8(1)), "accepted")
    policy(b, jp, "Jordan changes Maya's rules in epoch 3; this device can't read them, so its private state "
                  "freezes until the secret arrives", lg.enc_policy(lg.SET_RULES, M.acc, rules={**RULES, "history_days": 7}),
           expect="deferred")


EMPTY_CASES = [
    ("fatal_first_not_genesis", "a log that doesn't start with GENESIS", c_first_not_genesis),
    ("fatal_genesis_bad_author", "GENESIS author is not the founder device", c_genesis_author),
    ("fatal_genesis_bad_prev_hash", "GENESIS with a prev_hash", c_genesis_prev),
    ("fatal_genesis_bad_cert", "GENESIS with a forged certificate", c_genesis_cert),
    ("accepted_genesis_bad_details", "GENESIS with unreadable details", c_genesis_details),
]
CASES = [
    ("fatal_device_active_member", "new member's device is already active", c_device_active_member),
    ("fatal_device_active_device", "device added twice", c_device_active_device),
    ("fatal_last_admin_set_admin", "only admin drops the flag", c_last_admin_flag),
    ("fatal_not_admin_remove_member", "non-admin removes another member",
     lambda b: epoch_entry(b, lg.REMOVE_MEMBER, ap, "Alex (not an admin) removes Maya", M.acc, [jp, ap], "fatal",
                           "not_admin")),
    ("fatal_not_admin_remove_device", "non-admin removes another person's device",
     lambda b: epoch_entry(b, lg.REMOVE_DEVICE, ap, "Alex (not an admin) removes Jordan's phone", jp.id, [ap, mp],
                           "fatal", "not_admin")),
    ("fatal_update_key_unchanged", "key rotation to the same key", c_same_key),
    ("fatal_bad_prev_hash", "prev_hash does not match", c_prev),
    ("fatal_bad_seq", "seq skips", c_seq),
    ("fatal_bad_signature", "signature does not verify", c_sig),
    ("fatal_bad_epoch", "wrong epoch", c_epoch),
    ("fatal_bad_circle_id", "wrong circle", c_cid),
    ("fatal_bad_version", "unknown version", c_version),
    ("fatal_malformed", "truncated entry", c_trunc),
    ("fatal_unknown_entry_type", "unknown entry type", c_unknown_type),
    ("fatal_unexpected_genesis", "a second genesis", c_genesis),
    ("fatal_author_not_active", "author device was removed", c_removed_author),
    ("fatal_not_admin", "non-admin adds a member", c_not_admin_add),
    ("fatal_bad_consent", "join consent for another circle", c_bad_consent),
    ("fatal_already_member", "member added twice", c_already),
    ("fatal_bad_cert", "certificate signed by the wrong identity key", c_bad_cert),
    ("fatal_wrong_account", "device certificate for another account", c_wrong_account),
    ("fatal_bad_bundle", "key bundle validity window too long", c_bad_bundle),
    ("fatal_bad_wraps", "epoch wraps miss a device", c_bad_wraps),
    ("fatal_last_admin", "last admin leaves", c_last_admin),
    ("fatal_last_device", "account's last device removed", c_last_device),
    ("fatal_unknown_device", "removing an unknown device", c_unknown_device),
    ("fatal_not_member", "SET_ADMIN for a non-member", c_not_member_admin),
    ("rejected_not_guardian", "Alex is no longer Maya's guardian",
     rj(lg.enc_policy(lg.SET_RULES, M.acc, rules=lg.DEFAULT_RULES), ap, "not_guardian",
        "Alex (no longer a guardian) changes Maya's rules")),
    ("rejected_teen_self_rules", "a teen changes her own rules",
     rj(lg.enc_policy(lg.SET_RULES, M.acc, rules={**RULES, "pause_mode": 2, "schedule": []}), mp, "not_guardian",
        "Maya changes her own rules")),
    ("rejected_bad_pause", "pause longer than 24 hours",
     rj(lg.enc_policy(lg.GRANT_PAUSE, M.acc, pause_id=rnd("pause/long", 8), kind=1, start=T0, end=T0 + 25 * HOUR),
        jp, "bad_pause", "Jordan grants a 25-hour pause")),
    ("rejected_bad_guardians_empty", "empty guardian list",
     rj(lg.enc_policy(lg.SET_GUARDIANS, M.acc, guardians=[]), jp, "bad_guardians", "Jordan removes every guardian")),
    ("rejected_bad_guardians_teen", "a teen as guardian",
     rj(lg.enc_policy(lg.SET_GUARDIANS, M.acc, guardians=[M.acc]), jp, "bad_guardians",
        "Jordan makes Maya her own guardian")),
    ("rejected_unknown_policy", "unknown POLICY subtype",
     rj(u8(0x63) + M.acc, jp, "unknown_policy", "POLICY subtype 0x63")),
    ("rejected_teen_until_not_reached", "teen ends her settings early",
     rj(lg.enc_policy(lg.END_TEEN, M.acc), mp, "teen_until_not_reached", "Maya tries END_TEEN before teen_until")),
    ("rejected_bad_details", "details do not decrypt", c_bad_details),
    ("rejected_not_teen", "teen rules for an adult",
     rj(lg.enc_policy(lg.SET_RULES, A.acc, rules=RULES), jp, "not_teen", "Jordan sets teen rules for Alex")),
    ("rejected_not_admin_rename", "non-admin renames the circle",
     rj(lg.enc_policy(lg.SET_CIRCLE_NAME, name="Alex's circle"), ap, "not_admin", "Alex renames the circle")),
    ("rejected_unknown_pause", "revoking a pause that does not exist",
     rj(lg.enc_policy(lg.REVOKE_PAUSE, M.acc, pause_id=rnd("pause/none", 8)), jp, "unknown_pause",
        "Jordan revokes an unknown pause")),
    ("rejected_bad_rules", "history_days 0",
     rj(lg.enc_policy(lg.SET_RULES, M.acc, rules={**RULES, "history_days": 0}), jp, "bad_rules",
        "Jordan sets history to 0 days")),
    ("rejected_not_member", "teen rules for a non-member",
     rj(lg.enc_policy(lg.SET_RULES, S.acc, rules=RULES), jp, "not_member", "Jordan sets rules for Sam")),
    ("accepted_teen_leaves", "a teen may leave; the protocol makes it visible", c_teen_leaves),
    ("accepted_add_member_bad_details", "undecryptable member details", c_add_bad_details),
    ("accepted_end_teen_by_teen", "teen ends her settings at teen_until", c_end_teen_teen),
    ("accepted_end_teen_by_guardian", "guardian ends teen settings", c_end_teen_guardian),
    ("accepted_guardian_repair", "last guardian leaves; an adult admin takes over", c_repair),
    ("accepted_guardian_repair_adults", "last guardian leaves; no adult admin, so every adult", c_repair_adults),
    ("accepted_guardian_repair_no_adults", "no adult remains; teen settings end", c_repair_none),
    ("accepted_guardian_repair_admin_only", "repair prefers adult admins over other adults", c_repair_admin_only),
    ("fatal_rekey_not_admin", "only admins start epochs", c_rekey_not_admin),
    ("fatal_pending_removal_with_commit", "a removal that starts no epoch carries no commitment", c_pending_with_commit),
    ("accepted_removal_clears_pending", "a removal that starts an epoch clears the pending flag",
     c_removal_clears_pending),
    ("accepted_admin_device_removes_itself", "a device removing itself never creates the next key",
     c_admin_device_removes_itself),
    ("fatal_self_removal_with_key", "a leaving member must not create the next key", c_self_leave_with_key),
    ("fatal_rekey_pending_policy", "no encrypted entries while a rekey is pending", c_pending_policy),
    ("fatal_rekey_pending_add_member", "no new members while a rekey is pending", c_pending_add),
    ("accepted_rekey_clears_pending", "an admin's rekey clears the pending flag", c_pending_cleared),
    ("accepted_non_admin_removes_own_device", "a non-admin's removal leaves a rekey pending", c_own_device),
    ("accepted_last_member_leaves", "the circle closes", c_last_member),
    ("rejected_details_unsorted_ids", "an ID list out of order inside details", c_details_unsorted),
    ("rejected_details_bad_schedule", "a schedule that isn't a multiple of 6 bytes", c_details_schedule),
    ("accepted_add_member_unsorted_guardians", "member details that don't parse", c_add_unsorted),
    ("deferred_missing_secret", "a device without the epoch secret defers private rules", c_deferred),
]
for name, desc, fn in EMPTY_CASES:
    case(name, desc, fn, empty=True)
for name, desc, fn in CASES:
    case(name, desc, fn)

# ======================= envelopes ======================================================
HEAD13 = B.state.head
S13 = B.state
HEAD6 = bytes.fromhex(B.records[6]["hash"])


RECEIVER_NOW = T0 + 2 * DAY + 5 * MIN
SERVER_REASONS = {"malformed", "bad_version", "bad_kind", "wrong_circle", "unknown_log_head", "sender_not_active",
                  "bad_signature", "expired", "bad_time", "replay", "bad_wraps", "bad_ttl"}


def open_env(raw, st, me, keys, seen):
    return ev.open_envelope(raw, st, me, keys, seen, RECEIVER_NOW)


def env(tag, sender, kind, recipients, payload_obj, seq=1, head=HEAD13, cid=None, pad_override=None,
        payload_secret=None, wrap_hook=None, reorder=False, sent_at=T0 + 2 * DAY, ttl=7 * 86400):
    hdr = ev.env_header(kind, cid or CID, sender.id, seq, sent_at, ttl, head)
    secret = rnd(f"env/{tag}/secret")
    ikm = lambda rid: rnd(f"env/{tag}/wrap/{rid.hex()}")
    wraps = ev.seal_wraps(hdr, recipients, secret, ikm)
    if wrap_hook:
        wraps = wrap_hook(wraps)
    if reorder:
        wraps = wraps[104:] + wraps[:104]
    pb = payload_obj if isinstance(payload_obj, bytes) else ev.payload_bytes(payload_obj)
    padded = pad_override if pad_override is not None else ev.pad(pb)
    raw = ev.assemble(sender.dsk, hdr, wraps, ev.seal_payload(hdr, wraps, padded, payload_secret or secret))
    meta = dict(sender=sender.label, kind=kind, seq=seq, sent_at=sent_at, ttl_s=ttl,
                log_head=head.hex(), message_secret=secret.hex(),
                wrap_ikm={rid.hex(): ikm(rid).hex() for rid, _ in recipients},
                payload_bytes=pb.hex(), padded_length=len(padded), raw=raw.hex())
    return raw, meta


LOC = {"t": "loc", "ts": T0 + 2 * DAY - 4000, "lat": 436532000, "lon": -793832000, "acc": 12, "spd": 0,
       "bat": 81, "chg": False, "act": "still", "prec": "exact"}
alat, alon = ev.approx_e7(436612345, -794098765)
LOC_APPROX = {"t": "loc", "ts": T0 + 2 * DAY - 9000, "lat": alat, "lon": alon, "acc": 2000, "bat": 64,
              "prec": "approx"}
PAUSE_REQ = {"t": "pause_req", "id": b64u(rnd("pause/2", 8)), "kind": 1, "start": T0 + 2 * DAY + HOUR,
             "end": T0 + 2 * DAY + 3 * HOUR, "note": "Study group at the library"}

valid_envs = []
for tag, desc, sender, kind, recips, payload, sent in [
    ("e1", "Jordan's location to the circle", jp, ev.CIRCLE, [ap, mp], LOC, T0 + 2 * DAY),
    ("e2", "Maya asks her guardian for a pause (direct)", mp, ev.DIRECT, [jp], PAUSE_REQ, T0 + 2 * DAY),
    ("e3", "Maya shares an approximate location", mp, ev.CIRCLE, [jp, ap], LOC_APPROX, T0 + 2 * DAY),
    ("e4", "Jordan's location sent exactly 31 days before the receiver's clock: the oldest accepted", jp, ev.CIRCLE,
     [ap, mp], LOC, RECEIVER_NOW - 31 * DAY),
    ("e5", "Jordan's location dated exactly 1 day after the receiver's clock: the furthest ahead accepted", jp,
     ev.CIRCLE, [ap, mp], LOC, RECEIVER_NOW + DAY),
]:
    raw, meta = env(tag, sender, kind, [(d.id, d.dek_pub) for d in recips], payload, sent_at=sent)
    seen = set()
    rec = []
    for d in recips:
        got = open_env(raw, S13, d.id, {bytes.fromhex(k): bytes.fromhex(v) for k, v in d.keys().items()}, set())
        ev.server_check(raw, S13, RECEIVER_NOW, set())
        assert got == payload
        rec.append(dict(device=d.label, device_id=d.id.hex(), keys=d.keys(), payload=payload))
    valid_envs.append(dict(name=tag, description=desc, log_seq=FINAL, **meta, recipients=rec))

E1 = bytes.fromhex(valid_envs[0]["raw"])
E2 = bytes.fromhex(valid_envs[1]["raw"])
invalid_envs = []


def bad(name, desc, raw, receiver, reason, keys=None):
    k = keys or receiver.keys()
    try:
        open_env(raw, S13, receiver.id, {bytes.fromhex(a): bytes.fromhex(b) for a, b in k.items()}, set())
        got = "ok"
    except ev.EnvelopeError as e:
        got = e.reason
    assert got == reason, (name, got)
    try:
        ev.server_check(raw, S13, RECEIVER_NOW, set())
        sgot = None
    except ev.EnvelopeError as e:
        sgot = e.reason
    assert sgot == (reason if reason in SERVER_REASONS else None), (name, sgot)
    invalid_envs.append(dict(name=name, description=desc, log_seq=FINAL, raw=raw.hex(), receiver=receiver.label,
                             receiver_device_id=receiver.id.hex(), receiver_keys=k, error=reason))


both = [(ap.id, ap.dek_pub), (mp.id, mp.dek_pub)]
bad("malformed", "cut short", E1[:-3], ap, "malformed")
bad("bad_version", "version byte 1 (signature not reached)", b"\x01" + E1[1:], ap, "bad_version")
bad("bad_kind", "kind 3", env("k3", jp, 3, both, LOC)[0], ap, "bad_kind")
bad("wrong_circle", "another circle's ID", env("wc", jp, 1, both, LOC, cid=rnd("other-circle", 16))[0], ap,
    "wrong_circle")
bad("unknown_log_head", "log head not in the receiver's log", env("ul", jp, 1, both, LOC, head=rnd("nohead"))[0],
    ap, "unknown_log_head")
bad("sender_not_active", "from the removed tablet",
    env("na", jt, 1, [(jp.id, jp.dek_pub)] + both, LOC, head=HEAD6)[0], ap, "sender_not_active")
bad("expired", "sent 31 days and 1 ms before the receiver's clock",
    env("ex", jp, 1, both, LOC, sent_at=RECEIVER_NOW - 31 * DAY - 1)[0], ap, "expired")
bad("bad_time", "sent more than a day after the receiver's clock",
    env("ft", jp, 1, both, LOC, sent_at=RECEIVER_NOW + DAY + 1)[0], ap, "bad_time")
bad("bad_signature", "seq changed after signing", E1[:36] + bytes([E1[36] ^ 1]) + E1[37:], ap, "bad_signature")
bad("bad_wraps", "wraps not sorted by device ID", env("ro", jp, 1, both, LOC, reorder=True)[0], ap, "bad_wraps")
bad("not_a_recipient", "direct envelope for someone else", E2, ap, "not_a_recipient")
bad("unknown_key", "wrapped to Maya's retired key", env("uk", jp, 1, [(ap.id, ap.dek_pub), (mp.id, mp.deks[0][1])],
                                                       LOC)[0], mp, "unknown_key")


def garble_for(dev):
    def hook(w):
        out = bytearray(w)
        for i in range(0, len(w), 104):
            if w[i:i + 16] == dev.id:
                out[i + 56:i + 104] = rnd("garbage", 48)
        return bytes(out)
    return hook


bad("bad_wrap", "Alex's wrap holds garbage", env("bw", jp, 1, both, LOC, wrap_hook=garble_for(ap))[0], ap, "bad_wrap")
bad("bad_ciphertext", "payload sealed under a different message secret",
    env("bc", jp, 1, both, LOC, payload_secret=rnd("other-secret"))[0], ap, "bad_ciphertext")
bad("bad_padding", "no 0x80 marker", env("bp", jp, 1, both, LOC, pad_override=ev.payload_bytes(LOC) + bytes(
    256 - len(ev.payload_bytes(LOC))))[0], ap, "bad_padding")
bad("bad_payload", "payload is not a JSON object with \"t\"", env("bj", jp, 1, both, b"[1,2,3]")[0], ap,
    "bad_payload")
seen = set()
first = open_env(E1, S13, ap.id, {bytes.fromhex(a): bytes.fromhex(b) for a, b in ap.keys().items()}, seen)
try:
    open_env(E1, S13, ap.id, {bytes.fromhex(a): bytes.fromhex(b) for a, b in ap.keys().items()}, seen)
    raise AssertionError("replay accepted")
except ev.EnvelopeError as e:
    assert e.reason == "replay"
replay_case = dict(name="replay", description="the same envelope delivered twice", log_seq=FINAL,
                   receiver=ap.label, receiver_device_id=ap.id.hex(), receiver_keys=ap.keys(),
                   sequence=[E1.hex(), E1.hex()], results=["ok", "replay"])
server_rejects = []
for tag, desc, recips, ttl, reason in [
        ("tt", "ttl_s of 30 seconds (minimum 60)", both, 30, "bad_ttl"),
        ("tm", "ttl_s one second over 30 days", both, 2_592_001, "bad_ttl"),
        ("ir", "also wrapped to the removed tablet", both + [(jt.id, jt.dek_pub)], 7 * 86400, "bad_wraps")]:
    raw, _ = env(tag, jp, 1, recips, LOC, ttl=ttl)
    try:
        ev.server_check(raw, S13, RECEIVER_NOW, set())
        raise AssertionError(tag)
    except ev.EnvelopeError as e:
        assert e.reason == reason
    assert open_env(raw, S13, ap.id, {bytes.fromhex(a): bytes.fromhex(b) for a, b in ap.keys().items()}, set()) == LOC
    server_rejects.append(dict(name={"tt": "ttl_too_short", "tm": "ttl_too_long", "ir": "inactive_recipient"}[tag],
                               description=desc + "; recipients can still open it", log_seq=FINAL,
                               raw=raw.hex(), server_error=reason, receiver=ap.label,
                               receiver_device_id=ap.id.hex(), receiver_keys=ap.keys(), payload=LOC))

# ======================= small vectors ======================================================
padding = []
for n in (0, 1, 254, 255, 256, 511, 1000, 65535):
    padded = ev.pad(b"a" * n)
    padding.append(dict(payload_length=n, payload_byte="61", padded_length=len(padded),
                        padded_sha256=hashlib.sha256(padded).hexdigest()))
unpad_invalid = [dict(description="all zeros", padded=bytes(256).hex()),
                 dict(description="length 300 is not a bucket", padded=(b"x" + b"\x80" + bytes(298)).hex()),
                 dict(description="last non-zero byte is not 0x80", padded=(b"x\x81" + bytes(254)).hex())]
for u in unpad_invalid:
    assert ev.unpad(bytes.fromhex(u["padded"])) is None

approx = []
for lat, lon in [(436612345, -794098765), (436532000, -793832000), (-338688000, 1512093000), (0, 0), (-1, -1),
                 (199999, 200000), (900000000, 1800000000), (-900000000, -1800000000)]:
    a, o = ev.approx_e7(lat, lon)
    approx.append(dict(lat=lat, lon=lon, approx_lat=a, approx_lon=o))

safety = []
for x, y in [(J, A), (A, M), (M, J)]:
    safety.append(dict(a=x.name, b=y.name, ik_pub_a=x.ik_pub.hex(), ik_pub_b=y.ik_pub.hex(),
                       half_a=idn.safety_half(x.ik_pub), half_b=idn.safety_half(y.ik_pub),
                       code=idn.safety_code(x.ik_pub, y.ik_pub), qr=idn.safety_qr(x.ik_pub, y.ik_pub)))

# invite and join (Maya's invite, matching log entry 2)
invite = rv.make_invite(SERVER_URL, SERVER_KEY, CID, INVITE_MAYA, A.ik_pub, rv.ROLE_TEEN, T0 + 7 * DAY,
                        b"reg-token-from-the-server-admin")
app_link, web_link = rv.invite_links(SERVER_URL, invite)
iid_m = rv.invite_id(INVITE_MAYA)
consent_m = rv.consent_sig(M.ik, CID, iid_m, mp.cert, mp.bundles[0])
join_nonce = rnd("join/maya/nonce", 12)
join_msg = rv.make_join_request(INVITE_MAYA, mp.cert, mp.bundles[0], consent_m, "Maya", join_nonce)
opened = rv.open_join_request(rv.parse_invite(invite), join_msg)
assert opened["name"] == "Maya" and lg.parse_body(lg.ADD_MEMBER, lg.parse_entry(B.raws[2]).body_bytes)["consent"] \
    == consent_m
invite_vec = dict(invite=invite.hex(), app_link=app_link, web_link=web_link,
                  fields=dict(server_url=SERVER_URL, server_key=SERVER_KEY.hex(), circle_id=CID.hex(),
                              secret=INVITE_MAYA.hex(), inviter_ik_pub=A.ik_pub.hex(), role_hint=2,
                              expires_at=T0 + 7 * DAY, reg_token=b"reg-token-from-the-server-admin".hex()),
                  invite_id=iid_m.hex(), join_key=rv.join_key(INVITE_MAYA).hex(),
                  join_request=dict(cert=mp.cert.hex(), bundle=mp.bundles[0].hex(), consent=consent_m.hex(),
                                    name="Maya", nonce=join_nonce.hex(), message=join_msg.hex()),
                  log_entry_seq=2)

# device linking: Jordan's phone links the tablet (direction 1) ...
LINK_T = rnd("link/tablet", 16)
link_t = rv.make_link(rv.LINK_FROM_EXISTING, SERVER_URL, SERVER_KEY, LINK_T, T0 + 50 * MIN, J.acc, J.ik_pub)
req_pt = rv.link_request_plaintext(jt.dsk_pub, 2, jt.bundles[0], "Jordan's iPad")
req_nonce = rnd("link/tablet/request-nonce", 12)
req_msg = rv.make_link_request(LINK_T, req_pt, req_nonce)
req = rv.open_link_request(LINK_T, J.acc, req_msg)
resp_payload = ev.payload_bytes({"cert": b64u(jt.cert), "ik": b64u(J.ik), "confirm": b64u(rv.link_confirm(LINK_T)),
                                 "circles": [{"id": b64u(CID), "epochs": [b64u(B.secrets[0])]}]})
resp_ikm = rnd("link/tablet/response-ikm")
resp_msg = rv.make_link_response(LINK_T, jp.dsk, jp.cert, jt.deks[0][1], jt.id, resp_payload, resp_ikm)
assert rv.open_link_response(LINK_T, J.ik_pub, resp_msg, jt.deks[0][0], jt.id)["ik"] == b64u(J.ik)
# ... and a browser shows its own QR (direction 2); the phone answers with an offer
LINK_W = rnd("link/web", 16)
link_w = rv.make_link(rv.LINK_FROM_NEW, SERVER_URL, SERVER_KEY, LINK_W, T0 + 2 * DAY)
offer_nonce = rnd("link/web/offer-nonce", 12)
offer_msg = rv.make_link_offer(LINK_W, J.acc, J.ik_pub, offer_nonce)
assert rv.open_link_offer(LINK_W, offer_msg)["account_id"] == J.acc
web_req_pt = rv.link_request_plaintext(jw.dsk_pub, 3, jw.bundles[0], "Jordan's browser")
web_req_nonce = rnd("link/web/request-nonce", 12)
web_req = rv.make_link_request(LINK_W, web_req_pt, web_req_nonce)
web_code = rv.open_link_request(LINK_W, J.acc, web_req)["code"]
web_payload = ev.payload_bytes({"cert": b64u(jw.cert), "confirm": b64u(rv.link_confirm(LINK_W)),
                                "circles": [{"id": b64u(CID), "epochs": [b64u(B.secrets[e]) for e in sorted(B.secrets)]}]})
web_ikm = rnd("link/web/response-ikm")
web_resp = rv.make_link_response(LINK_W, jp.dsk, jp.cert, jw.deks[0][1], jw.id, web_payload, web_ikm)
assert "ik" not in rv.open_link_response(LINK_W, J.ik_pub, web_resp, jw.deks[0][0], jw.id)
link_vec = dict(
    from_existing=dict(link=link_t.hex(), app_link="kinfold://link/" + b64u(link_t), secret=LINK_T.hex(),
                       link_id=rv.link_id(LINK_T).hex(), link_key=rv.link_key(LINK_T).hex(),
                       confirm=rv.link_confirm(LINK_T).hex(), request_plaintext=req_pt.hex(),
                       request_nonce=req_nonce.hex(), request=req_msg.hex(), code=req["code"],
                       response_payload=resp_payload.decode(), response_ikm=resp_ikm.hex(),
                       response=resp_msg.hex(), new_device=jt.label, new_device_dek_sk=jt.deks[0][0].hex()),
    from_new=dict(link=link_w.hex(), app_link="kinfold://link/" + b64u(link_w), secret=LINK_W.hex(),
                  link_id=rv.link_id(LINK_W).hex(), offer_nonce=offer_nonce.hex(), offer=offer_msg.hex(),
                  account_id=J.acc.hex(), ik_pub=J.ik_pub.hex(), request_plaintext=web_req_pt.hex(),
                  request_nonce=web_req_nonce.hex(), request=web_req.hex(), code=web_code,
                  response_payload=web_payload.decode(), response_ikm=web_ikm.hex(), response=web_resp.hex(),
                  new_device=jw.label, new_device_dek_sk=jw.deks[0][0].hex()))

# share link
SHARE = rnd("share/1", 16)
share_payload = {"t": "loc", "ts": T0 + 3 * HOUR, "lat": 436532000, "lon": -793832000, "acc": 15, "prec": "exact",
                 "name": "Jordan"}
share_nonce = rnd("share/1/nonce/1", 12)
share_msg = rv.make_share_update(SHARE, 1, T0 + 5 * HOUR, ev.payload_bytes(share_payload), share_nonce)
assert rv.open_share_update(SHARE, share_msg)["payload"] == share_payload
share_vec = dict(server_url=SERVER_URL, secret=SHARE.hex(), link_id=rv.share_id(SHARE).hex(),
                 share_key=rv.share_key(SHARE).hex(), payload_bytes=ev.payload_bytes(share_payload).hex(),
                 url=rv.share_url(SERVER_URL, SHARE), update=dict(seq=1, expires_at=T0 + 5 * HOUR,
                                                                   nonce=share_nonce.hex(), payload=share_payload,
                                                                   message=share_msg.hex()))

# server identity and login
info = idn.make_server_info(SERVER_SEED, SERVER_URL, T0 - 30 * DAY, T0 + 365 * DAY)
assert idn.parse_server_info(info)["sig_ok"]
challenge = rnd("auth/challenge")
auth_vec = dict(server_seed=SERVER_SEED.hex(), server_key=SERVER_KEY.hex(), server_info=info.hex(),
                server_url=SERVER_URL, challenge=challenge.hex(), device=jp.label, device_id=jp.id.hex(),
                expires_at=T0 + 5 * MIN, challenge_sig=idn.challenge_sig(SERVER_SEED, challenge, jp.id,
                                                                         T0 + 5 * MIN).hex(),
                device_sig=idn.auth_sig(jp.dsk, SERVER_KEY, challenge, jp.id).hex())

# primitives
prims = dict(
    label_prefix=LABEL_PREFIX,
    H=[dict(label="kinfold/v0/test", data="616263", out=H("test", b"abc").hex())],
    kdf=[dict(label="kinfold/v0/test", ikm=bytes(range(32)).hex(), length=42, out=kdf(bytes(range(32)), "test",
                                                                                         42).hex())],
    sign=[dict(label="kinfold/v0/test", seed=J.ik.hex(), data="616263", sig=sign(J.ik, "test", b"abc").hex())],
    b64u=[dict(bytes="", text=""), dict(bytes="fb", text="-w"), dict(bytes="fbff", text="-_8"),
          dict(bytes="fbffbf", text="-_-_")])

# RFC 9180: check our HPKE against every encryption in the official case for this suite
rfc = json.load(open(sys.argv[2]))
case_ = next(c for c in rfc if c["mode"] == 0 and c["kem_id"] == 0x20 and c["kdf_id"] == 1 and c["aead_id"] == 2)
X = {k: bytes.fromhex(v) for k, v in case_.items() if isinstance(v, str)}
enc_, ss_, key_, nonce_ = hpke_setup_sender(X["pkRm"], X["info"], X["ikmE"])
assert (enc_, ss_, key_, nonce_) == (X["enc"], X["shared_secret"], X["key"], X["base_nonce"])
for i, e in enumerate(case_["encryptions"]):
    n = bytes(a ^ b for a, b in zip(nonce_, i.to_bytes(12, "big")))
    assert aead_seal(key_, n, bytes.fromhex(e["pt"]), bytes.fromhex(e["aad"])).hex() == e["ct"]
assert hpke_open(X["enc"], X["skRm"], X["info"], bytes.fromhex(case_["encryptions"][0]["aad"]),
                 bytes.fromhex(case_["encryptions"][0]["ct"])) == bytes.fromhex(case_["encryptions"][0]["pt"])
hpke_vec = {k: case_[k] for k in ("mode", "kem_id", "kdf_id", "aead_id", "info", "ikmE", "pkEm", "skEm", "ikmR",
                                  "pkRm", "skRm", "enc", "shared_secret", "key", "base_nonce")}
hpke_vec["encryptions"] = case_["encryptions"][:2]
hpke_vec["source"] = ("RFC 9180 test vectors (github.com/cfrg/draft-irtf-cfrg-hpke, test-vectors.json): mode 0, "
                      "KEM 0x0020, KDF 0x0001, AEAD 0x0002; first 2 of 257 encryptions")

out = dict(
    protocol="kinfold/v0", status="draft", license="CC0-1.0",
    generated_by="reference/python/gen_vectors.py",
    conventions=["Byte strings are lowercase hex. Links, URLs, names, digit codes and JSON text are plain strings; "
                 "decoded payloads are JSON objects.",
                 "Times are milliseconds since the Unix epoch, UTC.",
                 "Every secret and nonce here comes from SHA-256(\"kinfold-test-vector/\" || tag); "
                 "never reuse them outside tests."],
    primitives=prims, hpke_rfc9180=hpke_vec,
    identities={p.name: p.json() for p in (J, A, M, S)},
    log=dict(circle_id=CID.hex(), epoch_secrets={str(k): v.hex() for k, v in B.secrets.items()},
             entries=B.records, final_seq=FINAL, cases=cases),
    envelopes=dict(receiver_now=RECEIVER_NOW, valid=valid_envs, invalid=invalid_envs, replay=replay_case,
                   server_rejects=server_rejects),
    padding=dict(valid=padding, invalid=unpad_invalid),
    approx=approx, safety_codes=safety, invite=invite_vec, device_link=link_vec, share_link=share_vec,
    auth=auth_vec)
Path(sys.argv[1]).write_text(json.dumps(out, indent=1, ensure_ascii=False) + "\n")
print("wrote", sys.argv[1], "entries", len(B.records), "cases", len(cases), "envelopes",
      len(valid_envs), "+", len(invalid_envs))
