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
from kinfold_ref import push as ps  # noqa: E402
from kinfold_ref import rendezvous as rv  # noqa: E402
from kinfold_ref.crypto import (ED25519_L, H, LABEL_PREFIX, P25519, aead_seal, ed25519_key_invalid,  # noqa: E402
                                ed25519_public, hpke_key_schedule, hpke_open, hpke_setup_sender, kdf, sign,
                                verify_raw, x25519_key_invalid, x25519_public)
from kinfold_ref.encoding import b64u, pad_to, u8, u16, u32, u64, vec16, vec32  # noqa: E402

assert hpke_key_schedule       # imported so a typo there fails here, not in a checker


def rnd(tag: str, n: int = 32) -> bytes:
    """Deterministic test bytes: SHA-256("kinfold-test-vector/" || tag), extended with "/1", "/2"... past 32."""
    out, i = b"", 0
    while len(out) < n:
        out += hashlib.sha256(b"kinfold-test-vector/" + tag.encode() + (f"/{i}".encode() if i else b"")).digest()
        i += 1
    return out[:n]


T0 = 1_793_635_200_000          # 2026-11-02T16:00:00Z
MIN, HOUR, DAY = 60_000, 3_600_000, 86_400_000
U64_MAX = 2 ** 64 - 1           # the last millisecond a u64 can hold
TEEN_UNTIL = 1_939_248_000_000  # 2031-06-15T00:00:00Z
SERVER_URL = "https://family.example"
LINK_BASE = "https://link.kinfold.example"
SERVER_SEED = rnd("server/key")
SERVER_KEY = ed25519_public(SERVER_SEED)


class Device:
    def __init__(self, person, name, kind):
        self.person, self.name, self.kind = person, name, kind
        self.label = f"{person.name}/{name}"
        self.dsk = rnd(f"{self.label}/dsk")
        self.dsk_pub = ed25519_public(self.dsk)
        self.id = idn.device_id(self.dsk_pub)
        self.deks, self.bundles = [], []
        self.recert()
        if kind != idn.RECOVERY:                 # a recovery device has no encryption key
            self.new_key(T0 - DAY)

    def recert(self):
        """(Re)issue the certificate under the person's current identity key."""
        self.cert = idn.make_cert(self.person.ik, self.dsk_pub, self.kind, T0 - DAY, self.person.acc)

    def new_key(self, not_before, **kw):
        sk = rnd(f"{self.label}/dek/{len(self.deks)}")
        self.deks.append((sk, x25519_public(sk)))
        b = idn.make_bundle(self.dsk, self.person.acc, self.deks[-1][1], not_before, not_before + 14 * DAY, **kw)
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

    def all_keys(self) -> dict:
        return {idn.key_id(pub).hex(): sk.hex() for sk, pub in self.deks}

    def json(self):
        return dict(label=self.label, kind=self.kind, dsk_seed=self.dsk.hex(), dsk_pub=self.dsk_pub.hex(),
                    device_id=self.id.hex(), cert=self.cert.hex(),
                    deks=[dict(sk=sk.hex(), pub=pub.hex(), key_id=idn.key_id(pub).hex()) for sk, pub in self.deks],
                    bundles=[b.hex() for b in self.bundles])


class Person:
    def __init__(self, name, devices):
        self.name = name
        self.iks = [rnd(f"{name}/ik")]            # identity seeds, oldest first
        self.acc = idn.account_id(ed25519_public(self.iks[0]))
        self.chain = b""                          # one IdentityLink per rotation
        self.dev = {}
        for n, k in devices:
            self.dev[n] = Device(self, n, k)

    @property
    def ik(self):
        return self.iks[-1]

    @property
    def ik_pub(self):
        return ed25519_public(self.ik)

    def add(self, name, kind):
        self.dev[name] = Device(self, name, kind)
        return self.dev[name]

    def rotate(self) -> bytes:
        """A new identity key; returns the IdentityLink. Devices keep the certificates they have."""
        new = rnd(f"{self.name}/ik/{len(self.iks)}")
        link = idn.make_identity_link(self.acc, self.ik, new)
        self.iks.append(new)
        self.chain += link
        return link

    def json(self):
        return dict(ik_seeds=[s.hex() for s in self.iks], ik_pubs=[ed25519_public(s).hex() for s in self.iks],
                    ik_seed=self.ik.hex(), ik_pub=self.ik_pub.hex(), account_id=self.acc.hex(),
                    chain=self.chain.hex(), devices={n: d.json() for n, d in self.dev.items()})


J = Person("jordan", [("phone", 1), ("tablet", 2), ("web", 3), ("ha", 4), ("recovery", 5)])
A = Person("alex", [("phone", 1), ("tablet", 2)])
M = Person("maya", [("phone", 1)])
S = Person("sam", [("phone", 1)])
jp, jt, jw, jh, jr = (J.dev[n] for n in ("phone", "tablet", "web", "ha", "recovery"))
ap, at, mp, sp = A.dev["phone"], A.dev["tablet"], M.dev["phone"], S.dev["phone"]


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

    def details(self, hdr, f, pt, secret=None, padded=None):
        """The 540-byte details field. padded: the exact 512 bytes to encrypt, to build bad padding."""
        sec = secret or self.secrets[f["epoch"]]
        nonce = rnd(f"log/{f['seq']}/{f['t']}/details-nonce", 12)
        if padded is not None:
            return nonce + aead_seal(lg.log_key(sec), nonce, padded, hdr)
        return lg.seal_details(sec, hdr, pt, nonce)

    def wraps(self, f, devices, secret, new_epoch, tag=""):
        info = lambda rid, kid: lg.epoch_wrap_info(f["circle_id"], f["seq"], f["prev_hash"], new_epoch, rid, kid)
        ikm = lambda rid: rnd(f"log/{f['seq']}{tag}/wrap/{rid.hex()}")
        recips = [(d.id, d.dek_pub) for d in devices]
        return idn.make_wraps(recips, info, secret, ikm), {d.id.hex(): ikm(d.id).hex() for d in devices}

    def commit(self, desc, author, raw, expect, reason=None, details_pt=None, extra=None, quiet=False):
        """Apply `raw` as a client and as a server, assert the outcome, and record it.
        quiet: leave the state out of the record (bulk set-up entries)."""
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
        rec = dict(seq=int.from_bytes(raw[20:28], "big") if len(raw) >= 28 else None, author=author.label,
                   description=desc, raw=raw.hex(), hash=lg.entry_hash(raw).hex(),
                   result=res, reason=why, public_result=pres, public_reason=pwhy)
        if details_pt is not None:
            rec["details_plaintext"] = details_pt.hex()
        if extra:
            rec.update(extra)
        if new is not None:
            if not quiet:
                rec["state_after"] = lg.state_json(new)
            self.state, self.pstate = new, pnew
            self.raws.append(raw)
        self.records.append(rec)
        return rec


ADULT_TERMS = lg.enc_terms(lg.ADULT, 0, [], lg.DEFAULT_RULES)


def teen_terms(guardians, rules=lg.DEFAULT_RULES, teen_until=TEEN_UNTIL, sort=True):
    return lg.enc_terms(lg.TEEN, teen_until, sorted(guardians) if sort else guardians, rules)


def policy(b, author, desc, pt, expect="accepted", reason=None, created_at=None, secret=None, padded=None,
           quiet=False, **over):
    hdr, f = b.head(lg.POLICY, author, created_at, **over)
    raw = lg.build_entry(author.dsk, hdr, b.details(hdr, f, pt, secret, padded))
    return b.commit(desc, author, raw, expect, reason, details_pt=pt, quiet=quiet)


def add_member(b, author, new_dev, invite_secret, admin, terms, desc, expect="accepted", reason=None,
               consent_circle=None, created_at=None, details_secret=None, details_terms=None, cert=None,
               bundle=None, chain=None, signer_ik=None, quiet=False, padded=None):
    """terms: the MemberTerms the invitee signed. details_terms: what the admin wrote instead, if different."""
    p = new_dev.person
    hdr, f = b.head(lg.ADD_MEMBER, author, created_at)
    iid = rv.invite_id(invite_secret)
    salt = kdf(invite_secret, "test", 16)                     # any 16 bytes; derived so vectors stay small
    commit = lg.terms_commit(salt, terms)
    cert = cert or new_dev.cert
    bundle = bundle or new_dev.bundle
    chain = p.chain if chain is None else chain
    consent = rv.consent_sig(signer_ik or p.ik, consent_circle or b.state.circle_id, iid, cert, bundle, commit)
    details_pt = lg.enc_member_details(salt, terms if details_terms is None else details_terms)
    body = (cert + vec16(chain) + bundle + iid + commit + consent + u8(admin)
            + b.details(hdr, f, details_pt, details_secret, padded))
    raw = lg.build_entry(author.dsk, hdr, body)
    return b.commit(desc, author, raw, expect, reason, details_pt=details_pt, quiet=quiet,
                    extra=dict(invite_secret=invite_secret.hex(), invite_id=iid.hex(), terms_salt=salt.hex(),
                               terms=terms.hex(), terms_commit=commit.hex()))


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
    """A removal that starts no epoch: no commitment, no wraps (6.4)."""
    hdr, f = b.head(t, author)
    raw = lg.build_entry(author.dsk, hdr, target + lg.ZERO32 + vec32(b""))
    return b.commit(desc, author, raw, expect, reason)


def simple(b, t, author, body, desc, expect="accepted", reason=None, created_at=None, quiet=False, **over):
    """An entry whose body needs no encryption."""
    hdr, f = b.head(t, author, created_at, **over)
    return b.commit(desc, author, lg.build_entry(author.dsk, hdr, body), expect, reason, quiet=quiet)


def set_admin(b, author, acc, flag, desc, expect="accepted", reason=None):
    return simple(b, lg.SET_ADMIN, author, acc + u8(flag), desc, expect, reason)


def add_device(b, author, dev, desc, expect="accepted", reason=None, cert=None, bundle=None, **kw):
    return simple(b, lg.ADD_DEVICE, author, (cert or dev.cert) + (bundle or dev.bundle), desc, expect, reason, **kw)


# ======================= the main log ==========================================
B = LogBuilder()
RULES = dict(pause_mode=2, approx_mode=1, speed_alert_kmh=110, phone_use_alerts=1, history_days=14,
             silence_alert_min=60, tz="America/Vancouver",
             schedule=[dict(kind=1, days=0b0011111, start_min=930, end_min=1020)])
PAUSE1 = rnd("pause/1", 8)
INVITE_ALEX, INVITE_MAYA = rnd("invite/alex", 16), rnd("invite/maya", 16)
MAYA_TERMS = teen_terms([J.acc, A.acc])

hdr, f = B.head(lg.GENESIS, jp, T0)
pt = lg.enc_genesis_details("Family")
raw = lg.build_entry(jp.dsk, hdr, jp.cert + vec16(b"") + jp.bundle + lg.epoch_commit(0, B.secrets[0])
                     + B.details(hdr, f, pt))
B.commit("Jordan creates the circle \"Family\" (epoch 0)", jp, raw, "accepted", details_pt=pt)
CID = B.state.circle_id

add_member(B, jp, ap, INVITE_ALEX, 1, ADULT_TERMS, "Jordan adds Alex as an adult admin")
add_member(B, ap, mp, INVITE_MAYA, 0, MAYA_TERMS, "Alex adds Maya as a teen; guardians Jordan and Alex")
policy(B, jp, "Jordan sets Maya's rules", lg.enc_policy(lg.SET_RULES, M.acc, rules=RULES))
policy(B, ap, "Alex grants Maya a 2-hour pause",
       lg.enc_policy(lg.GRANT_PAUSE, M.acc, pause_id=PAUSE1, kind=1, start=T0 + 2 * HOUR, end=T0 + 4 * HOUR))
add_device(B, jp, jt, "Jordan adds a tablet")
mp.new_key(T0 + DAY)
simple(B, lg.UPDATE_KEY, mp, mp.bundle, "Maya's phone rotates its encryption key", created_at=T0 + DAY)
epoch_entry(B, lg.REMOVE_DEVICE, jp, "Jordan removes the tablet (epoch 1)", jt.id, [jp, ap, mp])
set_admin(B, jp, A.acc, 0, "Jordan makes Alex a non-admin")
policy(B, jp, "Jordan renames the circle", lg.enc_policy(lg.SET_CIRCLE_NAME, name="Rivera family"))
epoch_entry(B, lg.REKEY, jp, "Jordan's phone starts a new epoch (epoch 2)", None, [jp, ap, mp])
policy(B, jp, "Jordan revokes Maya's pause", lg.enc_policy(lg.REVOKE_PAUSE, M.acc, pause_id=PAUSE1))
policy(B, mp, "Maya tries to grant herself a pause: rejected, stays in the chain as a no-op",
       lg.enc_policy(lg.GRANT_PAUSE, M.acc, pause_id=rnd("pause/self", 8), kind=1, start=T0 + 3 * HOUR,
                     end=T0 + 5 * HOUR), expect="rejected", reason="not_guardian")
policy(B, ap, "Alex hands guardianship of Maya to Jordan alone",
       lg.enc_policy(lg.SET_GUARDIANS, M.acc, guardians=[J.acc]))
BASE = B.state.seq
assert BASE == 13
B13 = B.fork()                  # most cases start here: Jordan admin, Alex not, Maya a teen, epoch 2
S13, HEAD13 = B13.state, B13.state.head

# ======================= cases ====================================================
cases = []


def case(name, desc, fn, base="13"):
    """base: "13" (after entry 13), "final" (after the whole main log) or "empty"."""
    b = {"13": B13.fork, "final": B.fork, "empty": LogBuilder}[base]()
    fn(b)
    base_seq = BASE if base == "13" else -1 if base == "empty" else FINAL
    rec = dict(name=name, description=desc, base_seq=base_seq, entries=b.records)
    if b.withheld:
        rec["withheld_epochs"] = sorted(b.withheld)
    added = {str(k): v.hex() for k, v in b.secrets.items() if k not in B.secrets and k <= b.state.epoch}
    if added:
        rec["new_epoch_secrets"] = added
    cases.append(rec)


def fresh_bundle(b, dev, dek_tag, acc=None, **kw):
    """A bundle for a new key, current at the builder's next entry."""
    return idn.make_bundle(dev.dsk, acc or dev.person.acc, x25519_public(rnd(dek_tag)), b.clock, b.clock + 14 * DAY,
                           **kw)


def fatal_policy(b, **over):
    hdr, f = b.head(lg.POLICY, jp, **over)
    pt = lg.enc_policy(lg.SET_CIRCLE_NAME, name="Never applied")
    return lg.build_entry(jp.dsk, hdr, b.details(hdr, f, pt, b.secrets[b.state.epoch]))


def c_prev(b):
    b.commit("prev_hash does not match the head", jp, fatal_policy(b, prev_hash=lg.ZERO32), "fatal", "bad_prev_hash")


def c_seq(b):
    b.commit("seq skips one", jp, fatal_policy(b, seq=BASE + 2), "fatal", "bad_seq")


def c_sig(b):
    raw = fatal_policy(b)
    b.commit("last signature byte flipped", jp, raw[:-1] + bytes([raw[-1] ^ 1]), "fatal", "bad_signature")


def c_epoch(b):
    b.commit("epoch is behind the circle's", jp, fatal_policy(b, epoch=1), "fatal", "bad_epoch")


def c_cid(b):
    b.commit("circle_id of another circle", jp, fatal_policy(b, circle_id=rnd("other-circle", 16)), "fatal",
             "bad_circle_id")


def c_version(b):
    b.commit("version 1: a client reports that the circle needs a newer app, not tampering", jp,
             fatal_policy(b, version=1), "fatal", "bad_version")


def c_trunc(b):
    b.commit("entry cut short by 10 bytes", jp, fatal_policy(b)[:-10], "fatal", "malformed")


def c_unknown_type(b):
    simple(b, 0x0D, jp, b"", "entry type 0x0D", "fatal", "unknown_entry_type")


def c_too_large(b):
    hdr, f = b.head(lg.POLICY, jp)
    raw = lg.build_entry(jp.dsk, hdr, bytes(lg.MAX_ENTRY + 1 - lg.HEADER_LEN - 4 - 64))
    assert len(raw) == lg.MAX_ENTRY + 1
    b.commit("an entry of 65,537 bytes, refused before anything in it is read", jp, raw, "fatal", "too_large")


def c_details_length(b):
    hdr, f = b.head(lg.POLICY, jp)
    body = b.details(hdr, f, lg.enc_policy(lg.SET_CIRCLE_NAME, name="Short"))[:-1]
    b.commit("POLICY whose details field is 539 bytes", jp, lg.build_entry(jp.dsk, hdr, body), "fatal", "malformed")


def genesis_entry(b, author, cert, bundle, signer, details_secret=None, chain=b"", **over):
    hdr, f = b.head(lg.GENESIS, author, **over)
    pt = lg.enc_genesis_details("Family")
    body = (cert + vec16(chain) + bundle + lg.epoch_commit(0, b.secrets[0])
            + b.details(hdr, f, pt, details_secret or b.secrets[0]))
    return lg.build_entry(signer, hdr, body), pt


def c_genesis(b):
    raw, _ = genesis_entry(b, sp, sp.cert, sp.bundle, sp.dsk, details_secret=rnd("x"))
    b.commit("a second GENESIS", sp, raw, "fatal", "unexpected_genesis")


def c_removed_author(b):
    set_admin(b, jt, J.acc, 1, "signed by the removed tablet", "fatal", "author_not_active")


def c_not_admin_add(b):
    add_member(b, ap, sp, rnd("invite/sam", 16), 0, ADULT_TERMS, "Alex (no longer an admin) adds Sam", "fatal",
               "not_admin")


def c_bad_consent(b):
    add_member(b, jp, sp, rnd("invite/sam", 16), 0, ADULT_TERMS,
               "Sam's consent was signed for a different circle", "fatal", "bad_consent",
               consent_circle=rnd("other-circle", 16))


def c_already(b):
    add_member(b, jp, ap, rnd("invite/alex2", 16), 0, ADULT_TERMS, "Alex added a second time", "fatal",
               "already_member")


class Forged:
    dsk = rnd("forged/dsk")
    dsk_pub = ed25519_public(dsk)
    id = idn.device_id(dsk_pub)
    label = "forged/device"


def forged_cert(acc, ik_pub_field, signer_ik):
    tbs = u8(0) + u16(1) + acc + Forged.dsk_pub + u8(1) + u64(T0)
    return tbs + ik_pub_field + sign(signer_ik, "device-cert", tbs)


def c_bad_cert(b):
    cert = forged_cert(A.acc, A.ik_pub, J.ik)            # carries Alex's identity key, signed by Jordan's
    bundle = idn.make_bundle(Forged.dsk, A.acc, x25519_public(rnd("forged/dek")), b.clock, b.clock + DAY)
    add_device(b, ap, None, "certificate carries Alex's identity key but was signed by Jordan's", "fatal",
               "bad_cert", cert=cert, bundle=bundle)


def c_wrong_account(b):
    add_device(b, ap, jw, "Alex's phone posts a well-formed certificate for one of Jordan's devices", "fatal",
               "wrong_account")


def c_bad_bundle(b):
    bundle = idn.make_bundle(ap.dsk, A.acc, x25519_public(rnd("alex/phone/dek/long")), b.clock, b.clock + 40 * DAY)
    simple(b, lg.UPDATE_KEY, ap, bundle, "key bundle valid for 40 days (limit 35)", "fatal", "bad_bundle")


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
    set_admin(b, jp, S.acc, 1, "SET_ADMIN for someone outside the circle", "fatal", "not_member")


# rejected POLICY entries: servers accept them, clients treat them as no-ops
def rj(subtype_pt, author, reason, desc, **kw):
    return lambda b: policy(b, author, desc, subtype_pt, expect="rejected", reason=reason, **kw)


def c_bad_details(b):
    policy(b, jp, "details encrypted under the wrong key", lg.enc_policy(lg.REVOKE_PAUSE, M.acc, pause_id=PAUSE1),
           expect="rejected", reason="bad_details", secret=rnd("wrong-key"))


def c_details_padding(b):
    pt = lg.enc_policy(lg.SET_CIRCLE_NAME, name="No marker")
    policy(b, jp, "details whose 512 bytes have no 0x80 padding marker", pt, expect="rejected",
           reason="bad_details", padded=pt + bytes(lg.DETAILS_PLAIN - len(pt)))


# accepted edge cases
def c_teen_leaves(b):
    pending_removal(b, lg.REMOVE_MEMBER, mp, "Maya leaves on her own: valid, and everyone is alerted; she would know any "
                    "key she made, so the epoch stays and a rekey is pending", M.acc)


def c_add_bad_details(b):
    add_member(b, jp, sp, rnd("invite/sam", 16), 0, teen_terms([J.acc]),
               "Sam is added with details that do not decrypt: added as an adult and flagged",
               reason="bad_details", details_secret=rnd("wrong-key"))
    assert b.state.flags[-1] == (BASE + 1, "bad_details")


def c_terms_mismatch(b):
    add_member(b, jp, sp, rnd("invite/sam", 16), 0, ADULT_TERMS,
               "Sam agreed to join as an adult, but the admin wrote teen terms into the entry: the details don't "
               "match the commitment Sam signed, so Sam is added as an adult and the entry is flagged",
               reason="bad_details", details_terms=teen_terms([J.acc]))
    assert member(b, S)["role"] == "adult"


def c_invite_reused(b):
    add_member(b, jp, sp, INVITE_ALEX, 0, ADULT_TERMS, "Sam is added with the invite Alex already used", "fatal",
               "invite_reused")


def c_consent_other_terms(b):
    hdr, f = b.head(lg.ADD_MEMBER, jp)
    iid, salt = rv.invite_id(rnd("invite/sam", 16)), rnd("invite/sam/salt", 16)
    signed, written = lg.terms_commit(salt, ADULT_TERMS), lg.terms_commit(salt, teen_terms([J.acc]))
    consent = rv.consent_sig(S.ik, b.state.circle_id, iid, sp.cert, sp.bundle, signed)
    body = (sp.cert + vec16(b"") + sp.bundle + iid + written + consent + u8(0)
            + b.details(hdr, f, lg.enc_member_details(salt, teen_terms([J.acc]))))
    b.commit("the entry commits to teen terms, but Sam's consent covers the adult terms he was shown", jp,
             lg.build_entry(jp.dsk, hdr, body), "fatal", "bad_consent")


def c_end_teen_teen(b):
    policy(b, mp, "Maya ends her own teen settings once teen_until has passed",
           lg.enc_policy(lg.END_TEEN, M.acc), created_at=TEEN_UNTIL)


def c_end_teen_guardian(b):
    policy(b, jp, "Jordan, her guardian, ends Maya's teen settings early", lg.enc_policy(lg.END_TEEN, M.acc))


def member(b, person):
    st = lg.state_json(b.state)
    return next(m for m in st["members"] if m["account_id"] == person.acc.hex())


def maya(b):
    return member(b, M)


def c_repair(b):
    set_admin(b, jp, A.acc, 1, "Jordan makes Alex an admin again")
    pending_removal(b, lg.REMOVE_MEMBER, jp, "Jordan leaves; Maya's only guardian is gone, so guardianship passes to "
                    "the remaining adult admin, Alex", J.acc)
    assert maya(b)["guardians"] == [A.acc.hex()]


def c_first_not_genesis(b):
    set_admin(b, jp, J.acc, 1, "the first entry is not GENESIS", "fatal", "bad_seq")


def c_genesis_author(b):
    raw, _ = genesis_entry(b, ap, jp.cert, jp.bundles[0], ap.dsk)
    b.commit("GENESIS whose author is not the founder's device", ap, raw, "fatal", "bad_author")


def c_genesis_prev(b):
    raw, _ = genesis_entry(b, jp, jp.cert, jp.bundles[0], jp.dsk, prev_hash=rnd("prev"))
    b.commit("GENESIS with a non-zero prev_hash", jp, raw, "fatal", "bad_prev_hash")


def c_genesis_cert(b):
    cert = forged_cert(A.acc, J.ik_pub, J.ik)             # well-formed, but Jordan's key doesn't prove Alex's account
    bundle = idn.make_bundle(Forged.dsk, A.acc, x25519_public(rnd("forged/dek")), T0 - DAY, T0 + DAY)
    raw, _ = genesis_entry(b, Forged, cert, bundle, Forged.dsk)
    b.commit("GENESIS whose certificate names Alex's account under Jordan's identity key, with no chain to prove it",
             Forged, raw, "fatal", "bad_cert")


def c_genesis_details(b):
    raw, pt = genesis_entry(b, jp, jp.cert, jp.bundles[0], jp.dsk, details_secret=rnd("wrong-key"))
    b.commit("GENESIS whose details don't decrypt: accepted with no name, and flagged", jp, raw, "accepted",
             "bad_details", details_pt=pt)


def c_genesis_kind(kind_dev):
    def fn(b):
        bundle = kind_dev.bundle if kind_dev.bundles else idn.make_bundle(
            kind_dev.dsk, J.acc, x25519_public(rnd("recovery/pretend-dek")), T0 - DAY, T0 + DAY)
        raw, _ = genesis_entry(b, kind_dev, kind_dev.cert, bundle, kind_dev.dsk)
        b.commit(f"GENESIS written by a {idn.DEVICE_KINDS[kind_dev.kind]} device", kind_dev, raw, "fatal",
                 "kind_not_allowed")
    return fn


def c_genesis_unknown_kind(b):
    cert = idn.make_cert(J.ik, jp.dsk_pub, 9, T0 - DAY)
    raw, _ = genesis_entry(b, jp, cert, jp.bundles[0], jp.dsk)
    b.commit("GENESIS whose founder certificate says kind 9: the kind check (step 8) comes before the "
             "certificate check (step 9)", jp, raw, "fatal", "kind_not_allowed")


def c_device_active_member(b):
    cert = idn.make_cert(S.ik, ap.dsk_pub, 1, T0)
    bundle = fresh_bundle(b, ap, "sam/alex-device/dek", acc=S.acc)
    add_member(b, jp, sp, rnd("invite/sam", 16), 0, ADULT_TERMS,
               "Sam joins with a certificate for Alex's phone, which is already in the circle", "fatal",
               "device_active", cert=cert, bundle=bundle)


def c_device_active_device(b):
    add_device(b, jp, jp, "Jordan adds his phone a second time", "fatal", "device_active", bundle=jp.bundles[0])


def c_last_admin_flag(b):
    set_admin(b, jp, J.acc, 0, "Jordan, the only admin, drops his own admin flag", "fatal", "last_admin")


def c_same_key(b):
    bundle = idn.make_bundle(ap.dsk, A.acc, ap.dek_pub, b.clock, b.clock + DAY)
    simple(b, lg.UPDATE_KEY, ap, bundle, "UPDATE_KEY that republishes the current key", "fatal", "bad_bundle")


def c_repair_adults(b):
    set_admin(b, jp, M.acc, 1, "Jordan makes Maya an admin")
    pending_removal(b, lg.REMOVE_MEMBER, jp, "Jordan leaves; no adult admin remains, so guardianship passes to every "
                    "adult member: Alex", J.acc)
    assert maya(b)["guardians"] == [A.acc.hex()]


def c_repair_none(b):
    set_admin(b, jp, M.acc, 1, "Jordan makes Maya an admin")
    epoch_entry(b, lg.REMOVE_MEMBER, jp, "Jordan removes Alex (epoch 3)", A.acc, [jp, mp])
    pending_removal(b, lg.REMOVE_MEMBER, jp, "Jordan leaves; no adult remains, so Maya's teen settings end", J.acc)
    assert maya(b)["role"] == "adult" and maya(b)["rules"] is None


def c_repair_two_teens(b):
    set_admin(b, jp, M.acc, 1, "Jordan makes Maya an admin")
    add_member(b, jp, sp, rnd("invite/sam", 16), 0, teen_terms([J.acc]), "Jordan adds Sam as a second teen")
    epoch_entry(b, lg.REMOVE_MEMBER, jp, "Jordan removes Alex (epoch 3)", A.acc, [jp, mp, sp])
    pending_removal(b, lg.REMOVE_MEMBER, jp, "Jordan leaves; no adult remains. Both teens' settings end in the same "
                    "pass, so neither becomes the other's guardian", J.acc)
    assert maya(b)["role"] == member(b, S)["role"] == "adult" and not maya(b)["guardians"] + member(b, S)["guardians"]


def leave_maya(b):
    pending_removal(b, lg.REMOVE_MEMBER, mp, "Maya leaves; a rekey is now pending", M.acc)


def c_removal_clears_pending(b):
    leave_maya(b)
    epoch_entry(b, lg.REMOVE_MEMBER, jp, "Jordan removes Alex (epoch 3), which also clears the pending rekey", A.acc,
                [jp])
    assert lg.state_json(b.state)["rekey_pending"] is False


def c_admin_device_removes_itself(b):
    add_device(b, jp, jt, "Jordan adds his tablet back")
    pending_removal(b, lg.REMOVE_DEVICE, jt, "The tablet removes itself: Jordan is an admin, but this device is "
                    "leaving, so a rekey is pending", jt.id)


def c_pending_with_commit(b):
    simple(b, lg.REMOVE_MEMBER, mp, M.acc + rnd("leaver-commit") + vec32(b""),
           "Maya leaves with a commitment but no wraps", "fatal", "bad_wraps")


def c_rekey_not_admin(b):
    epoch_entry(b, lg.REKEY, mp, "Maya (not an admin) starts a new epoch", None, [jp, ap, mp], "fatal", "not_admin")


def c_self_leave_with_key(b):
    epoch_entry(b, lg.REMOVE_MEMBER, mp, "Maya leaves and hands out a new key she would know", M.acc, [jp, ap],
                "fatal", "bad_wraps")


def c_pending_policy(b):
    leave_maya(b)
    policy(b, jp, "Jordan renames the circle before anyone rekeys", lg.enc_policy(lg.SET_CIRCLE_NAME, name="Riveras"),
           expect="fatal", reason="rekey_pending")


def c_pending_add(b):
    leave_maya(b)
    add_member(b, jp, sp, rnd("invite/sam", 16), 0, ADULT_TERMS, "Jordan adds Sam before anyone rekeys", "fatal",
               "rekey_pending")


def c_pending_cleared(b):
    leave_maya(b)
    epoch_entry(b, lg.REKEY, jp, "Jordan rekeys (epoch 3), which clears the pending flag", None, [jp, ap])
    policy(b, jp, "Jordan renames the circle in the new epoch", lg.enc_policy(lg.SET_CIRCLE_NAME, name="Riveras"))


def c_own_device(b):
    add_device(b, ap, at, "Alex adds a tablet")
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
               teen_terms(sorted([J.acc, A.acc], reverse=True), sort=False),
               "Sam is added as a teen with guardians out of order: added as an adult and flagged",
               reason="bad_details")


def c_add_nine_guardians(b):
    nine = sorted([J.acc] + [rnd(f"guardian/{i}", 16) for i in range(8)])
    add_member(b, jp, sp, rnd("invite/sam", 16), 0, teen_terms(nine),
               "Sam is added as a teen with nine guardians (limit 8): added as an adult and flagged",
               reason="bad_details")


def c_repair_admin_only(b):
    set_admin(b, jp, A.acc, 1, "Jordan makes Alex an admin again")
    add_member(b, jp, sp, rnd("invite/sam", 16), 0, ADULT_TERMS, "Jordan adds Sam as an adult who isn't an admin")
    pending_removal(b, lg.REMOVE_MEMBER, jp, "Jordan leaves; guardianship passes to the adult admins (Alex), not to "
                    "every adult", J.acc)
    assert maya(b)["guardians"] == [A.acc.hex()]


def c_deferred(b):
    b.withheld = {3}
    epoch_entry(b, lg.REKEY, jp, "Jordan rekeys (epoch 3); this device never receives the new secret", None,
                [jp, ap, mp])
    set_admin(b, jp, A.acc, 1, "Jordan makes Alex an admin in epoch 3: no details, so this device still applies it "
                               "in full")
    policy(b, jp, "Jordan changes Maya's rules in epoch 3; this device can't read them, so its private state "
                  "freezes until the secret arrives", lg.enc_policy(lg.SET_RULES, M.acc, rules={**RULES, "history_days": 7}),
           expect="deferred")
    assert lg.state_json(b.state)["state_hash"] is None


# --- limits (16.6) -------------------------------------------------------------------------------

def c_too_many_members(b):
    for i in range(lg.MAX_MEMBERS - len(b.state.members)):
        extra = Person(f"extra{i}", [("phone", 1)])
        add_member(b, jp, extra.dev["phone"], rnd(f"invite/extra{i}", 16), 0, ADULT_TERMS,
                   f"Jordan adds member {len(b.state.members) + 1} of 32", quiet=True)
    assert len(b.state.members) == 32
    add_member(b, jp, sp, rnd("invite/sam", 16), 0, ADULT_TERMS, "a 33rd member", "fatal", "too_many_members")


def c_too_many_devices(b):
    for i in range(2, lg.MAX_DEVICES + 1):
        add_device(b, jp, Device(J, f"phone{i}", 1), f"Jordan adds device {i} of 8", quiet=True)
    assert len(b.state.members[J.acc].devices) == 8
    add_device(b, jp, Device(J, "phone9", 1), "a ninth device for one account", "fatal", "too_many_devices")


def c_pause_cap(b):
    ids = sorted(rnd(f"pause/cap/{i}", 8) for i in range(17))
    for i in range(16):                          # the first two end at the same time, earlier than the rest
        end = T0 + 3 * DAY + (0 if i < 2 else i) * HOUR
        policy(b, jp, f"Jordan grants pause {i + 1} of 16",
               lg.enc_policy(lg.GRANT_PAUSE, M.acc, pause_id=ids[i], kind=1, start=end - HOUR, end=end), quiet=True)
    policy(b, jp, "a 17th pause: the stored pause that ends earliest is dropped, and of two that end together the "
                  "one with the lower ID",
           lg.enc_policy(lg.GRANT_PAUSE, M.acc, pause_id=ids[16], kind=2, start=T0 + 9 * DAY, end=T0 + 9 * DAY + HOUR))
    kept = [p["id"] for p in maya(b)["pauses"]]
    assert len(kept) == 16 and ids[0].hex() not in kept and ids[1].hex() in kept and ids[16].hex() in kept


# --- key bundles (4.4) ---------------------------------------------------------------------------

def c_bundle_expired(b):
    old = idn.make_bundle(ap.dsk, A.acc, x25519_public(rnd("alex/phone/dek/old")), T0 - 30 * DAY, T0 - 16 * DAY)
    simple(b, lg.UPDATE_KEY, ap, old, "a bundle that expired before the entry was written (a replayed old bundle)",
           "fatal", "bad_bundle")


def c_bundle_future(b):
    t = b.clock + 10 * MIN                       # the entry's created_at
    late = idn.make_bundle(ap.dsk, A.acc, x25519_public(rnd("alex/phone/dek/late")), t + 10 * MIN + 1, t + 14 * DAY)
    simple(b, lg.UPDATE_KEY, ap, late, "a bundle that starts 10 minutes and 1 ms after the entry", "fatal",
           "bad_bundle")


def c_bundle_edge(b):
    t = b.clock + 10 * MIN
    edge = idn.make_bundle(ap.dsk, A.acc, x25519_public(rnd("alex/phone/dek/edge")), t + 10 * MIN, t + 14 * DAY)
    simple(b, lg.UPDATE_KEY, ap, edge, "a bundle that starts exactly 10 minutes after the entry: the latest accepted")


def c_bundle_low_order(b):
    low = bytes.fromhex("e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800")
    simple(b, lg.UPDATE_KEY, ap, idn.make_bundle(ap.dsk, A.acc, low, b.clock, b.clock + 14 * DAY),
           "a bundle whose encryption key is a low-order point nobody could seal to", "fatal", "bad_bundle")


def c_bundle_end_of_time(b):
    t = U64_MAX - 2 * MIN                        # the entry's created_at
    last = idn.make_bundle(ap.dsk, A.acc, x25519_public(rnd("alex/phone/dek/end-of-time")), t - MIN, U64_MAX)
    simple(b, lg.UPDATE_KEY, ap, last, "an entry and a bundle in the last minutes a u64 can hold: valid and current, "
           "though not_before + 35 days and created_at + 10 minutes both pass 2^64", created_at=t)


def c_bundle_features(b):
    simple(b, lg.UPDATE_KEY, ap, fresh_bundle(b, ap, "alex/phone/dek/features", proto_max=3, features=0x80000001),
           "a bundle advertising protocol version 3 and feature bits this version doesn't know: still valid")


# --- device kinds and options (6.3, 16.7) --------------------------------------------------------

def c_web_without_option(b):
    add_device(b, jp, jw, "a web device while the circle's options don't allow them", "fatal", "kind_not_allowed")


def c_ha_not_allowed(b):
    simple(b, lg.SET_OPTIONS, jp, u32(lg.OPT_WEB), "Jordan allows web devices only")
    add_device(b, jp, jh, "a Home Assistant device while only web devices are allowed", "fatal", "kind_not_allowed")


def c_add_device_recovery_kind(b):
    bundle = idn.make_bundle(jr.dsk, J.acc, x25519_public(rnd("recovery/pretend-dek")), b.clock, b.clock + DAY)
    add_device(b, jp, jr, "ADD_DEVICE with a recovery certificate (ADD_RECOVERY is the entry for those)", "fatal",
               "kind_not_allowed", bundle=bundle)


def c_add_member_web(b):
    cert = idn.make_cert(S.ik, sp.dsk_pub, idn.WEB, T0)
    add_member(b, jp, sp, rnd("invite/sam", 16), 0, ADULT_TERMS, "a new member whose first device is a web device",
               "fatal", "kind_not_allowed", cert=cert)


def c_bad_options(b):
    simple(b, lg.SET_OPTIONS, jp, u32(4), "SET_OPTIONS with a bit this version doesn't define", "fatal",
           "bad_options")


def c_options_not_admin(b):
    simple(b, lg.SET_OPTIONS, ap, u32(lg.OPT_WEB), "Alex (not an admin) changes the circle's options", "fatal",
           "not_admin")


# --- identity rotation (4.3, 6.4) ----------------------------------------------------------------

def rotation(acc, old_seed, new_seed, new_pub=None, break_new_sig=False):
    link = idn.make_identity_link(acc, old_seed, new_seed)
    if new_pub is not None:
        link = link[:32] + new_pub + link[64:]
    if break_new_sig:
        link = link[:-1] + bytes([link[-1] ^ 1])
    return link


def c_rotation(reason_desc, make):
    return lambda b: simple(b, lg.ROTATE_IDENTITY, ap, make(), reason_desc, "fatal", "bad_rotation")


# --- rules (5.5) ---------------------------------------------------------------------------------

def bad_rules(desc, **change):
    return rj(lg.enc_policy(lg.SET_RULES, M.acc, rules={**RULES, **change}), jp, "bad_rules", desc)


def tz_bytes_rules(tz: bytes) -> bytes:
    """SET_RULES with arbitrary bytes for the time zone."""
    return lg.enc_policy(lg.SET_RULES, M.acc, rules={**RULES, "tz": tz.decode("latin-1")})


EMPTY_CASES = [
    ("fatal_first_not_genesis", "a log that doesn't start with GENESIS", c_first_not_genesis),
    ("fatal_genesis_bad_author", "GENESIS author is not the founder device", c_genesis_author),
    ("fatal_genesis_bad_prev_hash", "GENESIS with a prev_hash", c_genesis_prev),
    ("fatal_genesis_bad_cert", "GENESIS whose certificate doesn't prove its account", c_genesis_cert),
    ("accepted_genesis_bad_details", "GENESIS with unreadable details", c_genesis_details),
    ("fatal_genesis_by_web", "a web device can't found a circle", c_genesis_kind(jw)),
    ("fatal_genesis_by_home_assistant", "a Home Assistant device can't found a circle", c_genesis_kind(jh)),
    ("fatal_genesis_by_recovery", "a recovery device can't found a circle", c_genesis_kind(jr)),
    ("fatal_genesis_unknown_kind", "a device kind outside the registry may write nothing", c_genesis_unknown_kind),
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
    ("fatal_too_large", "an entry over 65,536 bytes", c_too_large),
    ("fatal_details_wrong_length", "a details field that isn't 540 bytes", c_details_length),
    ("fatal_unknown_entry_type", "unknown entry type", c_unknown_type),
    ("fatal_unexpected_genesis", "a second genesis", c_genesis),
    ("fatal_author_not_active", "author device was removed", c_removed_author),
    ("fatal_not_admin", "non-admin adds a member", c_not_admin_add),
    ("fatal_bad_consent", "join consent for another circle", c_bad_consent),
    ("fatal_bad_consent_other_terms", "join consent for other terms than the entry commits to", c_consent_other_terms),
    ("fatal_invite_reused", "an invite ID used twice", c_invite_reused),
    ("fatal_already_member", "member added twice", c_already),
    ("fatal_bad_cert", "certificate signed by the wrong identity key", c_bad_cert),
    ("fatal_wrong_account", "device certificate for another account", c_wrong_account),
    ("fatal_bad_bundle", "key bundle validity window too long", c_bad_bundle),
    ("fatal_bundle_expired", "key bundle no longer current", c_bundle_expired),
    ("fatal_bundle_not_yet_current", "key bundle that starts too far ahead", c_bundle_future),
    ("accepted_bundle_starts_10_minutes_ahead", "the edge of \"current\"", c_bundle_edge),
    ("fatal_bundle_low_order_key", "key bundle with an invalid X25519 key", c_bundle_low_order),
    ("accepted_bundle_unknown_features", "proto_max and features never affect validity", c_bundle_features),
    ("accepted_bundle_at_end_of_time", "times at the top of the u64 range, which a check written as a sum gets wrong",
     c_bundle_end_of_time),
    ("fatal_bad_wraps", "epoch wraps miss a device", c_bad_wraps),
    ("fatal_last_admin", "last admin leaves", c_last_admin),
    ("fatal_last_device", "account's last device removed", c_last_device),
    ("fatal_unknown_device", "removing an unknown device", c_unknown_device),
    ("fatal_not_member", "SET_ADMIN for a non-member", c_not_member_admin),
    ("fatal_too_many_members", "a circle holds at most 32 members", c_too_many_members),
    ("fatal_too_many_devices", "an account holds at most 8 devices", c_too_many_devices),
    ("fatal_web_device_not_allowed", "web devices need the circle's option", c_web_without_option),
    ("fatal_home_assistant_not_allowed", "each kind has its own option bit", c_ha_not_allowed),
    ("fatal_add_device_recovery_kind", "ADD_DEVICE takes kinds 1 to 4", c_add_device_recovery_kind),
    ("fatal_add_member_web_device", "a member's first device is a phone or tablet", c_add_member_web),
    ("fatal_bad_options", "undefined option bit", c_bad_options),
    ("fatal_set_options_not_admin", "only admins change options", c_options_not_admin),
    ("fatal_rotation_wrong_old_key", "the link's old key isn't the author's current identity key",
     c_rotation("a rotation from a key that isn't Alex's current identity key",
                lambda: rotation(A.acc, rnd("stranger/ik"), rnd("alex/ik/x")))),
    ("fatal_rotation_to_members_key", "the new key already belongs to a member",
     c_rotation("Alex rotates to Jordan's identity key", lambda: rotation(A.acc, A.ik, J.ik))),
    ("fatal_rotation_bad_new_signature", "the new key didn't sign the link",
     c_rotation("a rotation whose new-key signature is damaged",
                lambda: rotation(A.acc, A.ik, rnd("alex/ik/x"), break_new_sig=True))),
    ("fatal_rotation_small_order_key", "the new key is an invalid key",
     c_rotation("a rotation to a small-order key",
                lambda: rotation(A.acc, A.ik, rnd("alex/ik/x"), new_pub=bytes([1]) + bytes(31)))),
    ("fatal_rotation_same_key", "the new key equals the old one",
     c_rotation("a rotation to the same key", lambda: rotation(A.acc, A.ik, A.ik))),
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
    ("rejected_bad_guardians_nine", "more than 8 guardians",
     rj(lg.enc_policy(lg.SET_GUARDIANS, M.acc, guardians=sorted(rnd(f"guardian/{i}", 16) for i in range(9))), jp,
        "bad_guardians", "Jordan names nine guardians")),
    ("rejected_unknown_policy", "unknown POLICY subtype",
     rj(u8(0x63) + M.acc, jp, "unknown_policy", "POLICY subtype 0x63")),
    ("rejected_teen_until_not_reached", "teen ends her settings early",
     rj(lg.enc_policy(lg.END_TEEN, M.acc), mp, "teen_until_not_reached", "Maya tries END_TEEN before teen_until")),
    ("rejected_bad_details", "details do not decrypt", c_bad_details),
    ("rejected_details_bad_padding", "details that decrypt but aren't padded", c_details_padding),
    ("rejected_not_teen", "teen rules for an adult",
     rj(lg.enc_policy(lg.SET_RULES, A.acc, rules=RULES), jp, "not_teen", "Jordan sets teen rules for Alex")),
    ("rejected_not_admin_rename", "non-admin renames the circle",
     rj(lg.enc_policy(lg.SET_CIRCLE_NAME, name="Alex's circle"), ap, "not_admin", "Alex renames the circle")),
    ("rejected_unknown_pause", "revoking a pause that does not exist",
     rj(lg.enc_policy(lg.REVOKE_PAUSE, M.acc, pause_id=rnd("pause/none", 8)), jp, "unknown_pause",
        "Jordan revokes an unknown pause")),
    ("rejected_bad_rules", "history_days 0", bad_rules("Jordan sets history to 0 days", history_days=0)),
    ("rejected_bad_rules_silence", "a silence alert under 15 minutes",
     bad_rules("Jordan sets the silence alert to 10 minutes", silence_alert_min=10)),
    ("rejected_bad_rules_no_time_zone", "a schedule with no time zone",
     bad_rules("Jordan sets a schedule but no time zone", tz="")),
    ("rejected_bad_rules_time_zone_characters", "a time zone with a byte outside the allowed set",
     rj(tz_bytes_rules(b"Europe/Z\xfcrich"), jp, "bad_rules", "a time zone holding the byte 0xFC")),
    ("rejected_bad_rules_time_zone_length", "a time zone over 64 bytes",
     rj(tz_bytes_rules(b"A" * 65), jp, "bad_rules", "a 65-byte time zone")),
    ("rejected_not_member", "teen rules for a non-member",
     rj(lg.enc_policy(lg.SET_RULES, S.acc, rules=RULES), jp, "not_member", "Jordan sets rules for Sam")),
    ("accepted_rules_silence_off", "a silence alert of 0 switches it off",
     lambda b: policy(b, jp, "Jordan switches Maya's silence alert off",
                      lg.enc_policy(lg.SET_RULES, M.acc, rules={**RULES, "silence_alert_min": 0}))),
    ("accepted_teen_leaves", "a teen may leave; the protocol makes it visible", c_teen_leaves),
    ("accepted_add_member_bad_details", "undecryptable member details", c_add_bad_details),
    ("accepted_add_member_terms_mismatch", "details that aren't the terms the new member signed", c_terms_mismatch),
    ("accepted_end_teen_by_teen", "teen ends her settings at teen_until", c_end_teen_teen),
    ("accepted_end_teen_by_guardian", "guardian ends teen settings", c_end_teen_guardian),
    ("accepted_guardian_repair", "last guardian leaves; an adult admin takes over", c_repair),
    ("accepted_guardian_repair_adults", "last guardian leaves; no adult admin, so every adult", c_repair_adults),
    ("accepted_guardian_repair_no_adults", "no adult remains; teen settings end", c_repair_none),
    ("accepted_guardian_repair_two_teens", "repair judges every teen against the same snapshot", c_repair_two_teens),
    ("accepted_guardian_repair_admin_only", "repair prefers adult admins over other adults", c_repair_admin_only),
    ("accepted_pause_cap", "at most 16 stored pauses", c_pause_cap),
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
    ("accepted_add_member_nine_guardians", "member details with too many guardians", c_add_nine_guardians),
    ("deferred_missing_secret", "a device without the epoch secret defers private rules", c_deferred),
]
for name, desc, fn in EMPTY_CASES:
    case(name, desc, fn, base="empty")
for name, desc, fn in CASES:
    case(name, desc, fn)


# Draft 0.3 entry types, continuing the same log
simple(B, lg.SET_OPTIONS, jp, u32(lg.OPT_WEB | lg.OPT_HOME_ASSISTANT),
       "Jordan allows web and Home Assistant devices in this circle")
add_device(B, jp, jw, "Jordan's phone links his browser (a web device)")
add_device(B, jp, jh, "Jordan's phone links a Home Assistant install")
simple(B, lg.ADD_RECOVERY, jp, jr.cert, "Jordan makes a recovery kit: its key joins as a recovery device")
jw.new_key(B.clock + 10 * MIN)
simple(B, lg.UPDATE_KEY, jw, jw.bundle, "The browser rotates its own encryption key")
ALEX_LINK = A.rotate()
simple(B, lg.ROTATE_IDENTITY, ap, ALEX_LINK,
       "Alex replaces his identity key after losing a phone; his account ID stays the same")
at.recert()                     # the tablet joins under Alex's new identity key
add_device(B, ap, at, "Alex adds a tablet, certified by his new identity key")
FINAL = B.state.seq
assert FINAL == 20 and B.state.receiving_changed_seq == 20
SF, HEADF = B.state, B.state.head
assert lg.state_json(SF)["members"][0]


# ======================= cases on the whole main log ==================================
j2 = J.add("phone2", 1)          # the phone Jordan sets up from his recovery kit
R = Person("riley", [("phone", 1)])
R.rotate()                       # Riley replaced an identity key before ever joining this circle
rp = R.dev["phone"]
rp.recert()


def c_web_leaves(b):
    pending_removal(b, lg.REMOVE_DEVICE, jw, "The browser removes itself. It can't create the next key, so a rekey "
                    "is pending", jw.id)


def c_recovery(b):
    add_device(b, jr, j2, "Jordan lost his phone. A new phone, holding the recovery kit, signs as the recovery "
                          "device and adds itself")
    epoch_entry(b, lg.REMOVE_DEVICE, jr, "Still signing as the recovery device, it removes the lost phone. Jordan "
                "is an admin, so this starts epoch 3", jp.id, [j2, jw, jh, ap, at, mp])
    assert b.state.epoch == 3 and not b.state.rekey_pending


def c_recovery_other_account(b):
    pending_removal(b, lg.REMOVE_DEVICE, jr, "the recovery device tries to remove Alex's tablet", at.id, "fatal",
                    "kind_not_allowed")


def c_second_recovery(b):
    simple(b, lg.ADD_RECOVERY, jp, Device(J, "recovery2", 5).cert, "a second recovery device for one account",
           "fatal", "too_many_devices")


def c_recovery_wrong_kind(b):
    simple(b, lg.ADD_RECOVERY, jp, j2.cert, "ADD_RECOVERY with a phone's certificate", "fatal", "kind_not_allowed")


def c_remove_recovery(b):
    pending_removal(b, lg.REMOVE_DEVICE, jp, "Jordan retires the recovery kit. A recovery device never held an "
                    "epoch secret, so the epoch stays and no rekey is pending", jr.id)
    assert b.state.epoch == 2 and not b.state.rekey_pending


def c_remove_recovery_with_wraps(b):
    epoch_entry(b, lg.REMOVE_DEVICE, jp, "removing a recovery device with a new epoch attached", jr.id,
                [jp, jw, jh, ap, at, mp], "fatal", "bad_wraps")


def c_old_identity_cert(b):
    old_cert = idn.make_cert(A.iks[0], Forged.dsk_pub, 1, T0, A.acc)
    bundle = idn.make_bundle(Forged.dsk, A.acc, x25519_public(rnd("forged/dek")), b.clock, b.clock + DAY)
    add_device(b, ap, None, "a device certified by the identity key Alex has retired", "fatal", "wrong_account",
               cert=old_cert, bundle=bundle)


def c_chain(b):
    add_member(b, jp, rp, rnd("invite/riley", 16), 0, ADULT_TERMS,
               "Riley joins. Her identity key isn't her first, so the entry carries the chain that ties it to her "
               "account ID")
    m = member(b, R)
    assert m["ik_pub"] == R.ik_pub.hex() != ed25519_public(R.iks[0]).hex()


def c_chain_missing(b):
    add_member(b, jp, rp, rnd("invite/riley", 16), 0, ADULT_TERMS, "the same certificate with no chain", "fatal",
               "bad_cert", chain=b"")


def c_chain_wrong(b):
    other = idn.make_identity_link(R.acc, rnd("stranger/ik"), R.ik)
    add_member(b, jp, rp, rnd("invite/riley", 16), 0, ADULT_TERMS,
               "a chain that starts from a key that isn't the account's first", "fatal", "bad_cert", chain=other)


def c_chain_too_long(b):
    add_member(b, jp, rp, rnd("invite/riley", 16), 0, ADULT_TERMS, "a chain of nine links (limit 8)", "fatal",
               "malformed", chain=R.chain * 9)


def c_options_cleared(b):
    simple(b, lg.SET_OPTIONS, jp, u32(0), "Jordan switches web and Home Assistant devices off again. Devices "
           "already in the circle stay until someone removes them")
    assert jw.id.hex() in [d["device_id"] for d in member(b, J)["devices"]]
    add_device(b, jp, Device(J, "web2", 3), "a new web device after the option was cleared", "fatal",
               "kind_not_allowed")


def kind_case(dev, t):
    """One entry of type t written by a web, Home Assistant or recovery device (the table in 6.3)."""
    kind = idn.DEVICE_KINDS[dev.kind]
    name = lg.ENTRY_NAMES[t]

    def fn(b):
        no = ("fatal", "kind_not_allowed")
        desc = f"{name} written by a {kind} device"
        if t == lg.ADD_MEMBER:
            add_member(b, dev, sp, rnd("invite/sam", 16), 0, ADULT_TERMS, desc, *no)
        elif t == lg.REMOVE_MEMBER:
            pending_removal(b, t, dev, desc, M.acc, *no)
        elif t == lg.ADD_DEVICE:
            ok = dev.kind == idn.RECOVERY
            add_device(b, dev, j2, desc + (": allowed" if ok else ""), *(("accepted", None) if ok else no))
        elif t == lg.REMOVE_DEVICE:
            pending_removal(b, t, dev, f"{name} of itself by a {kind} device: allowed", dev.id)
        elif t == lg.UPDATE_KEY:
            if dev.kind == idn.RECOVERY:
                simple(b, t, dev, idn.make_bundle(dev.dsk, J.acc, x25519_public(rnd("recovery/pretend-dek")), b.clock,
                                                  b.clock + DAY), desc, *no)
            else:
                simple(b, t, dev, fresh_bundle(b, dev, f"{dev.label}/dek/kind-case"), desc + ": allowed")
        elif t == lg.POLICY:
            policy(b, dev, desc, lg.enc_policy(lg.SET_CIRCLE_NAME, name="From the web"), *no)
        elif t == lg.REKEY:
            epoch_entry(b, t, dev, desc, None, [jp, jw, jh, ap, at, mp], *no)
        elif t == lg.SET_ADMIN:
            set_admin(b, dev, A.acc, 1, desc, *no)
        elif t == lg.ADD_RECOVERY:
            simple(b, t, dev, Device(J, "recovery2", 5).cert, desc, *no)
        elif t == lg.SET_OPTIONS:
            simple(b, t, dev, u32(0), desc, *no)
        elif t == lg.ROTATE_IDENTITY:
            simple(b, t, dev, idn.make_identity_link(J.acc, J.ik, rnd("jordan/ik/x")), desc, *no)
    return f"kind_{kind.replace('-', '_')}_{name.lower()}", f"{name} from a {kind} device", fn


def kind_remove_other(dev):
    kind = idn.DEVICE_KINDS[dev.kind]
    return (f"kind_{kind.replace('-', '_')}_remove_device_other", f"a {kind} device removing another device",
            lambda b: pending_removal(b, lg.REMOVE_DEVICE, dev, f"a {kind} device removes Maya's phone", mp.id,
                                      "fatal", "kind_not_allowed"))


FINAL_CASES = [
    ("accepted_web_device_removes_itself", "a web device may remove itself", c_web_leaves),
    ("accepted_recovery_kit_used", "a recovery device adds a phone and removes the lost one", c_recovery),
    ("fatal_recovery_removes_other_account", "a recovery device acts only on its own account's devices",
     c_recovery_other_account),
    ("fatal_second_recovery_device", "one recovery device per account", c_second_recovery),
    ("fatal_add_recovery_wrong_kind", "ADD_RECOVERY takes kind 5 only", c_recovery_wrong_kind),
    ("accepted_remove_recovery_device", "removing a recovery device never changes the epoch", c_remove_recovery),
    ("fatal_remove_recovery_with_wraps", "removing a recovery device carries no secret", c_remove_recovery_with_wraps),
    ("fatal_add_device_retired_identity", "after a rotation only the new identity key certifies devices",
     c_old_identity_cert),
    ("accepted_add_member_with_chain", "a member whose identity key has rotated", c_chain),
    ("fatal_add_member_chain_missing", "the account ID isn't the hash of the certificate's key", c_chain_missing),
    ("fatal_add_member_chain_wrong", "a chain that doesn't start at the account's first key", c_chain_wrong),
    ("fatal_add_member_chain_too_long", "more than eight links", c_chain_too_long),
    ("fatal_options_cleared", "clearing an option stops new devices of that kind, not existing ones",
     c_options_cleared),
]
KIND_TYPES = [t for t in sorted(lg.ENTRY_NAMES) if t != lg.GENESIS]
for name, desc, fn in FINAL_CASES + [kind_case(d, t) for d in (jw, jh, jr) for t in KIND_TYPES] \
        + [kind_remove_other(d) for d in (jw, jh, jr)]:
    case(name, desc, fn, base="final")

# ======================= envelopes ======================================================
HEAD6 = bytes.fromhex(B.records[6]["hash"])
RECEIVER_NOW = T0 + 2 * DAY + 5 * MIN
SERVER_REASONS = {"malformed", "bad_version", "bad_kind", "wrong_circle", "sender_not_active", "bad_signature",
                  "unknown_log_head", "expired", "bad_time", "replay", "bad_wraps", "bad_ttl", "stale_head"}
LOGS = {BASE: (S13, HEAD13), FINAL: (SF, HEADF)}


def keymap(d):
    return {bytes.fromhex(a): bytes.fromhex(b) for a, b in d.items()}


def open_env(raw, st, dev, keys=None, seen=None):
    return ev.open_envelope(raw, st, dev.id, keymap(keys or dev.all_keys()), set() if seen is None else seen,
                            RECEIVER_NOW)


def server(raw, st, seen=None):
    try:
        ev.server_check(raw, st, RECEIVER_NOW, {} if seen is None else seen)
        return None
    except ev.EnvelopeError as e:
        return e.reason


def env(tag, sender, kind, recipients, payload_obj, seq=1, head=None, cid=None, pad_override=None,
        payload_secret=None, wrap_hook=None, reorder=False, sent_at=T0 + 2 * DAY, ttl=7 * 86400, at_seq=BASE):
    """recipients: devices (wrapped to their current key) or (device_id, dek_pub) pairs."""
    recipients = [(r.id, r.dek_pub) if isinstance(r, Device) else r for r in recipients]
    hdr = ev.env_header(kind, cid or CID, sender.id, seq, sent_at, ttl, head or LOGS[at_seq][1])
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
                log_head=(head or LOGS[at_seq][1]).hex(), message_secret=secret.hex(),
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
LIVE_REQ = {"t": "sig", "k": "live_req", "until": T0 + 2 * DAY + 5 * MIN}
GRANT = ps.make_watch_grant(mp.dsk, CID, mp.id, J.acc, 60, RECEIVER_NOW + 7 * DAY)
PLACE_N = rnd("place/1/n", 8)
PLACE = {"t": "place", "id": b64u(ev.place_id(M.acc, PLACE_N)), "creator": b64u(M.acc), "n": b64u(PLACE_N), "v": 1,
         "name": "Library", "lat": 436677000, "lon": -793948000, "r": 120}
EVT = {"t": "evt", "ts": T0 + 2 * DAY - 60000, "k": "arrive", "place": PLACE["id"]}
CHECKIN = {"t": "checkin", "ts": T0 + 2 * DAY - 30000, "lat": 436677000, "lon": -793948000, "acc": 9,
           "place": PLACE["id"], "note": "Made it"}
SOS = {"t": "sos", "ts": T0 + 2 * DAY - 5000, "state": "start", "lat": 436532000, "lon": -793832000, "acc": 8}
CHAT = {"t": "chat", "id": b64u(rnd("chat/1", 8)), "text": "Dinner at 7? \U0001F35D"}
EPOCHS = [b64u(B.secrets[e]) for e in sorted(B.secrets)]
ALL_F = [jp, jw, jh, ap, at, mp]                 # the receiving devices after the whole main log


def others(sender):
    return [d for d in ALL_F if d is not sender]


def nest(depth):
    """A value nested `depth` levels deep, counting the payload object itself as level 1."""
    v = 1
    for _ in range(depth - 1):
        v = [v]
    return v


valid_envs = []
VALID = [
    # (tag, description, sender, kind, recipients, payload, sent_at, log seq, head)
    ("e1", "Jordan's location to the circle", jp, ev.CIRCLE, [ap, mp], LOC, None, BASE, None),
    ("e2", "Maya asks for a pause. The request goes to the whole circle, so who her guardians are doesn't show in "
           "who receives it", mp, ev.CIRCLE, [jp, ap], PAUSE_REQ, None, BASE, None),
    ("e3", "Maya shares an approximate location", mp, ev.CIRCLE, [jp, ap], LOC_APPROX, None, BASE, None),
    ("e4", "Jordan's location sent exactly 31 days before the receiver's clock: the oldest accepted", jp, ev.CIRCLE,
     [ap, mp], LOC, RECEIVER_NOW - 31 * DAY, BASE, None),
    ("e5", "Jordan's location dated exactly 1 day after the receiver's clock: the furthest ahead accepted", jp,
     ev.CIRCLE, [ap, mp], LOC, RECEIVER_NOW + DAY, BASE, None),
    ("e6", "Maya asks Jordan's phone for a live location (direct)", mp, ev.DIRECT, [jp], LIVE_REQ, None, BASE, None),
    ("e7", "a payload at every limit of section 8.1: 8 levels, a 4,096-byte string, a 256-item array, 2^53 - 1, and "
           "a whole number written as 1.0", jp, ev.CIRCLE, [ap, mp],
     ('{"t":"test_limits","deep":' + json.dumps(nest(8), separators=(",", ":")) + ',"s":"' + "a" * 4096
      + '","list":' + json.dumps([0] * 256, separators=(",", ":")) + ',"big":9007199254740991,"whole":1.0}').encode(),
     None, BASE, None),
    ("f1", "Jordan's location after the whole log: a circle envelope names every receiving device", jp, ev.CIRCLE,
     others(jp), LOC, None, FINAL, None),
    ("f2", "Jordan's browser asks Maya's phone for a live location: a web device may send `sig`", jw, ev.DIRECT, [mp],
     LIVE_REQ, None, FINAL, None),
    ("f3", "The Home Assistant device asks for epoch secrets it lacks: the one thing it may send", jh, ev.CIRCLE,
     others(jh), {"t": "refresh_req", "epochs": [1, 2]}, None, FINAL, None),
    ("f4", "Jordan's phone answers with a refresh, to the whole circle", jp, ev.CIRCLE, others(jp),
     {"t": "refresh", "epochs": EPOCHS, "head": b64u(HEADF)}, None, FINAL, None),
    ("f5", "Alex's phone welcomes the tablet it added in entry 20", ap, ev.DIRECT, [at],
     {"t": "welcome", "epochs": EPOCHS, "head": b64u(HEADF)}, None, FINAL, None),
    ("f6", "Alex's phone hands his new identity key and its chain to his tablet", ap, ev.DIRECT, [at],
     {"t": "ik", "ik": b64u(A.ik), "chain": b64u(A.chain)}, None, FINAL, None),
    ("f7", "Maya's phone issues a watch grant for Jordan", mp, ev.CIRCLE, others(mp),
     {"t": "watch_grant", "grant": b64u(GRANT)}, None, FINAL, None),
    ("f8", "Maya, a teen, creates a place of her own", mp, ev.CIRCLE, others(mp), PLACE, None, FINAL, None),
    ("f9", "Jordan, Maya's guardian, declines her pause request", jp, ev.CIRCLE, others(jp),
     {"t": "pause_deny", "id": PAUSE_REQ["id"], "teen": b64u(M.acc), "note": "After dinner"}, None, FINAL, None),
    ("f10", "Maya's heartbeat: flags are a list, and it carries her phone's state hash", mp, ev.CIRCLE, others(mp),
     {"t": "hb", "ts": T0 + 2 * DAY - 2000, "flags": ["sharing", "saver", "precise_off"], "bat": 18, "chg": False,
      "tz": -480, "sh": b64u(lg.state_hash(SF))}, None, FINAL, None),
    ("f11", "a payload type this version doesn't know: it passes every check and the app ignores it", jp, ev.CIRCLE,
     others(jp), {"t": "future_thing", "x": 1}, None, FINAL, None),
    ("f12", "a direct envelope may carry an older log head; only circle envelopes must be current", jp, ev.DIRECT,
     [mp], LIVE_REQ, None, FINAL, HEAD13),
    ("f13", "Maya's phone reports that she arrived at the library", mp, ev.CIRCLE, others(mp), EVT, None, FINAL, None),
    ("f14", "Alex checks in from his tablet", at, ev.CIRCLE, others(at), CHECKIN, None, FINAL, None),
    ("f15", "Maya starts an SOS", mp, ev.CIRCLE, others(mp), SOS, None, FINAL, None),
    ("f16", "Jordan's profile, with names for his devices", jp, ev.CIRCLE, others(jp),
     {"t": "profile", "name": "Jordan", "color": "#2f6f4f",
      "devices": {b64u(jp.id): "Jordan's phone", b64u(jw.id): "Jordan's browser", b64u(jh.id): "Home Assistant"}},
     None, FINAL, None),
    ("f17", "a chat message; text is UTF-8, written as it is rather than in \\u escapes", ap, ev.CIRCLE, others(ap),
     CHAT, None, FINAL, None),
]
for tag, desc, sender, kind, recips, payload, sent, at_seq, head in VALID:
    st = LOGS[at_seq][0]
    raw, meta = env(tag, sender, kind, recips, payload, sent_at=sent or T0 + 2 * DAY, at_seq=at_seq, head=head)
    expect = ev.parse_payload(payload) if isinstance(payload, bytes) else payload
    assert server(raw, st) is None, tag
    rec = []
    for d in recips:
        got = open_env(raw, st, d)
        assert got == expect, (tag, got)
        rec.append(dict(device=d.label, device_id=d.id.hex(), keys=d.all_keys()))
    valid_envs.append(dict(name=tag, description=desc, log_seq=at_seq, **meta, payload=expect, recipients=rec))

E1 = bytes.fromhex(valid_envs[0]["raw"])
E6 = bytes.fromhex(valid_envs[5]["raw"])
invalid_envs = []


def bad(name, desc, raw, receiver, reason, keys=None, at_seq=BASE, server_reason="same"):
    """An envelope the receiver must refuse with `reason`. server_reason: what a server answers
    (None = it stores the envelope); by default the same code when a server can see the fault."""
    st = LOGS[at_seq][0]
    k = keys or receiver.all_keys()
    try:
        open_env(raw, st, receiver, k)
        got = "ok"
    except ev.EnvelopeError as e:
        got = e.reason
    assert got == reason, (name, got)
    if server_reason == "same":
        server_reason = reason if reason in SERVER_REASONS else None
    assert server(raw, st) == server_reason, (name, server(raw, st))
    invalid_envs.append(dict(name=name, description=desc, log_seq=at_seq, raw=raw.hex(), receiver=receiver.label,
                             receiver_device_id=receiver.id.hex(), receiver_keys=k, error=reason,
                             server_error=server_reason))


both = [ap, mp]
bad("malformed", "cut short", E1[:-3], ap, "malformed")
bad("bad_version", "version byte 1 (signature not reached)", b"\x01" + E1[1:], ap, "bad_version")
bad("bad_kind", "kind 3", env("k3", jp, 3, both, LOC)[0], ap, "bad_kind")
bad("wrong_circle", "another circle's ID", env("wc", jp, 1, both, LOC, cid=rnd("other-circle", 16))[0], ap,
    "wrong_circle")
bad("sender_not_active", "from the removed tablet",
    env("na", jt, 1, [jp] + both, LOC, head=HEAD6)[0], ap, "sender_not_active")
bad("sender_before_log_head", "from the removed tablet, with a log head nobody knows: the sender check comes first",
    env("nb", jt, 1, [jp] + both, LOC, head=rnd("nohead"))[0], ap, "sender_not_active")
bad("bad_signature", "seq changed after signing", E1[:36] + bytes([E1[36] ^ 1]) + E1[37:], ap, "bad_signature")
UNKNOWN_HEAD = env("ul", jp, 1, both, LOC, head=rnd("nohead"))[0]
bad("signature_before_log_head", "an unknown log head and a damaged signature: the signature check comes first, so "
    "no fork alarm rests on an envelope nobody signed", UNKNOWN_HEAD[:-1] + bytes([UNKNOWN_HEAD[-1] ^ 1]), ap,
    "bad_signature")
bad("unknown_log_head", "validly signed, with a log head that isn't in the receiver's log", UNKNOWN_HEAD, ap,
    "unknown_log_head")
bad("expired", "sent 31 days and 1 ms before the receiver's clock",
    env("ex", jp, 1, both, LOC, sent_at=RECEIVER_NOW - 31 * DAY - 1)[0], ap, "expired")
bad("bad_time", "sent more than a day after the receiver's clock",
    env("ft", jp, 1, both, LOC, sent_at=RECEIVER_NOW + DAY + 1)[0], ap, "bad_time")
bad("bad_time_end_of_time", "sent at the last millisecond a u64 can hold: far ahead of the receiver's clock, though "
    "sent_at + 31 days, wrapped around, would look long past", env("et", jp, 1, both, LOC, sent_at=U64_MAX)[0], ap,
    "bad_time")
bad("bad_wraps", "wraps not sorted by device ID", env("ro", jp, 1, both, LOC, reorder=True)[0], ap, "bad_wraps")
bad("bad_wraps_none", "no wraps at all", env("nw", jp, 2, [], LOC)[0], ap, "bad_wraps")
crowd = [(rnd(f"crowd/{i}", 16), x25519_public(rnd(f"crowd/{i}/dek"))) for i in range(254)]
bad("bad_wraps_256", "256 wraps (limit 255)", env("cw", jp, 2, both + crowd, LIVE_REQ)[0], ap, "bad_wraps")
bad("not_a_recipient", "a direct envelope for someone else", E6, ap, "not_a_recipient")
bad("unknown_key", "wrapped to Maya's retired key", env("uk", jp, 1, [ap, (mp.id, mp.deks[0][1])], LOC)[0], mp,
    "unknown_key", keys=mp.keys())


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
for tag, desc, text in [
        ("depth", "nested 9 levels deep", '{"t":"test_limits","deep":' + json.dumps(nest(9), separators=(",", ":")) + "}"),
        ("string", "a 4,097-byte string", '{"t":"chat","id":"AAAAAAAAAAA","text":"' + "a" * 4097 + '"}'),
        ("array", "an array of 257 items", '{"t":"test_limits","list":' + json.dumps([0] * 257, separators=(",", ":")) + "}"),
        ("fraction", "a number that isn't whole", '{"t":"loc","lat":436532000.5}'),
        ("range", "the number 2^53", '{"t":"loc","ts":9007199254740992}'),
        ("type", "\"t\" is not a string", '{"t":7}'),
        ("utf8", "bytes that aren't UTF-8", b'{"t":"chat","text":"\xff"}'),
        ("surrogate", "half of a surrogate pair, written as a \\u escape: valid JSON, but not text",
         '{"t":"chat","id":"AAAAAAAAAAA","text":"\\ud83c"}')]:
    bad(f"bad_payload_{tag}", desc, env(f"bl/{tag}", jp, 1, both, text if isinstance(text, bytes) else text.encode())[0],
        ap, "bad_payload")

# who may send what (8.2), checked last
DENY = [
    ("web_sends_location", "a web device sends a location", jw, ev.CIRCLE, others(jw), LOC, ap),
    ("home_assistant_sends_signal", "a Home Assistant device asks for a live location", jh, ev.DIRECT, [mp], LIVE_REQ,
     mp),
    ("location_in_direct_envelope", "a location addressed to one device: `loc` is a circle payload", jp, ev.DIRECT,
     [mp], LOC, mp),
    ("signal_in_circle_envelope", "a live request sent to everyone: `sig` is a direct payload", jp, ev.CIRCLE,
     others(jp), LIVE_REQ, mp),
    ("pause_request_from_adult", "a pause request from Jordan, who isn't a teen", jp, ev.CIRCLE, others(jp), PAUSE_REQ,
     ap),
    ("pause_denied_by_non_guardian", "Alex, no longer Maya's guardian, declines her pause", ap, ev.CIRCLE, others(ap),
     {"t": "pause_deny", "id": PAUSE_REQ["id"], "teen": b64u(M.acc)}, mp),
    ("pause_denied_for_adult", "a pause_deny naming Alex, who isn't a teen", jp, ev.CIRCLE, others(jp),
     {"t": "pause_deny", "id": PAUSE_REQ["id"], "teen": b64u(A.acc)}, mp),
    ("pause_denied_without_teen", "a pause_deny with no `teen` field", jp, ev.CIRCLE, others(jp),
     {"t": "pause_deny", "id": PAUSE_REQ["id"]}, mp),
    ("welcome_from_other_account", "a welcome for Alex's tablet from Jordan, who didn't add it", jp, ev.DIRECT, [at],
     {"t": "welcome", "epochs": EPOCHS, "head": b64u(HEADF)}, at),
    ("watch_grant_relayed", "Maya's watch grant sent by Jordan's phone instead of the phone it names", jp, ev.CIRCLE,
     others(jp), {"t": "watch_grant", "grant": b64u(GRANT)}, ap),
    ("identity_key_wrong_seed", "an `ik` whose seed isn't the identity key the log shows", ap, ev.DIRECT, [at],
     {"t": "ik", "ik": b64u(A.iks[0]), "chain": b64u(A.chain)}, at),
    ("identity_key_other_account", "an `ik` from another person's phone", jp, ev.DIRECT, [at],
     {"t": "ik", "ik": b64u(A.ik), "chain": b64u(A.chain)}, at),
    ("place_teen_claims_other_creator", "Maya, a teen, sends a place whose creator is Jordan", mp, ev.CIRCLE,
     others(mp), {**PLACE, "id": b64u(ev.place_id(J.acc, PLACE_N)), "creator": b64u(J.acc)}, jp),
    ("place_id_mismatch", "a place whose id isn't the hash of its creator and n", jp, ev.CIRCLE, others(jp),
     {**PLACE, "creator": b64u(J.acc)}, ap),
]
for name, desc, sender, kind, recips, payload, receiver in DENY:
    bad("not_allowed_" + name, desc, env("deny/" + name, sender, kind, recips, payload, at_seq=FINAL)[0], receiver,
        "not_allowed", at_seq=FINAL)
bad("sender_is_recovery_device", "signed by Jordan's recovery device, which never sends",
    env("rs", jr, 1, ALL_F, LOC, at_seq=FINAL)[0], ap, "sender_not_active", at_seq=FINAL)

seen = set()
first = open_env(E1, S13, ap, seen=seen)
try:
    open_env(E1, S13, ap, seen=seen)
    raise AssertionError("replay accepted")
except ev.EnvelopeError as e:
    assert e.reason == "replay"
replay_case = dict(name="replay", description="the same envelope delivered twice", log_seq=BASE,
                   receiver=ap.label, receiver_device_id=ap.id.hex(), receiver_keys=ap.all_keys(),
                   sequence=[E1.hex(), E1.hex()], results=["ok", "replay"])

E1B = env("e1-other", jp, ev.CIRCLE, both, LOC_APPROX)[0]       # the same seq as E1, different bytes
sseen = {}
got = []
for raw in (E1, E1, E1B):
    try:
        got.append(ev.server_check(raw, S13, RECEIVER_NOW, sseen))
    except ev.EnvelopeError as e:
        got.append(e.reason)
assert got == ["stored", "duplicate", "replay"]
server_repost = dict(name="repost", description="a server takes the same bytes again as a success (a retry after a "
                     "lost reply) and refuses different bytes under the same seq", log_seq=BASE,
                     sequence=[E1.hex(), E1.hex(), E1B.hex()], results=got)

server_rejects = []


def server_only(name, desc, raw, reason, receiver, at_seq=BASE):
    st = LOGS[at_seq][0]
    assert server(raw, st) == reason, (name, server(raw, st))
    payload = open_env(raw, st, receiver)
    server_rejects.append(dict(name=name, description=desc + "; recipients can still open it", log_seq=at_seq,
                               raw=raw.hex(), server_error=reason, receiver=receiver.label,
                               receiver_device_id=receiver.id.hex(), receiver_keys=receiver.all_keys(),
                               payload=payload))


server_only("ttl_too_short", "ttl_s of 30 seconds (minimum 60)", env("tt", jp, 1, both, LOC, ttl=30)[0], "bad_ttl", ap)
server_only("ttl_too_long", "ttl_s one second over 30 days", env("tm", jp, 1, both, LOC, ttl=2_592_001)[0], "bad_ttl",
            ap)
server_only("inactive_recipient", "also wrapped to the removed tablet", env("ir", jp, 1, both + [jt], LOC)[0],
            "bad_wraps", ap)
server_only("recovery_recipient", "a direct envelope also wrapped to the recovery device, which isn't a receiving "
            "device", env("rr", jp, 2, [mp, (jr.id, x25519_public(rnd("recovery/pretend-dek")))], LIVE_REQ,
                          at_seq=FINAL)[0], "bad_wraps", mp, FINAL)
server_only("stale_head", "a circle envelope built on entry 13, before devices were added",
            env("sh", jp, 1, both, LOC, head=HEAD13, at_seq=FINAL)[0], "stale_head", ap, FINAL)
server_only("circle_leaves_one_out", "a circle envelope that leaves out Maya's phone",
            env("lo", jp, 1, [jw, jh, ap, at], LOC, at_seq=FINAL)[0], "bad_wraps", ap, FINAL)

# ======================= small vectors ======================================================
padding = []
for n in (0, 1, 254, 255, 256, 511, 1000, 65535):
    padded = ev.pad(b"a" * n)
    padding.append(dict(payload_length=n, payload_byte="61", padded_length=len(padded),
                        padded_sha256=hashlib.sha256(padded).hexdigest()))
pad_to_vec = [dict(payload_length=n, payload_byte="61", to=size,
                   padded_sha256=hashlib.sha256(pad_to(b"a" * n, size)).hexdigest())
              for n, size in ((0, 512), (130, 512), (511, 512), (76, 2560), (2559, 2560))]
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
for x, y, note in [(J, A, "after Alex's rotation: his half follows his current identity key"), (A, M, ""), (M, J, "")]:
    safety.append(dict(a=x.name, b=y.name, ik_pub_a=x.ik_pub.hex(), ik_pub_b=y.ik_pub.hex(),
                       half_a=idn.safety_half(x.ik_pub), half_b=idn.safety_half(y.ik_pub),
                       code=idn.safety_code(x.ik_pub, y.ik_pub), qr=idn.safety_qr(x.ik_pub, y.ik_pub), note=note))
assert len(safety[0]["code"].replace(" ", "")) == 60 and len(safety[0]["half_a"]) == 30
assert idn.safety_half(ed25519_public(A.iks[0])) != idn.safety_half(A.ik_pub)

# invite and join (Maya's invite, matching log entry 2; Alex invited her before he rotated his identity key)
ALEX_IK0 = ed25519_public(A.iks[0])
MAYA_SALT = kdf(INVITE_MAYA, "test", 16)
NAMES = {J.acc: "Jordan", A.acc: "Alex"}
invite = rv.make_invite(SERVER_URL, SERVER_KEY, CID, INVITE_MAYA, ALEX_IK0, T0 + 7 * DAY,
                        b"reg-token-from-the-server-admin", MAYA_SALT, MAYA_TERMS, "Family", "Alex",
                        [NAMES[g] for g in sorted([J.acc, A.acc])])
inv = rv.parse_invite(invite)
assert inv["terms"]["role"] == lg.TEEN and inv["terms_bytes"] == MAYA_TERMS
iid_m = rv.invite_id(INVITE_MAYA)
commit_m = lg.terms_commit(MAYA_SALT, MAYA_TERMS)
consent_m = rv.consent_sig(M.ik, CID, iid_m, mp.cert, mp.bundles[0], commit_m)
join_nonce = rnd("join/maya/nonce", 12)
join_msg = rv.make_join_request(INVITE_MAYA, mp.cert, b"", mp.bundles[0], commit_m, consent_m, "Maya", join_nonce)
opened = rv.open_join_request(inv, join_msg, T0 + 20 * MIN)
entry2 = lg.parse_body(lg.ADD_MEMBER, lg.parse_entry(B.raws[2]).body_bytes)
assert opened["name"] == "Maya" and entry2["consent"] == consent_m and entry2["terms_commit"] == commit_m \
    and entry2["invite_id"] == iid_m
res_nonce, dec_nonce = rnd("join/maya/result-nonce", 12), rnd("join/maya/declined-nonce", 12)
join_added = rv.make_join_result(INVITE_MAYA, rv.JOIN_ADDED, bytes.fromhex(B.records[2]["hash"]), res_nonce)
join_declined = rv.make_join_result(INVITE_MAYA, rv.JOIN_DECLINED, bytes(32), dec_nonce)
assert rv.open_join_result(INVITE_MAYA, join_added)["head"].hex() == B.records[2]["hash"]
assert rv.open_join_result(INVITE_MAYA, join_declined)["outcome"] == rv.JOIN_DECLINED
invite_vec = dict(
    invite=invite.hex(), code=rv.invite_code(invite), link_base=LINK_BASE, link=rv.invite_link(LINK_BASE, invite),
    fields=dict(server_url=SERVER_URL, server_key=SERVER_KEY.hex(), circle_id=CID.hex(), secret=INVITE_MAYA.hex(),
                inviter_ik_pub=ALEX_IK0.hex(), expires_at=T0 + 7 * DAY,
                reg_token=b"reg-token-from-the-server-admin".hex(), terms_salt=MAYA_SALT.hex(),
                terms=MAYA_TERMS.hex(), circle_name="Family", inviter_name="Alex",
                guardian_names=inv["guardian_names"]),
    terms=dict(role=2, teen_until=TEEN_UNTIL, guardians=[g.hex() for g in inv["terms"]["guardians"]],
               rules=lg.rules_json(inv["terms"]["rules"])),
    invite_id=iid_m.hex(), join_key=rv.join_key(INVITE_MAYA).hex(),
    join_result_key=rv.join_result_key(INVITE_MAYA).hex(), terms_commit=commit_m.hex(),
    join_request=dict(now=T0 + 20 * MIN, cert=mp.cert.hex(), chain="", bundle=mp.bundles[0].hex(),
                      consent=consent_m.hex(), name="Maya", nonce=join_nonce.hex(), message=join_msg.hex()),
    join_result=dict(added=dict(nonce=res_nonce.hex(), message=join_added.hex(), outcome=1,
                                head=B.records[2]["hash"]),
                     declined=dict(nonce=dec_nonce.hex(), message=join_declined.hex(), outcome=2, head=bytes(32).hex())),
    log_entry_seq=2)


# device linking (10): commit, nonce, request, code, response
def link_vector(tag, direction, existing, new, name, epochs, expires, now, send_ik):
    """existing: the phone that confirms; new: the device being added."""
    p = existing.person
    secret = rnd(f"link/{tag}", 16)
    link = (rv.make_link(direction, SERVER_URL, SERVER_KEY, secret, expires, p.acc, p.ik_pub)
            if direction == rv.LINK_FROM_EXISTING else rv.make_link(direction, SERVER_URL, SERVER_KEY, secret, expires))
    out = dict(direction=direction, link=link.hex(), code_text=rv.link_code_text(link), secret=secret.hex(),
               link_id=rv.link_id(secret).hex(), link_key=rv.link_key(secret).hex(),
               confirm=rv.link_confirm(secret).hex(), existing_device=existing.label, new_device=new.label,
               new_device_dek_sk=new.deks[0][0].hex(), account_id=p.acc.hex(), ik_pub=p.ik_pub.hex(), now=now)
    n = lambda what: rnd(f"link/{tag}/{what}-nonce", 12)
    if direction == rv.LINK_FROM_NEW:
        offer = rv.link_seal(secret, rv.MSG_OFFER, p.acc + p.ik_pub, n("offer"))
        assert rv.open_link_offer(secret, offer) == dict(account_id=p.acc, ik_pub=p.ik_pub)
        out.update(offer_nonce=n("offer").hex(), offer=offer.hex())
    r_new, r_old = rnd(f"link/{tag}/r-new"), rnd(f"link/{tag}/r-old")
    body = rv.link_request_body(new.dsk_pub, new.kind, new.bundles[0], name)
    commit = rv.link_commit(secret, r_new, body)
    commit_msg = rv.link_seal(secret, rv.MSG_COMMIT, commit, n("commit"))
    nonce_msg = rv.link_seal(secret, rv.MSG_NONCE, r_old, n("nonce"))
    request_msg = rv.link_seal(secret, rv.MSG_REQUEST, r_new + body, n("request"))
    assert rv.link_open(secret, rv.MSG_NONCE, nonce_msg) == r_old
    req = rv.open_link_request(secret, direction, p.acc, commit_msg, r_old, request_msg, now)
    assert req["name"] == name and req["kind"] == new.kind
    payload = {"cert": b64u(new.cert)}
    if send_ik:
        payload.update(ik=b64u(p.ik), chain=b64u(p.chain))
    payload.update(confirm=b64u(rv.link_confirm(secret)), circles=[{"id": b64u(CID), "epochs": epochs}])
    payload = ev.payload_bytes(payload)
    ikm = rnd(f"link/{tag}/response-ikm")
    response = rv.make_link_response(secret, existing.dsk, existing.cert, new.deks[0][1], new.id, payload, ikm)
    got = rv.open_link_response(secret, p.ik_pub, response, new.deks[0][0], new.dsk_pub, new.kind, p.acc)
    assert ("ik" in got) == send_ik
    out.update(r_new=r_new.hex(), r_old=r_old.hex(), request_body=body.hex(), device_name=name,
               commit=commit.hex(), commit_nonce=n("commit").hex(), commit_message=commit_msg.hex(),
               nonce_nonce=n("nonce").hex(), nonce_message=nonce_msg.hex(),
               request_nonce=n("request").hex(), request=request_msg.hex(), code=req["code"],
               response_payload=payload.decode(), response_ikm=ikm.hex(), response=response.hex())
    return out, (secret, commit_msg, r_old, request_msg, body, r_new)


ap.recert()          # after the rotation Alex's phone re-issued its own certificate under the new key (4.3)
link_t, parts_t = link_vector("tablet", rv.LINK_FROM_EXISTING, jp, jt, "Jordan's iPad", [b64u(B.secrets[0])],
                              T0 + 50 * MIN + 120_000, T0 + 50 * MIN, True)
link_w, parts_w = link_vector("web", rv.LINK_FROM_NEW, jp, jw, "Jordan's browser", EPOCHS,
                              T0 + DAY + 90 * MIN + 300_000, T0 + DAY + 90 * MIN, False)
link_a, _ = link_vector("alex-tablet", rv.LINK_FROM_EXISTING, ap, at, "Alex's tablet", EPOCHS,
                        T0 + DAY + 140 * MIN + 120_000, T0 + DAY + 140 * MIN, True)
assert json.loads(link_a["response_payload"])["chain"] == b64u(A.chain) != ""
link_refused = []
for name, desc, direction, args, why in [
        ("request_not_committed", "the request isn't the one the new device committed to",
         rv.LINK_FROM_EXISTING, (parts_t[1], parts_t[2],
                                 rv.link_seal(parts_t[0], rv.MSG_REQUEST, rnd("link/other-r-new") + parts_t[4],
                                              rnd("link/refused/1", 12))), "bad_commit"),
        ("kind_does_not_fit_direction", "a web device asking through a code that an existing phone showed",
         rv.LINK_FROM_EXISTING, None, "kind_not_allowed")]:
    secret = parts_t[0]
    if args is None:
        body = rv.link_request_body(jw.dsk_pub, jw.kind, jw.bundles[0], "Jordan's browser")
        r_new = rnd("link/refused/r-new")
        args = (rv.link_seal(secret, rv.MSG_COMMIT, rv.link_commit(secret, r_new, body), rnd("link/refused/2", 12)),
                parts_t[2], rv.link_seal(secret, rv.MSG_REQUEST, r_new + body, rnd("link/refused/3", 12)))
    try:
        rv.open_link_request(secret, direction, J.acc, args[0], args[1], args[2], T0 + 50 * MIN)
        raise AssertionError(name)
    except rv.RendezvousError as e:
        assert e.reason == why, (name, e.reason)
    link_refused.append(dict(name=name, description=desc, secret=secret.hex(), direction=direction,
                             account_id=J.acc.hex(), now=T0 + 50 * MIN, commit_message=args[0].hex(),
                             r_old=args[1].hex(), request=args[2].hex()))
link_vec = dict(from_existing=link_t, from_new=link_w, from_existing_rotated=link_a, refused=link_refused)

# recovery kits, setup codes, server moves
kit_j = rv.make_recovery_kit(SERVER_URL, SERVER_KEY, J.acc, J.ik, J.chain, jr.dsk, T0 + DAY + 100 * MIN)
kit_a = rv.make_recovery_kit(SERVER_URL, SERVER_KEY, A.acc, A.ik, A.chain, rnd("alex/recovery/dsk"), T0 + 2 * DAY)
pk = rv.parse_recovery_kit(kit_j)
assert ed25519_public(pk["recovery_dsk_seed"]) == jr.dsk_pub and ed25519_public(pk["ik_seed"]) == J.ik_pub
assert len(rv.parse_recovery_kit(kit_a)["chain"]) == 1
recovery_vec = [dict(owner=p.name, kit=k.hex(), code=rv.recovery_code(k), account_id=p.acc.hex(),
                     ik_seed=p.ik.hex(), chain=p.chain.hex(), recovery_dsk_seed=seed.hex(),
                     recovery_device_id=idn.device_id(ed25519_public(seed)).hex(), created_at=t)
                for p, k, seed, t in ((J, kit_j, jr.dsk, T0 + DAY + 100 * MIN),
                                      (A, kit_a, rnd("alex/recovery/dsk"), T0 + 2 * DAY))]
setup = idn.make_setup(SERVER_URL, SERVER_KEY, b"first-account-token", T0 + HOUR)
assert idn.parse_setup(idn.read_code("KFS0", idn.setup_code(setup)))["server_key"] == SERVER_KEY
setup_vec = dict(setup=setup.hex(), code=idn.setup_code(setup), server_url=SERVER_URL, server_key=SERVER_KEY.hex(),
                 reg_token=b"first-account-token".hex(), expires_at=T0 + HOUR)
NEW_SERVER_SEED = rnd("server/key/2")
NEW_URL = "https://kinfold.family.example"
moves = []
for name, desc, signer, new_key, ok in [
        ("new_address_and_key", "the server moves and replaces its key", SERVER_SEED,
         ed25519_public(NEW_SERVER_SEED), True),
        ("new_address_only", "only the address changes: new_key equals old_key", SERVER_SEED, SERVER_KEY, True),
        ("signed_by_the_new_key", "a notice the old key didn't sign", NEW_SERVER_SEED,
         ed25519_public(NEW_SERVER_SEED), False)]:
    raw = idn.make_server_move(signer, SERVER_URL, NEW_URL, new_key, T0 + 30 * DAY)
    if not ok:                                    # names the old key, but carries the new key's signature
        raw = raw[:1] + vec16(SERVER_URL.encode()) + SERVER_KEY + raw[1 + 2 + len(SERVER_URL) + 32:]
    mv = idn.parse_server_move(raw)
    assert mv["sig_ok"] == ok and mv["old_key"] == SERVER_KEY and mv["new_url"] == NEW_URL
    moves.append(dict(name=name, description=desc, move=raw.hex(), old_url=SERVER_URL, old_key=SERVER_KEY.hex(),
                      new_url=NEW_URL, new_key=new_key.hex(), issued_at=T0 + 30 * DAY, valid=ok))

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
                expires_at=T0 + MIN, challenge_sig=idn.challenge_sig(SERVER_SEED, challenge, jp.id, T0 + MIN).hex(),
                device_sig=idn.auth_sig(jp.dsk, SERVER_KEY, challenge, jp.id).hex())

# silence-watch grants (14.1), judged against the whole main log at the envelopes' clock
grants = []
for name, desc, raw, ok in [
        ("maya_grants_jordan", "Maya's phone lets Jordan be told after 60 minutes of silence", GRANT, True),
        ("shortest_interval", "15 minutes, the shortest interval", ps.make_watch_grant(
            mp.dsk, CID, mp.id, J.acc, 15, RECEIVER_NOW + 35 * DAY), True),
        ("signed_by_another_device", "names Maya's phone but was signed by Jordan's", ps.make_watch_grant(
            jp.dsk, CID, mp.id, J.acc, 60, RECEIVER_NOW + 7 * DAY), False),
        ("interval_too_short", "after_min of 14", ps.make_watch_grant(
            mp.dsk, CID, mp.id, J.acc, 14, RECEIVER_NOW + 7 * DAY), False),
        ("interval_too_long", "after_min of 1,441", ps.make_watch_grant(
            mp.dsk, CID, mp.id, J.acc, 1441, RECEIVER_NOW + 7 * DAY), False),
        ("expired", "not_after has passed", ps.make_watch_grant(mp.dsk, CID, mp.id, J.acc, 60, RECEIVER_NOW), False),
        ("too_far_ahead", "not_after more than 35 days away", ps.make_watch_grant(
            mp.dsk, CID, mp.id, J.acc, 60, RECEIVER_NOW + 35 * DAY + 1), False),
        ("web_device", "a browser can't be watched: it doesn't share a location", ps.make_watch_grant(
            jw.dsk, CID, jw.id, A.acc, 60, RECEIVER_NOW + 7 * DAY), False),
        ("watcher_not_a_member", "the watcher isn't in the circle", ps.make_watch_grant(
            mp.dsk, CID, mp.id, S.acc, 60, RECEIVER_NOW + 7 * DAY), False),
        ("other_circle", "a grant for another circle", ps.make_watch_grant(
            mp.dsk, rnd("other-circle", 16), mp.id, J.acc, 60, RECEIVER_NOW + 7 * DAY), False)]:
    assert ps.watch_grant_ok(raw, SF, RECEIVER_NOW) == ok, name
    grants.append(dict(name=name, description=desc, grant=raw.hex(), valid=ok))
grant_vec = dict(log_seq=FINAL, now=RECEIVER_NOW, grants=grants,
                 fields=dict(circle_id=CID.hex(), watched_device_id=mp.id.hex(), watcher_account_id=J.acc.hex(),
                             after_min=60, not_after=RECEIVER_NOW + 7 * DAY))

# push messages (14.2) and the relay signature (14.4)
PUSH_AT = RECEIVER_NOW
RECORD = (PUSH_AT - 1500, bytes.fromhex(valid_envs[5]["raw"]))       # e6: Maya's live request to Jordan's phone
pushes = []
for name, desc, dev, ptype, body in [
        ("wake", "connect and fetch the inbox", jp, ps.WAKE, b""),
        ("records", "one delivery record: Maya's live request (envelope e6)", jp, ps.RECORDS,
         ps.records_body([RECORD])),
        ("silence", "Maya's phone has been quiet", jp, ps.SILENCE, ps.silence_body(CID, mp.id, PUSH_AT - 62 * MIN))]:
    push = ps.make_push(SERVER_SEED, dev.id, ptype, PUSH_AT, body)
    ikm = rnd(f"push/{name}/ikm")
    sealed = ps.seal_push(push, dev.id, dev.dek_pub, ikm)
    got = ps.open_push(sealed, dev.id, keymap(dev.all_keys()), SERVER_KEY, PUSH_AT + 30_000)
    assert len(sealed) == ps.PUSH_SEALED and got["type"] == ptype
    pushes.append(dict(name=name, description=desc, device=dev.label, device_id=dev.id.hex(), keys=dev.all_keys(),
                       type=ptype, sent_at=PUSH_AT, body=body.hex(), push=push.hex(), ikm=ikm.hex(),
                       sealed=sealed.hex(), now=PUSH_AT + 30_000))
assert ps.open_push(bytes.fromhex(pushes[1]["sealed"]), jp.id, keymap(jp.all_keys()), SERVER_KEY, PUSH_AT)["records"] \
    == [RECORD]
WAKE_PUSH, WAKE_SEALED = bytes.fromhex(pushes[0]["push"]), bytes.fromhex(pushes[0]["sealed"])
bad_pushes = []
for name, desc, sealed, dev, now in [
        ("other_server", "signed by a key that isn't this device's server",
         ps.seal_push(ps.make_push(NEW_SERVER_SEED, jp.id, ps.WAKE, PUSH_AT, b""), jp.id, jp.dek_pub,
                      rnd("push/bad/1")), jp, PUSH_AT),
        ("for_another_device", "sealed to Jordan's phone, but signed for Alex's",
         ps.seal_push(ps.make_push(SERVER_SEED, ap.id, ps.WAKE, PUSH_AT, b""), jp.id, jp.dek_pub,
                      rnd("push/bad/2")), jp, PUSH_AT),
        ("stale", "sent 10 minutes and 1 ms before the device's trusted time", WAKE_SEALED, jp,
         PUSH_AT + 10 * MIN + 1),
        ("wrong_size", "one byte short", WAKE_SEALED[:-1], jp, PUSH_AT),
        ("unknown_type", "type 9", ps.seal_push(ps.make_push(SERVER_SEED, jp.id, 9, PUSH_AT, b""), jp.id, jp.dek_pub,
                                               rnd("push/bad/3")), jp, PUSH_AT),
        ("wake_with_body", "a wake that carries bytes", ps.seal_push(
            ps.make_push(SERVER_SEED, jp.id, ps.WAKE, PUSH_AT, b"x"), jp.id, jp.dek_pub, rnd("push/bad/4")), jp,
         PUSH_AT)]:
    try:
        ps.open_push(sealed, dev.id, keymap(dev.all_keys()), SERVER_KEY, now)
        raise AssertionError(name)
    except ps.PushError:
        pass
    bad_pushes.append(dict(name=name, description=desc, device=dev.label, device_id=dev.id.hex(),
                           keys=dev.all_keys(), sealed=sealed.hex(), now=now))
CAPABILITY = rnd("relay/capability", 180)          # opaque to everyone but the relay
relay = dict(capability=CAPABILITY.hex(), sealed=WAKE_SEALED.hex(), sent_at=PUSH_AT, delivery=3,
             sig=ps.relay_sig(SERVER_SEED, CAPABILITY, WAKE_SEALED, PUSH_AT, 3).hex(),
             note="delivery 3 is a location push; the same signature fails for any other delivery type")
assert ps.relay_sig_ok(SERVER_KEY, CAPABILITY, WAKE_SEALED, PUSH_AT, 3, bytes.fromhex(relay["sig"]))
assert not ps.relay_sig_ok(SERVER_KEY, CAPABILITY, WAKE_SEALED, PUSH_AT, 1, bytes.fromhex(relay["sig"]))
push_vec = dict(server_key=SERVER_KEY.hex(), valid=pushes, invalid=bad_pushes, relay=relay)

# state hash (6.9): the bytes that are hashed, for the state after the whole main log
state_hash_vec = dict(log_seq=FINAL, state_bytes=lg.state_bytes(SF).hex(), state_hash=lg.state_hash(SF).hex())

# ======================= Ed25519 and X25519 edge cases (3.3, 3.5) ==========================
# A small, slow Ed25519 in affine coordinates, used only to build keys and signatures that
# no ordinary library will produce, and to state the expected verdict from the equation itself.
P, L = P25519, ED25519_L
ED_D = -121665 * pow(121666, -1, P) % P
SQRT_M1 = pow(2, (P - 1) // 4, P)
IDENT = (0, 1)


def ed_add(p1, p2):
    (x1, y1), (x2, y2) = p1, p2
    k = ED_D * x1 * x2 * y1 * y2 % P
    return ((x1 * y2 + x2 * y1) * pow(1 + k, -1, P) % P, (y1 * y2 + x1 * x2) * pow(1 - k, -1, P) % P)


def ed_mul(k, pt):
    acc = IDENT
    while k:
        if k & 1:
            acc = ed_add(acc, pt)
        pt = ed_add(pt, pt)
        k >>= 1
    return acc


def ed_decode(b, strict):
    """The point, or None. With strict=False a y of p or more is reduced first, as a lax library does."""
    y, sign = int.from_bytes(b, "little") & ((1 << 255) - 1), b[31] >> 7
    if y >= P:
        if strict:
            return None
        y -= P
    x2 = (y * y - 1) * pow(ED_D * y * y + 1, -1, P) % P
    x = pow(x2, (P + 3) // 8, P)
    if (x * x - x2) % P:
        x = x * SQRT_M1 % P
    if (x * x - x2) % P:
        return None
    return ((P - x) % P if x & 1 != sign else x, y)


def ed_encode(pt):
    return (pt[1] | ((pt[0] & 1) << 255)).to_bytes(32, "little")


BASE_PT = ed_decode((4 * pow(5, -1, P) % P).to_bytes(32, "little"), True)
T8 = ed_decode(bytes.fromhex("26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05"), True)
SMALL = [ed_mul(i, T8) for i in range(8)]          # the eight small-order points; SMALL[0] is the identity
assert ed_mul(8, T8) == IDENT != ed_mul(4, T8) and ed_mul(L, BASE_PT) == IDENT
assert {ed_encode(t)[:31] + bytes([ed_encode(t)[31] & 0x7F]) for t in SMALL} \
    == {bytes.fromhex(h) for h in ("00" * 32, "01" + "00" * 31, "ec" + "ff" * 30 + "7f",
                                   "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
                                   "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a")}
T2 = SMALL[4]
assert T2 == (0, P - 1)


def order(pt):
    return next(m for m in (1, 2, 4, 8) if ed_mul(m, pt) == IDENT)


ED_SEED = rnd("ed25519/edge/seed")
_h = hashlib.sha512(ED_SEED).digest()
ED_A = int.from_bytes(bytes([_h[0] & 248]) + _h[1:31] + bytes([(_h[31] & 63) | 64]), "little")   # the clamped scalar
ED_PUB = ed_encode(ed_mul(ED_A, BASE_PT))
assert ED_PUB == ed25519_public(ED_SEED)


def k_of(r_enc, pub, msg):
    k = int.from_bytes(hashlib.sha512(r_enc + pub + msg).digest(), "little")
    return k % L, k


def find_msg(tag, r_enc, pub, want):
    """A message whose (k mod L, k) satisfies `want`."""
    for i in range(100_000):
        msg = f"kinfold ed25519 edge case: {tag} #{i}".encode()
        if want(*k_of(r_enc, pub, msg)):
            return msg
    raise AssertionError(tag)


def equation(pub, msg, sig, strict):
    """[S]B = R + [k]A with k reduced mod L: section 3.3 when strict, otherwise with none of its byte checks."""
    r_enc, s = sig[:32], int.from_bytes(sig[32:], "little")
    if strict and (s >= L or ed25519_key_invalid(pub) or ed25519_key_invalid(r_enc)):
        return False
    a_pt, r_pt = ed_decode(pub, strict), ed_decode(r_enc, strict)
    if a_pt is None or r_pt is None:
        return False
    return ed_mul(s, BASE_PT) == ed_add(r_pt, ed_mul(k_of(r_enc, pub, msg)[0], a_pt))


ed_cases = []


def ed_case(name, desc, pub, msg, r_enc, s, valid, lax, cofactored=None):
    """valid: the verdict section 3.3 requires. lax: what the bare equation gives without the byte checks,
    which is what some libraries return. cofactored: noted where multiplying by 8 would change the answer."""
    sig = r_enc + s.to_bytes(32, "little")
    assert equation(pub, msg, sig, True) == valid, name
    assert equation(pub, msg, sig, False) == lax, name
    assert verify_raw(pub, msg, sig) == valid, (name, "the reference's library disagrees")
    rec = dict(name=name, description=desc, pub=pub.hex(), msg=msg.hex(), sig=sig.hex(), valid=valid,
               without_byte_checks=lax)
    if cofactored is not None:
        rec["cofactored"] = cofactored
    ed_cases.append(rec)


def nonce_r(tag):
    r = int.from_bytes(rnd(f"ed25519/edge/r/{tag}", 64), "little") % L
    return r, ed_mul(r, BASE_PT)


# 1. an ordinary signature, and the same with S + L
msg = b"kinfold ed25519 edge case: ordinary"
r = int.from_bytes(hashlib.sha512(_h[32:] + msg).digest(), "little") % L          # RFC 8032's own nonce
r_enc = ed_encode(ed_mul(r, BASE_PT))
s_val = (r + k_of(r_enc, ED_PUB, msg)[0] * ED_A) % L
ed_case("ordinary", "a signature as RFC 8032 makes it", ED_PUB, msg, r_enc, s_val, True, True)
ed_case("s_not_reduced", "the same signature with L added to S (check 1)", ED_PUB, msg, r_enc, s_val + L, False, True)

# 2. small-order keys: with R = [r]B and S = r the equation holds whenever [k]A is the identity
for i, t in enumerate(SMALL):
    r, r_pt = nonce_r(f"small-key/{i}")
    pub, r_enc = ed_encode(t), ed_encode(r_pt)
    msg = find_msg(f"small-order key {i}", r_enc, pub, lambda k, _: k % order(t) == 0)
    ed_case(f"small_order_key_{i}", f"the key is a point of order {order(t)} (check 3)", pub, msg, r_enc, r, False,
            True)

# 3. keys in a second, non-canonical spelling (y of p or more, or x = 0 with the sign bit set)
for i, (pub, what) in enumerate([
        (bytes.fromhex("01" + "00" * 30 + "80"), "y = 1 with the sign bit set"),
        (bytes.fromhex("ec" + "ff" * 31), "y = p - 1 with the sign bit set"),
        (bytes.fromhex("ed" + "ff" * 30 + "7f"), "y = p"),
        (bytes.fromhex("ed" + "ff" * 31), "y = p with the sign bit set"),
        (bytes.fromhex("ee" + "ff" * 30 + "7f"), "y = p + 1"),
        (bytes.fromhex("ee" + "ff" * 31), "y = p + 1 with the sign bit set")]):
    t = ed_decode(pub, False)
    r, r_pt = nonce_r(f"noncanonical-key/{i}")
    r_enc = ed_encode(r_pt)
    msg = find_msg(f"non-canonical key {i}", r_enc, pub, lambda k, _: k % order(t) == 0)
    ed_case(f"noncanonical_key_{i}", f"the key is written as {what} (checks 2 and 3)", pub, msg, r_enc, r, False, True)

# 4. small-order and non-canonical R
r_enc = ed_encode(IDENT)
msg = b"kinfold ed25519 edge case: R is the identity"
ed_case("small_order_r_identity", "R is the identity and S = k*a (check 3)", ED_PUB, msg, r_enc,
        k_of(r_enc, ED_PUB, msg)[0] * ED_A % L, False, True)
r_enc = bytes.fromhex("ee" + "ff" * 30 + "7f")
msg = b"kinfold ed25519 edge case: R is the identity, written as y = p + 1"
ed_case("noncanonical_r", "R is the identity written as y = p + 1 (check 2)", ED_PUB, msg, r_enc,
        k_of(r_enc, ED_PUB, msg)[0] * ED_A % L, False, True)
MIXED8 = ed_encode(ed_add(ed_mul(ED_A, BASE_PT), T8))          # a key with a torsion part of order 8
for i in (1, 4):
    r_enc = ed_encode(SMALL[i])
    msg = find_msg(f"small-order R {i}", r_enc, MIXED8, lambda k, _: ed_add(SMALL[i], ed_mul(k % 8, T8)) == IDENT)
    ed_case(f"small_order_r_{i}", f"R is a point of order {order(SMALL[i])}; the key's torsion part cancels it "
            "(check 3)", MIXED8, msg, r_enc, k_of(r_enc, MIXED8, msg)[0] * ED_A % L, False, True)

# 5. mixed-order keys pass the byte checks, so the verdict is the equation's: no cofactor, k reduced mod L
MIXED2 = ed_encode(ed_add(ed_mul(ED_A, BASE_PT), T2))
for name, desc, pub, want, valid in [
        ("mixed_key_torsion_cancels", "key = [a]B + (a point of order 2); k mod L is even, so the torsion part drops "
         "out", MIXED2, lambda k, _: k % 2 == 0, True),
        ("mixed_key_torsion_remains", "the same key; k mod L is odd. A verifier that multiplies by the cofactor "
         "would accept this", MIXED2, lambda k, _: k % 2 == 1, False),
        ("mixed_key_k_reduced_first", "the same key; k mod L is even but the unreduced 512-bit k is odd. Accepting "
         "it shows k is reduced before it multiplies the key", MIXED2, lambda k, full: k % 2 == 0 and full % 2 == 1,
         True),
        ("mixed_key_k_reduced_first_reject", "the same key; k mod L is odd but the unreduced k is even", MIXED2,
         lambda k, full: k % 2 == 1 and full % 2 == 0, False),
        ("mixed_key_order_8_cancels", "key = [a]B + (a point of order 8); k mod L is a multiple of 8", MIXED8,
         lambda k, _: k % 8 == 0, True),
        ("mixed_key_order_8_remains", "the same key; k mod L is 4 mod 8", MIXED8, lambda k, _: k % 8 == 4, False)]:
    r, r_pt = nonce_r(name)
    r_enc = ed_encode(r_pt)
    msg = find_msg(name, r_enc, pub, want)
    ed_case(name, desc, pub, msg, r_enc, (r + k_of(r_enc, pub, msg)[0] * ED_A) % L, valid, valid, cofactored=True)
r, r_pt = nonce_r("mixed-r")
r_enc = ed_encode(ed_add(r_pt, T2))
msg = find_msg("mixed R and key", r_enc, MIXED2, lambda k, _: k % 2 == 1)
ed_case("mixed_key_and_r", "R and the key both carry the point of order 2, and k mod L is odd, so the two cancel",
        MIXED2, msg, r_enc, (r + k_of(r_enc, MIXED2, msg)[0] * ED_A) % L, True, True, cofactored=True)
not_on_curve = next(bytes([y]) + bytes(31) for y in range(2, 256) if ed_decode(bytes([y]) + bytes(31), True) is None)
ed_case("key_not_on_curve", "the key's y is on no curve point: it passes the byte checks, and nothing verifies "
        "under it", not_on_curve, b"kinfold ed25519 edge case: not on the curve", ed_encode(nonce_r("off")[1]), 1,
        False, False)
assert not ed25519_key_invalid(not_on_curve) and not ed25519_key_invalid(MIXED2)

ed_keys = [dict(pub=ed_encode(t).hex(), invalid=True, note=f"order {order(t)}") for t in SMALL]
ed_keys += [dict(pub=c["pub"], invalid=True, note="non-canonical") for c in ed_cases
            if c["name"].startswith("noncanonical_key")]
ed_keys += [dict(pub=ED_PUB.hex(), invalid=False, note="an ordinary key"),
            dict(pub=MIXED2.hex(), invalid=False, note="mixed order: not caught by the byte checks, and allowed"),
            dict(pub=not_on_curve.hex(), invalid=False, note="not on the curve: no separate check (3.3)")]
for k in ed_keys:
    assert ed25519_key_invalid(bytes.fromhex(k["pub"])) == k["invalid"]

x_good = x25519_public(rnd("x25519/edge/sk"))
x_keys = [dict(pub=h, invalid=True, note=n) for h, n in [
    ("00" * 32, "0: low order"), ("01" + "00" * 31, "1: low order"),
    ("e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800", "low order"),
    ("5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157", "low order"),
    ("ec" + "ff" * 30 + "7f", "p - 1: low order"),
    ("ed" + "ff" * 30 + "7f", "p: not below p"), ("ee" + "ff" * 30 + "7f", "p + 1: not below p"),
    ("ff" * 31 + "7f", "2^255 - 1: not below p"),
    ((x_good[:31] + bytes([x_good[31] | 0x80])).hex(), "an ordinary key with the top bit set")]]
x_keys.append(dict(pub=x_good.hex(), invalid=False, note="an ordinary key"))
for k in x_keys:
    assert x25519_key_invalid(bytes.fromhex(k["pub"])) == k["invalid"], k

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
    protocol="kinfold/v0", status="draft 0.3", license="CC0-1.0",
    generated_by="reference/python/gen_vectors.py",
    conventions=["Byte strings are lowercase hex. Codes, links, URLs, names, digit codes and JSON text are plain "
                 "strings; decoded payloads are JSON objects.",
                 "Times are milliseconds since the Unix epoch, UTC.",
                 "Every secret and nonce here comes from SHA-256(\"kinfold-test-vector/\" || tag); "
                 "never reuse them outside tests."],
    primitives=prims, hpke_rfc9180=hpke_vec,
    ed25519=dict(signatures=ed_cases, keys=ed_keys), x25519=dict(keys=x_keys),
    identities={p.name: p.json() for p in (J, A, M, S, R)},
    log=dict(circle_id=CID.hex(), epoch_secrets={str(k): v.hex() for k, v in B.secrets.items()},
             entries=B.records, base_seq=BASE, final_seq=FINAL, cases=cases, state_hash=state_hash_vec),
    envelopes=dict(receiver_now=RECEIVER_NOW, valid=valid_envs, invalid=invalid_envs, replay=replay_case,
                   server_repost=server_repost, server_rejects=server_rejects),
    padding=dict(valid=padding, pad_to=pad_to_vec, invalid=unpad_invalid),
    approx=approx, safety_codes=safety, invite=invite_vec, device_link=link_vec, recovery_kits=recovery_vec,
    setup=setup_vec, server_moves=moves, share_link=share_vec, auth=auth_vec, watch_grants=grant_vec,
    push=push_vec)
Path(sys.argv[1]).write_text(json.dumps(out, indent=1, ensure_ascii=False) + "\n")
print("wrote", sys.argv[1], "entries", len(B.records), "cases", len(cases), "envelopes",
      len(valid_envs), "+", len(invalid_envs), "+", len(server_rejects), "ed25519", len(ed_cases))
