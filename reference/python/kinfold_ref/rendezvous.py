# SPDX-License-Identifier: Apache-2.0
"""Invites and joining (PROTOCOL.md section 9), linking devices and recovery kits
(section 10), share links (section 12)."""
import json

from .crypto import VERSION, H, aead_open, aead_seal, ed25519_public, hpke_open, hpke_seal, kdf, sign, verify
from .encoding import DecodeError, Reader, b64u, pad, u8, u64, unb64u, unpad, utf8, vec16, vec32
from .identity import (HOME_ASSISTANT, PHONE, TABLET, WEB, bundle_current, bundle_ok, cert_wellformed, chain_proves,
                       device_id, parse_chain, read_bundle, read_cert)
from .log import read_terms, terms_commit

ROLE_ADULT, ROLE_TEEN = 1, 2
JOIN_ADDED, JOIN_DECLINED = 1, 2


class RendezvousError(Exception):
    def __init__(self, reason):
        super().__init__(reason)
        self.reason = reason


# --- invites (section 9) ----------------------------------------------------------------

def make_invite(server_url, server_key, circle_id, secret, inviter_ik_pub, expires_at, reg_token, terms_salt,
                terms: bytes, circle_name: str, inviter_name: str, guardian_names) -> bytes:
    """terms: the MemberTerms bytes (log.enc_terms). guardian_names: one per guardian, in order."""
    return (u8(VERSION) + vec16(server_url.encode("utf-8")) + server_key + circle_id + secret
            + inviter_ik_pub + u64(expires_at) + vec16(reg_token) + terms_salt + terms
            + vec16(circle_name.encode("utf-8")) + vec16(inviter_name.encode("utf-8"))
            + vec16("\n".join(guardian_names).encode("utf-8")))


def parse_invite(b: bytes) -> dict:
    r = Reader(b)
    d = dict(version=r.u8(), server_url=utf8(r.vec16()), server_key=r.take(32), circle_id=r.take(16),
             secret=r.take(16), inviter_ik_pub=r.take(32), expires_at=r.u64(), reg_token=r.vec16(),
             terms_salt=r.take(16))
    start = r.pos
    d["terms"] = read_terms(r)
    d["terms_bytes"] = b[start:r.pos]
    d["circle_name"], d["inviter_name"] = utf8(r.vec16()), utf8(r.vec16())
    names = utf8(r.vec16())
    d["guardian_names"] = names.split("\n") if names else []
    r.end()
    if d["version"] != VERSION:
        raise DecodeError("invite version")
    return d


def invite_code(invite: bytes) -> str:
    return "KFI0" + b64u(invite)


def invite_link(link_base: str, invite: bytes) -> str:
    """link_base: the one HTTPS origin built into the app (9.1), never a family's own server."""
    return link_base + "/join#" + b64u(invite)


def invite_id(secret: bytes) -> bytes:
    return H("invite-id", secret)[:16]


def join_key(secret: bytes) -> bytes:
    return kdf(secret, "join-key", 32)


def join_result_key(secret: bytes) -> bytes:
    return kdf(secret, "join-result-key", 32)


def consent_sig(ik_seed, circle_id, inv_id, cert_raw, bundle_raw, commit) -> bytes:
    return sign(ik_seed, "join-consent", circle_id + inv_id + cert_raw + bundle_raw + commit)


def make_join_request(secret, cert_raw, chain: bytes, bundle_raw, commit, consent, name: str, nonce: bytes) -> bytes:
    iid = invite_id(secret)
    pt = cert_raw + vec16(chain) + bundle_raw + commit + consent + vec16(name.encode("utf-8"))
    head = u8(VERSION) + iid
    return head + nonce + vec32(aead_seal(join_key(secret), nonce, pt, head))


def open_join_request(invite: dict, msg: bytes, now: int) -> dict:
    """Run by the inviter's device before it shows the request. Raises RendezvousError."""
    try:
        r = Reader(msg)
        version, iid, nonce, ct = r.u8(), r.take(16), r.take(12), r.vec32()
        r.end()
    except DecodeError:
        raise RendezvousError("malformed")
    if version != VERSION or iid != invite_id(invite["secret"]):
        raise RendezvousError("wrong_invite")
    pt = aead_open(join_key(invite["secret"]), nonce, ct, msg[:17])
    if pt is None:
        raise RendezvousError("bad_ciphertext")
    try:
        r = Reader(pt)
        cert, chain, bundle = read_cert(r), parse_chain(r.vec16()), read_bundle(r)
        commit, consent, name = r.take(32), r.take(64), utf8(r.vec16())
        r.end()
    except DecodeError:
        raise RendezvousError("malformed")
    if not cert_wellformed(cert) or not chain_proves(cert, chain) or cert.kind not in (PHONE, TABLET):
        raise RendezvousError("bad_cert")
    if not bundle_ok(bundle, cert.dsk_pub, cert.account_id) or not bundle_current(bundle, now):
        raise RendezvousError("bad_bundle")
    if commit != terms_commit(invite["terms_salt"], invite["terms_bytes"]):
        raise RendezvousError("bad_terms")        # the invitee agreed to something else
    signed = invite["circle_id"] + iid + cert.raw + bundle.raw + commit
    if not verify(cert.ik_pub, "join-consent", signed, consent):
        raise RendezvousError("bad_consent")
    return dict(cert=cert, chain=b"".join(chain), bundle=bundle, terms_commit=commit, consent=consent, name=name)


def make_join_result(secret, outcome: int, head: bytes, nonce: bytes) -> bytes:
    hdr = u8(VERSION) + invite_id(secret)
    return hdr + nonce + vec32(aead_seal(join_result_key(secret), nonce, u8(outcome) + head, hdr))


def open_join_result(secret, msg: bytes) -> dict:
    try:
        r = Reader(msg)
        version, iid, nonce, ct = r.u8(), r.take(16), r.take(12), r.vec32()
        r.end()
    except DecodeError:
        raise RendezvousError("malformed")
    if version != VERSION or iid != invite_id(secret):
        raise RendezvousError("wrong_invite")
    pt = aead_open(join_result_key(secret), nonce, ct, msg[:17])
    if pt is None:
        raise RendezvousError("bad_ciphertext")
    if len(pt) != 33 or pt[0] not in (JOIN_ADDED, JOIN_DECLINED) or (pt[0] == JOIN_DECLINED and any(pt[1:])):
        raise RendezvousError("malformed")
    return dict(outcome=pt[0], head=pt[1:])


# --- linking devices (section 10) ------------------------------------------------------------

LINK_FROM_EXISTING, LINK_FROM_NEW = 1, 2
MSG_OFFER, MSG_REQUEST, MSG_COMMIT, MSG_NONCE = 1, 2, 3, 4
KINDS_FOR_DIRECTION = {LINK_FROM_EXISTING: (PHONE, TABLET), LINK_FROM_NEW: (WEB, HOME_ASSISTANT)}


def make_link(direction, server_url, server_key, secret, expires_at, account_id=b"", ik_pub=b"") -> bytes:
    out = u8(VERSION) + u8(direction) + vec16(server_url.encode("utf-8")) + server_key + secret + u64(expires_at)
    if direction == LINK_FROM_EXISTING:
        out += account_id + ik_pub
    return out


def parse_link(b: bytes) -> dict:
    r = Reader(b)
    d = dict(version=r.u8(), direction=r.u8(), server_url=utf8(r.vec16()), server_key=r.take(32),
             secret=r.take(16), expires_at=r.u64())
    if d["direction"] == LINK_FROM_EXISTING:
        d["account_id"], d["ik_pub"] = r.take(16), r.take(32)
    elif d["direction"] != LINK_FROM_NEW:
        raise DecodeError("link direction")
    r.end()
    if d["version"] != VERSION:
        raise DecodeError("link version")
    return d


def link_code_text(link: bytes) -> str:
    """What the QR code holds. It is never a URL (10.1)."""
    return "KFL0" + b64u(link)


def link_id(secret):
    return H("link-id", secret)[:16]


def link_key(secret):
    return kdf(secret, "link-key", 32)


def link_confirm(secret):
    return kdf(secret, "link-confirm", 16)


def link_seal(secret, msg_type, pt, nonce) -> bytes:
    """A LinkMessage: offer, commit, nonce or request."""
    head = u8(VERSION) + link_id(secret) + u8(msg_type)
    return head + nonce + vec32(aead_seal(link_key(secret), nonce, pt, head))


def link_open(secret, msg_type, msg) -> bytes:
    try:
        r = Reader(msg)
        version, lid, mt, nonce, ct = r.u8(), r.take(16), r.u8(), r.take(12), r.vec32()
        r.end()
    except DecodeError:
        raise RendezvousError("malformed")
    if version != VERSION or lid != link_id(secret) or mt != msg_type:
        raise RendezvousError("wrong_link")
    pt = aead_open(link_key(secret), nonce, ct, msg[:18])
    if pt is None:
        raise RendezvousError("bad_ciphertext")
    return pt


def open_link_offer(secret, msg) -> dict:
    pt = link_open(secret, MSG_OFFER, msg)
    if len(pt) != 48:
        raise RendezvousError("malformed")
    return dict(account_id=pt[:16], ik_pub=pt[16:])


def link_request_body(dsk_pub, kind, bundle_raw, name: str) -> bytes:
    return dsk_pub + u8(kind) + bundle_raw + vec16(name.encode("utf-8"))


def link_commit(secret, r_new: bytes, body: bytes) -> bytes:
    """What the new device posts first: it fixes its request before it sees r_old."""
    return H("link-commit", link_id(secret) + r_new + body)


def link_code(secret, r_old: bytes, r_new: bytes, body: bytes) -> str:
    v = int.from_bytes(H("link-code", link_id(secret) + r_old + r_new + body)[:4], "big")
    return f"{v % 1_000_000:06d}"


def open_link_request(secret, direction, account_id, commit_msg, r_old, request_msg, now) -> dict:
    """Run by the existing device once it holds the commit and the request (10.2 step 5)."""
    commit = link_open(secret, MSG_COMMIT, commit_msg)
    pt = link_open(secret, MSG_REQUEST, request_msg)
    if len(commit) != 32 or len(pt) < 32:
        raise RendezvousError("malformed")
    r_new, body = pt[:32], pt[32:]
    if link_commit(secret, r_new, body) != commit:
        raise RendezvousError("bad_commit")
    try:
        r = Reader(body)
        dsk_pub, kind, bundle, name = r.take(32), r.u8(), read_bundle(r), utf8(r.vec16())
        r.end()
    except DecodeError:
        raise RendezvousError("malformed")
    if kind not in KINDS_FOR_DIRECTION[direction]:
        raise RendezvousError("kind_not_allowed")
    if not bundle_ok(bundle, dsk_pub, account_id) or not bundle_current(bundle, now):
        raise RendezvousError("bad_bundle")
    return dict(dsk_pub=dsk_pub, kind=kind, bundle=bundle, name=name, code=link_code(secret, r_old, r_new, body))


def link_response_info(secret, new_device_id) -> bytes:
    return H("link-info", link_id(secret) + new_device_id)


def make_link_response(secret, sender_dsk_seed, sender_cert_raw, new_dek_pub, new_device_id,
                       payload: bytes, ikm_e: bytes) -> bytes:
    enc, ct = hpke_seal(new_dek_pub, link_response_info(secret, new_device_id), b"", payload, ikm_e)
    body = u8(VERSION) + link_id(secret) + sender_cert_raw + enc + vec32(ct)
    return body + sign(sender_dsk_seed, "link-response", body)


def open_link_response(secret, expected_ik_pub, msg, my_dek_sk, my_dsk_pub, my_kind, my_account_id) -> dict:
    """Run by the new device (10.3). my_account_id and expected_ik_pub come from the code
    (direction 1) or the offer (direction 2)."""
    my_device_id = device_id(my_dsk_pub)
    try:
        r = Reader(msg)
        version, lid, sender = r.u8(), r.take(16), read_cert(r)
        enc, ct, sig = r.take(32), r.vec32(), r.take(64)
        r.end()
    except DecodeError:
        raise RendezvousError("malformed")
    if version != VERSION or lid != link_id(secret):
        raise RendezvousError("wrong_link")
    if (not cert_wellformed(sender) or sender.kind not in (PHONE, TABLET)
            or sender.account_id != my_account_id or sender.ik_pub != expected_ik_pub):
        raise RendezvousError("bad_cert")
    if not verify(sender.dsk_pub, "link-response", msg[:-64], sig):
        raise RendezvousError("bad_signature")
    pt = hpke_open(enc, my_dek_sk, link_response_info(secret, my_device_id), b"", ct)
    if pt is None:
        raise RendezvousError("bad_ciphertext")
    try:
        obj = json.loads(pt.decode("utf-8"))
        if obj.get("confirm") != b64u(link_confirm(secret)):
            raise RendezvousError("bad_confirm")
        mine = read_cert(Reader(unb64u(obj["cert"])))
        if (not cert_wellformed(mine) or mine.dsk_pub != my_dsk_pub or mine.kind != my_kind
                or mine.account_id != my_account_id or mine.ik_pub != expected_ik_pub):
            raise RendezvousError("bad_cert")
        if "ik" in obj:                           # direction 1 only: the identity key and its chain
            chain = parse_chain(unb64u(obj.get("chain", "")))
            if ed25519_public(unb64u(obj["ik"])) != expected_ik_pub or not chain_proves(mine, chain):
                raise RendezvousError("bad_identity")
    except (ValueError, KeyError, TypeError):     # DecodeError is a ValueError
        raise RendezvousError("malformed")
    return obj


# --- recovery kit (section 10.4) -------------------------------------------------------------

def make_recovery_kit(server_url, server_key, account_id, ik_seed, chain: bytes, recovery_dsk_seed,
                      created_at) -> bytes:
    return (u8(VERSION) + vec16(server_url.encode("utf-8")) + server_key + account_id + ik_seed + vec16(chain)
            + recovery_dsk_seed + u64(created_at))


def recovery_code(kit: bytes) -> str:
    return "KFR0" + b64u(kit)


def parse_recovery_kit(b: bytes) -> dict:
    r = Reader(b)
    d = dict(version=r.u8(), server_url=utf8(r.vec16()), server_key=r.take(32), account_id=r.take(16),
             ik_seed=r.take(32), chain=parse_chain(r.vec16()), recovery_dsk_seed=r.take(32), created_at=r.u64())
    r.end()
    if d["version"] != VERSION:
        raise DecodeError("recovery kit version")
    return d


# --- share links (section 12) ----------------------------------------------------------------

def share_id(secret):
    return H("share-id", secret)[:16]


def share_key(secret):
    return kdf(secret, "share-key", 32)


def share_url(server_url, secret) -> str:
    return f"{server_url}/s/{b64u(share_id(secret))}#{b64u(secret)}"


def make_share_update(secret, seq, expires_at, payload: bytes, nonce) -> bytes:
    head = u8(VERSION) + share_id(secret) + u64(seq) + u64(expires_at)
    return head + nonce + vec32(aead_seal(share_key(secret), nonce, pad(payload), head))


def open_share_update(secret, msg) -> dict:
    try:
        r = Reader(msg)
        version, sid, seq, exp, nonce, ct = r.u8(), r.take(16), r.u64(), r.u64(), r.take(12), r.vec32()
        r.end()
    except DecodeError:
        raise RendezvousError("malformed")
    if version != VERSION or sid != share_id(secret):
        raise RendezvousError("wrong_link")
    padded = aead_open(share_key(secret), nonce, ct, msg[:33])
    if padded is None:
        raise RendezvousError("bad_ciphertext")
    p = unpad(padded)
    if p is None:
        raise RendezvousError("bad_padding")
    return dict(seq=seq, expires_at=exp, payload=json.loads(p.decode("utf-8")))
