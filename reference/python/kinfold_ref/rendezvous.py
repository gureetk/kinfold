# SPDX-License-Identifier: Apache-2.0
"""Invites and joining (PROTOCOL.md section 9), linking devices (section 10),
share links (section 12)."""
import json

from .crypto import VERSION, H, aead_open, aead_seal, hpke_open, hpke_seal, kdf, sign, verify
from .encoding import DecodeError, Reader, b64u, u8, u64, utf8, vec16, vec32
from .envelope import pad, unpad
from .identity import CERT_LEN, bundle_ok, cert_ok, read_bundle, read_cert

ROLE_ADULT, ROLE_TEEN = 1, 2


class RendezvousError(Exception):
    def __init__(self, reason):
        super().__init__(reason)
        self.reason = reason


# --- invites (section 9) ----------------------------------------------------------------

def make_invite(server_url, server_key, circle_id, secret, inviter_ik_pub, role_hint, expires_at,
                reg_token=b"") -> bytes:
    return (u8(VERSION) + vec16(server_url.encode("utf-8")) + server_key + circle_id + secret
            + inviter_ik_pub + u8(role_hint) + u64(expires_at) + vec16(reg_token))


def parse_invite(b: bytes) -> dict:
    r = Reader(b)
    d = dict(version=r.u8(), server_url=utf8(r.vec16()), server_key=r.take(32), circle_id=r.take(16),
             secret=r.take(16), inviter_ik_pub=r.take(32), role_hint=r.u8(), expires_at=r.u64(),
             reg_token=r.vec16())
    r.end()
    if d["version"] != VERSION or d["role_hint"] not in (ROLE_ADULT, ROLE_TEEN):
        raise DecodeError("invite version or role")
    return d


def invite_links(server_url: str, invite: bytes):
    code = b64u(invite)
    return "kinfold://join/" + code, server_url + "/join#" + code


def invite_id(secret: bytes) -> bytes:
    return H("invite-id", secret)[:16]


def join_key(secret: bytes) -> bytes:
    return kdf(secret, "join-key", 32)


def consent_sig(ik_seed, circle_id, inv_id, cert_raw, bundle_raw) -> bytes:
    return sign(ik_seed, "join-consent", circle_id + inv_id + cert_raw + bundle_raw)


def make_join_request(secret, cert_raw, bundle_raw, consent, name: str, nonce: bytes) -> bytes:
    iid = invite_id(secret)
    pt = cert_raw + bundle_raw + consent + vec16(name.encode("utf-8"))
    head = u8(VERSION) + iid
    return head + nonce + vec32(aead_seal(join_key(secret), nonce, pt, head))


def open_join_request(invite: dict, msg: bytes) -> dict:
    """Run by the inviter's device. Raises RendezvousError."""
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
        cert, bundle, consent, name = read_cert(r), read_bundle(r), r.take(64), utf8(r.vec16())
        r.end()
    except DecodeError:
        raise RendezvousError("malformed")
    if not cert_ok(cert) or not bundle_ok(bundle, cert.dsk_pub, cert.account_id):
        raise RendezvousError("bad_cert")
    if not verify(cert.ik_pub, "join-consent", invite["circle_id"] + iid + cert.raw + bundle.raw, consent):
        raise RendezvousError("bad_consent")
    return dict(cert=cert, bundle=bundle, consent=consent, name=name)


# --- linking devices (section 10) ------------------------------------------------------------

LINK_FROM_EXISTING, LINK_FROM_NEW = 1, 2
MSG_OFFER, MSG_REQUEST = 1, 2


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


def link_id(secret):
    return H("link-id", secret)[:16]


def link_key(secret):
    return kdf(secret, "link-key", 32)


def link_confirm(secret):
    return kdf(secret, "link-confirm", 16)


def _link_seal(secret, msg_type, pt, nonce) -> bytes:
    head = u8(VERSION) + link_id(secret) + u8(msg_type)
    return head + nonce + vec32(aead_seal(link_key(secret), nonce, pt, head))


def _link_open(secret, msg_type, msg) -> bytes:
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


def make_link_offer(secret, account_id, ik_pub, nonce) -> bytes:
    return _link_seal(secret, MSG_OFFER, account_id + ik_pub, nonce)


def open_link_offer(secret, msg) -> dict:
    pt = _link_open(secret, MSG_OFFER, msg)
    if len(pt) != 48:
        raise RendezvousError("malformed")
    return dict(account_id=pt[:16], ik_pub=pt[16:])


def link_request_plaintext(dsk_pub, kind, bundle_raw, name: str) -> bytes:
    return dsk_pub + u8(kind) + bundle_raw + vec16(name.encode("utf-8"))


def make_link_request(secret, plaintext, nonce) -> bytes:
    return _link_seal(secret, MSG_REQUEST, plaintext, nonce)


def open_link_request(secret, account_id, msg) -> dict:
    pt = _link_open(secret, MSG_REQUEST, msg)
    try:
        r = Reader(pt)
        dsk_pub, kind, bundle, name = r.take(32), r.u8(), read_bundle(r), utf8(r.vec16())
        r.end()
    except DecodeError:
        raise RendezvousError("malformed")
    if not bundle_ok(bundle, dsk_pub, account_id):
        raise RendezvousError("bad_bundle")
    return dict(dsk_pub=dsk_pub, kind=kind, bundle=bundle, name=name, code=link_code(secret, pt))


def link_code(secret, request_plaintext) -> str:
    v = int.from_bytes(H("link-code", link_id(secret) + request_plaintext)[:4], "big")
    return f"{v % 1_000_000:06d}"


def link_response_info(secret, new_device_id) -> bytes:
    return H("link-info", link_id(secret) + new_device_id)


def make_link_response(secret, sender_dsk_seed, sender_cert_raw, new_dek_pub, new_device_id,
                       payload: bytes, ikm_e: bytes) -> bytes:
    enc, ct = hpke_seal(new_dek_pub, link_response_info(secret, new_device_id), b"", payload, ikm_e)
    body = u8(VERSION) + link_id(secret) + sender_cert_raw + enc + vec32(ct)
    return body + sign(sender_dsk_seed, "link-response", body)


def open_link_response(secret, expected_ik_pub, msg, my_dek_sk, my_device_id) -> dict:
    try:
        r = Reader(msg)
        version, lid, cert, enc, ct, sig = r.u8(), r.take(16), read_cert(r), r.take(32), r.vec32(), r.take(64)
        r.end()
    except DecodeError:
        raise RendezvousError("malformed")
    if version != VERSION or lid != link_id(secret):
        raise RendezvousError("wrong_link")
    if not cert_ok(cert) or cert.ik_pub != expected_ik_pub:
        raise RendezvousError("bad_cert")
    if not verify(cert.dsk_pub, "link-response", msg[:-64], sig):
        raise RendezvousError("bad_signature")
    pt = hpke_open(enc, my_dek_sk, link_response_info(secret, my_device_id), b"", ct)
    if pt is None:
        raise RendezvousError("bad_ciphertext")
    obj = json.loads(pt.decode("utf-8"))
    if obj.get("confirm") != b64u(link_confirm(secret)):
        raise RendezvousError("bad_confirm")
    return obj


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
