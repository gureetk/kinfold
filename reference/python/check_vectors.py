#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Check every group in spec/vectors/kinfold-v0.json against the reference
implementation, using only the parse / verify / open paths (no builders except
where a group is explicitly deterministic). Exit status 1 on any failure.

Usage: check_vectors.py spec/vectors/kinfold-v0.json
"""
import hashlib
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from kinfold_ref import envelope as ev  # noqa: E402
from kinfold_ref import identity as idn  # noqa: E402
from kinfold_ref import log as lg  # noqa: E402
from kinfold_ref import rendezvous as rv  # noqa: E402
from kinfold_ref.crypto import (aead_seal, ed25519_public, hkdf_expand, hkdf_extract, hpke_open,  # noqa: E402
                                hpke_setup_sender, verify, x25519_public)
from kinfold_ref.encoding import Reader, b64u, unb64u, vec16  # noqa: E402

v = json.load(open(sys.argv[1]))
hx = bytes.fromhex
counts, failures = {}, []


def check(group, name, cond):
    counts[group] = counts.get(group, 0) + 1
    if not cond:
        failures.append(f"{group}: {name}")


# --- primitives --------------------------------------------------------------------------
P = v["primitives"]
for t in P["H"]:
    check("primitives", "H", hashlib.sha256(vec16(t["label"].encode()) + hx(t["data"])).hexdigest() == t["out"])
for t in P["kdf"]:
    out = hkdf_expand(hkdf_extract(b"", hx(t["ikm"])), vec16(t["label"].encode()), t["length"])
    check("primitives", "kdf", out.hex() == t["out"])
for t in P["sign"]:
    pub = ed25519_public(hx(t["seed"]))
    check("primitives", "sign", verify(pub, t["label"][len(P["label_prefix"]):], hx(t["data"]), hx(t["sig"])))
for t in P["b64u"]:
    check("primitives", "b64u", b64u(hx(t["bytes"])) == t["text"] and unb64u(t["text"]) == hx(t["bytes"]))

# --- HPKE (RFC 9180) ------------------------------------------------------------------------
R = {k: hx(x) for k, x in v["hpke_rfc9180"].items() if isinstance(x, str) and k != "source"}
enc, ss, key, nonce = hpke_setup_sender(R["pkRm"], R["info"], R["ikmE"])
check("hpke", "setup", (enc, ss, key, nonce) == (R["enc"], R["shared_secret"], R["key"], R["base_nonce"]))
for i, e in enumerate(v["hpke_rfc9180"]["encryptions"]):
    n = bytes(a ^ b for a, b in zip(nonce, i.to_bytes(12, "big")))
    check("hpke", f"seal {i}", aead_seal(key, n, hx(e["pt"]), hx(e["aad"])).hex() == e["ct"])
e0 = v["hpke_rfc9180"]["encryptions"][0]
check("hpke", "open", hpke_open(R["enc"], R["skRm"], R["info"], hx(e0["aad"]), hx(e0["ct"])) == hx(e0["pt"]))

# --- identities ------------------------------------------------------------------------------
devices, dek_sk = {}, {}
for name, p in v["identities"].items():
    ik_pub = ed25519_public(hx(p["ik_seed"]))
    check("identities", name, ik_pub.hex() == p["ik_pub"] and idn.account_id(ik_pub).hex() == p["account_id"])
    for d in p["devices"].values():
        dsk_pub = ed25519_public(hx(d["dsk_seed"]))
        cert = idn.read_cert(Reader(hx(d["cert"])))
        check("identities", d["label"], dsk_pub.hex() == d["dsk_pub"] and idn.device_id(dsk_pub).hex() == d["device_id"]
              and idn.cert_ok(cert) and cert.dsk_pub == dsk_pub and cert.kind == d["kind"])
        for k in d["deks"]:
            check("identities", d["label"] + " dek", x25519_public(hx(k["sk"])).hex() == k["pub"]
                  and idn.key_id(hx(k["pub"])).hex() == k["key_id"])
            dek_sk[hx(k["key_id"])] = hx(k["sk"])
        for b in d["bundles"]:
            bu = idn.read_bundle(Reader(hx(b)))
            check("identities", d["label"] + " bundle", idn.bundle_ok(bu, dsk_pub, hx(p["account_id"])))
        devices[d["label"]] = d

# --- member log ---------------------------------------------------------------------------------
L = v["log"]
secrets = {int(k): hx(x) for k, x in L["epoch_secrets"].items()}
raws = [hx(e["raw"]) for e in L["entries"]]


def run(state, pstate, entry, secs, tag):
    raw = hx(entry["raw"])
    try:
        new, res, why = lg.apply(state, raw, secs)
    except lg.Fatal as f:
        new, res, why = state, "fatal", f.reason
    try:
        pnew, pres, pwhy = lg.apply(pstate, raw, None)
    except lg.Fatal as f:
        pnew, pres, pwhy = pstate, "fatal", f.reason
    check("log", f"{tag} result", (res, why) == (entry["result"], entry["reason"]))
    check("log", f"{tag} public result", (pres, pwhy) == (entry["public_result"], entry["public_reason"]))
    check("log", f"{tag} hash", lg.entry_hash(raw).hex() == entry["hash"])
    if "state_after" in entry:
        check("log", f"{tag} state", lg.state_json(new) == entry["state_after"])
        check("log", f"{tag} public state",
              lg.state_json(pnew, private=False) == {k: x for k, x in lg.state_json(new, private=False).items()})
    if "new_epoch_secret" in entry and res != "fatal":
        body = lg.parse_body(raw[3], lg.parse_entry(raw).body_bytes)
        e = lg.parse_entry(raw)
        for rid, kid, enc_, ct in body["wraps"]:
            info = lg.epoch_wrap_info(e.circle_id, e.seq, e.prev_hash, entry["new_epoch"], rid, kid)
            got = hpke_open(enc_, dek_sk[kid], info, b"", ct)
            check("log", f"{tag} epoch wrap", got == hx(entry["new_epoch_secret"])
                  and lg.epoch_commit(entry["new_epoch"], got) == body["commit"])
    return (new, pnew) if res != "fatal" else (state, pstate)


st, pst = lg.State(), lg.State()
for e in L["entries"]:
    st, pst = run(st, pst, e, secrets, f"seq {e['seq']}")
check("log", "circle_id", st.circle_id.hex() == L["circle_id"])
for c in L["cases"]:
    s0, p0 = lg.replay(raws, secrets, upto=c["base_seq"])[0], lg.replay(raws, None, upto=c["base_seq"])[0]
    secs = {**secrets, **{int(k): hx(x) for k, x in c.get("new_epoch_secrets", {}).items()}}
    for e in c["entries"]:
        s0, p0 = run(s0, p0, e, secs, c["name"])

# --- envelopes ---------------------------------------------------------------------------------
E = v["envelopes"]
NOW = E["receiver_now"]
SERVER_REASONS = {"malformed", "bad_version", "bad_kind", "wrong_circle", "unknown_log_head", "sender_not_active",
                  "bad_signature", "expired", "replay", "bad_wraps", "bad_ttl"}
keys = lambda d: {hx(a): hx(b) for a, b in d.items()}


def server(raw, state, seen=None):
    try:
        ev.server_check(raw, state, NOW, set() if seen is None else seen)
        return None
    except ev.EnvelopeError as e:
        return e.reason
for t in E["valid"]:
    state = lg.replay(raws, secrets, upto=t["log_seq"])[0]
    raw = hx(t["raw"])
    for r in t["recipients"]:
        got = ev.open_envelope(raw, state, hx(r["device_id"]), keys(r["keys"]), set(), NOW)
        check("envelopes", f"{t['name']} -> {r['device']}", got == r["payload"])
    check("envelopes", f"{t['name']} server", server(raw, state) is None)
    # deterministic rebuild ("seal" test): optional for platforms that cannot fix the HPKE ephemeral key
    sender = devices[t["sender"]]
    hdr = ev.env_header(t["kind"], state.circle_id, hx(sender["device_id"]), t["seq"], t["sent_at"], t["ttl_s"],
                        hx(t["log_head"]))
    recips = [(hx(r["device_id"]), x25519_public(next(iter(keys(r["keys"]).values())))) for r in t["recipients"]]
    rebuilt = ev.build_envelope(hx(sender["dsk_seed"]), hdr, recips, hx(t["payload_bytes"]), hx(t["message_secret"]),
                                lambda rid: hx(t["wrap_ikm"][rid.hex()]))
    check("envelopes", f"{t['name']} rebuild", rebuilt == raw and len(ev.pad(hx(t["payload_bytes"]))) == t["padded_length"])
for t in E["invalid"]:
    state = lg.replay(raws, secrets, upto=t["log_seq"])[0]
    try:
        ev.open_envelope(hx(t["raw"]), state, hx(t["receiver_device_id"]), keys(t["receiver_keys"]), set(), NOW)
        got = "ok"
    except ev.EnvelopeError as e:
        got = e.reason
    check("envelopes", t["name"], got == t["error"])
    check("envelopes", t["name"] + " server",
          server(hx(t["raw"]), state) == (t["error"] if t["error"] in SERVER_REASONS else None))
for t in E["server_rejects"]:
    state = lg.replay(raws, secrets, upto=t["log_seq"])[0]
    check("envelopes", t["name"] + " server", server(hx(t["raw"]), state) == t["server_error"])
    got = ev.open_envelope(hx(t["raw"]), state, hx(t["receiver_device_id"]), keys(t["receiver_keys"]), set(), NOW)
    check("envelopes", t["name"] + " client", got == t["payload"])
t = E["replay"]
state, seen, got = lg.replay(raws, secrets, upto=t["log_seq"])[0], set(), []
for raw in t["sequence"]:
    try:
        ev.open_envelope(hx(raw), state, hx(t["receiver_device_id"]), keys(t["receiver_keys"]), seen, NOW)
        got.append("ok")
    except ev.EnvelopeError as e:
        got.append(e.reason)
check("envelopes", "replay", got == t["results"])

# --- padding, approximate positions, safety codes ------------------------------------------------------
for t in v["padding"]["valid"]:
    p = ev.pad(hx(t["payload_byte"]) * t["payload_length"])
    check("padding", f"len {t['payload_length']}", len(p) == t["padded_length"]
          and hashlib.sha256(p).hexdigest() == t["padded_sha256"] and ev.unpad(p) == hx(t["payload_byte"]) * t["payload_length"])
for t in v["padding"]["invalid"]:
    check("padding", t["description"], ev.unpad(hx(t["padded"])) is None)
for t in v["approx"]:
    check("approx", f"{t['lat']},{t['lon']}", ev.approx_e7(t["lat"], t["lon"]) == (t["approx_lat"], t["approx_lon"]))
for t in v["safety_codes"]:
    a, b = hx(t["ik_pub_a"]), hx(t["ik_pub_b"])
    check("safety", t["a"] + "/" + t["b"], idn.safety_half(a) == t["half_a"] and idn.safety_half(b) == t["half_b"]
          and idn.safety_code(a, b) == t["code"] == idn.safety_code(b, a) and idn.safety_qr(a, b) == t["qr"])

# --- invite and join ------------------------------------------------------------------------------------
I = v["invite"]
inv = rv.parse_invite(hx(I["invite"]))
f = I["fields"]
check("invite", "fields", inv["server_url"] == f["server_url"] and inv["server_key"].hex() == f["server_key"]
      and inv["circle_id"].hex() == f["circle_id"] and inv["secret"].hex() == f["secret"]
      and inv["inviter_ik_pub"].hex() == f["inviter_ik_pub"] and inv["role_hint"] == f["role_hint"]
      and inv["expires_at"] == f["expires_at"] and inv["reg_token"].hex() == f["reg_token"])
check("invite", "links", rv.invite_links(inv["server_url"], hx(I["invite"])) == (I["app_link"], I["web_link"])
      and unb64u(I["app_link"].split("/")[-1]) == hx(I["invite"]))
check("invite", "ids", rv.invite_id(inv["secret"]).hex() == I["invite_id"] and rv.join_key(inv["secret"]).hex() == I["join_key"])
j = rv.open_join_request(inv, hx(I["join_request"]["message"]))
check("invite", "join request", j["name"] == "Maya" and j["cert"].raw.hex() == I["join_request"]["cert"]
      and j["consent"].hex() == I["join_request"]["consent"])
entry = lg.parse_entry(raws[I["log_entry_seq"]])
body = lg.parse_body(entry.type, entry.body_bytes)
check("invite", "log entry", body["invite_id"].hex() == I["invite_id"] and body["consent"] == j["consent"])

# --- device linking ------------------------------------------------------------------------------------
D = v["device_link"]["from_existing"]
lk = rv.parse_link(hx(D["link"]))
secret = lk["secret"]
check("link", "ids", rv.link_id(secret).hex() == D["link_id"] and rv.link_key(secret).hex() == D["link_key"]
      and rv.link_confirm(secret).hex() == D["confirm"] and D["app_link"] == "kinfold://link/" + b64u(hx(D["link"])))
req = rv.open_link_request(secret, lk["account_id"], hx(D["request"]))
check("link", "request", req["code"] == D["code"] and req["name"] == "Jordan's iPad")
nd = devices[D["new_device"]]
resp = rv.open_link_response(secret, lk["ik_pub"], hx(D["response"]), hx(D["new_device_dek_sk"]), hx(nd["device_id"]))
check("link", "response", resp == json.loads(D["response_payload"]) and unb64u(resp["cert"]) == hx(nd["cert"]))
W = v["device_link"]["from_new"]
lw = rv.parse_link(hx(W["link"]))
offer = rv.open_link_offer(lw["secret"], hx(W["offer"]))
check("link", "offer", lw["direction"] == 2 and offer["account_id"].hex() == W["account_id"]
      and offer["ik_pub"].hex() == W["ik_pub"])
wreq = rv.open_link_request(lw["secret"], offer["account_id"], hx(W["request"]))
check("link", "web request", wreq["code"] == W["code"] and wreq["kind"] == 3)
wd = devices[W["new_device"]]
wresp = rv.open_link_response(lw["secret"], offer["ik_pub"], hx(W["response"]), hx(W["new_device_dek_sk"]),
                              hx(wd["device_id"]))
check("link", "web response", wresp == json.loads(W["response_payload"]) and "ik" not in wresp)

# --- share link, server identity, login ---------------------------------------------------------------
SH = v["share_link"]
s = hx(SH["secret"])
check("share", "ids", rv.share_id(s).hex() == SH["link_id"] and rv.share_key(s).hex() == SH["share_key"]
      and rv.share_url("https://family.example", s) == SH["url"])
u = rv.open_share_update(s, hx(SH["update"]["message"]))
check("share", "update", u["payload"] == SH["update"]["payload"] and u["seq"] == 1
      and json.loads(hx(SH["payload_bytes"])) == SH["update"]["payload"]
      and rv.share_url(SH["server_url"], s) == SH["url"])
AU = v["auth"]
info = idn.parse_server_info(hx(AU["server_info"]))
check("auth", "server info", info["sig_ok"] and info["server_key"].hex() == AU["server_key"] and info["url"] == AU["server_url"])
ch, did, sk = hx(AU["challenge"]), hx(AU["device_id"]), hx(AU["server_key"])
check("auth", "challenge", verify(sk, "auth-challenge", ch + did + AU["expires_at"].to_bytes(8, "big"), hx(AU["challenge_sig"])))
dsk_pub = hx(devices[AU["device"]]["dsk_pub"])
check("auth", "device", verify(dsk_pub, "auth", sk + ch + did, hx(AU["device_sig"])))

for g, n in counts.items():
    print(f"{g:12} {n:4} checks")
if failures:
    print("\n".join(["FAILED:"] + failures))
    sys.exit(1)
print("all", sum(counts.values()), "checks passed")
