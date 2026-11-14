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
from kinfold_ref import push as ps  # noqa: E402
from kinfold_ref import rendezvous as rv  # noqa: E402
from kinfold_ref.crypto import (aead_seal, ed25519_key_invalid, ed25519_public, hkdf_expand, hkdf_extract,  # noqa: E402
                                hpke_open, hpke_setup_sender, verify, verify_raw, x25519_key_invalid, x25519_public)
from kinfold_ref.encoding import Reader, b64u, pad_to, unb64u, unpad, vec16  # noqa: E402

v = json.load(open(sys.argv[1]))
hx = bytes.fromhex
counts, failures = {}, []


def check(group, name, cond):
    counts[group] = counts.get(group, 0) + 1
    if not cond:
        failures.append(f"{group}: {name}")


def refused(fn, exc):
    try:
        fn()
        return False
    except exc:
        return True


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

# --- Ed25519 and X25519 edge cases (3.3, 3.5) ---------------------------------------------------
for t in v["ed25519"]["signatures"]:
    check("ed25519", t["name"], verify_raw(hx(t["pub"]), hx(t["msg"]), hx(t["sig"])) == t["valid"])
for t in v["ed25519"]["keys"]:
    check("ed25519", "key " + t["pub"][:16], ed25519_key_invalid(hx(t["pub"])) == t["invalid"])
for t in v["x25519"]["keys"]:
    check("x25519", "key " + t["pub"][:16], x25519_key_invalid(hx(t["pub"])) == t["invalid"])

# --- identities ------------------------------------------------------------------------------
devices, dek_sk, dek_pub = {}, {}, {}
for name, p in v["identities"].items():
    ik_pub = ed25519_public(hx(p["ik_seed"]))
    acc = idn.account_id(ed25519_public(hx(p["ik_seeds"][0])))
    chain = idn.parse_chain(hx(p["chain"]))
    check("identities", name, ik_pub.hex() == p["ik_pub"] and acc.hex() == p["account_id"]
          and [ed25519_public(hx(s)).hex() for s in p["ik_seeds"]] == p["ik_pubs"]
          and len(chain) == len(p["ik_seeds"]) - 1)
    for d in p["devices"].values():
        dsk_pub = ed25519_public(hx(d["dsk_seed"]))
        cert = idn.read_cert(Reader(hx(d["cert"])))
        check("identities", d["label"], dsk_pub.hex() == d["dsk_pub"] and idn.device_id(dsk_pub).hex() == d["device_id"]
              and idn.cert_wellformed(cert) and cert.dsk_pub == dsk_pub and cert.kind == d["kind"]
              and cert.account_id == acc and cert.ik_pub == ik_pub and idn.chain_proves(cert, chain))
        for k in d["deks"]:
            check("identities", d["label"] + " dek", x25519_public(hx(k["sk"])).hex() == k["pub"]
                  and idn.key_id(hx(k["pub"])).hex() == k["key_id"])
            dek_sk[hx(k["key_id"])] = hx(k["sk"])
            dek_pub[hx(k["key_id"])] = hx(k["pub"])
        for b in d["bundles"]:
            bu = idn.read_bundle(Reader(hx(b)))
            check("identities", d["label"] + " bundle", idn.bundle_ok(bu, dsk_pub, acc))
        check("identities", d["label"] + " recovery has no key", d["kind"] != idn.RECOVERY or not d["deks"])
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
              lg.state_json(pnew, private=False) == lg.state_json(new, private=False))
    if "new_epoch_secret" in entry and res != "fatal":
        e = lg.parse_entry(raw)
        body = lg.parse_body(e.type, e.body_bytes)
        for rid, kid, enc_, ct in body["wraps"]:
            info = lg.epoch_wrap_info(e.circle_id, e.seq, e.prev_hash, entry["new_epoch"], rid, kid)
            got = hpke_open(enc_, dek_sk[kid], info, b"", ct)
            check("log", f"{tag} epoch wrap", got == hx(entry["new_epoch_secret"])
                  and lg.epoch_commit(entry["new_epoch"], got) == body["commit"])
    if "terms_commit" in entry and res != "fatal":
        check("log", f"{tag} terms", lg.terms_commit(hx(entry["terms_salt"]), hx(entry["terms"])).hex()
              == entry["terms_commit"])
    return (new, pnew) if res != "fatal" else (state, pstate)


st, pst = lg.State(), lg.State()
for e in L["entries"]:
    st, pst = run(st, pst, e, secrets, f"seq {e['seq']}")
check("log", "circle_id", st.circle_id.hex() == L["circle_id"])
check("log", "final_seq", st.seq == L["final_seq"])
SH = L["state_hash"]
at = lg.replay(raws, secrets, upto=SH["log_seq"])[0]
check("log", "state bytes", lg.state_bytes(at).hex() == SH["state_bytes"] and lg.state_hash(at).hex() == SH["state_hash"])
# 6.5, beyond the vector file: a secret that doesn't match the log's commitment is discarded, so the
# first entry that needs it is deferred, and so is everything after it. It never becomes bad_details.
entries = [lg.parse_entry(raw) for raw in raws]
for epoch, wrong in ((0, secrets[2]), (2, secrets[1])):
    s0, got = lg.State(), []
    for raw in raws:
        s0, res, why = lg.apply(s0, raw, {**secrets, epoch: wrong})
        got.append((res, why))
    first = next(i for i, e in enumerate(entries) if e.epoch == epoch and e.type in (lg.GENESIS, lg.ADD_MEMBER, lg.POLICY))
    check("log", f"a wrong epoch-{epoch} secret is discarded",
          got[:first] == [(e["result"], e["reason"]) for e in L["entries"][:first]]
          and all(g == ("deferred", None) for g in got[first:]) and s0.private_unknown_from == first
          and lg.state_json(s0, private=False) == lg.state_json(st, private=False))
for c in L["cases"]:
    s0, p0 = lg.replay(raws, secrets, upto=c["base_seq"])[0], lg.replay(raws, None, upto=c["base_seq"])[0]
    secs = {**secrets, **{int(k): hx(x) for k, x in c.get("new_epoch_secrets", {}).items()}}
    for w in c.get("withheld_epochs", []):
        secs.pop(w, None)            # the device under test never received this secret (6.5)
    for e in c["entries"]:
        s0, p0 = run(s0, p0, e, secs, c["name"])

# --- envelopes ---------------------------------------------------------------------------------
E = v["envelopes"]
NOW = E["receiver_now"]
keys = lambda d: {hx(a): hx(b) for a, b in d.items()}
states = {}


def state_at(seq):
    if seq not in states:
        states[seq] = lg.replay(raws, secrets, upto=seq)[0]
    return states[seq]


def server(raw, state, seen=None):
    try:
        ev.server_check(raw, state, NOW, {} if seen is None else seen)
        return None
    except ev.EnvelopeError as e:
        return e.reason


def client(raw, state, device_id, ks, seen=None):
    try:
        return ev.open_envelope(raw, state, device_id, ks, set() if seen is None else seen, NOW)
    except ev.EnvelopeError as e:
        return e.reason


for t in E["valid"]:
    state, raw = state_at(t["log_seq"]), hx(t["raw"])
    for r in t["recipients"]:
        check("envelopes", f"{t['name']} -> {r['device']}",
              client(raw, state, hx(r["device_id"]), keys(r["keys"])) == t["payload"])
    check("envelopes", f"{t['name']} server", server(raw, state) is None)
    # deterministic rebuild ("seal" test): optional for platforms that cannot fix the HPKE ephemeral key
    env = ev.parse_envelope(raw)
    hdr = ev.env_header(t["kind"], state.circle_id, hx(devices[t["sender"]]["device_id"]), t["seq"], t["sent_at"],
                        t["ttl_s"], hx(t["log_head"]))
    recips = [(rid, dek_pub[kid]) for rid, kid, _, _ in env["wraps"]]
    rebuilt = ev.build_envelope(hx(devices[t["sender"]]["dsk_seed"]), hdr, recips, hx(t["payload_bytes"]),
                                hx(t["message_secret"]), lambda rid: hx(t["wrap_ikm"][rid.hex()]))
    check("envelopes", f"{t['name']} rebuild", rebuilt == raw and len(ev.pad(hx(t["payload_bytes"]))) == t["padded_length"])
for t in E["invalid"]:
    state = state_at(t["log_seq"])
    check("envelopes", t["name"],
          client(hx(t["raw"]), state, hx(t["receiver_device_id"]), keys(t["receiver_keys"])) == t["error"])
    check("envelopes", t["name"] + " server", server(hx(t["raw"]), state) == t["server_error"])
for t in E["server_rejects"]:
    state = state_at(t["log_seq"])
    check("envelopes", t["name"] + " server", server(hx(t["raw"]), state) == t["server_error"])
    check("envelopes", t["name"] + " client",
          client(hx(t["raw"]), state, hx(t["receiver_device_id"]), keys(t["receiver_keys"])) == t["payload"])
t = E["replay"]
seen, got = set(), []
for raw in t["sequence"]:
    out = client(hx(raw), state_at(t["log_seq"]), hx(t["receiver_device_id"]), keys(t["receiver_keys"]), seen)
    got.append(out if isinstance(out, str) else "ok")
check("envelopes", "replay", got == t["results"])
t = E["server_repost"]
seen, got = {}, []
for raw in t["sequence"]:
    try:
        got.append(ev.server_check(hx(raw), state_at(t["log_seq"]), NOW, seen))
    except ev.EnvelopeError as e:
        got.append(e.reason)
check("envelopes", "server repost", got == t["results"])

# 7.6, beyond the vector file: a device whose private state is frozen (6.5) holds the payloads whose
# sender rule needs roles, and opens them once it has caught up. Rules that need no roles still apply.
frozen = lg.replay(raws, {0: secrets[0]})[0]
by_name = {t["name"]: t for t in E["valid"] + E["invalid"]}


def held(name):
    t = by_name[name]
    r = t["recipients"][0] if "recipients" in t else dict(device_id=t["receiver_device_id"], keys=t["receiver_keys"])
    try:
        ev.open_envelope(hx(t["raw"]), frozen, hx(r["device_id"]), keys(r["keys"]), set(), NOW)
        return False
    except ev.Held:
        return True
    except ev.EnvelopeError:
        return False


check("envelopes", "frozen state", frozen.private_unknown_from is not None)
for name in ("f9", "f8", "not_allowed_pause_request_from_adult", "not_allowed_place_id_mismatch"):
    check("envelopes", f"held while frozen: {name}", held(name))
for name in ("f1", "f5", "f6", "f7", "f10"):
    t = by_name[name]
    r = t["recipients"][0]
    check("envelopes", f"opened while frozen: {name}",
          client(hx(t["raw"]), frozen, hx(r["device_id"]), keys(r["keys"])) == t["payload"])
t = by_name["not_allowed_web_sends_location"]
check("envelopes", "refused while frozen: a location from a web device",
      client(hx(t["raw"]), frozen, hx(t["receiver_device_id"]), keys(t["receiver_keys"])) == "not_allowed")

# The limits of 8.1 by hand, at both edges: these don't come from the vector file.


def payload_ok(text) -> bool:
    try:
        ev.parse_payload(text if isinstance(text, bytes) else text.encode("utf-8"))
        return True
    except ev.EnvelopeError:
        return False


def nested(levels):
    out = "1"
    for _ in range(levels - 1):
        out = '{"a":' + out + "}"
    return '{"t":"x","v":' + out + "}"


LIMITS = [
    ("8 levels are accepted and 9 refused", payload_ok(nested(8)) and not payload_ok(nested(9))),
    ("a 4,096-byte string is accepted and 4,097 refused",
     payload_ok('{"t":"x","s":"' + "a" * 4096 + '"}') and not payload_ok('{"t":"x","s":"' + "a" * 4097 + '"}')),
    ("string length is counted in UTF-8 bytes",
     payload_ok('{"t":"x","s":"' + "\u00e9" * 2048 + '"}') and not payload_ok('{"t":"x","s":"' + "\u00e9" * 2049 + '"}')),
    ("a key longer than 4,096 bytes is refused", not payload_ok('{"t":"x","' + "k" * 4097 + '":1}')),
    ("a top-level avatar may hold 43,700 bytes, and no more",
     payload_ok('{"t":"profile","avatar":"' + "A" * 43700 + '"}')
     and not payload_ok('{"t":"profile","avatar":"' + "A" * 43701 + '"}')
     and not payload_ok('{"t":"profile","avatar":"' + "\u00e9" * 21851 + '"}')),
    ("an avatar deeper down is an ordinary string", not payload_ok('{"t":"profile","x":{"avatar":"' + "A" * 4097 + '"}}')),
    ("256 array items are accepted and 257 refused",
     payload_ok('{"t":"x","a":[' + ",".join(["0"] * 256) + "]}") and not payload_ok('{"t":"x","a":[' + ",".join(["0"] * 257) + "]}")),
    ("whole numbers up to 2^53 - 1 either side of zero",
     payload_ok('{"t":"x","n":9007199254740991}') and payload_ok('{"t":"x","n":-9007199254740991}')
     and not payload_ok('{"t":"x","n":9007199254740992}') and not payload_ok('{"t":"x","n":-9007199254740992}')),
    ("1.0 and 1e3 are whole; 1.5 and 1e-1 are not",
     payload_ok('{"t":"x","n":1.0}') and payload_ok('{"t":"x","n":1e3}') and not payload_ok('{"t":"x","n":1.5}')
     and not payload_ok('{"t":"x","n":1e-1}')),
    ("true, false and null are allowed", payload_ok('{"t":"x","a":true,"b":false,"c":null}')),
    ("an unpaired surrogate is refused, in a value, a key or an avatar",
     not payload_ok('{"t":"x","s":"\\ud800"}') and not payload_ok('{"t":"x","\\udc00":1}')
     and not payload_ok('{"t":"profile","avatar":"\\ud800"}') and payload_ok('{"t":"x","s":"\\ud83d\\ude00"}')),
    ("NaN and Infinity are not JSON", not payload_ok('{"t":"x","n":NaN}') and not payload_ok('{"t":"x","n":Infinity}')),
    ("the top level must be an object with a string \"t\"",
     not payload_ok("[1]") and not payload_ok('"x"') and not payload_ok('{"t":1}') and not payload_ok("{}")
     and payload_ok('{"t":""}')),
]
for name, cond in LIMITS:
    check("limits", name, cond)

# --- padding, approximate positions, safety codes ------------------------------------------------------
for t in v["padding"]["valid"]:
    p = ev.pad(hx(t["payload_byte"]) * t["payload_length"])
    check("padding", f"len {t['payload_length']}", len(p) == t["padded_length"]
          and hashlib.sha256(p).hexdigest() == t["padded_sha256"] and ev.unpad(p) == hx(t["payload_byte"]) * t["payload_length"])
for t in v["padding"]["pad_to"]:
    body = hx(t["payload_byte"]) * t["payload_length"]
    p = pad_to(body, t["to"])
    check("padding", f"pad_to {t['payload_length']}/{t['to']}", len(p) == t["to"]
          and hashlib.sha256(p).hexdigest() == t["padded_sha256"] and unpad(p, (t["to"],)) == body
          and unpad(p + b"\x00", (t["to"],)) is None)
for t in v["padding"]["invalid"]:
    check("padding", t["description"], ev.unpad(hx(t["padded"])) is None)
for t in v["approx"]:
    check("approx", f"{t['lat']},{t['lon']}", ev.approx_e7(t["lat"], t["lon"]) == (t["approx_lat"], t["approx_lon"]))
for t in v["safety_codes"]:
    a, b = hx(t["ik_pub_a"]), hx(t["ik_pub_b"])
    check("safety", t["a"] + "/" + t["b"], idn.safety_half(a) == t["half_a"] and idn.safety_half(b) == t["half_b"]
          and idn.safety_code(a, b) == t["code"] == idn.safety_code(b, a) and idn.safety_qr(a, b) == t["qr"]
          and len(t["code"].split()) == 12)

# --- invite and join ------------------------------------------------------------------------------------
I = v["invite"]
inv = rv.parse_invite(hx(I["invite"]))
f = I["fields"]
check("invite", "fields", inv["server_url"] == f["server_url"] and inv["server_key"].hex() == f["server_key"]
      and inv["circle_id"].hex() == f["circle_id"] and inv["secret"].hex() == f["secret"]
      and inv["inviter_ik_pub"].hex() == f["inviter_ik_pub"] and inv["expires_at"] == f["expires_at"]
      and inv["reg_token"].hex() == f["reg_token"] and inv["terms_salt"].hex() == f["terms_salt"]
      and inv["terms_bytes"].hex() == f["terms"] and inv["circle_name"] == f["circle_name"]
      and inv["inviter_name"] == f["inviter_name"] and inv["guardian_names"] == f["guardian_names"])
T = inv["terms"]
check("invite", "terms", dict(role=T["role"], teen_until=T["teen_until"], guardians=[g.hex() for g in T["guardians"]],
                              rules=lg.rules_json(T["rules"])) == I["terms"])
check("invite", "code and link", rv.invite_code(hx(I["invite"])) == I["code"]
      and rv.invite_link(I["link_base"], hx(I["invite"])) == I["link"]
      and idn.read_code("KFI0", I["code"]) == hx(I["invite"]))
check("invite", "ids", rv.invite_id(inv["secret"]).hex() == I["invite_id"]
      and rv.join_key(inv["secret"]).hex() == I["join_key"]
      and rv.join_result_key(inv["secret"]).hex() == I["join_result_key"]
      and lg.terms_commit(inv["terms_salt"], inv["terms_bytes"]).hex() == I["terms_commit"])
JR = I["join_request"]
j = rv.open_join_request(inv, hx(JR["message"]), JR["now"])
check("invite", "join request", j["name"] == JR["name"] and j["cert"].raw.hex() == JR["cert"]
      and j["consent"].hex() == JR["consent"] and j["chain"].hex() == JR["chain"]
      and j["terms_commit"].hex() == I["terms_commit"])
entry = lg.parse_entry(raws[I["log_entry_seq"]])
body = lg.parse_body(entry.type, entry.body_bytes)
check("invite", "log entry", body["invite_id"].hex() == I["invite_id"] and body["consent"] == j["consent"]
      and body["terms_commit"].hex() == I["terms_commit"])
for name, r in I["join_result"].items():
    got = rv.open_join_result(inv["secret"], hx(r["message"]))
    check("invite", f"join result {name}", got["outcome"] == r["outcome"] and got["head"].hex() == r["head"])

# --- device linking ------------------------------------------------------------------------------------
for name in ("from_existing", "from_new", "from_existing_rotated"):
    D = v["device_link"][name]
    lk = rv.parse_link(hx(D["link"]))
    secret = lk["secret"]
    check("link", f"{name} ids", lk["direction"] == D["direction"] and rv.link_id(secret).hex() == D["link_id"]
          and rv.link_key(secret).hex() == D["link_key"] and rv.link_confirm(secret).hex() == D["confirm"]
          and rv.link_code_text(hx(D["link"])) == D["code_text"]
          and idn.read_code("KFL0", D["code_text"]) == hx(D["link"]))
    if lk["direction"] == rv.LINK_FROM_NEW:
        who = rv.open_link_offer(secret, hx(D["offer"]))
    else:
        who = dict(account_id=lk["account_id"], ik_pub=lk["ik_pub"])
    check("link", f"{name} account", who["account_id"].hex() == D["account_id"] and who["ik_pub"].hex() == D["ik_pub"])
    r_old = rv.link_open(secret, rv.MSG_NONCE, hx(D["nonce_message"]))
    req = rv.open_link_request(secret, lk["direction"], who["account_id"], hx(D["commit_message"]), r_old,
                               hx(D["request"]), D["now"])
    check("link", f"{name} request", req["code"] == D["code"] and req["name"] == D["device_name"]
          and r_old.hex() == D["r_old"]
          and rv.link_commit(secret, hx(D["r_new"]), hx(D["request_body"])).hex() == D["commit"]
          and rv.link_code(secret, r_old, hx(D["r_new"]), hx(D["request_body"])) == D["code"])
    nd = devices[D["new_device"]]
    resp = rv.open_link_response(secret, who["ik_pub"], hx(D["response"]), hx(D["new_device_dek_sk"]),
                                 hx(nd["dsk_pub"]), nd["kind"], who["account_id"])
    check("link", f"{name} response", resp == json.loads(D["response_payload"]) and unb64u(resp["cert"]) == hx(nd["cert"])
          and ("ik" in resp) == (lk["direction"] == rv.LINK_FROM_EXISTING))
for t in v["device_link"]["refused"]:
    check("link", "refused: " + t["name"], refused(
        lambda: rv.open_link_request(hx(t["secret"]), t["direction"], hx(t["account_id"]), hx(t["commit_message"]),
                                     hx(t["r_old"]), hx(t["request"]), t["now"]), rv.RendezvousError))

# --- recovery kits, setup codes, server moves ----------------------------------------------------------
for t in v["recovery_kits"]:
    kit = rv.parse_recovery_kit(idn.read_code("KFR0", t["code"]))
    check("recovery", t["owner"], idn.read_code("KFR0", t["code"]) == hx(t["kit"])
          and kit["account_id"].hex() == t["account_id"] and kit["ik_seed"].hex() == t["ik_seed"]
          and b"".join(kit["chain"]).hex() == t["chain"] and kit["recovery_dsk_seed"].hex() == t["recovery_dsk_seed"]
          and idn.device_id(ed25519_public(kit["recovery_dsk_seed"])).hex() == t["recovery_device_id"]
          and kit["created_at"] == t["created_at"]
          and idn.chain_proves(idn.read_cert(Reader(idn.make_cert(kit["ik_seed"], ed25519_public(
              kit["recovery_dsk_seed"]), idn.RECOVERY, 0, kit["account_id"]))), kit["chain"]))
SU = v["setup"]
su = idn.parse_setup(idn.read_code("KFS0", SU["code"]))
check("setup", "code", idn.read_code("KFS0", SU["code"]) == hx(SU["setup"]) and su["server_url"] == SU["server_url"]
      and su["server_key"].hex() == SU["server_key"] and su["reg_token"].hex() == SU["reg_token"]
      and su["expires_at"] == SU["expires_at"])
for t in v["server_moves"]:
    mv = idn.parse_server_move(hx(t["move"]))
    check("moves", t["name"], mv["sig_ok"] == t["valid"] and mv["old_url"] == t["old_url"]
          and mv["old_key"].hex() == t["old_key"] and mv["new_url"] == t["new_url"]
          and mv["new_key"].hex() == t["new_key"] and mv["issued_at"] == t["issued_at"])

# --- share link, server identity, login ---------------------------------------------------------------
SH = v["share_link"]
s = hx(SH["secret"])
check("share", "ids", rv.share_id(s).hex() == SH["link_id"] and rv.share_key(s).hex() == SH["share_key"]
      and rv.share_url(SH["server_url"], s) == SH["url"])
u = rv.open_share_update(s, hx(SH["update"]["message"]))
check("share", "update", u["payload"] == SH["update"]["payload"] and u["seq"] == 1
      and json.loads(hx(SH["payload_bytes"])) == SH["update"]["payload"])
AU = v["auth"]
info = idn.parse_server_info(hx(AU["server_info"]))
check("auth", "server info", info["sig_ok"] and info["server_key"].hex() == AU["server_key"] and info["url"] == AU["server_url"])
check("auth", "fingerprint", idn.server_fingerprint(hx(AU["server_key"])) == AU["fingerprint"])
ch, did, sk = hx(AU["challenge"]), hx(AU["device_id"]), hx(AU["server_key"])
check("auth", "challenge", verify(sk, "auth-challenge", ch + did + AU["expires_at"].to_bytes(8, "big"), hx(AU["challenge_sig"])))
dsk_pub = hx(devices[AU["device"]]["dsk_pub"])
check("auth", "device", verify(dsk_pub, "auth", sk + ch + did, hx(AU["device_sig"])))

# --- watch grants, pushes, the relay signature (section 14) ------------------------------------------------
W = v["watch_grants"]
for t in W["grants"]:
    check("watch", t["name"], ps.watch_grant_ok(hx(t["grant"]), state_at(W["log_seq"]), W["now"]) == t["valid"])
g, wf = ps.parse_watch_grant(hx(W["grants"][0]["grant"])), W["fields"]
check("watch", "fields", g["circle_id"].hex() == wf["circle_id"] and g["watched_device_id"].hex() == wf["watched_device_id"]
      and g["watcher_account_id"].hex() == wf["watcher_account_id"] and g["after_min"] == wf["after_min"]
      and g["issued_at"] == wf["issued_at"] and g["not_after"] == wf["not_after"])
PU = v["push"]
for t in PU["valid"]:
    got = ps.open_push(hx(t["sealed"]), hx(t["device_id"]), keys(t["keys"]), hx(PU["server_key"]), t["now"])
    check("push", t["name"], got["type"] == t["type"] and got["sent_at"] == t["sent_at"]
          and len(hx(t["sealed"])) == ps.PUSH_SEALED)
    kid = hx(t["sealed"])[:8]
    check("push", t["name"] + " rebuild", ps.seal_push(hx(t["push"]), hx(t["device_id"]), dek_pub[kid],
                                                       hx(t["ikm"])) == hx(t["sealed"]))
    if t["type"] == ps.RECORDS:
        check("push", t["name"] + " records", ps.records_body(got["records"]) == hx(t["body"]))
    if t["type"] == ps.SILENCE:
        check("push", t["name"] + " body", ps.silence_body(got["circle_id"], got["watched_device_id"],
                                                           got["last_seen_at"]) == hx(t["body"]))
for t in PU["invalid"]:
    check("push", "dropped: " + t["name"], refused(
        lambda: ps.open_push(hx(t["sealed"]), hx(t["device_id"]), keys(t["keys"]), hx(PU["server_key"]), t["now"]),
        ps.PushError))
RL = PU["relay"]
args = (hx(PU["server_key"]), hx(RL["capability"]), hx(RL["sealed"]), RL["sent_at"])
check("push", "relay signature", ps.relay_sig_ok(*args, RL["delivery"], hx(RL["sig"]))
      and not any(ps.relay_sig_ok(*args, d, hx(RL["sig"])) for d in (1, 2, 3) if d != RL["delivery"]))

for g, n in counts.items():
    print(f"{g:12} {n:4} checks")
if failures:
    print("\n".join(["FAILED:"] + failures))
    sys.exit(1)
print("all", sum(counts.values()), "checks passed")
