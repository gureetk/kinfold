#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Two clients built on the Python reference (reference/python) drive a running server
through the HTTP API: they register, create a circle, invite and join, send an envelope
each way, fetch it and open it. Every step checks what the server answered.

Usage: clients.py REFERENCE_DIR SERVER_URL SETUP_CODE
Exit status 0 when everything worked.
"""
import json
import os
import sys
import urllib.error
import urllib.request

sys.path.insert(0, sys.argv[1])

from kinfold_ref import crypto as cr  # noqa: E402
from kinfold_ref import encoding as enc  # noqa: E402
from kinfold_ref import envelope as ev  # noqa: E402
from kinfold_ref import identity as idn  # noqa: E402
from kinfold_ref import log as lg  # noqa: E402
from kinfold_ref import rendezvous as rv  # noqa: E402

URL, SETUP_CODE = sys.argv[2], sys.argv[3]
DAY = 86_400_000
b64u, unb64u = enc.b64u, enc.unb64u
http = urllib.request.build_opener(urllib.request.ProxyHandler({}))  # straight to the server


def step(text):
    print("--", text, flush=True)


def frames(*parts):
    return b"".join(enc.u32(len(p)) + p for p in parts)


def unframes(b):
    r, out = enc.Reader(b), []
    while r.pos < len(b):
        out.append(r.vec32())
    return out


def check(cond, what):
    if not cond:
        raise SystemExit("FAILED: " + what)


class Client:
    def __init__(self, name):
        self.name = name
        self.ik_seed = os.urandom(32)
        self.ik_pub = cr.ed25519_public(self.ik_seed)
        self.account = idn.account_id(self.ik_pub)
        self.dsk_seed = os.urandom(32)
        self.device = idn.device_id(cr.ed25519_public(self.dsk_seed))
        self.dek_sk = os.urandom(32)
        self.dek_pub = cr.x25519_public(self.dek_sk)
        self.keys = {idn.key_id(self.dek_pub): self.dek_sk}
        self.token, self.time, self.seq, self.seen, self.cursor = None, None, 0, set(), None

    def call(self, method, path, body=None, ctype=None, expect=(200,)):
        req = urllib.request.Request(URL + path, data=body, method=method)
        req.add_header("Kinfold-Api", "1")
        if ctype:
            req.add_header("Content-Type", ctype)
        if self.token:
            req.add_header("Authorization", "Bearer " + b64u(self.token))
        try:
            resp = http.open(req, timeout=40)
            status, headers, data = resp.status, resp.headers, resp.read()
        except urllib.error.HTTPError as e:
            status, headers, data = e.code, e.headers, e.read()
        self.time = int(headers["Kinfold-Time"])  # trusted time comes from the server (8.4)
        check(status in expect, f"{self.name}: {method} {path} answered {status} {data[:300]!r}")
        return status, headers, data

    def json(self, method, path, obj, expect=(200,)):
        _, _, data = self.call(method, path, json.dumps(obj).encode(), "application/json", expect)
        return json.loads(data) if data else None

    def octets(self, method, path, body, expect=(201,)):
        return self.call(method, path, body, "application/octet-stream", expect)

    def trust(self, server_key):
        """Check the server's identity document against the key from a code (13.1)."""
        _, _, data = self.call("GET", "/.well-known/kinfold")
        doc = json.loads(data)
        info = idn.parse_server_info(unb64u(doc["server_info"]))
        check(info["sig_ok"] and info["server_key"] == server_key and info["url"] == URL,
              f"{self.name}: the server's identity document")
        check(doc["api"]["min"] <= 1 <= doc["api"]["max"], "API revision")
        self.server_key = server_key
        return doc

    def register(self, reg_token):
        now = self.time
        self.cert = idn.make_cert(self.ik_seed, cr.ed25519_public(self.dsk_seed), idn.PHONE, now, self.account)
        self.bundle = idn.make_bundle(self.dsk_seed, self.account, self.dek_pub, now - 3_600_000, now + 7 * DAY)
        _, _, data = self.octets("POST", "/v1/accounts", frames(self.cert, b"", self.bundle, reg_token))
        out = json.loads(data)
        check(unb64u(out["account_id"]) == self.account and unb64u(out["device_id"]) == self.device,
              f"{self.name}: registration answer")

    def login(self):
        ch = self.json("POST", "/v1/auth/challenge", {"device_id": b64u(self.device)})
        challenge, exp = unb64u(ch["challenge"]), ch["expires_at"]
        check(cr.verify(self.server_key, "auth-challenge", challenge + self.device + enc.u64(exp), unb64u(ch["challenge_sig"])),
              f"{self.name}: the challenge is signed by the server's key")
        sig = idn.auth_sig(self.dsk_seed, self.server_key, challenge, self.device)
        out = self.json("POST", "/v1/auth/session",
                        {"device_id": b64u(self.device), "challenge": b64u(challenge), "device_sig": b64u(sig)})
        self.token = unb64u(out["token"])

    def send(self, state, kind, payload, seq=None):
        """Seal an envelope to the given state's devices and post it (7.1-7.3, 7.5)."""
        if seq is None:
            self.seq += 1
            seq = self.seq
        if kind == ev.CIRCLE:
            to = [d for d in state.receiving_devices() if d.device_id != self.device]
        else:
            named = payload.pop("_to")
            to = [d for d in state.receiving_devices() if d.device_id in named]
        hdr = ev.env_header(kind, state.circle_id, self.device, seq, self.time, 3600, state.head)
        raw = ev.build_envelope(self.dsk_seed, hdr, [(d.device_id, d.bundle.dek_pub) for d in to],
                                json.dumps(payload, separators=(",", ":")).encode(), os.urandom(32), lambda rid: os.urandom(32))
        _, _, data = self.octets("POST", f"/v1/circles/{b64u(state.circle_id)}/envelopes", raw)
        return raw, json.loads(data)["received_at"]

    def fetch(self, state):
        """Fetch the inbox and open every record (7.6)."""
        path = "/v1/inbox" + (f"?since={self.cursor}" if self.cursor else "")
        _, headers, data = self.call("GET", path)
        self.cursor = headers["Kinfold-Cursor"]
        out = []
        for rec in unframes(data):
            received_at, raw = int.from_bytes(rec[:8], "big"), rec[8:]
            check(received_at <= self.time, "received_at is the server's clock")
            out.append(ev.open_envelope(raw, state, self.device, self.keys, self.seen, self.time))
        return out


def replay(entries, secrets=None):
    st = lg.State()
    for raw in entries:
        st, res, why = lg.apply(st, raw, secrets)
        check(res == "accepted" and why is None, f"log entry {st.seq}: {res} {why}")
    return st


def main():
    setup = idn.parse_setup(idn.read_code("KFS0", SETUP_CODE))
    check(setup["server_url"] == URL, "the setup code names this server")

    step("A: trusts the server through the setup code, registers with its token and logs in")
    a = Client("A")
    a.trust(setup["server_key"])
    a.register(setup["reg_token"])
    a.login()
    a.call("GET", "/v1/devices")
    a.octets("POST", "/v1/accounts", frames(a.cert, b"", a.bundle, setup["reg_token"]), expect=(403,))  # spent

    step("A: creates a circle")
    secret0 = os.urandom(32)
    hdr = lg.header(lg.GENESIS, bytes(16), 0, bytes(32), a.time, a.device, 0)
    body = (a.cert + enc.vec16(b"") + a.bundle + lg.epoch_commit(0, secret0)
            + lg.seal_details(secret0, hdr, lg.enc_genesis_details("Family"), os.urandom(12)))
    genesis = lg.build_entry(a.dsk_seed, hdr, body)
    _, _, data = a.octets("POST", "/v1/circles", genesis)
    cid = lg.circle_id_of(genesis)
    check(unb64u(json.loads(data)["circle_id"]) == cid, "circle_id")
    a.octets("POST", "/v1/circles", genesis)  # posting twice is safe
    a_secrets = {0: secret0}
    a_state = replay([genesis], a_secrets)

    step("A: invites B, with a registration token minted with the invite")
    secret, salt = os.urandom(16), os.urandom(16)
    terms = lg.enc_terms(lg.ADULT, 0, [], lg.DEFAULT_RULES)
    inv_id = rv.invite_id(secret)
    expires = a.time + DAY
    out = a.json("POST", "/v1/invites", {"circle_id": b64u(cid), "invite_id": b64u(inv_id), "expires_at": expires,
                                         "reg_token": True}, expect=(201,))
    invite = rv.make_invite(URL, setup["server_key"], cid, secret, a.ik_pub, expires, unb64u(out["reg_token"]),
                            salt, terms, "Family", "A", [])
    code = rv.invite_code(invite)

    step("B: scans the invite, trusts the server through it, registers and logs in")
    inv = rv.parse_invite(idn.read_code("KFI0", code))
    b = Client("B")
    b.trust(inv["server_key"])
    b.register(inv["reg_token"])
    b.login()
    b.call("GET", f"/v1/circles/{b64u(cid)}/head", expect=(404,))  # not a member yet

    step("B: asks to join")
    commit = lg.terms_commit(inv["terms_salt"], inv["terms_bytes"])
    consent = rv.consent_sig(b.ik_seed, inv["circle_id"], inv_id, b.cert, b.bundle, commit)
    request = rv.make_join_request(inv["secret"], b.cert, b"", b.bundle, commit, consent, "B", os.urandom(12))
    b.octets("POST", f"/v1/invites/{b64u(inv_id)}/requests", request)
    b.octets("POST", f"/v1/invites/{b64u(inv_id)}/requests", request)  # posting twice is safe

    step("A: opens the request, appends ADD_MEMBER, welcomes B and posts the result")
    _, _, data = a.call("GET", f"/v1/invites/{b64u(inv_id)}/requests")
    reqs = unframes(data)
    check(len(reqs) == 1, "one join request waiting")
    jr = rv.open_join_request(rv.parse_invite(invite), reqs[0], a.time)
    check(jr["name"] == "B", "the request opens")
    hdr = lg.header(lg.ADD_MEMBER, cid, a_state.seq + 1, a_state.head, a.time, a.device, a_state.epoch)
    details = lg.seal_details(secret0, hdr, lg.enc_member_details(salt, terms), os.urandom(12))
    body = (jr["cert"].raw + enc.vec16(jr["chain"]) + jr["bundle"].raw + inv_id + jr["terms_commit"] + jr["consent"]
            + enc.u8(0) + details)
    add = lg.build_entry(a.dsk_seed, hdr, body)
    _, _, data = a.octets("POST", f"/v1/circles/{b64u(cid)}/log", add)
    check(json.loads(data)["seq"] == 1 and unb64u(json.loads(data)["head"]) == lg.entry_hash(add), "append answer")
    a.octets("POST", f"/v1/circles/{b64u(cid)}/log", add)  # posting twice is safe
    stale = lg.build_entry(a.dsk_seed, lg.header(lg.POLICY, cid, 1, a_state.head, a.time, a.device, 0), os.urandom(540))
    _, _, data = a.octets("POST", f"/v1/circles/{b64u(cid)}/log", stale, expect=(409,))
    check(json.loads(data)["error"] == "conflict" and json.loads(data)["seq"] == 1, "a stale entry gets 409 conflict")
    a_state = replay([genesis, add], a_secrets)
    a.send(a_state, ev.DIRECT, {"t": "welcome", "epochs": [b64u(secret0)], "head": b64u(a_state.head),
                                "_to": [b.device]})
    result = rv.make_join_result(secret, rv.JOIN_ADDED, a_state.head, os.urandom(12))
    a.octets("PUT", f"/v1/invites/{b64u(inv_id)}/result", result, expect=(204,))
    b.octets("POST", f"/v1/invites/{b64u(inv_id)}/requests", request, expect=(410,))  # the invite is spent

    step("B: reads the result, verifies the log and opens the welcome")
    _, _, data = b.call("GET", f"/v1/invites/{b64u(inv_id)}/result?wait=5")
    res = rv.open_join_result(inv["secret"], data)
    check(res["outcome"] == rv.JOIN_ADDED, "B was added")
    _, headers, data = b.call("GET", f"/v1/circles/{b64u(cid)}/log")
    entries = unframes(data)
    check(headers["Kinfold-Seq"] == "1" and unb64u(headers["Kinfold-Head"]) == res["head"], "log headers")
    public = replay(entries)
    check(lg.circle_id_of(entries[0]) == inv["circle_id"] and public.head == res["head"], "the log B was promised")
    e1 = lg.parse_entry(entries[1])
    b1 = lg.parse_body(e1.type, e1.body_bytes)
    inviter = public.device(e1.author)
    check(b1["invite_id"] == inv_id and b1["terms_commit"] == commit and b1["consent"] == consent
          and public.members[inviter.account_id].ik_pub == inv["inviter_ik_pub"], "the ADD_MEMBER that answers B (9.4)")
    welcome = b.fetch(public)
    check(len(welcome) == 1 and welcome[0]["t"] == "welcome", "B's inbox holds the welcome")
    epochs = [unb64u(x) for x in welcome[0]["epochs"]]
    check(lg.epoch_commit(0, epochs[0]) == public.commits[0], "the epoch secret matches the log")
    b_state = replay(entries, dict(enumerate(epochs)))
    check(b_state.name == "Family" and b_state.members[b.account].role == lg.ADULT, "B reads the circle's details")

    step("A and B: one envelope each way, fetched and opened")
    a_loc = {"t": "loc", "ts": a.time, "lat": 492_827_000, "lon": -1_231_207_000, "acc": 12, "prec": "exact"}
    b_loc = {"t": "loc", "ts": b.time, "lat": 491_000_000, "lon": -1_230_000_000, "acc": 30, "prec": "exact"}
    raw_ab, received = a.send(a_state, ev.CIRCLE, dict(a_loc))
    b.send(b_state, ev.CIRCLE, dict(b_loc))
    got = b.fetch(b_state)
    check(got == [a_loc], f"B opens A's position: {got}")
    got = a.fetch(a_state)
    check(got == [b_loc], f"A opens B's position: {got}")
    check(b.fetch(b_state) == [], "the cursor moved past what B has read")

    step("A: the same envelope again is a success, other bytes under the same seq a replay")
    _, _, data = a.octets("POST", f"/v1/circles/{b64u(cid)}/envelopes", raw_ab)
    check(json.loads(data)["received_at"] == received, "the repost answers with the first received_at")
    hdr = ev.env_header(ev.CIRCLE, cid, a.device, a.seq, a.time, 3600, a_state.head)
    other = ev.build_envelope(a.dsk_seed, hdr, [(d.device_id, d.bundle.dek_pub) for d in a_state.receiving_devices()
                                                if d.device_id != a.device],
                              b'{"t":"hb","ts":1,"flags":["sharing"]}', os.urandom(32), lambda rid: os.urandom(32))
    _, _, data = a.octets("POST", f"/v1/circles/{b64u(cid)}/envelopes", other, expect=(422,))
    check(json.loads(data)["error"] == "replay" and json.loads(data)["seq"] == 1, "422 replay with the circle's head")

    step("both: list their circles")
    for c in (a, b):
        lst = json.loads(c.call("GET", "/v1/circles")[2])
        check([unb64u(x["circle_id"]) for x in lst] == [cid] and lst[0]["seq"] == 1, f"{c.name}'s circles")
    print("ok: two reference clients registered, joined and exchanged envelopes through the server")


main()
