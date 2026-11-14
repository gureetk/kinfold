#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Answers the server's differential test with the Python reference implementation.

Usage: oracle.py REFERENCE_DIR VECTORS_FILE

Reads one JSON request per line on stdin and writes one JSON answer per line:

  {"op": "apply", "state": NAME, "raw": HEX, "keep": NAME?}
      -> {"result": "accepted" | "fatal", "reason": CODE | null, "state": PUBLIC_STATE | null}
      In public mode (what a server runs). With "keep", an accepted state is saved under
      that name for later requests.
  {"op": "envelope", "state": NAME, "raw": HEX, "now": MS, "seen": [[SENDER_HEX, SEQ, DIGEST_HEX], ...]}
      -> {"result": "stored" | "duplicate" | CODE}
  {"op": "grant", "state": NAME, "raw": HEX, "now": MS} -> {"valid": BOOL}

The states "empty" and "m0" to "m20" (the main log after each entry) exist from the start.
An exception inside the reference is answered with {"error": TEXT}.
"""
import json
import sys
import traceback

sys.path.insert(0, sys.argv[1])

from kinfold_ref import envelope as ev  # noqa: E402
from kinfold_ref import log as lg  # noqa: E402
from kinfold_ref import push as ps  # noqa: E402

vectors = json.load(open(sys.argv[2]))
states = {"empty": lg.State()}
s = lg.State()
for i, e in enumerate(vectors["log"]["entries"]):
    s, _, _ = lg.apply(s, bytes.fromhex(e["raw"]), None)
    states[f"m{i}"] = s


def answer(q):
    st = states[q["state"]]
    raw = bytes.fromhex(q["raw"])
    if q["op"] == "apply":
        try:
            ns, _, _ = lg.apply(st, raw, None)
        except lg.Fatal as f:
            return {"result": "fatal", "reason": f.reason, "state": None}
        if q.get("keep"):
            states[q["keep"]] = ns
        return {"result": "accepted", "reason": None, "state": lg.state_json(ns, private=False)}
    if q["op"] == "envelope":
        seen = {(bytes.fromhex(a), n): bytes.fromhex(d) for a, n, d in q["seen"]}
        try:
            return {"result": ev.server_check(raw, st, q["now"], seen)}
        except ev.EnvelopeError as e:
            return {"result": e.reason}
    if q["op"] == "grant":
        return {"valid": ps.watch_grant_ok(raw, st, q["now"])}
    raise ValueError("unknown op " + q["op"])


for line in sys.stdin:
    q = json.loads(line)
    try:
        out = answer(q)
    except Exception:  # a crash in the reference is itself a finding
        out = {"error": traceback.format_exc()}
    out["id"] = q["id"]
    sys.stdout.write(json.dumps(out) + "\n")
    sys.stdout.flush()
