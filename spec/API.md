# Kinfold HTTP API, version 0

**Status:** draft 0.3, November 2026. Not stable. It carries the objects of [PROTOCOL.md](PROTOCOL.md) draft 0.3 and applies the November 2026 design review. The server in `server/` implements §1 to §12 and the part of §16 that a first device needs, with these gaps: it doesn't send Web Push messages yet, and takes no `apns` registrations; `stream_post` isn't offered; the viewer page shows a position as text until the map of §13 is in.
**License:** [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/).

Section numbers written "spec §…" point into PROTOCOL.md. Where the two documents disagree about bytes, the spec wins.

## Contents

1. Conventions
2. Errors
3. Limits
4. Discovery and health
5. Accounts, devices and login
6. Circles and the member log
7. Envelopes, the inbox and the stream
8. Silence watches
9. Invites
10. Linking devices
11. Share links
12. Push
13. Maps and search
14. The iOS relay
15. What the server keeps and enforces
16. Admin API (outline)
17. Open items

---

## 1. Conventions

- **Transport.** HTTPS with TLS 1.3. Every path below starts at the server's base URL, the `server_url` of its identity document (spec §13.1).
- **Protocol objects** (log entries, envelopes, grants and so on) travel as raw bytes with `Content-Type: application/octet-stream`. Where a body holds several objects it is a list of **frames**: a `u32` length, then that many bytes, repeated.
- **Everything else is JSON** (`application/json`), at most 16 KB. Inside JSON, binary values are base64url without padding and times are integers in milliseconds, as in spec §2. Unknown fields are ignored.
- **IDs in paths** are base64url: 22 characters for a 16-byte ID.
- **Nothing sensitive in a URL.** Paths and query strings carry only opaque IDs, cursors and numbers. Search text, names and tokens go in bodies or headers, because URLs are what proxies log.
- **Sessions.** `Authorization: Bearer <token>`, from login (§5). The **Who** column of each table says which devices may call an endpoint:

| Who | Meaning |
| --- | --- |
| — | No session |
| any | Any logged-in device |
| P | A phone or tablet |
| R | A receiving device: phone, tablet, web or Home Assistant |
| P+K | A phone or tablet, or the account's recovery device |

- **Circle access.** A call that names a circle succeeds only for an active device of that circle at the server's current head (with one exception in §6). Everyone else gets 404, the same answer as for a circle that doesn't exist.
- **Server time.** Every response carries `Kinfold-Time`, the server's clock in milliseconds. Devices build their trusted time on it (spec §8.4).
- **API revision.** Clients send `Kinfold-Api: 1` with every call under `/v1/`. A server that no longer supports a client's revision answers 426; a call without the header, or naming a revision above the discovery document's `api.max`, gets 400 `bad_request`.
- **Posting twice is safe.** Every call that stores a protocol object succeeds again when the same bytes are sent again, with the answer the first call got. Clients retry after a lost reply without changing anything. An envelope is checked again before it counts as a repeat (spec §7.6 steps 1 to 8), so one that has since expired, or whose sender has since left, is refused like any other.
- **No cross-origin access.** The server sends no CORS headers. The browser map talks to `kinfold-web`, which forwards its requests and sets the headers a browser can't, such as `Authorization` on a WebSocket.
- **Logs.** The server MUST NOT log bodies, tokens, IDs, positions or IP addresses. A reverse proxy in front of it MUST be set up the same way; the project ships a Caddy configuration with access logs off.

---

## 2. Errors

Errors are JSON: `{"error": "<code>", "message": "<text for developers>"}` plus the fields shown.

| Status | `error` | When |
| --- | --- | --- |
| 400 | `bad_request` | Unreadable JSON, a missing field, a bad parameter, the wrong content type |
| 401 | `unauthorized` | No session, or one that has expired or been revoked. Log in again. Also every login failure, whatever the cause |
| 403 | `forbidden` | The session is fine but this kind of device, or this account, may not make the call |
| 403 | `bad_token` | A registration token that is unknown, spent or expired |
| 404 | `not_found` | No such thing, or a circle the caller isn't in |
| 409 | `conflict` | A log append built on an old head. Carries `seq` and `head` |
| 409 | `slot_taken` | A mailbox slot or result that was already written with different bytes |
| 409 | `out_of_order` | A link slot written before the one it answers |
| 409 | `still_member` | Deleting an account that is still in a circle |
| 409 | `already_registered` | Registering an account or device that is already registered |
| 409 | `stale_grant` | A watch grant no newer than the one registered, or than one the watched account deleted (§8) |
| 409 | `stale_update` | A share update whose `seq` isn't above the one the server keeps (§11) |
| 410 | `gone` | An invite, link mailbox or share link that has ended |
| 413 | `too_large` | A body over the endpoint's limit (§3) |
| 422 | `bad_grant` | A watch grant that isn't valid (spec §14.1), or whose IDs aren't the path's |
| 422 | a reason code from spec §16.5 | A protocol object was read and refused: `bad_signature`, `stale_head`, `bad_wraps` and so on. For log entries and envelopes the answer carries the circle's current `seq` and `head`, so the sender can see how far behind it is |
| 426 | `update_required` | The client's API revision is too old. Carries `api_min` |
| 429 | `rate_limited` | Too many requests. Carries a `Retry-After` header |
| 503 | `repair_mode` | A normal log append while the server is in repair mode (§6) |
| 503 | `unavailable` | The server is starting, stopping, or its clock isn't synchronized |

A server whose clock isn't synchronized MUST NOT answer anything but `/healthz`: a wrong `Kinfold-Time` would mislead every phone.

---

## 3. Limits

Sizes that every implementation must agree on are in spec §16.6. The API adds these.

| Body | Limit |
| --- | --- |
| Log entry | 65,536 bytes |
| Envelope | 92,232 bytes |
| JSON body | 16 KB |
| Account registration | 4 KB |
| Device registration | 1 KB |
| Join request, join result | 4 KB |
| Link slot | 1 KB; the `response` slot 256 KB |
| Share update | 2 KB |
| Search text | 256 bytes |
| Log page | 1,024 entries or 4 MB, whichever comes first |
| Inbox page | 256 records or 4 MB |

Default rate limits. The operator can change them; clients MUST handle 429 at any of them. A limit per address counts the address of the connection, which the server keeps in memory for the length of the window and never writes down. A refused request counts like an accepted one. So does an envelope posted again, which the server checks again (§1); a log entry posted again doesn't.

| What | Default |
| --- | --- |
| Login challenges | 10 a minute per device ID, 60 a minute per address |
| Log appends | 30 an hour per device, 500 a day per circle |
| Envelopes | 20 a minute and 600 an hour per device |
| Stream connections | 10 a minute per device; the next is closed with 4429 |
| `Kinfold-Wake: notify` | 60 an hour per device |
| `Kinfold-Wake: locate` | 6 an hour per sender and recipient |
| Pending invites | 16 per circle; 3 waiting requests per invite |
| Link mailboxes without a session | 6 an hour per address, 60 an hour for the whole server |
| Link mailboxes with a session | 20 an hour per device |
| Share links | 5 open per device; one update every 5 seconds |
| Search | 30 a minute per device |
| Stored envelopes | 512 MB per circle; the oldest are dropped first |

---

## 4. Discovery and health

| Method and path | Who | Purpose |
| --- | --- | --- |
| `GET /.well-known/kinfold` | — | The server's identity and what it offers |
| `GET /healthz` | — | `200 {"ok": true}` when the server can serve; nothing else |
| `GET /v1/server/status` | P | For accounts the operator has marked as operators: `{"uptime_ms", "clock_synced", "repair", "free_disk", "last_backup_at"}`, with `null` for what the server doesn't know. 403 for everyone else |

```json
{
  "server_info": "<ServerInfo, base64url>",
  "api": {"min": 1, "max": 1},
  "features": ["tiles", "search", "web_devices", "webpush", "relay", "member_tokens", "stream_post"],
  "relay": "https://push.example.org",
  "vapid_key": "<P-256 public key, base64url>",
  "repair": false,
  "move": "<ServerMove, base64url>"
}
```

- `server_info` is the only signed part. A client checks it against the server key it trusts before believing anything else (spec §13.1).
- `features` lists what the operator has switched on. `web_devices` means direction-2 linking is available (§10); `member_tokens` means admins can mint registration tokens with invites (§9); `apns` may appear on a server that holds its own Apple key (§12).
- `relay` is the iOS relay this server sends through. An app whose built-in relay differs warns the person that pushes won't arrive.
- `vapid_key` is present with `webpush`. The app hands it to its UnifiedPush distributor.
- `move` is present while a move is announced (spec §13.3), at the old address and the new one, for at least 90 days.

---

## 5. Accounts, devices and login

| Method and path | Who | Body | Result |
| --- | --- | --- | --- |
| `POST /v1/accounts` | — | Frames: `DeviceCert`, identity chain (may be empty), `KeyBundle`, registration token | `201 {"account_id", "device_id"}` |
| `DELETE /v1/accounts/me` | P | — | 204. 409 `still_member` while the account is in any circle |
| `POST /v1/accounts/me/identity` | P | `IdentityLink` | 204. The account's identity key becomes the link's new key |
| `GET /v1/devices` | any | — | The account's registered devices: `[{"device_id", "kind", "created_at", "last_seen_at"}]` |
| `POST /v1/devices` | P+K | Frames: `DeviceCert`, `KeyBundle` (left out for a recovery device) | `201 {"device_id"}` |
| `DELETE /v1/devices/{device_id}` | P+K, or the device itself | — | 204. Its sessions, push registration and watches end |
| `GET /v1/circles` | any | — | `[{"circle_id", "seq", "head"}]` for every circle the account is in |
| `POST /v1/auth/challenge` | — | `{"device_id"}` | `{"challenge", "expires_at", "challenge_sig"}` |
| `POST /v1/auth/session` | — | `{"device_id", "challenge", "device_sig"}` | `{"token", "expires_at"}` |
| `DELETE /v1/auth/session` | any | — | 204 |

**Registering.** The server checks the certificate, the chain and the bundle as spec §6.4 does for `ADD_MEMBER` (kind 1 or 2 only), with the bundle current at the server's clock, and spends the token. A refusal is 422 with `malformed`, `bad_cert`, `kind_not_allowed` or `bad_bundle`; a token that is unknown, spent or expired is 403 `bad_token`; an account or device the server already has is 409 `already_registered`. Tokens are single-use and come from a setup code (spec §13.1), the operator's command line, or an invite (§9). They are bytes: base64url inside JSON, a raw frame here.

**Devices.** Registration with the server is what lets a device log in; being in a circle's log is what lets it take part there. A phone that links a device, or makes a recovery kit, registers the new device here and then appends `ADD_DEVICE` or `ADD_RECOVERY` to each circle. The certificate MUST carry the account's current identity key (422 `wrong_account` otherwise), and the bundle MUST be current at the server's clock (422 `bad_bundle`). Web and Home Assistant devices can be registered only while the operator allows them (403 otherwise). An account has at most 8 registered devices, one of them a recovery device (422 `too_many_devices`).

**Rotating the identity key.** The link's old key MUST be the account's current one and its new key a different, valid key, with both signatures verifying for the account (spec §4.3); otherwise, or once the account's chain holds 8 links, the answer is 422 `bad_rotation`. The account keeps its devices.

**Deleting an account** removes its devices, sessions, registrations, watches, invites and share links. The app first leaves every circle. The server holds nothing readable to export; the app exports what the phone itself holds.

**Login** follows spec §13.2. A challenge lives 60 seconds and works once: the first attempt that names it uses it up, whether or not it succeeds. The challenge call answers the same way for a device the server has never seen. A session lasts at most 24 hours, is bound to one device, and ends at once when the device is deregistered. Being removed from a circle doesn't end a session; it ends that circle's access (§6).

**After every login** a client puts its push registration (§12) and its watches (§8) again. Both calls replace what is there, so nothing is lost when a server has been restored from a backup.

---

## 6. Circles and the member log

| Method and path | Who | Body | Result |
| --- | --- | --- | --- |
| `POST /v1/circles` | P | A `GENESIS` entry | `201 {"circle_id"}` |
| `GET /v1/circles/{id}/head` | any | — | `{"seq", "head", "epoch", "rekey_pending"}` |
| `GET /v1/circles/{id}/log?after={seq}&limit={n}` | any | — | Frames, one entry each, in order. Headers `Kinfold-Seq` and `Kinfold-Head` give the current head |
| `POST /v1/circles/{id}/log` | any | One entry | `201 {"seq", "head"}` |
| `POST /v1/circles/{id}/log/repair` | any | One entry | `201 {"seq", "head"}`. Only in repair mode |

**Creating.** The founder certificate's device MUST be the session's device, and its account the session's account (403 otherwise). The same `GENESIS` again succeeds, however late: its hash is the circle ID.

**Reading.** Leave `after` out to start at `GENESIS`. Recovery devices may read the log; they need it to add a phone.

**Appending.** The entry's author MUST be the session's device (403 otherwise). The server runs spec §6.3 steps 1 to 9 and then checks `created_at` against its clock (`bad_time`), in that order. An entry whose `seq` or `prev_hash` doesn't follow the current head gets 409 `conflict` with the current `seq` and `head`; any other failure gets 422 with its reason code and the same two fields. An entry that is already in the log, byte for byte, succeeds again with its own `seq` and `head`. Entries are appended one at a time. On success the server applies the public effects at once: it tells every active device (a `log` frame on the stream, §7), ends the circle access of removed devices and members, ends watches that name them, closes a spent invite to new requests, and ends the invites of members who are no longer in the circle (§9).

**Being removed.** A device that has been removed, or whose account has, may still read the log up to and including the entry that removed it, for 30 days. That is the one exception to circle access. For such a device `Kinfold-Seq` and `Kinfold-Head` give the entry that removed it, not the circle's current head. It lets the phone check who signed its removal instead of taking an error's word for it. The server also sends it a `removed` event (§7).

**Closed circles.** When the last member leaves, the circle is closed. The server deletes it 30 days later.

**Repair mode.** After restoring from a backup the operator starts the server in repair mode (§16). It then:

- reports `"repair": true` in the discovery document;
- refuses normal appends with 503 `repair_mode`, so a phone that slept through the outage can't branch the log;
- accepts, on the repair path, the entry that follows its head from any active device of the circle, whoever authored it. Steps 1 to 9 still apply. `created_at` may be any age but not more than 10 minutes ahead (spec §6.7);
- accepts on `POST /v1/circles`, from any phone or tablet, the `GENESIS` of a circle the backup lost entirely, with the same rule for `created_at`. Its other entries then follow on the repair path.

Phones notice on their own: an envelope whose `log_head` the server doesn't know is refused with `unknown_log_head` and the server's `seq`, and a phone that holds more of the log than that re-posts what is missing. Repair mode ends when the operator switches it off, or by itself after 72 hours. Outside repair mode the repair path answers 404.

---

## 7. Envelopes, the inbox and the stream

| Method and path | Who | Body | Result |
| --- | --- | --- | --- |
| `POST /v1/circles/{id}/envelopes` | R | One envelope. Optional header `Kinfold-Wake` | `201 {"received_at"}` |
| `GET /v1/inbox?since={cursor}&limit={n}` | R | — | Frames, one delivery record each |
| `GET /v1/stream?since={cursor}` | R | WebSocket | Live delivery |

**Uploading.** The sender MUST be the session's device (403 otherwise). The server makes the checks of spec §7.5 and answers 422 with the reason, plus the circle's `seq` and `head`. On `stale_head` or `bad_wraps` the sender fetches the log and builds the envelope again with a new `seq`. The same bytes again answer 201 with the `received_at` of the first upload; different bytes under a stored `(sender, seq)` are 422 `replay`. A `Kinfold-Wake` other than `notify` or `locate`, or `locate` on a circle envelope, is 400.

**`Kinfold-Wake`** asks the server to wake recipients that have no open stream (spec §14.3):

| Value | Allowed on | The server |
| --- | --- | --- |
| *(absent)* | Any envelope | Stores it for the next fetch |
| `notify` | Any envelope | Sends each offline recipient a push (§12) |
| `locate` | Direct envelopes | Sends each offline recipient a location push where it has one registered, otherwise as for `notify` |

A recipient with an open stream gets the record at once whatever the header says.

**Delivery records.** A record is `u64 received_at ‖ envelope`: the server's clock when it stored the envelope, then the envelope unchanged. The inbox is per device and covers all its circles. The response headers are `Kinfold-Cursor`, an opaque token to pass as `since` next time (sent even when no record is, so a device keeps its place), and `Kinfold-More: 1` when more records wait. Records come only from circles in which the device is still an active receiving device. Fetching deletes nothing; a record stays until its envelope's `ttl_s` runs out, counted from `received_at`. Leave `since` out to get everything still stored.

**The stream** is a WebSocket. Phones send `Authorization` and `Kinfold-Api` with the upgrade request; browsers reach it through `kinfold-web`. A call without a session, from a device that doesn't receive, or with a bad cursor is refused with the usual errors before the upgrade, and a request that isn't a WebSocket upgrade is 400. Every message is binary: one type byte, then the body.

| Type | Direction | Body |
| --- | --- | --- |
| 0x01 `record` | server → device | A delivery record |
| 0x02 `cursor` | server → device | A cursor covering every record sent so far |
| 0x03 `log` | server → device | `circle_id[16] ‖ u64 seq ‖ head[32]`: the circle's log has grown; fetch it |
| 0x04 `push` | server → device | A `Push` (spec §14.2), signed but not sealed. Used for silence alerts |
| 0x05 `event` | server → device | JSON, below |
| 0x06 `time` | server → device | `u64` server time. Sent on connecting and at least every 15 minutes |
| 0x10 `post` | device → server | `u32 id ‖ u8 wake ‖ envelope`, with wake 0 none, 1 notify, 2 locate. Only with the `stream_post` feature |
| 0x11 `result` | server → device | `u32 id ‖ u16 status ‖ JSON`: the answer the upload call would have given |

On connecting, the server sends a `time` message, what the inbox holds after `since`, and a `cursor`. Then it sends live records as they are stored, each batch followed by a `cursor`, and log frames and events as they happen; a connection that falls behind gets only the latest log frame of each circle. A `cursor` message carries the cursor's text, the same as `Kinfold-Cursor`. A device keeps the last cursor it received and reconnects with it. Devices ping at their own pace with WebSocket pings; the server closes a connection on which nothing has come from the device, not even a ping, for 35 minutes. A device sends nothing else: without `stream_post`, a message from it closes the stream with 1008. One device has one stream: a second connection closes the first.

| Close code | Meaning | The device |
| --- | --- | --- |
| 4000 | The server is restarting, or shutting down as the connection arrives | Reconnects with backoff |
| 4401 | The session ended | Logs in again |
| 4408 | Idle too long | Reconnects |
| 4409 | Replaced by a newer connection from the same device | Does nothing |
| 4426 | The app is too old for this server | Tells the person |
| 4429 | Rate limited | Waits, then reconnects |

Reconnecting backs off from 1 second to 5 minutes, with jitter.

**Events.** Each is `{"type": …}` with the fields shown, IDs in base64url. They are hints: every one can be confirmed by a fetch, and a connection that falls far behind may miss some.

| `type` | Fields | Meaning |
| --- | --- | --- |
| `removed` | `circle_id`, `seq` | This device left the circle at that entry. Fetch the log and check it |
| `join_request` | `invite_id` | A join request is waiting (§9) |
| `share_view` | `link_id`, `views` | A share link was opened (§11) |
| `watch_ended` | `circle_id`, `watched_device_id`, `reason` | A watch this account held has ended: `expired`, `deleted` or `device_removed` (§8) |
| `push_dropped` | — | The push address stopped working; register again (§12) |
| `notice` | `code` | `repair_mode`, `moving` or `restarting` |

---

## 8. Silence watches

| Method and path | Who | Body | Result |
| --- | --- | --- | --- |
| `PUT /v1/circles/{id}/watches/{device_id}` | P | A `WatchGrant` | 204 |
| `GET /v1/circles/{id}/watches` | P | — | The watches this account holds, and the watches on this account's devices |
| `DELETE /v1/circles/{id}/watches/{device_id}?watcher={account_id}` | P | — | 204 |

**Registering.** `{device_id}` is the watched phone or tablet. The server checks the grant (spec §14.1): the signature under that device's signing key in the log, the circle and device IDs against the path, the watcher account against the session, `after_min` between 15 and 1,440, and `not_after` in the future and at most 35 days away. A grant that fails is 422 `bad_grant`; one that names another watcher than the session's account is 403. There is one watch per watcher account and watched device. A newer grant, one with a later `not_after`, replaces the one registered and the silence goes on counting; the same grant again succeeds; an older one is 409 `stale_grant`.

**Listing** returns `[{"watched_device_id", "watcher_account_id", "after_min", "not_after"}]`, empty when there are none. Nobody can be watched without being able to see it.

**Ending.** The watcher may delete its own watch (`watcher` left out). So may any phone or tablet of the watched account, naming the watcher; anyone else gets 403, and a watch that doesn't exist 404. When the watched account deletes a watch, the server remembers it until the grant's `not_after`, and refuses grants no newer than the deleted one with 409 `stale_grant`, so that the watcher can't bring the watch back with a grant it already holds. A watch also ends when its grant expires or the watched device leaves the circle. In every case the watcher gets a `watch_ended` event, which is how a guardian learns that a teen's phone has dropped one. A watch whose watcher's account leaves the circle ends without one.

**Firing.** A watch is reset each time the server stores a circle envelope from the watched device, and by nothing else; a new watch counts from the last one the server stored, or from its registration. The check runs once a minute. When `after_min` passes without one, the server:

1. wakes the watched device (§12: a location push where it has one, otherwise a background wake);
2. waits two minutes;
3. if still nothing has arrived, sends a `Push` of type `silence` to every phone and tablet of the watcher account, over the stream or by push. Its `last_seen_at` is when the server last stored a circle envelope from the device, or 0 if it doesn't know.

It alerts once per silence and is armed again when the device is next heard.

---

## 9. Invites

| Method and path | Who | Body | Result |
| --- | --- | --- | --- |
| `POST /v1/invites` | P | `{"circle_id", "invite_id", "expires_at", "reg_token": true}` | `201 {"reg_token": "…"}` |
| `POST /v1/invites/{invite_id}/requests` | P | A `JoinRequest` | 201 |
| `GET /v1/invites/{invite_id}/requests` | P | — | Frames, one `JoinRequest` each |
| `PUT /v1/invites/{invite_id}/result` | P | A `JoinResult` | 204 |
| `GET /v1/invites/{invite_id}/result?wait={s}` | P | — | 200 with the `JoinResult`, or 204 when there is none yet |
| `DELETE /v1/invites/{invite_id}` | P | — | 204 |

- **Creating.** The caller MUST be an admin of the circle, which the server can see (403 otherwise). `expires_at` is in the future and at most 7 days away (400 otherwise). With `"reg_token": true`, on a server with `member_tokens`, the answer carries a single-use registration token that expires with the invite; the inviter puts it in the invite (spec §9.1). Without that feature the invite is made all the same and the answer carries no token: the operator issues tokens. Posting the same invite again succeeds and keeps its requests and the `expires_at` it was first given; with `"reg_token": true` it returns a new token, and the one before stops working. An invite ID that another circle or account uses is 409 `slot_taken`.
- **Requests.** Any registered phone or tablet that knows the invite ID may post one. The server can't read it, but checks its clear part: version 0, the invite ID of the path, a nonce and one ciphertext (422 `malformed` otherwise). The same request twice is stored once; a fourth waiting request gets 429. The inviter's phones get a `join_request` event, or a wake-up when they are offline. Only devices of the inviter's account may read requests or write the result (403 otherwise); they or any admin of the circle may delete the invite.
- **Result.** Written once: the same bytes again succeed, different bytes are 409 `slot_taken`. A device that posted a request may read it (403 for any other), waiting up to 25 seconds per call (`wait`).
- **Ending.** When an `ADD_MEMBER` with that `invite_id` is appended, the server deletes the invite's requests and takes no more (410 `gone`), but keeps the result slot open: the inviter appends the entry first and posts the result after it (spec §9.2). The invite ends at `expires_at` if no result was written, 24 hours after its result was written, on `DELETE`, or when the inviter's account leaves the circle or is removed from it; after that every call about it gets 410 `gone`. A registration token minted with the invite stops working once the invite is used or ends.

---

## 10. Linking devices

| Method and path | Who | Body | Result |
| --- | --- | --- | --- |
| `POST /v1/links` | P for direction 1; — for direction 2 | `{"link_id", "direction", "expires_at"}` | 201 |
| `PUT /v1/links/{link_id}/{slot}` | See below | One `LinkMessage`, or the `LinkResponse` | 204 |
| `GET /v1/links/{link_id}/{slot}?wait={s}` | See below | — | 200 with the slot's bytes, or 204 when it is empty |

The slots are `offer`, `commit`, `nonce`, `request` and `response` (spec §10.2).

| Slot | Written by | Session to write | Session to read |
| --- | --- | --- | --- |
| `offer` (direction 2 only) | The existing phone | P | — |
| `commit` | The new device | — | P |
| `nonce` | The existing phone | P | — |
| `request` | The new device | — | P |
| `response` | The existing phone | P | — |

- **Creating a mailbox.** In direction 1 the existing phone creates it; it lives at most 120 seconds. In direction 2 the new device creates it without a session; it lives at most 300 seconds, exists only on servers with `web_devices` (403 otherwise), and is rate-limited per address and for the whole server. An `expires_at` that isn't in the future or is too far away is 400. A `link_id` in use is 409 `slot_taken`; the same mailbox posted again is 201.
- **One account.** A mailbox belongs to the account that created it (direction 1) or that wrote its `offer` (direction 2). Every later call that needs a session must come from that account.
- **Once, and in order.** Each slot is written once: the same bytes again succeed, different bytes are 409 `slot_taken`. `commit` can't be written before `offer` in direction 2, `nonce` before `commit`, `request` before `nonce`, or `response` before `request` (409 `out_of_order`). The order is part of what makes the confirmation code trustworthy (spec §10.2). Direction 1 has no `offer` slot (404).
- **What the server checks.** Of a `LinkMessage`: version 0, the path's `link_id`, the slot's `msg_type`, a nonce and a ciphertext, and nothing after. Of the `LinkResponse`: version 0, the `link_id`, the session's own device certificate, `enc`, a ciphertext and a signature under that device's key. Anything else is 422 `malformed`.
- **Waiting.** `wait` holds a read open for up to 25 seconds.
- **The new device.** Before it writes `response`, the existing phone registers the new device (§5) and appends `ADD_DEVICE` to its circles.
- **Ending.** A mailbox ends at `expires_at`, or 60 seconds after its `response` is first read; calls about it then get 410 `gone`, until the server deletes it within the minute. Mailboxes are kept in memory only, so a restart ends them too and the devices start again.

The server can read none of the messages. Knowing `link_id` is what lets the new device use the mailbox, and `link_id` comes from the code on a screen.

---

## 11. Share links

| Method and path | Who | Body | Result |
| --- | --- | --- | --- |
| `POST /v1/shares` | P | `{"link_id", "expires_at"}` | 201 |
| `POST /v1/shares/{link_id}/updates` | The creating device | A `ShareUpdate` | 204 |
| `GET /v1/shares/{link_id}` | P, same account | — | `{"expires_at", "views", "last_view_at"}` |
| `DELETE /v1/shares/{link_id}` | P, same account | — | 204 |
| `GET /v1/shares/{link_id}/latest?after={seq}&wait={s}` | — | — | 200 with the newest `ShareUpdate`, 204 when none is newer than `after`, 410 once the link has ended |
| `GET /s/{link_id}` | — | — | The viewer page |

- **Making a link.** A link lasts at most 24 hours (400 otherwise). A device has at most 5 open (429). A `link_id` in use is 409 `slot_taken`; the same link posted again is 201.
- **Updates.** Only the device that made the link posts them (403). The server checks what it can see: version 0, the link's ID, a `seq`, the link's own `expires_at`, a nonce and a ciphertext, and nothing after (422 `malformed`). It keeps only the update with the highest `seq`: the same bytes again succeed, a lower or equal `seq` is 409 `stale_update`. One update every 5 seconds (429). An ended link answers 410 to every call about it.
- **The viewer's call**, `latest`, needs no session but sends `Kinfold-Api` like any `/v1/` call; it waits up to 25 seconds (`wait`). An unknown link is 404.
- **Ending.** `DELETE` ends a link at once and drops its update; `GET /v1/shares/{link_id}` and `DELETE` from another account are 403.
- **Views.** The server counts page loads per link, at most 60 a minute, and tells the creating device with a `share_view` event, so the person sharing sees that the link was opened. Loads of an ended link don't count. It stores no addresses. `last_view_at` is 0 before the first view.
- **The viewer page** is the same static page for every link, whatever the ID, with its script and styles under `/assets/`; the key never leaves the part of the URL after `#`. It is served with a content security policy that allows scripts, styles, workers and connections from this server only, and with `Referrer-Policy: no-referrer`, `Cache-Control: no-store`, `X-Content-Type-Options: nosniff` and `frame-ancestors 'none'`. Its map comes from the coarse archive (§13).
- What a share link trusts is in spec §12. The app says so when a link is made.

---

## 12. Push

A device with an open stream needs no push. Android phones keep a stream by default. Push is for iPhones, and for Android phones that use a UnifiedPush distributor.

| Method and path | Who | Body | Result |
| --- | --- | --- | --- |
| `PUT /v1/push` | R | One registration, below | 204. Replaces the device's registration |
| `DELETE /v1/push` | R | — | 204 |

```json
{"kind": "relay",   "notify": "<capability>", "locate": "<capability>"}
{"kind": "webpush", "endpoint": "https://…", "p256dh": "<key>", "auth": "<secret>"}
{"kind": "apns",    "notify": "<token>", "locate": "<token>", "environment": "production"}
```

- **`relay`** is the App Store build's route. The capabilities come from the relay (§14), as base64url. `locate` is present when the app has Apple's location-push entitlement and the person has allowed location all the time. A server with no relay configured refuses it (403).
- **`webpush`** is UnifiedPush. The server sends the sealed push as a Web Push message (RFC 8030), encrypted to `p256dh` and `auth` (RFC 8291) and signed with its VAPID key (RFC 8292).
- **`apns`** exists only on a server that holds its own Apple key, for families who build the iOS app themselves; any other server refuses it (403).
- **Who.** Any receiving device (403 for a recovery device). A registration that breaks a rule here, or the rules for push addresses below, is 400.

**What is sent.** Always the sealed, signed, fixed-size push of spec §14.2, and nothing else, sealed to the newest current key bundle the server knows for the device: the one it registered with, or a later one in a circle's log. A device with a stream open gets no push. For an envelope uploaded with `Kinfold-Wake`, the server sends a `records` push when the delivery record fits in one, otherwise a `wake` push, and the device fetches its inbox. An upload whose wake-up is past its limit (§3) is refused whole, with 429, and nothing is stored. Every Web Push request uses the same `TTL` (3,600) and `Urgency` (`high`), so a distributor can't tell an alert from a wake-up.

**Delivery types.** Apple needs to be told how to deliver a push, so the server names one of three:

| Delivery | Used for | On the iPhone |
| --- | --- | --- |
| alert | `notify`; silence alerts | A notification extension opens the push, fetches the inbox if it has to, and shows the alert. If it can't, it shows a fixed text |
| background | Waking a device that has no location-push registration | The app may get a short time to run; Apple limits how often |
| location | `locate`; the wake-up before a silence alert | The location-push extension reads the position and uploads it |

The relay and Apple see the delivery type. Neither sees what kind of alert it is.

**Rules for push addresses.** A `webpush` endpoint is a URL chosen by the phone, so without rules any member could aim the server at its own network.

- The scheme is `https`. The URL is at most 1,000 bytes.
- Every address the host resolves to MUST be public: not loopback, private, carrier-grade NAT, link-local, unique-local, multicast or unspecified, in IPv4, IPv6 or IPv4-mapped form.
- The check is made when the address is registered and again before every send, and the server connects to the address it checked.
- Redirects are not followed. The request times out after 10 seconds. The response body is ignored.
- The operator MAY list push hosts that are allowed without the public-address test, for a distributor on the home network. With such a list, the operator MAY refuse every other host.
- A 404 or 410 from the push host, or 410 from the relay, ends the registration, and the device is sent `push_dropped`: at once if it has a stream open, otherwise when it next opens one.

---

## 13. Maps and search

| Method and path | Who | Result |
| --- | --- | --- |
| `GET /v1/tiles` | any | The regions this server offers |
| `GET /tiles/{region}.pmtiles` | any | A whole region, for download |
| `GET /tiles/coarse.pmtiles` | — | A low-zoom archive for the share viewer |
| `POST /v1/search` | P, or a web device | Address search, when the add-on is installed |

```json
{
  "regions": [
    {"id": "bc", "name": "British Columbia", "bbox": [-139.1, 48.2, -114.0, 60.0],
     "minzoom": 0, "maxzoom": 15, "size": 1480000000, "sha256": "…", "updated_at": 1794000000000}
  ],
  "attribution": "© OpenStreetMap contributors"
}
```

- **Download whole regions; never browse them.** A request for part of a map file shows the server what is on someone's screen, and with it where family members are. Apps download a region once, check its hash, and draw from the file on the phone. They MUST NOT read a region over the network tile by tile. To hold apps to that, the server answers only whole-file requests and open-ended ranges (`Range: bytes=N-`, used to resume a download) on region files. `If-Range` and `ETag` are supported.
- **The exception is the browser.** A web device can't hold a region, so the operator MAY allow closed ranges on region files for web devices. The app's settings and the web map both say what that shows the server.
- **The coarse archive** covers the same area to zoom 13 at most and needs no session. The share viewer uses it, and so does the web map unless the operator allows more.
- **Search** takes `{"q": "…", "lang": "en", "limit": 5}` and optionally `"near": [lat, lon]`, and returns `{"results": [{"name", "address", "lat", "lon"}]}`. The server passes the text to the search add-on and logs nothing. Apps SHOULD send the centre of the downloaded region as `near`, never the phone's position. The server does see the text of every search, which is why search is an add-on a family can leave out.

---

## 14. The iOS relay

The relay is a separate small service run by the project (spec §14.4). It has two calls and keeps no data.

| Method and path | Called by | Body | Result |
| --- | --- | --- | --- |
| `POST /v1/register` | The app | `{"token", "kind", "server_key", "environment"}` | `{"capability"}` |
| `POST /v1/push` | A family's server | `{"capability", "sealed", "sent_at", "delivery", "sig"}` | 202 |

- **Registering.** `token` is the Apple device token; `kind` is `notify` or `locate`. The capability is the token, its kind and `server_key`, sealed under a key only the relay holds. An app registers again whenever Apple gives it a new token or it moves to another server.
- **Pushing.** `sig` is `relay_sig` of spec §14.4, made with the server key inside the capability; `sent_at` must be within five minutes; `delivery` is `alert`, `background` or `location` and must suit the capability's kind. The relay wraps the sealed push in an Apple notification of that type and forwards it. Every alert it sends looks the same.
- **Answers.** 202 when Apple accepted the push. 410 when Apple reports the token dead: the server drops the registration. 429 with `Retry-After` when a capability or a server key is sending too much.
- **What it sees.** Which server key wakes which Apple token, when, and with which delivery type. It never sees content, circles, accounts or addresses of families' servers beyond the connection itself, and it logs none of it.

---

## 15. What the server keeps and enforces

The server holds, for each circle, the log and the public state of spec §6.1: members, admin flags, devices with their kinds and current bundles, the epoch and its commitments, the rekey flag, the options and the spent invite IDs. It never holds an epoch secret.

It enforces:

- every log rule a server can check: spec §6.3 steps 1 to 9, with `created_at` within 10 minutes of its clock;
- the envelope checks of spec §7.5, including that a circle envelope names every receiving device;
- watch grants (spec §14.1) and login (spec §13.2);
- who may call what: the **Who** columns here, which repeat for the API what spec §6.3 says about device kinds for the log;
- the limits of §3.

What has run out is refused at once and deleted by a sweep every minute:

- envelopes at the end of their time-to-live, and its record of each `(sender, seq)` pair 32 days after the envelope was sent;
- login challenges, sessions and registration tokens when they expire;
- invites once nothing can use them: after `expires_at`, and a day after their result if one was written (§9);
- a removed device's access to the log after 30 days (§6);
- watches the watched account deleted, when their grant would have run out (§8);
- closed circles 30 days after their last member left, with everything that names them;
- link mailboxes within a minute of ending, and share links when they expire, at most 24 hours after they were made (§10, §11).

A silence check runs once a minute.

---

## 16. Admin API (outline)

Administration is a separate API on a Unix socket that file permissions protect. It is never reachable over the network. The `kinfold` command line uses it, and so does the optional web console in `kinfold-web`. It handles nothing that is encrypted and can show no location, name or role.

| Area | Operations |
| --- | --- |
| First setup | Print a setup code (spec §13.1) as a QR code in the terminal, with the server key's fingerprint |
| Registration | Create, list and revoke registration tokens; switch `member_tokens` on or off |
| Accounts and devices | List by ID, kind and last-seen day; attach a nickname that only the operator sees; remove a device or an account; mark an account as an operator |
| Circles | List by ID with member and device counts and log length; nothing else is known |
| Settings | Web devices on or off; search on or off; push hosts; rate limits; the relay address |
| Backup and restore | Back up; restore, which starts the server in repair mode; end repair mode; show each circle's head while phones repair it |
| Maps and search | Add, update and remove regions; build the coarse archive; manage the search index |
| Server key | Show the fingerprint; announce a move (spec §13.3); replace the key |
| Health | Clock state, disk, queue sizes, last backup, relay reachability |

Removing a device on the server cuts off its sessions and deliveries at once. It doesn't change any circle's log, so phones keep encrypting to it until a member removes it there. It is the emergency step when the only admin's only phone is gone and there is no recovery kit.

The web console adds its own protections, since a console on `localhost` is a known target for DNS rebinding: it checks `Host` and `Origin` on every request, uses anti-forgery tokens, and opens only through a one-time link from the command line.

**What exists so far.** The socket (`admin.sock` in the server's data directory, mode 0600) speaks JSON over HTTP:

| Method and path | Command line | Does |
| --- | --- | --- |
| `POST /setup` | `kinfold setup [--expires 24h]` | A registration token and the setup code carrying it, with the server's URL and key |
| `POST /tokens`, `GET /tokens`, `DELETE /tokens/{id}` | `kinfold token create\|list\|revoke` | Registration tokens; only their hashes are kept, and `id` is the first 8 bytes of the hash in hex |
| `GET /settings`, `PATCH /settings` | `kinfold settings [--member-tokens on\|off] [--web-devices on\|off]` | `member_tokens` and `web_devices` |
| `POST /repair`, `DELETE /repair` | `kinfold repair start [--hours 72]\|end` | Repair mode (§6), at most 72 hours |
| `PUT /operators/{account_id}`, `DELETE …` | `kinfold operator add\|remove ACCOUNT_ID` | Who may read `/v1/server/status` |

The setup code is printed as text for now, with the server key in base64url.

---

## 17. Open items

- **Stored objects** (spec §8.7): endpoints to put, list and fetch encrypted objects, and how the server drops old revisions. Needed before places ship.
- **Batch upload.** One call for several envelopes after a phone has been offline.
- **Quotas.** What a phone is told, and shows, when a circle's stored envelopes hit the limit.
- **Relay abuse limits** and whether registering with the relay should need Apple's app attestation.
- **Federation** between servers is out of scope for v0.
- **The server key's fingerprint.** Spec §13.1 asks apps that let a person type an address to show the server key's fingerprint for comparison with the command line's, but defines no format. The command line prints the whole key in base64url until it does.
- **Revoking a watch grant.** A `WatchGrant` carries no signed time of issue, so the server can't tell a grant the watcher held back from one issued after the watched account deleted the watch. §8 refuses the same or older grants; a newer one issued before the deletion still gets through until the protocol settles this.
- **Restoring registrations.** Repair mode (§6) restores logs. Devices and accounts registered after the backup are lost with it; how they register again, without new tokens for everyone, is still to be settled.
