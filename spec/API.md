# Kinfold server API, v0 (sketch)

**Status:** sketch to accompany [PROTOCOL.md](PROTOCOL.md) v0; endpoints and shapes will firm up with the Phase 1 server. License: CC BY 4.0.

## Conventions

- HTTPS only (TLS 1.3). Base path `/v1`.
- Protocol objects (log entries, envelopes, join requests, link messages, share updates) travel as **raw bytes** with `Content-Type: application/octet-stream`. Lists of them use a `u32` length before each item. Everything else is JSON.
- Authenticated requests carry `Authorization: Bearer <session token>` from login (PROTOCOL.md §13.2).
- IDs in paths are base64url (no padding).
- Errors are JSON: `{"error": "<code>", "detail": "<text>"}`. Protocol rejections use the reason codes in PROTOCOL.md §16.5 (for example `{"error": "bad_wraps"}` with status 422).
- Servers MUST enforce size limits (an envelope at most 70 KB, a log entry at most 64 KB) and per-device rate limits, and MUST NOT log request bodies, positions or IP addresses.

## Endpoints

| Method and path | Auth | Body → response | Notes |
| --- | --- | --- | --- |
| `GET /.well-known/kinfold` | — | → `{"kinfold": 0, "server_info": b64u, "registration": "token" \| "closed", "push_relay": url?, "features": […]}` | `server_info` is the signed ServerInfo (§13.1) |
| `POST /v1/accounts` | registration token | `{"cert": b64u, "bundle": b64u, "reg_token": "…"}` → `{"account_id", "device_id"}` | Registers an account with its first device. Tokens come from the admin CLI, or from an invite |
| `POST /v1/auth/challenge` | — | `{"device_id"}` → `{"challenge", "expires_at", "sig"}` | §13.2 |
| `POST /v1/auth/session` | — | `{"device_id", "challenge", "sig"}` → `{"token", "expires_at"}` | Sessions last at most 24 hours |
| `POST /v1/devices` | session | `{"cert", "bundle"}` → 201 | Registers a newly linked device with the server; its `ADD_DEVICE` entries go to each circle's log |
| `POST /v1/circles` | session | GENESIS entry → `{"circle_id"}` | |
| `GET /v1/circles/{id}/log?after={seq}` | member device | → entries | The full log from `after + 1`; `after=-1` from genesis |
| `POST /v1/circles/{id}/log` | member device | entry → `{"seq", "head"}` | Public rules (§6.3 steps 1–8) and `created_at` within ±10 min; `409 {"error": "conflict", "head", "seq"}` if the head moved |
| `POST /v1/circles/{id}/envelopes` | member device | envelope → 201 | Checks §7.5; stores until `ttl_s`; pushes to recipients |
| `GET /v1/circles/{id}/envelopes?since={cursor}` | member device | → `{"cursor"}` + envelopes wrapped to this device | |
| `GET /v1/stream` | session | WebSocket | Live delivery of envelopes and new log entries for all the device's circles |
| `PUT /v1/circles/{id}/watches/{account_id}` | member device | `{"after_min": 60}` → 204 | Silence watch (§14); `DELETE` removes it |
| `POST /v1/invites` | admin device | `{"invite_id", "circle_id", "expires_at"}` → 201 | Opens a join mailbox; one per invite |
| `POST /v1/invites/{invite_id}/requests` | registered device | JoinRequest → 202 | §9.2; limited to a few per invite |
| `GET /v1/invites/{invite_id}/requests` | the creating device | → JoinRequests | |
| `DELETE /v1/invites/{invite_id}` | the creating device | → 204 | Also deleted automatically when it expires or its member is added |
| `POST /v1/links` | session, or none for direction 2 | `{"link_id", "expires_at"}` → 201 | Device-link mailbox (§10); at most 10 minutes |
| `POST /v1/links/{link_id}/{offer\|request\|response}` | — | LinkMessage or LinkResponse → 202 | One of each per mailbox |
| `GET /v1/links/{link_id}/{offer\|request\|response}` | — | → message, or 404 until posted | Long-poll allowed |
| `POST /v1/shares` | session | `{"link_id", "expires_at"}` → 201 | §12; `expires_at` at most 24 hours ahead |
| `POST /v1/shares/{link_id}/updates` | the creating device | ShareUpdate → 201 | Keeps only the newest few |
| `GET /v1/shares/{link_id}/latest` | — | → ShareUpdate | Used by the viewer page |
| `DELETE /v1/shares/{link_id}` | the creating device | → 204 | Ends the link at once |
| `GET /s/{link_id}` | — | → viewer page | Static HTML; the key stays in the fragment |
| `POST /v1/push/register` | session | `{"relay_capability": b64u}` → 204 | iOS only (§14) |
| `GET /v1/search?q=` | session | → results | Address search, proxied to a self-hosted Photon instance |
| `GET /tiles/{region}.pmtiles` | session or share link | HTTP range requests | Map tiles |

## Server state machine

The server keeps the **public state** of each circle (members, admin flags, devices with current bundles, epoch, head) by running PROTOCOL.md §6 in public mode on every append, exactly as the vectors' `public_result` fields describe. It uses that state to decide who may read a circle's log and envelopes, who may post, and whose devices may be named in wraps. A device that leaves a circle loses access at once.

## Open items

- Pagination limits and cursor format.
- Object store for long-lived encrypted data (PROTOCOL.md Appendix B).
- The admin API, which runs on a local Unix socket and is not part of this HTTP API.
