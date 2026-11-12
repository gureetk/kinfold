# Server (Phase 1)

The Go server will live here: accounts, devices, circles, member log, envelope store, live relay, silence watches, invites, share links, map tiles and the search proxy. Go standard library plus SQLite, with five or fewer direct dependencies.

Its protocol obligations are the public rules: PROTOCOL.md §6.3 steps 1–8 for log appends, §7.5 for envelopes, §13 for login, all checked against `spec/vectors` in public mode.

License: AGPL-3.0-or-later.
