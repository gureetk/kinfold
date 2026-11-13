-- SPDX-License-Identifier: AGPL-3.0-or-later
--
-- The server's tables, schema version 1. Times are milliseconds since 1970 (UTC); IDs,
-- keys, hashes and protocol objects are blobs. Nothing here can be read by the server
-- beyond what PROTOCOL.md makes public.

CREATE TABLE settings (
	id            INTEGER PRIMARY KEY CHECK (id = 1),
	member_tokens INTEGER NOT NULL,
	web_devices   INTEGER NOT NULL,
	repair_until  INTEGER NOT NULL
) STRICT;
INSERT INTO settings VALUES (1, 0, 0, 0);

-- Registration tokens, by the SHA-256 of the token.
CREATE TABLE tokens (
	hash       BLOB PRIMARY KEY,
	created_at INTEGER NOT NULL,
	expires_at INTEGER NOT NULL,
	spent      INTEGER NOT NULL,
	invite     BLOB              -- the invite a member token came with
) STRICT, WITHOUT ROWID;

CREATE TABLE accounts (
	id         BLOB PRIMARY KEY,
	ik         BLOB NOT NULL,    -- the current identity key
	chain      BLOB,             -- the identity chain that leads to it
	operator   INTEGER NOT NULL,
	created_at INTEGER NOT NULL
) STRICT, WITHOUT ROWID;

CREATE TABLE devices (
	id           BLOB PRIMARY KEY,
	account      BLOB NOT NULL,
	kind         INTEGER NOT NULL,
	dsk          BLOB NOT NULL,
	cert         BLOB NOT NULL,
	bundle       BLOB,           -- none for a recovery device
	created_at   INTEGER NOT NULL,
	last_seen_at INTEGER NOT NULL
) STRICT, WITHOUT ROWID;
CREATE INDEX devices_account ON devices (account);

CREATE TABLE challenges (
	challenge  BLOB PRIMARY KEY,
	device     BLOB NOT NULL,
	expires_at INTEGER NOT NULL
) STRICT, WITHOUT ROWID;

-- Sessions, by the SHA-256 of the token.
CREATE TABLE sessions (
	hash       BLOB PRIMARY KEY,
	device     BLOB NOT NULL,
	expires_at INTEGER NOT NULL
) STRICT, WITHOUT ROWID;
CREATE INDEX sessions_device ON sessions (device);

-- Circles and their logs. A circle's state is replayed from its entries.
CREATE TABLE circles (
	id         BLOB PRIMARY KEY,
	seq        INTEGER NOT NULL, -- the head's seq
	head       BLOB NOT NULL,
	created_at INTEGER NOT NULL,
	closed_at  INTEGER           -- when its last member left
) STRICT, WITHOUT ROWID;
CREATE INDEX circles_closed ON circles (closed_at) WHERE closed_at IS NOT NULL;

CREATE TABLE entries (
	circle      BLOB NOT NULL REFERENCES circles ON DELETE CASCADE,
	seq         INTEGER NOT NULL,
	hash        BLOB NOT NULL,
	raw         BLOB NOT NULL,
	appended_at INTEGER NOT NULL,
	PRIMARY KEY (circle, seq),
	UNIQUE (circle, hash)
) STRICT, WITHOUT ROWID;

-- Who is a member of which circle, after its head.
CREATE TABLE members (
	account BLOB NOT NULL,
	circle  BLOB NOT NULL REFERENCES circles ON DELETE CASCADE,
	PRIMARY KEY (account, circle)
) STRICT, WITHOUT ROWID;
CREATE INDEX members_circle ON members (circle);

CREATE TABLE removals (
	circle BLOB NOT NULL,
	device BLOB NOT NULL,
	seq    INTEGER NOT NULL,     -- the entry that removed it
	at     INTEGER NOT NULL,
	PRIMARY KEY (circle, device)
) STRICT, WITHOUT ROWID;
CREATE INDEX removals_at ON removals (at);

-- Envelopes in order of arrival; seq is never reused, so an inbox cursor stays valid.
CREATE TABLE envelopes (
	seq         INTEGER PRIMARY KEY AUTOINCREMENT,
	circle      BLOB NOT NULL,
	sender      BLOB NOT NULL,
	received_at INTEGER NOT NULL,
	expires_at  INTEGER NOT NULL,
	raw         BLOB NOT NULL
) STRICT;
CREATE INDEX envelopes_expiry ON envelopes (expires_at);
CREATE INDEX envelopes_circle ON envelopes (circle);

-- Which device an envelope is for.
CREATE TABLE deliveries (
	device BLOB NOT NULL,
	seq    INTEGER NOT NULL REFERENCES envelopes ON DELETE CASCADE,
	PRIMARY KEY (device, seq)
) STRICT, WITHOUT ROWID;
CREATE INDEX deliveries_seq ON deliveries (seq);

-- The replay record of each circle (PROTOCOL.md §7.5). seq is the envelope's u64.
CREATE TABLE seen (
	circle      BLOB NOT NULL,
	sender      BLOB NOT NULL,
	seq         INTEGER NOT NULL,
	digest      BLOB NOT NULL,
	received_at INTEGER NOT NULL,
	keep_until  INTEGER NOT NULL,
	PRIMARY KEY (circle, sender, seq)
) STRICT, WITHOUT ROWID;
CREATE INDEX seen_expiry ON seen (keep_until);

-- Invite mailboxes. requests and askers are lists of frames.
CREATE TABLE invites (
	id         BLOB PRIMARY KEY,
	circle     BLOB NOT NULL,
	account    BLOB NOT NULL,
	expires_at INTEGER NOT NULL,
	requests   BLOB NOT NULL,
	askers     BLOB NOT NULL,
	used       INTEGER NOT NULL,
	result     BLOB,
	result_at  INTEGER NOT NULL,
	ended      INTEGER NOT NULL
) STRICT, WITHOUT ROWID;
CREATE INDEX invites_circle ON invites (circle);
CREATE INDEX invites_expiry ON invites (expires_at);
