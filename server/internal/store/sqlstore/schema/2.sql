-- SPDX-License-Identifier: AGPL-3.0-or-later
--
-- Schema version 2: silence watches.

-- Silence watches (API.md §8).
CREATE TABLE watches (
	circle    BLOB NOT NULL,
	device    BLOB NOT NULL,    -- the watched phone or tablet
	watcher   BLOB NOT NULL,    -- the watcher's account
	grant_raw BLOB NOT NULL,    -- the WatchGrant
	after_min INTEGER NOT NULL,
	not_after INTEGER NOT NULL,
	since     INTEGER NOT NULL, -- when the current silence began
	woke_at   INTEGER NOT NULL,
	alerted   INTEGER NOT NULL,
	revoked   INTEGER NOT NULL, -- deleted by the watched account; kept until not_after
	PRIMARY KEY (circle, device, watcher)
) STRICT, WITHOUT ROWID;

-- When each device last stored a circle envelope.
CREATE TABLE heard (
	circle BLOB NOT NULL,
	device BLOB NOT NULL,
	at     INTEGER NOT NULL,
	PRIMARY KEY (circle, device)
) STRICT, WITHOUT ROWID;
