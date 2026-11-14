-- SPDX-License-Identifier: AGPL-3.0-or-later
--
-- Schema version 4: push registrations (API.md §12).

CREATE TABLE pushes (
	device   BLOB PRIMARY KEY,
	kind     TEXT NOT NULL,  -- relay, webpush, or dropped
	notify   BLOB,           -- relay capabilities
	locate   BLOB,
	endpoint TEXT NOT NULL,  -- webpush
	p256dh   BLOB,
	auth     BLOB
) STRICT, WITHOUT ROWID;
