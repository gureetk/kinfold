-- SPDX-License-Identifier: AGPL-3.0-or-later
--
-- Schema version 3: share links (API.md §11).

CREATE TABLE shares (
	id         BLOB PRIMARY KEY,
	account    BLOB NOT NULL,
	device     BLOB NOT NULL,    -- the creating device
	expires_at INTEGER NOT NULL,
	update_raw BLOB,             -- the latest ShareUpdate
	seq        INTEGER NOT NULL, -- its seq
	views      INTEGER NOT NULL,
	last_view  INTEGER NOT NULL,
	ended      INTEGER NOT NULL  -- deleted: kept, empty, until expires_at
) STRICT, WITHOUT ROWID;
CREATE INDEX shares_device ON shares (device);
CREATE INDEX shares_expiry ON shares (expires_at);
