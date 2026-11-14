-- SPDX-License-Identifier: AGPL-3.0-or-later
--
-- Schema version 6: when the last backup was written (API.md §16).

ALTER TABLE settings ADD COLUMN last_backup_at INTEGER NOT NULL DEFAULT 0;
