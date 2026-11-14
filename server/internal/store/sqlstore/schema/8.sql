-- SPDX-License-Identifier: AGPL-3.0-or-later
--
-- Schema version 8: a watch grant's issued_at (PROTOCOL.md §14.1), and when the watched
-- account deleted a watch (API.md §8).

-- Grants stored before this version are in the shorter form without issued_at, which no
-- longer parses. Phones put their watches again after every login (API.md §5).
DELETE FROM watches;
ALTER TABLE watches ADD COLUMN issued_at INTEGER NOT NULL DEFAULT 0;
ALTER TABLE watches ADD COLUMN revoked_at INTEGER NOT NULL DEFAULT 0;
