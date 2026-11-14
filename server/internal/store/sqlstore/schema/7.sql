-- SPDX-License-Identifier: AGPL-3.0-or-later
--
-- Schema version 7: the operator's rate limits (API.md §3) and closed ranges on map regions
-- for web devices (§13).

ALTER TABLE settings ADD COLUMN web_tile_ranges INTEGER NOT NULL DEFAULT 0;
ALTER TABLE settings ADD COLUMN limits TEXT NOT NULL DEFAULT '';
