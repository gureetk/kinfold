-- SPDX-License-Identifier: AGPL-3.0-or-later
--
-- Schema version 5: nicknames that only the operator sees (API.md §16).

ALTER TABLE accounts ADD COLUMN nickname TEXT NOT NULL DEFAULT '';
ALTER TABLE devices ADD COLUMN nickname TEXT NOT NULL DEFAULT '';
