-- SPDX-License-Identifier: AGPL-3.0-or-later
--
-- Schema version 9: the Apple environment of an apns push registration (API.md §12).

ALTER TABLE pushes ADD COLUMN environment TEXT NOT NULL DEFAULT '';
