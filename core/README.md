# Shared core (Phase 1)

Kotlin Multiplatform: encoding, member-log validation (PROTOCOL.md §6), envelopes (§7), payloads (§8), invites and linking (§9–10), compiled into the Android app, the iOS app and the web map. Cryptographic primitives come from each platform through a small interface; this module never implements them itself.

Exit test: every group in `spec/vectors` passes on JVM, iOS and JS targets.

License: GPL-3.0-or-later with the app-store permission (draft).
