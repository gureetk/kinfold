# Shared core (Phase 1)

Kotlin Multiplatform: encoding, member-log validation (PROTOCOL.md §6), envelopes (§7), payloads (§8), invites, linking and recovery (§9–10), watch grants and pushes (§14), compiled into the Android app, the iOS app and the web map. Cryptographic primitives come from each platform through a small interface; this module never implements them itself. It does make the byte checks of §3.3 and §3.5 in front of them, so that every platform returns the same verdict on unusual keys and signatures.

Exit test: every group in `spec/vectors` passes on JVM, iOS and JS targets.

License: GPL-3.0-or-later with the app-store permission (draft).
