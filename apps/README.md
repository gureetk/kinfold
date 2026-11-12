# Apps (Phase 1)

- `android/` — Kotlin, Jetpack Compose, MapLibre Native; Material 3.
- `ios/` — Swift, SwiftUI, MapLibre Native; classic iOS conventions.

Both use the shared core in `../core` for envelopes, the member log and teen rules, with cryptography from the platform (CryptoKit on iOS; Tink or the platform on Android) behind a narrow interface. Both must pass every group in `spec/vectors`.

License: GPL-3.0-or-later with the app-store permission in `LICENSES/LicenseRef-Kinfold-AppStore-Exception.txt` (draft).
