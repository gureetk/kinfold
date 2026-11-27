# Apps (Phase 1)

- [`android/`](android/): Kotlin, Jetpack Compose with Material 3. The walking skeleton: set up, invite and join, background sharing, live-view requests, silence watches, sharing health, the family on a map (MapLibre Native, on a region downloaded from the server), and the log.
- [`maps/`](maps/): what both apps draw their map with: the style, the glyphs and a world map of zoom 0 to 6, each made in the repository from its sources.
- `ios/`: Swift, SwiftUI, MapLibre Native; classic iOS conventions. Not started; `spikes/ios` holds the iOS spike app and the core's test host for now.

Both use the shared core in `../core` for envelopes, the member log and teen rules, with cryptography from the platform (CryptoKit on iOS; Tink or the platform on Android) behind a narrow interface. Both must pass every group in `spec/vectors`, which the core's own tests run on each platform.

Both keep a log of how sharing went, which the person can export and send: times, delays, distances, accuracies and states, never a coordinate, a key, a name or an address.

License: GPL-3.0-or-later with the app-store permission in `LICENSES/LicenseRef-Kinfold-AppStore-Exception.txt` (draft).
