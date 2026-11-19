// SPDX-License-Identifier: GPL-3.0-or-later WITH LicenseRef-Kinfold-AppStore-Exception
//
// The iOS spike app, ca.gureet.kinfold: a screen for each spike. Launched with --checks, as CI
// does in the simulator, it runs the checks below by itself, prints what they found and exits.

import SwiftUI

@main
struct KinfoldApp: App {
    var body: some Scene {
        WindowGroup {
            if Checks.requested {
                ChecksRunner()
            } else {
                ContentView()
            }
        }
    }
}

struct ContentView: View {
    var body: some View {
        NavigationStack {
            List {
                Section {
                    NavigationLink("The core in this app") { CoreCheckView() }
                } footer: {
                    Text("The Kotlin core, from KinfoldCore.xcframework, reaching CryptoKit. Its own tests run in the CoreTests app, from Xcode.")
                }
                Section {
                    NavigationLink("The test vectors in WebKit") { WebChecksView() }
                } header: {
                    Text("Spike 5")
                } footer: {
                    Text("spikes/web's page, run by this iPhone's WebKit, the engine Safari uses.")
                }
            }
            .navigationTitle("Kinfold spikes")
        }
    }
}
