// SPDX-License-Identifier: GPL-3.0-or-later WITH LicenseRef-Kinfold-AppStore-Exception
//
// What the person chooses, who asked for live updates, and the log to send when sharing misbehaves.

import KinfoldCore
import SwiftUI

struct SettingsView: View {
    let state: FamilyState
    @EnvironmentObject private var model: Model
    @State private var name = ""

    private var current: FamilyState { model.family ?? state }

    var body: some View {
        Form {
            Section("Your name") {
                TextField("Your name", text: $name)
                Button("Save") { model.app.setMyName(name: name.trimmed) }
                    .disabled(name.trimmed.isEmpty || name.trimmed == current.myName)
            }
            Section {
                Toggle("Share my location", isOn: Binding(
                    get: { model.sharing() },
                    set: { $0 ? model.startSharing(why: "turned on in settings") : model.stopSharing() }
                ))
                Toggle("Tell the family if my phone goes quiet", isOn: Binding(
                    get: { model.watchConsent() == 1 },
                    set: { model.app.setWatchConsent(on: $0) }
                ))
            } footer: {
                Text("After an hour without an update, your server tells the other adults. Turning it off ends every watch on this phone at once.")
            }
            Section("Who asked for live updates") {
                let asks = current.liveAsks
                if asks.isEmpty {
                    Text("Nobody yet.").foregroundStyle(.secondary)
                }
                ForEach(Array(asks.prefix(50).enumerated()), id: \.offset) { _, ask in
                    VStack(alignment: .leading) {
                        Text(nameOf(ask.from) ?? "A former member")
                        Text(Self.when(ask.at) + (ask.honored ? "" : " · not answered"))
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                }
            }
            Section {
                ShareLink(items: model.log.files()) {
                    Label("Export the log", systemImage: "square.and.arrow.up")
                }
            } footer: {
                Text("The log holds times, delays, distances and states, for finding out why sharing misbehaved. It never holds where anyone was, a name, a key or an address.")
            }
            Section("This phone") {
                LabeledContent("Server connection", value: model.streamUp ? "Open" : "Closed")
                LabeledContent("Location", value: Model.describe(model.authorization))
                LabeledContent("Sharing mode", value: model.app.mode)
            }
        }
        .navigationTitle("Settings")
        .onAppear { name = current.myName ?? "" }
    }

    private func nameOf(_ account: Bytes) -> String? {
        current.people.first { $0.accountId == account }?.name
    }

    static func when(_ ms: Int64) -> String {
        let f = DateFormatter()
        f.dateStyle = .medium
        f.timeStyle = .short
        return f.string(from: Date(timeIntervalSince1970: Double(ms) / 1000))
    }
}
