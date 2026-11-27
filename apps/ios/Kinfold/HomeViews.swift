// SPDX-License-Identifier: GPL-3.0-or-later WITH LicenseRef-Kinfold-AppStore-Exception
//
// The family: the map, each person, inviting someone, and the map of the area.

import Combine
import KinfoldCore
import SwiftUI

struct HomeView: View {
    let state: FamilyState
    @EnvironmentObject private var model: Model
    @EnvironmentObject private var maps: Maps
    @State private var inviting = false
    @State private var showMaps = false
    @State private var showSettings = false

    var body: some View {
        NavigationStack {
            VStack(spacing: 0) {
                ZStack(alignment: .bottomTrailing) {
                    FamilyMap(people: state.people, region: maps.file, version: maps.version) { event, keys, values in
                        model.app.log(event: event, keys: keys, values: values)
                    }
                    Text(maps.file == nil ? "Made with Natural Earth" : "© OpenStreetMap contributors · Natural Earth")
                        .font(.caption2)
                        .padding(4)
                        .background(.white.opacity(0.7))
                }
                .frame(maxHeight: .infinity)
                ScrollView {
                    VStack(alignment: .leading, spacing: 12) {
                        cards
                        ForEach(state.people, id: \.self) { p in
                            PersonRow(person: p)
                        }
                    }
                    .padding()
                }
                .frame(maxHeight: 360)
            }
            .navigationTitle(state.circleName ?? "Family")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .topBarLeading) {
                    Button {
                        inviting = true
                    } label: {
                        Label("Invite", systemImage: "person.badge.plus")
                    }
                }
                ToolbarItem(placement: .topBarTrailing) {
                    Menu {
                        Button("Map of your area") { showMaps = true }
                        Button("Settings") { showSettings = true }
                    } label: {
                        Label("More", systemImage: "ellipsis.circle")
                    }
                }
            }
            .navigationDestination(isPresented: $showMaps) { MapsView() }
            .navigationDestination(isPresented: $showSettings) { SettingsView(state: state) }
            .sheet(isPresented: $inviting) {
                InviteView()
            }
        }
    }

    @ViewBuilder private var cards: some View {
        if let ask = state.asks.first {
            Card {
                Text("\(ask.ask.name) asks to join").font(.headline)
                Button("Compare the safety code") { inviting = true }
                    .buttonStyle(.borderedProminent)
            }
        }
        if !model.sharing() {
            Card {
                Text("You aren't sharing your location").font(.headline)
                Text("Your family sees you only while Kinfold shares. Choose \"Allow While Using\", then \"Change to Always Allow\" when iOS asks, so it shares in the background too.")
                    .font(.subheadline)
                Button("Share my location") { model.startSharing(why: "turned on in the app") }
                    .buttonStyle(.borderedProminent)
            }
        } else if model.authorization != .authorizedAlways && model.authorization != .notDetermined {
            Card {
                Text("Sharing stops when Kinfold is closed").font(.headline)
                Text("For the family to see you all day, allow Kinfold your location Always, in Settings › Kinfold › Location.")
                    .font(.subheadline)
            }
        }
        if model.watchConsent() < 0 {
            Card {
                Text("Tell the family if your phone goes quiet?").font(.headline)
                Text("After an hour without an update from this phone, your server tells the family's other adults, so someone checks. Your server learns only that the phone went quiet.")
                    .font(.subheadline)
                HStack {
                    Button("Yes") { model.app.setWatchConsent(on: true) }.buttonStyle(.borderedProminent)
                    Button("No") { model.app.setWatchConsent(on: false) }.buttonStyle(.bordered)
                }
            }
        }
        if maps.file == nil {
            Card {
                Text("Download the map of your area").font(.headline)
                Text("Streets and places come from your server once, and the map is drawn on this phone from then on.")
                    .font(.subheadline)
                Button("See the maps") { showMaps = true }
            }
        }
    }
}

struct Card<Content: View>: View {
    @ViewBuilder let content: Content

    var body: some View {
        VStack(alignment: .leading, spacing: 8) { content }
            .padding()
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(Brand.cream, in: RoundedRectangle(cornerRadius: 12))
    }
}

struct PersonRow: View {
    let person: Person
    @EnvironmentObject private var model: Model

    var body: some View {
        HStack(alignment: .top, spacing: 12) {
            Text(FamilyMap.Coordinator.initials(person.name))
                .font(.headline)
                .foregroundStyle(.white)
                .frame(width: 40, height: 40)
                .background(person.isMe ? Brand.night : Brand.tangerine, in: Circle())
            VStack(alignment: .leading, spacing: 2) {
                Text((person.name ?? "Someone") + (person.isMe ? " (you)" : "")).font(.headline)
                Text(detail).font(.subheadline).foregroundStyle(.secondary)
                if person.watchedByMe {
                    Text("You'll hear if their phone goes quiet.").font(.caption)
                }
            }
            Spacer()
            if !person.isMe {
                Button("Refresh") { model.app.askForLive(account: person.accountId) }
                    .buttonStyle(.bordered)
            }
        }
    }

    private var detail: String {
        let now = Date().timeIntervalSince1970 * 1000
        guard let s = person.seen else {
            if let heard = person.heardAt {
                return "No position yet · heard from " + FamilyMap.Coordinator.ago(now - Double(heard.int64Value)) + " ago"
            }
            return "No position yet"
        }
        var parts = [FamilyMap.Coordinator.ago(now - Double(s.ts)) + " ago", "±\(s.accM) m"]
        if let bat = s.bat {
            parts.append("\(bat.int64Value)% battery" + (s.charging?.boolValue == true ? ", charging" : ""))
        }
        return parts.joined(separator: " · ")
    }
}

/**
 * An invite as a QR code for another phone to scan (§9.1), and the people asking to join with it,
 * each with the safety code to compare before letting them in.
 */
struct InviteView: View {
    @EnvironmentObject private var model: Model
    @Environment(\.dismiss) private var dismiss
    @State private var pending: PendingInvite?
    @State private var failed = false
    private let poll = Timer.publish(every: 3, on: .main, in: .common).autoconnect()

    var body: some View {
        NavigationStack {
            ScrollView {
                VStack(spacing: 16) {
                    let asks = model.family?.asks ?? []
                    ForEach(asks, id: \.self) { ask in
                        Card {
                            Text("\(ask.ask.name) asks to join").font(.headline)
                            Text("Check that their phone shows this safety code:")
                            Text(ask.safetyCode).font(.system(.title3, design: .monospaced).weight(.medium))
                            HStack {
                                Button("Allow") {
                                    model.app.allow(ask: ask) { _ in dismiss() }
                                }
                                .buttonStyle(.borderedProminent)
                                Button("Decline", role: .destructive) {
                                    model.app.decline(ask: ask) { _ in dismiss() }
                                }
                                .buttonStyle(.bordered)
                            }
                        }
                    }
                    if let pending {
                        if let image = QR.image(pending.code) {
                            Image(uiImage: image)
                                .interpolation(.none)
                                .resizable()
                                .scaledToFit()
                                .frame(maxWidth: 280)
                        }
                        Text("Scan this with Kinfold on the other phone, from \"Join your family with an invite\". It works for a day.")
                            .multilineTextAlignment(.center)
                        ShareLink(item: pending.code) {
                            Label("Send the invite as text", systemImage: "square.and.arrow.up")
                        }
                        Button("End this invite", role: .destructive) {
                            model.app.endInvite(pending: pending)
                            dismiss()
                        }
                    } else if failed {
                        Text("The invite couldn't be made. Check the connection and try again.").foregroundStyle(.red)
                    } else {
                        ProgressView()
                    }
                }
                .padding()
            }
            .navigationTitle("Invite")
            .toolbar {
                ToolbarItem(placement: .confirmationAction) {
                    Button("Done") {
                        model.app.closeInvite()
                        dismiss()
                    }
                }
            }
        }
        .onAppear {
            if pending == nil {
                model.app.invite { p in
                    pending = p
                    failed = p == nil
                }
            }
        }
        .onReceive(poll) { _ in model.app.pollAsks() }
    }
}

struct MapsView: View {
    @EnvironmentObject private var maps: Maps

    var body: some View {
        List {
            if let name = maps.regionName, maps.file != nil {
                Section("On this phone") {
                    Text(name)
                    Button("Remove", role: .destructive) { maps.remove() }
                }
            }
            Section {
                switch maps.state {
                case .idle:
                    Button("See the maps your server offers") { maps.list() }
                case .listing:
                    ProgressView()
                case let .offer(offers, credit):
                    if offers.isEmpty {
                        Text("Your server offers no map of an area yet. Its operator adds one with `kinfold region add`.")
                    }
                    ForEach(offers, id: \.self) { offer in
                        HStack {
                            VStack(alignment: .leading) {
                                Text(offer.name)
                                Text(Self.size(offer.size)).font(.caption).foregroundStyle(.secondary)
                            }
                            Spacer()
                            Button("Download") { maps.download(offer) }
                        }
                    }
                    if !credit.isEmpty { Text(credit).font(.caption) }
                case let .downloading(offer, have, total):
                    Text(offer.name)
                    ProgressView(value: Double(have), total: Double(max(total, 1)))
                    Text("\(Self.size(have)) of \(Self.size(total))").font(.caption)
                    Button("Pause") { maps.pause() }
                case let .failed(message):
                    Text(message).foregroundStyle(.red)
                    Button("Try again") { maps.list() }
                }
            } footer: {
                Text("A map comes from your server once, whole, and is checked before it's kept. It is drawn on this phone from then on: nobody learns where you look.")
            }
        }
        .navigationTitle("Map of your area")
    }

    static func size(_ bytes: Int64) -> String {
        ByteCountFormatter.string(fromByteCount: bytes, countStyle: .file)
    }
}
