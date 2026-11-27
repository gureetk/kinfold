// SPDX-License-Identifier: GPL-3.0-or-later WITH LicenseRef-Kinfold-AppStore-Exception
//
// The ways in: setting up from the server's setup code, and joining with an invite (PROTOCOL.md §9).

import KinfoldCore
import SwiftUI

struct StartView: View {
    @EnvironmentObject private var model: Model

    var body: some View {
        NavigationStack {
            VStack(alignment: .leading, spacing: 16) {
                Text("Your family's locations, on your family's own server, which can't read them.")
                    .foregroundStyle(.secondary)
                if model.waiting != nil || model.joining {
                    JoinWaitingView()
                } else {
                    NavigationLink {
                        JoinView()
                    } label: {
                        Label("Join your family with an invite", systemImage: "qrcode.viewfinder")
                            .frame(maxWidth: .infinity)
                    }
                    .buttonStyle(.borderedProminent)
                    NavigationLink {
                        SetUpView()
                    } label: {
                        Label("Set up from your server's code", systemImage: "server.rack")
                            .frame(maxWidth: .infinity)
                    }
                    .buttonStyle(.bordered)
                    Text("Set up only on the first phone in the family, with the code your server's `kinfold setup` shows. Everyone else joins with an invite from a phone already in.")
                        .font(.footnote)
                        .foregroundStyle(.secondary)
                }
                if let error = model.flowError {
                    Text(error).foregroundStyle(.red)
                }
                Spacer()
            }
            .padding()
            .navigationTitle("Kinfold")
        }
    }
}

/** A code typed or pasted, or scanned with the camera. */
struct CodeField: View {
    let title: String
    @Binding var code: String
    @State private var scanning = false

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            TextField(title, text: $code, axis: .vertical)
                .font(.system(.footnote, design: .monospaced))
                .textInputAutocapitalization(.never)
                .autocorrectionDisabled()
                .lineLimit(2...5)
                .textFieldStyle(.roundedBorder)
            Button {
                scanning = true
            } label: {
                Label("Scan the code", systemImage: "camera")
            }
        }
        .sheet(isPresented: $scanning) {
            Scanner { found in
                code = found
                scanning = false
            }
            .ignoresSafeArea()
        }
    }
}

struct SetUpView: View {
    @EnvironmentObject private var model: Model
    @State private var code = ""
    @State private var name = ""
    @State private var circle = "Family"

    var body: some View {
        Form {
            Section {
                CodeField(title: "The setup code (KFS0…)", code: $code)
            } footer: {
                Text("This phone checks the server's key against the code before it sends anything.")
            }
            Section("You") {
                TextField("Your name", text: $name)
                TextField("The family's name", text: $circle)
            }
            Section {
                if let flow = model.flow {
                    HStack {
                        ProgressView()
                        Text(flow)
                    }
                } else {
                    Button("Set up and create the family") {
                        model.setUp(code: code.trimmingCharacters(in: .whitespacesAndNewlines), myName: name.trimmed, circleName: circle.trimmed)
                    }
                    .disabled(code.isEmpty || name.trimmed.isEmpty || circle.trimmed.isEmpty)
                }
                if let error = model.flowError {
                    Text(error).foregroundStyle(.red)
                }
            }
        }
        .navigationTitle("Set up")
    }
}

/** For a phone set up but in no circle, as after a setup that stopped half way. */
struct CreateCircleView: View {
    @EnvironmentObject private var model: Model
    @State private var name = ""
    @State private var circle = "Family"

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    TextField("Your name", text: $name)
                    TextField("The family's name", text: $circle)
                } footer: {
                    Text("This phone is set up with your server, but in no family yet.")
                }
                Section {
                    if let flow = model.flow {
                        HStack {
                            ProgressView()
                            Text(flow)
                        }
                    } else {
                        Button("Create the family") {
                            model.createCircle(myName: name.trimmed, circleName: circle.trimmed)
                        }
                        .disabled(name.trimmed.isEmpty || circle.trimmed.isEmpty)
                    }
                    if let error = model.flowError {
                        Text(error).foregroundStyle(.red)
                    }
                }
            }
            .navigationTitle("Your family")
        }
    }
}

/**
 * The join screen (PROTOCOL.md §9.1): the terms on offer, before anything is sent. The circle's
 * and the inviter's names are what the invite says; the safety code, compared on both phones,
 * is what proves who invited.
 */
struct JoinView: View {
    @EnvironmentObject private var model: Model
    @State private var code = ""
    @State private var name = ""

    var body: some View {
        Form {
            Section {
                CodeField(title: "The invite (KFI0…)", code: $code)
            }
            if let terms = model.app.inviteTerms(code: code) {
                Section("The invite") {
                    Text("Join **\(terms.circleName)**, invited by **\(terms.inviterName.isEmpty ? "someone" : terms.inviterName)**.")
                    if terms.adult {
                        Text("You join as an adult: you see the family, the family sees you, and no one sets rules for you.")
                            .foregroundStyle(.secondary)
                    } else {
                        Text("This invite asks you to join with a teen's rules. This version of Kinfold can't join that way yet; ask for an adult's invite.")
                            .foregroundStyle(.red)
                    }
                }
                if terms.adult {
                    Section("You") {
                        TextField("Your name", text: $name)
                        Button("Join") {
                            model.join(code: terms.code, myName: name.trimmed)
                        }
                        .disabled(name.trimmed.isEmpty || model.flow != nil)
                        if let flow = model.flow {
                            HStack {
                                ProgressView()
                                Text(flow)
                            }
                        }
                    }
                }
            } else if !code.isEmpty {
                Text("That isn't an invite.").foregroundStyle(.red)
            }
            if let error = model.flowError {
                Text(error).foregroundStyle(.red)
            }
        }
        .navigationTitle("Join")
    }
}

/** While the inviter's phone decides: the safety code both phones show. */
struct JoinWaitingView: View {
    @EnvironmentObject private var model: Model

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            if let waiting = model.waiting {
                Text("Check that \(waiting.inviter)'s phone shows this safety code, then they let you in.")
                Text(waiting.code)
                    .font(.system(.title3, design: .monospaced).weight(.medium))
                    .padding()
                    .frame(maxWidth: .infinity)
                    .background(Brand.cream, in: RoundedRectangle(cornerRadius: 12))
                Text("If the codes differ, someone else made this invite: cancel, and don't join.")
                    .font(.footnote)
                    .foregroundStyle(.secondary)
            } else {
                HStack {
                    ProgressView()
                    Text(model.flow ?? "Joining")
                }
            }
            Button("Cancel", role: .cancel) { model.cancelFlow() }
        }
    }
}

extension String {
    var trimmed: String { trimmingCharacters(in: .whitespacesAndNewlines) }
}
