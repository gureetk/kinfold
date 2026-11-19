// SPDX-License-Identifier: GPL-3.0-or-later WITH LicenseRef-Kinfold-AppStore-Exception
//
// The app launched with --checks runs the core check and spike 5's page by itself, prints what
// they found to standard output, and exits with 0 if both passed. CI launches it that way in the
// simulator (xcrun simctl launch --console-pty ... ca.gureet.kinfold --checks).

import SwiftUI

enum Checks {
    static var requested: Bool { ProcessInfo.processInfo.arguments.contains("--checks") }

    @MainActor static func run() async {
        let core = await CoreCheck.run()
        say("== The core in this app ==\n\(core.text)\n")
        var web: (ok: Bool, text: String)?
        // The page takes a few seconds on a phone; ten minutes is the limit.
        for _ in 0..<600 {
            try? await Task.sleep(nanoseconds: 1_000_000_000)
            if let view = WebChecks.current, let result = await WebChecks.result(of: view) {
                web = result
                break
            }
        }
        say("== Spike 5's page in WebKit ==\n\(web?.text ?? "The page didn't finish in ten minutes.")\n")
        say(core.ok ? "The core check passed." : "The core check failed.")
        say(web.map { $0.ok ? "The page finished: every check passed." : "The page finished: some checks failed." } ?? "The page didn't finish.")
        exit(core.ok && web?.ok == true ? 0 : 1)
    }

    static func say(_ text: String) {
        FileHandle.standardOutput.write(Data((text + "\n").utf8))
    }
}

struct ChecksRunner: View {
    var body: some View {
        SpikeWebView()
            .task { await Checks.run() }
    }
}
