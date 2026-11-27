// SPDX-License-Identifier: GPL-3.0-or-later WITH LicenseRef-Kinfold-AppStore-Exception
//
// The simulator test's first steps (simulator-test.sh), taken from launch arguments instead of
// taps. Only in Debug builds, and only when launched with them: Xcode, simctl or devicectl can
// pass launch arguments, and nothing else can.

#if DEBUG
    import Foundation
    import KinfoldCore

    /**
     * Launch arguments, read through UserDefaults' argument domain:
     *
     * - `-KinfoldTestName NAME`: the person's name; without it, nothing happens;
     * - `-KinfoldTestSetup CODE` and `-KinfoldTestCircle NAME`: set up from the setup code and found the circle;
     * - `-KinfoldTestInvite CODE`: join with the invite instead;
     * - `-KinfoldTestAdmit YES`: once in, make an invite, write it to Documents/test-invite.txt, and let in the first person who asks;
     * - `-KinfoldTestWatch YES`: agree to a silence watch;
     * - `-KinfoldTestShare YES`: share the location;
     * - `-KinfoldTestRegion YES`: download the first map region the server offers.
     *
     * Once in, the home screen shows, as for a person, so the map is drawn.
     */
    enum TestDriver {
        private static let d = UserDefaults.standard

        static var active: Bool { d.string(forKey: "KinfoldTestName") != nil }

        static func run(_ model: Model) {
            guard let name = d.string(forKey: "KinfoldTestName") else { return }
            model.app.log(event: "test", keys: ["state"], values: ["start"])
            if d.bool(forKey: "KinfoldTestWatch") { model.app.setWatchConsent(on: true) }
            if let code = d.string(forKey: "KinfoldTestSetup") {
                let circle = d.string(forKey: "KinfoldTestCircle") ?? "Test-family"
                model.app.setUp(code: code, myName: name, circleName: circle, progress: { _ in }, done: { error in
                    if let error { return failed(model, error) }
                    afterIn(model)
                })
            } else if let code = d.string(forKey: "KinfoldTestInvite") {
                model.join(code: code, myName: name)
                waitUntilIn(model)
            }
        }

        private static func waitUntilIn(_ model: Model) {
            Timer.scheduledTimer(withTimeInterval: 1, repeats: true) { timer in
                if model.family?.circleId != nil && !model.joining {
                    timer.invalidate()
                    afterIn(model)
                } else if let error = model.flowError {
                    timer.invalidate()
                    failed(model, error)
                }
            }
        }

        private static func afterIn(_ model: Model) {
            model.app.log(event: "test", keys: ["state"], values: ["in"])
            if d.bool(forKey: "KinfoldTestShare") { model.startSharing(why: "test") }
            if d.bool(forKey: "KinfoldTestAdmit") { admit(model) }
            if d.bool(forKey: "KinfoldTestRegion") { region(model, attempt: 1) }
        }

        private static func admit(_ model: Model) {
            model.app.invite { pending in
                guard let pending else { return failed(model, "no invite") }
                let file = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask)[0].appendingPathComponent("test-invite.txt")
                try? pending.code.write(to: file, atomically: true, encoding: .utf8)
                Timer.scheduledTimer(withTimeInterval: 2, repeats: true) { timer in
                    if let ask = model.family?.asks.first {
                        timer.invalidate()
                        model.app.allow(ask: ask) { error in
                            if let error { failed(model, error) }
                        }
                    } else {
                        model.app.pollAsks()
                    }
                }
            }
        }

        private static func region(_ model: Model, attempt: Int) {
            model.maps.list()
            Timer.scheduledTimer(withTimeInterval: 1, repeats: true) { timer in
                switch model.maps.state {
                case let .offer(offers, _):
                    timer.invalidate()
                    if let first = offers.first { model.maps.download(first) } else { failed(model, "no region on offer") }
                case .failed:
                    timer.invalidate()
                    if attempt < 5 {
                        DispatchQueue.main.asyncAfter(deadline: .now() + 10) { region(model, attempt: attempt + 1) }
                    }
                default:
                    break
                }
            }
        }

        private static func failed(_ model: Model, _ error: String) {
            model.app.log(event: "test", keys: ["state", "error"], values: ["failed", error])
        }
    }
#endif
