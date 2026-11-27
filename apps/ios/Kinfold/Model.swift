// SPDX-License-Identifier: GPL-3.0-or-later WITH LicenseRef-Kinfold-AppStore-Exception
//
// What the app's parts share: the core (IosApp), the family as this phone knows it, sharing, and
// the few settings the person chooses. The core calls back on the main thread, and so does
// everything here.

import CoreLocation
import Foundation
import KinfoldCore
import Network
import SwiftUI
import UIKit
import UserNotifications

final class Model: NSObject, ObservableObject, IosPlatform, IosHooks {
    static let shared = Model()

    /** The family as the core keeps it; nil until it first reports. */
    @Published private(set) var family: FamilyState?
    /** Whether the stream to the server is open. */
    @Published private(set) var streamUp = false
    /** While a join waits for the inviter's phone: the safety code to compare, and who to compare it with. */
    @Published var waiting: (inviter: String, code: String)?
    /** What a setup or a join is doing, or nil. */
    @Published var flow: String?
    /** What went wrong in the last setup or join. */
    @Published var flowError: String?
    @Published private(set) var joining = false
    @Published private(set) var authorization: CLAuthorizationStatus = .notDetermined

    let log = EventLog()
    let locator = Locator()
    let maps = Maps()
    private(set) var app: IosApp!
    private let defaults = UserDefaults.standard
    private let paths = NWPathMonitor()
    private var path: NWPath?

    private override init() {
        super.init()
        app = IosApp(dir: Self.storageDirectory().path, sealer: KeychainSealer(), ios: self, hooks: self)
        maps.model = self
        locator.onFix = { [weak self] location in self?.fix(location) }
        locator.onAuthorization = { [weak self] status in
            self?.authorization = status
            self?.app.log(event: "permission", keys: ["location"], values: [Self.describe(status)])
        }
        UIDevice.current.isBatteryMonitoringEnabled = true
        paths.pathUpdateHandler = { [weak self] path in
            DispatchQueue.main.async { self?.pathChanged(path) }
        }
        paths.start(queue: DispatchQueue(label: "ca.gureet.kinfold.paths"))
    }

    /** Where the core keeps the device's files: inside the app's container, left out of backups. */
    private static func storageDirectory() -> URL {
        var dir = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0].appendingPathComponent("kinfold", isDirectory: true)
        try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true, attributes: [.protectionKey: FileProtectionType.completeUntilFirstUserAuthentication])
        var values = URLResourceValues()
        values.isExcludedFromBackup = true
        try? dir.setResourceValues(values)
        return dir
    }

    // ---- the app's life ----

    /** At launch, with a screen or without one: sharing goes on where it was. */
    func launched(byLocation: Bool) {
        app.log(event: "launch", keys: ["by_location", "sharing"], values: [KotlinBoolean(value: byLocation), KotlinBoolean(value: sharingOn)])
        if sharingOn {
            locator.start()
            app.connect()
        }
        #if DEBUG
            TestDriver.run(self)
        #endif
    }

    func phaseChanged(_ phase: ScenePhase) {
        switch phase {
        case .active:
            app.connect()
            app.pollAsks()
        case .background:
            // Sharing keeps the app running in the background; without it, iOS suspends the app
            // soon, and the stream would only die there.
            if !sharingOn { app.disconnect() }
        default:
            break
        }
    }

    /** A connection on the old network can die quietly: the stream starts again on the new one at once. */
    private func pathChanged(_ now: NWPath) {
        let before = path
        path = now
        app.log(event: "net", keys: ["state", "kind"], values: [now.status == .satisfied ? "available" : "lost", Self.kind(now)])
        if let before, before.status == .satisfied, now.status == .satisfied, Self.kind(before) != Self.kind(now) {
            app.restart(why: "network changed")
        }
    }

    private static func kind(_ path: NWPath) -> String {
        if path.usesInterfaceType(.wifi) { return "wifi" }
        if path.usesInterfaceType(.cellular) { return "cellular" }
        if path.usesInterfaceType(.wiredEthernet) { return "wired" }
        return path.status == .satisfied ? "other" : "none"
    }

    // ---- getting in ----

    func setUp(code: String, myName: String, circleName: String) {
        flowError = nil
        app.setUp(code: code, myName: myName, circleName: circleName, progress: { [weak self] text in
            self?.flow = text
        }, done: { [weak self] error in
            self?.flow = nil
            self?.flowError = error
        })
    }

    func createCircle(myName: String, circleName: String) {
        flowError = nil
        flow = "Creating \(circleName)"
        app.createCircle(myName: myName, circleName: circleName) { [weak self] error in
            self?.flow = nil
            self?.flowError = error
        }
    }

    func join(code: String, myName: String) {
        flowError = nil
        joining = true
        flow = "Connecting to the family's server"
        app.join(code: code, myName: myName, waiting: { [weak self] inviter, safetyCode in
            self?.flow = nil
            self?.waiting = (inviter, safetyCode)
        }, done: { [weak self] error in
            self?.flow = nil
            self?.waiting = nil
            self?.joining = false
            self?.flowError = error
        })
    }

    func cancelFlow() {
        app.cancel()
        flow = nil
        waiting = nil
        joining = false
    }

    // ---- sharing ----

    /** Whether the person has turned sharing on; a relaunch keeps it going until they stop it. */
    private(set) var sharingOn: Bool {
        get { defaults.bool(forKey: "sharing") }
        set {
            objectWillChange.send()
            defaults.set(newValue, forKey: "sharing")
        }
    }

    func startSharing(why: String) {
        sharingOn = true
        locator.requestPermission()
        locator.start()
        app.sharingChanged(on: true, why: why)
        askForNotifications()
    }

    func stopSharing() {
        sharingOn = false
        locator.stop()
        app.sharingChanged(on: false, why: "turned off in the app")
    }

    /** One fix from Core Location, for the core's engine to decide on. */
    private func fix(_ location: CLLocation) {
        guard location.horizontalAccuracy >= 0 else { return }
        let device = UIDevice.current
        let level = device.batteryLevel
        let charging = device.batteryState == .charging || device.batteryState == .full
        app.fix(
            atMs: Int64(location.timestamp.timeIntervalSince1970 * 1000),
            latE7: Int64((location.coordinate.latitude * 1e7).rounded()),
            lonE7: Int64((location.coordinate.longitude * 1e7).rounded()),
            accM: max(1, Int64(location.horizontalAccuracy.rounded())),
            spdCms: location.speed >= 0 ? Int64((location.speed * 100).rounded()) : -1,
            headingDeg: location.course >= 0 ? Int64(location.course.rounded()) : -1,
            batPct: level >= 0 ? Int32((level * 100).rounded()) : -1,
            charging: charging,
            mock: location.sourceInformation?.isSimulatedBySoftware ?? false
        )
    }

    // ---- IosPlatform ----

    func deviceName() -> String {
        var info = utsname()
        uname(&info)
        let machine = withUnsafeBytes(of: &info.machine) { raw in
            String(decoding: raw.prefix { $0 != 0 }, as: UTF8.self)
        }
        return "Apple " + machine
    }

    func watchConsent() -> Int32 {
        guard let on = defaults.object(forKey: "watch_consent") as? Bool else { return -1 }
        return on ? 1 : 0
    }

    func setWatchConsent(on: Bool) {
        objectWillChange.send()
        defaults.set(on, forKey: "watch_consent")
    }

    func writeLog(line: String) {
        log.write(line)
    }

    func timeOfDay(ms: Int64) -> String {
        Self.time.string(from: Date(timeIntervalSince1970: Double(ms) / 1000))
    }

    private static let time: DateFormatter = {
        let f = DateFormatter()
        f.dateStyle = .none
        f.timeStyle = .short
        return f
    }()

    // ---- IosHooks ----

    func sharing() -> Bool {
        sharingOn
    }

    func live(forMs: Int64) {
        locator.live(forMs: forMs)
    }

    func silenceAlert(id: Int32, title: String, text: String) {
        notify(id: "silence-\(id)", title: title, text: text)
    }

    func joinRequest(name: String) {
        if UIApplication.shared.applicationState != .active {
            notify(id: "join-request", title: "\(name) asks to join", text: "Open Kinfold and compare the safety code before you let them in.")
        }
    }

    func connected(up: Bool) {
        streamUp = up
    }

    func familyChanged(state: FamilyState) {
        family = state
    }

    // ---- notifications ----

    private func askForNotifications() {
        #if DEBUG
            if TestDriver.active { return }
        #endif
        UNUserNotificationCenter.current().requestAuthorization(options: [.alert, .sound]) { [weak self] granted, _ in
            DispatchQueue.main.async {
                self?.app.log(event: "permission", keys: ["notifications"], values: [granted ? "granted" : "denied"])
            }
        }
    }

    private func notify(id: String, title: String, text: String) {
        let content = UNMutableNotificationContent()
        content.title = title
        content.body = text
        content.sound = .default
        UNUserNotificationCenter.current().add(UNNotificationRequest(identifier: id, content: content, trigger: nil))
    }

    static func describe(_ status: CLAuthorizationStatus) -> String {
        switch status {
        case .authorizedAlways: return "always"
        case .authorizedWhenInUse: return "when_in_use"
        case .denied: return "denied"
        case .restricted: return "restricted"
        case .notDetermined: return "not_determined"
        @unknown default: return "unknown"
        }
    }
}
