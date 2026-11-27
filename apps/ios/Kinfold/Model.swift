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

    let log = Shared.log
    let locator = Locator()
    let maps = Maps()
    private(set) var app: IosApp!
    private let defaults = Shared.defaults
    private let paths = NWPathMonitor()
    private var path: NWPath?

    private override init() {
        super.init()
        let sealer = KeychainSealer()
        app = IosApp(dir: Shared.storageDirectory.path, sealer: sealer, ios: self, hooks: self)
        if sealer.failure != 0 {
            // Without the key, nothing secret can be kept: setting up and joining fail.
            app.log(event: "keychain", keys: ["state", "status"], values: ["failed", KotlinInt(value: sealer.failure)])
        }
        // Without the app group, the extensions can't open the device's files: pushes show the fixed text.
        app.log(event: "storage", keys: ["app_group"], values: [KotlinBoolean(value: Shared.inGroup)])
        maps.model = self
        locator.onFix = { [weak self] location in self?.fix(location) }
        locator.onAuthorization = { [weak self] status in
            self?.authorization = status
            self?.app.log(event: "permission", keys: ["location"], values: [Self.describe(status)])
            if status == .authorizedAlways { self?.startLocationPushes() }
        }
        UIDevice.current.isBatteryMonitoringEnabled = true
        paths.pathUpdateHandler = { [weak self] path in
            DispatchQueue.main.async { self?.pathChanged(path) }
        }
        paths.start(queue: DispatchQueue(label: "ca.gureet.kinfold.paths"))
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

    /** Whether the person has turned sharing on; a relaunch keeps it going until they stop it. The location-push extension reads it too. */
    private(set) var sharingOn: Bool {
        get { defaults.bool(forKey: Shared.sharingKey) }
        set {
            objectWillChange.send()
            defaults.set(newValue, forKey: Shared.sharingKey)
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

    func deviceName() -> String { Shared.deviceName() }

    func watchConsent() -> Int32 {
        guard let on = defaults.object(forKey: Shared.watchConsentKey) as? Bool else { return -1 }
        return on ? 1 : 0
    }

    func setWatchConsent(on: Bool) {
        objectWillChange.send()
        defaults.set(on, forKey: Shared.watchConsentKey)
    }

    func writeLog(line: String) {
        log.write(line)
    }

    func timeOfDay(ms: Int64) -> String { Shared.timeOfDay(ms) }

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
        if state.setUp && !pushesAsked {
            pushesAsked = true
            registerForPushes()
        }
    }

    // ---- pushes ----

    /** Apple's tokens for this phone (API.md §12): for alerts, and for location pushes once location is allowed all the time. */
    private var notifyToken: Data?
    private var locateToken: Data?
    private var locationPushes: CLLocationManager?

    /** Whether this build's tokens are from Apple's sandbox, as for a build run from Xcode (Config/Kinfold.xcconfig). */
    private static let pushSandbox = (Bundle.main.object(forInfoDictionaryKey: "KinfoldPushEnvironment") as? String) != "production"

    private var pushesAsked = false

    /**
     * Asks iOS for the tokens, so that the server can wake the phone through Apple when iOS has
     * suspended the app: alerts go to the notification extension, live-view requests to the
     * location-push extension. Once the phone is set up, at each launch.
     */
    private func registerForPushes() {
        #if DEBUG
            // The simulator in CI can't reach Apple; the test runs the extensions' core itself.
            if TestDriver.active { return }
        #endif
        UIApplication.shared.registerForRemoteNotifications()
        if locator.status == .authorizedAlways { startLocationPushes() }
    }

    private func startLocationPushes() {
        #if DEBUG
            if TestDriver.active { return }
        #endif
        guard locationPushes == nil else { return }
        let manager = CLLocationManager()
        locationPushes = manager
        manager.startMonitoringLocationPushes { [weak self] token, _ in
            DispatchQueue.main.async {
                guard let self else { return }
                if let token {
                    self.locateToken = token
                    self.registerPush()
                } else {
                    self.locationPushes = nil
                    self.app.log(event: "push_registration", keys: ["state", "route"], values: ["no_token", "location"])
                }
            }
        }
    }

    func gotNotifyToken(_ token: Data) {
        notifyToken = token
        registerPush()
    }

    func notifyTokenFailed() {
        app.log(event: "push_registration", keys: ["state", "route"], values: ["no_token", "alert"])
    }

    /** Sends the tokens to the server; again whenever iOS gives a new one. */
    private func registerPush() {
        guard let notifyToken else { return }
        app.registerPush(notify: notifyToken, locate: locateToken, sandbox: Self.pushSandbox)
    }

    /**
     * A background push, which the server sends for a live-view request when the phone has no
     * location-push token: iOS gives the app a few seconds, enough for the core to handle it and
     * for sharing to answer.
     */
    func backgroundPush(_ info: [AnyHashable: Any], completion: @escaping (UIBackgroundFetchResult) -> Void) {
        guard let payload = info["kinfold"] as? String else { return completion(.noData) }
        if sharingOn {
            locator.start()
            app.connect()
        }
        app.pushed(payload: payload) { kind in
            completion(kind == "dropped" || kind == "failed" ? .noData : .newData)
        }
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
