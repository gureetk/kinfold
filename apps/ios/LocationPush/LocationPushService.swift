// SPDX-License-Identifier: GPL-3.0-or-later WITH LicenseRef-Kinfold-AppStore-Exception
//
// The location-push extension, ca.gureet.kinfold.location: what answers a location push (API.md
// §12, delivery `location`) while iOS keeps the app suspended or has ended it. The server sends one
// for a live-view request, and to wake the phone before it tells a watcher the phone has gone quiet.

import CoreLocation
import Foundation
import KinfoldCore

/**
 * Opens the push with the core, on the app's files, and handles what it holds as the app would.
 * Then, if the person shares their location, it sends one fix, at once and encrypted to the
 * family; with no fix in 20 seconds, a heartbeat instead, so that a watcher still learns the phone
 * is there. An extension has little time and memory, so it stops as soon as the server has the
 * answer.
 */
final class LocationPushService: NSObject, CLLocationPushServiceExtension, CLLocationManagerDelegate {
    private var completion: (() -> Void)?
    private var core: IosExtension?
    private var manager: CLLocationManager?
    private var answered = false
    private var kind = "none"

    func didReceiveLocationPushPayload(_ payload: [String: Any], completion: @escaping () -> Void) {
        self.completion = completion
        guard let sealed = payload["kinfold"] as? String else {
            DispatchQueue.main.async { self.finish("no_payload") }
            return
        }
        // The core answers on the main thread, and Core Location calls back on the thread that made its manager.
        DispatchQueue.main.async {
            let core = Shared.extensionCore(route: "location")
            self.core = core
            core.pushed(payload: sealed) { [weak self] outcome in
                guard let self else { return }
                self.kind = outcome.kind
                if outcome.wantsFix { self.locate() } else { self.finish(outcome.kind) }
            }
        }
    }

    private func locate() {
        let m = CLLocationManager()
        m.delegate = self
        m.desiredAccuracy = kCLLocationAccuracyNearestTenMeters
        manager = m
        m.requestLocation()
        DispatchQueue.main.asyncAfter(deadline: .now() + 20) { [weak self] in self?.noFix("timeout") }
    }

    func locationManager(_ manager: CLLocationManager, didUpdateLocations locations: [CLLocation]) {
        guard !answered, let location = locations.last, location.horizontalAccuracy >= 0 else { return }
        answered = true
        let battery = Shared.battery()
        core?.fix(
            atMs: Int64(location.timestamp.timeIntervalSince1970 * 1000),
            latE7: Int64((location.coordinate.latitude * 1e7).rounded()),
            lonE7: Int64((location.coordinate.longitude * 1e7).rounded()),
            accM: max(1, Int64(location.horizontalAccuracy.rounded())),
            spdCms: location.speed >= 0 ? Int64((location.speed * 100).rounded()) : -1,
            headingDeg: location.course >= 0 ? Int64(location.course.rounded()) : -1,
            batPct: battery.pct,
            charging: battery.charging,
            mock: location.sourceInformation?.isSimulatedBySoftware ?? false
        ) { [weak self] sent in
            self?.finish(sent.boolValue ? "fix_sent" : "fix_failed")
        }
    }

    func locationManager(_ manager: CLLocationManager, didFailWithError error: Error) {
        noFix("no_fix")
    }

    private func noFix(_ why: String) {
        guard !answered, completion != nil else { return }
        answered = true
        let battery = Shared.battery()
        core?.heartbeat(batPct: battery.pct, charging: battery.charging, why: "location_push_" + why) { [weak self] sent in
            self?.finish(sent.boolValue ? "heartbeat_sent" : "heartbeat_failed")
        }
    }

    func serviceExtensionWillTerminate() {
        DispatchQueue.main.async { self.finish("terminated") }
    }

    private func finish(_ what: String) {
        guard let completion else { return }
        self.completion = nil
        manager?.delegate = nil
        core?.log(event: "extension", keys: ["route", "kind", "answer", "took_ms", "mem_mb"], values: ["location", kind, what, KotlinLong(value: core?.ranMs() ?? -1), KotlinLong(value: Shared.footprintMB())])
        Shared.log.flush()
        completion()
    }
}
