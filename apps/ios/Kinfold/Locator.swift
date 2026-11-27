// SPDX-License-Identifier: GPL-3.0-or-later WITH LicenseRef-Kinfold-AppStore-Exception
//
// The location engine's iOS side: Core Location's own updates, in the background too. The core's
// engine (Motion) decides what goes up.

import CoreLocation
import Foundation

/**
 * Fixes from `CLLocationUpdate.liveUpdates`, kept coming in the background by a
 * `CLBackgroundActivitySession`, with significant-change monitoring as the safety net that starts
 * the app again if iOS ended it. A live-view request adds a fix every 5 seconds for its time, even
 * when the phone is still and live updates pause.
 */
final class Locator: NSObject, CLLocationManagerDelegate {
    var onFix: ((CLLocation) -> Void)?
    var onAuthorization: ((CLAuthorizationStatus) -> Void)?

    private let manager = CLLocationManager()
    private var updates: Task<Void, Never>?
    private var session: CLBackgroundActivitySession?
    private var liveTimer: Timer?
    private var liveUntil = Date.distantPast

    override init() {
        super.init()
        manager.delegate = self
    }

    /** Asks for "Always": iOS asks for "While using" first, and offers "Always" later. */
    func requestPermission() {
        switch manager.authorizationStatus {
        case .notDetermined: manager.requestWhenInUseAuthorization()
        case .authorizedWhenInUse: manager.requestAlwaysAuthorization()
        default: break
        }
    }

    var status: CLAuthorizationStatus { manager.authorizationStatus }

    func start() {
        guard updates == nil else { return }
        session = CLBackgroundActivitySession()
        manager.startMonitoringSignificantLocationChanges()
        updates = Task { [weak self] in
            do {
                for try await update in CLLocationUpdate.liveUpdates() {
                    if Task.isCancelled { break }
                    guard let location = update.location else { continue }
                    DispatchQueue.main.async { self?.onFix?(location) }
                }
            } catch {
                // The updates ended; start() makes new ones.
            }
        }
    }

    func stop() {
        updates?.cancel()
        updates = nil
        session?.invalidate()
        session = nil
        manager.stopMonitoringSignificantLocationChanges()
        liveTimer?.invalidate()
        liveTimer = nil
    }

    /** A fix every 5 seconds for [forMs], each one uploaded: the answer to a live-view request. */
    func live(forMs: Int64) {
        liveUntil = max(liveUntil, Date().addingTimeInterval(Double(forMs) / 1000))
        manager.requestLocation()
        guard liveTimer == nil else { return }
        liveTimer = Timer.scheduledTimer(withTimeInterval: 5, repeats: true) { [weak self] timer in
            guard let self else { return timer.invalidate() }
            if Date() >= self.liveUntil {
                timer.invalidate()
                self.liveTimer = nil
                return
            }
            self.manager.requestLocation()
        }
    }

    func locationManager(_ manager: CLLocationManager, didUpdateLocations locations: [CLLocation]) {
        guard let location = locations.last else { return }
        onFix?(location)
    }

    func locationManager(_ manager: CLLocationManager, didFailWithError error: Error) {
        // A one-shot request that found nothing; the next one may.
    }

    func locationManagerDidChangeAuthorization(_ manager: CLLocationManager) {
        onAuthorization?(manager.authorizationStatus)
    }
}
