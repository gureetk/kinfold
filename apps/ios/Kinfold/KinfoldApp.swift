// SPDX-License-Identifier: GPL-3.0-or-later WITH LicenseRef-Kinfold-AppStore-Exception
//
// The iOS app, ca.gureet.kinfold: the walking skeleton, kept minimal. The core (KinfoldCore.xcframework)
// holds every rule; this app gives it storage, the location, the map and the screens.

import SwiftUI
import UIKit

@main
struct KinfoldApp: App {
    @UIApplicationDelegateAdaptor(AppDelegate.self) private var delegate
    @Environment(\.scenePhase) private var phase
    @StateObject private var model = Model.shared

    var body: some Scene {
        WindowGroup {
            RootView()
                .environmentObject(model)
                .environmentObject(model.maps)
        }
        .onChange(of: phase) { _, now in
            model.phaseChanged(now)
        }
    }
}

/**
 * Started by the system too, without a screen: after a location update or a significant change
 * when the app wasn't running. The model then picks sharing up where it was.
 */
final class AppDelegate: NSObject, UIApplicationDelegate {
    func application(_ application: UIApplication, didFinishLaunchingWithOptions options: [UIApplication.LaunchOptionsKey: Any]? = nil) -> Bool {
        let model = Model.shared
        model.launched(byLocation: options?[.location] != nil)
        return true
    }
}

/** The screen for where the phone is: not set up, set up but in no circle, or in the family. */
struct RootView: View {
    @EnvironmentObject private var model: Model

    var body: some View {
        Group {
            if let state = model.family, state.setUp, state.circleId != nil, !model.joining {
                HomeView(state: state)
            } else if let state = model.family, state.setUp, !model.joining, model.flow == nil {
                CreateCircleView()
            } else {
                StartView()
            }
        }
        .tint(Brand.tangerine)
    }
}

/** The brand's colours (plan §16). */
enum Brand {
    static let night = Color(red: 0x1E / 255, green: 0x21 / 255, blue: 0x30 / 255)
    static let tangerine = Color(red: 0xE8 / 255, green: 0x70 / 255, blue: 0x1F / 255)
    static let cream = Color(red: 0xFF / 255, green: 0xF6 / 255, blue: 0xEC / 255)
}
