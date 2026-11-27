// SPDX-License-Identifier: GPL-3.0-or-later WITH LicenseRef-Kinfold-AppStore-Exception
//
// What the app and its two extensions share: the app group's container, which holds the device's
// files and the log; the person's choices; and the phone as the core sees it. The app and both
// extensions compile this file.

import Foundation
import KinfoldCore
import UIKit

enum Shared {
    /** The app group of the app and its extensions. Its ID is also the Keychain access group of the storage key. */
    static let group = "group.ca.gureet.kinfold"

    /** Whether the app group's container is there; a build signed without the group uses the app's own. */
    static let inGroup = FileManager.default.containerURL(forSecurityApplicationGroupIdentifier: group) != nil

    private static let root: URL = FileManager.default.containerURL(forSecurityApplicationGroupIdentifier: group)?
        .appendingPathComponent("Library/Application Support", isDirectory: true)
        ?? FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]

    /**
     * A directory in the container, protected until the phone is first unlocked after it starts
     * (so that sharing works while it is locked), and left out of backups unless [inBackups].
     */
    static func directory(_ name: String, inBackups: Bool) -> URL {
        var dir = root.appendingPathComponent(name, isDirectory: true)
        try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true, attributes: [.protectionKey: FileProtectionType.completeUntilFirstUserAuthentication])
        if !inBackups {
            var values = URLResourceValues()
            values.isExcludedFromBackup = true
            try? dir.setResourceValues(values)
        }
        return dir
    }

    /** Where the core keeps the device's files. */
    static var storageDirectory: URL { directory("kinfold", inBackups: false) }

    /** The log, one for the process; the app's and the extensions' lines go to the same files. */
    static let log = EventLog()

    /** The person's choices, which the extensions read as well: sharing on or off, and the answer on watches. */
    static let defaults = UserDefaults(suiteName: group) ?? .standard

    static let sharingKey = "sharing"
    static let watchConsentKey = "watch_consent"

    /** The text a phone shows for an alert its notification extension couldn't open (API.md §12). */
    static var fallbackText: String {
        NSLocalizedString("push_fallback", comment: "An alert from the family that couldn't be opened")
    }

    /** The phone's model, as a profile's device list shows it, such as "Apple iPhone14,5". */
    static func deviceName() -> String {
        var info = utsname()
        uname(&info)
        let machine = withUnsafeBytes(of: &info.machine) { raw in
            String(decoding: raw.prefix { $0 != 0 }, as: UTF8.self)
        }
        return "Apple " + machine
    }

    static func timeOfDay(_ ms: Int64) -> String {
        time.string(from: Date(timeIntervalSince1970: Double(ms) / 1000))
    }

    private static let time: DateFormatter = {
        let f = DateFormatter()
        f.dateStyle = .none
        f.timeStyle = .short
        return f
    }()

    /** The battery as a payload carries it: the level in percent (-1 when unknown) and whether it charges. */
    static func battery() -> (pct: Int32, charging: Bool) {
        let device = UIDevice.current
        device.isBatteryMonitoringEnabled = true
        let level = device.batteryLevel
        return (level >= 0 ? Int32((level * 100).rounded()) : -1, device.batteryState == .charging || device.batteryState == .full)
    }

    /** The memory this process uses, in megabytes, as iOS counts it against an extension's limit; -1 if unknown. */
    static func footprintMB() -> Int64 {
        var info = task_vm_info_data_t()
        var count = mach_msg_type_number_t(MemoryLayout<task_vm_info_data_t>.size / MemoryLayout<integer_t>.size)
        let result = withUnsafeMutablePointer(to: &info) {
            $0.withMemoryRebound(to: integer_t.self, capacity: Int(count)) {
                task_info(mach_task_self_, task_flavor_t(TASK_VM_INFO), $0, &count)
            }
        }
        return result == KERN_SUCCESS ? Int64(info.phys_footprint / 1_048_576) : -1
    }

    /**
     * The core for an extension, on the app's files, as the person last left sharing. [route] is
     * `alert` or `location`, for the log.
     */
    static func extensionCore(route: String) -> IosExtension {
        let phone = Phone()
        let sealer = KeychainSealer()
        let core = IosExtension(dir: storageDirectory.path, sealer: sealer, ios: phone, sharing: defaults.bool(forKey: sharingKey), route: route)
        if sealer.failure != 0 {
            core.log(event: "keychain", keys: ["state", "status"], values: ["failed", KotlinInt(value: sealer.failure)])
        }
        return core
    }
}

/** The phone as the core asks about it, for an extension; the app's Model answers the same way. */
final class Phone: NSObject, IosPlatform {

    func deviceName() -> String { Shared.deviceName() }

    func watchConsent() -> Int32 {
        guard let on = Shared.defaults.object(forKey: Shared.watchConsentKey) as? Bool else { return -1 }
        return on ? 1 : 0
    }

    func setWatchConsent(on: Bool) {
        Shared.defaults.set(on, forKey: Shared.watchConsentKey)
    }

    func writeLog(line: String) {
        Shared.log.write(line)
    }

    func timeOfDay(ms: Int64) -> String { Shared.timeOfDay(ms) }
}
