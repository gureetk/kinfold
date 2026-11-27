// SPDX-License-Identifier: GPL-3.0-or-later WITH LicenseRef-Kinfold-AppStore-Exception
//
// What the phone saw, for the person to export and send when sharing misbehaves. The app and both
// extensions compile it.

import Foundation

/**
 * One JSON object a line, written by the core (LogLines), a file for each UTC day, as the Android
 * app keeps it. A line holds times, delays, distances, accuracies, states and IDs: never a
 * coordinate, a key, a name or an address. Files older than 30 days are deleted.
 *
 * The app and its extensions write to the same files, in the app group's container, each from
 * its own process: every line is one write to a file opened for appending, so lines never
 * overwrite each other.
 */
final class EventLog {
    static let keepDays = 30
    private let dir: URL
    private let queue = DispatchQueue(label: "ca.gureet.kinfold.log")
    private var day: String?
    private var handle: FileHandle?
    private var recentLines: [String] = []

    init() {
        dir = Shared.directory("logs", inBackups: true)
        prune()
    }

    func write(_ line: String) {
        queue.async {
            let today = Self.day.string(from: Date())
            if today != self.day {
                try? self.handle?.close()
                self.handle = nil
                self.day = today
                self.prune()
            }
            if self.handle == nil {
                let url = self.dir.appendingPathComponent("\(today).jsonl")
                if !FileManager.default.fileExists(atPath: url.path) {
                    FileManager.default.createFile(atPath: url.path, contents: nil, attributes: [.protectionKey: FileProtectionType.completeUntilFirstUserAuthentication])
                }
                let fd = open(url.path, O_WRONLY | O_APPEND | O_CLOEXEC)
                if fd >= 0 { self.handle = FileHandle(fileDescriptor: fd, closeOnDealloc: true) }
            }
            // A full disk loses lines, not the app.
            try? self.handle?.write(contentsOf: Data((line + "\n").utf8))
            self.recentLines.append(line)
            if self.recentLines.count > 200 { self.recentLines.removeFirst(self.recentLines.count - 200) }
        }
    }

    /** Returns once every line written so far is in its file: before an extension tells iOS it is done. */
    func flush() {
        queue.sync { try? handle?.synchronize() }
    }

    /** The latest lines, newest last. */
    func recent() -> [String] {
        queue.sync { recentLines }
    }

    /** Every day's file, oldest first, for the share sheet. */
    func files() -> [URL] {
        queue.sync { try? handle?.synchronize() }
        let urls = (try? FileManager.default.contentsOfDirectory(at: dir, includingPropertiesForKeys: nil)) ?? []
        return urls.filter { $0.pathExtension == "jsonl" }.sorted { $0.lastPathComponent < $1.lastPathComponent }
    }

    private func prune() {
        let cutoff = Self.day.string(from: Date().addingTimeInterval(-Double(Self.keepDays) * 86_400))
        for url in (try? FileManager.default.contentsOfDirectory(at: dir, includingPropertiesForKeys: nil)) ?? [] where url.pathExtension == "jsonl" {
            if url.deletingPathExtension().lastPathComponent < cutoff { try? FileManager.default.removeItem(at: url) }
        }
    }

    private static let day: DateFormatter = {
        let f = DateFormatter()
        f.locale = Locale(identifier: "en_US_POSIX")
        f.timeZone = TimeZone(identifier: "UTC")
        f.dateFormat = "yyyy-MM-dd"
        return f
    }()
}
