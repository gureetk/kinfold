// SPDX-License-Identifier: GPL-3.0-or-later WITH LicenseRef-Kinfold-AppStore-Exception
//
// The family's map region (API.md §13): listed by the core, downloaded whole here, and kept only
// once its SHA-256 matches the server's list.

import CryptoKit
import Foundation
import KinfoldCore
import UIKit

final class Maps: NSObject, ObservableObject, URLSessionDataDelegate {
    enum State {
        case idle
        case listing
        case offer([RegionOffer], String)
        case downloading(RegionOffer, Int64, Int64)
        case failed(String)
    }

    @Published private(set) var state: State = .idle
    /** Goes up each time the region on the phone changes, so the map loads its style again. */
    @Published private(set) var version = 0
    weak var model: Model?

    private let defaults = UserDefaults.standard
    private lazy var session: URLSession = {
        let config = URLSessionConfiguration.ephemeral
        config.tlsMinimumSupportedProtocolVersion = .TLSv13
        config.urlCache = nil
        config.httpCookieStorage = nil
        config.timeoutIntervalForRequest = 60
        return URLSession(configuration: config, delegate: self, delegateQueue: .main)
    }()

    private var task: URLSessionDataTask?
    private var offer: RegionOffer?
    private var handle: FileHandle?
    private var have: Int64 = 0
    private var total: Int64 = 0
    private var status = 0
    private var retried = false
    private var background: UIBackgroundTaskIdentifier = .invalid
    private var lastProgress: Int64 = 0

    private static var dir: URL {
        FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0].appendingPathComponent("maps", isDirectory: true)
    }

    private static var part: URL { dir.appendingPathComponent("region.pmtiles.part") }

    /** The region on the phone, or nil. */
    var file: URL? {
        guard defaults.string(forKey: "region_id") != nil else { return nil }
        let url = Self.dir.appendingPathComponent("region.pmtiles")
        return FileManager.default.fileExists(atPath: url.path) ? url : nil
    }

    var regionName: String? { defaults.string(forKey: "region_name") }

    func list() {
        guard let model else { return }
        state = .listing
        model.app.regions { [weak self] offers, credit, error in
            guard let self else { return }
            if let offers {
                self.state = .offer(offers, credit ?? "")
            } else {
                self.state = .failed(error ?? "The server's list of maps couldn't be read.")
            }
        }
    }

    /** Downloads [offer] whole, resuming what an earlier download of the same file left. */
    func download(_ offer: RegionOffer) {
        guard let model, task == nil else { return }
        try? FileManager.default.createDirectory(at: Self.dir, withIntermediateDirectories: true)
        if defaults.string(forKey: "region_part_sha") != offer.sha256 {
            try? FileManager.default.removeItem(at: Self.part)
        }
        defaults.set(offer.sha256, forKey: "region_part_sha")
        self.offer = offer
        retried = false
        background = UIApplication.shared.beginBackgroundTask(withName: "region") { [weak self] in self?.pause() }
        model.app.regionRequest(region: offer.region, relogin: false) { [weak self] url, headers, error in
            self?.start(url, headers, error)
        }
    }

    private func start(_ url: String?, _ headers: [String: String]?, _ error: String?) {
        guard let offer, let url, let headers, let target = URL(string: url) else {
            finish(failed: error ?? "The map couldn't be downloaded.")
            return
        }
        let attributes = (try? FileManager.default.attributesOfItem(atPath: Self.part.path)) ?? [:]
        have = (attributes[.size] as? NSNumber)?.int64Value ?? 0
        lastProgress = have
        var request = URLRequest(url: target)
        for (k, v) in headers { request.setValue(v, forHTTPHeaderField: k) }
        request.setValue("identity", forHTTPHeaderField: "Accept-Encoding")
        if have > 0 {
            request.setValue("bytes=\(have)-", forHTTPHeaderField: "Range")
            request.setValue(offer.etag, forHTTPHeaderField: "If-Range")
        }
        status = 0
        state = .downloading(offer, have, offer.size)
        model?.app.log(event: "region", keys: ["state", "size", "have"], values: ["downloading", KotlinLong(value: offer.size), KotlinLong(value: have)])
        task = session.dataTask(with: request)
        task?.resume()
    }

    func pause() {
        task?.cancel()
    }

    func remove() {
        task?.cancel()
        try? FileManager.default.removeItem(at: Self.dir.appendingPathComponent("region.pmtiles"))
        try? FileManager.default.removeItem(at: Self.part)
        defaults.removeObject(forKey: "region_id")
        defaults.removeObject(forKey: "region_name")
        defaults.removeObject(forKey: "region_part_sha")
        version += 1
        state = .idle
    }

    // ---- URLSessionDataDelegate, on the main queue ----

    func urlSession(_ session: URLSession, dataTask: URLSessionDataTask, didReceive response: URLResponse, completionHandler: @escaping (URLSession.ResponseDisposition) -> Void) {
        let r = response as? HTTPURLResponse
        status = r?.statusCode ?? 0
        switch status {
        case 206:
            // The rest of the same file: it must start where the part on the phone ends.
            let range = r?.value(forHTTPHeaderField: "Content-Range") ?? ""
            guard range.hasPrefix("bytes \(have)-") else {
                status = -1
                return completionHandler(.cancel)
            }
        case 200:
            // The whole file, from the start: a new region, or a server without ranges.
            try? FileManager.default.removeItem(at: Self.part)
            have = 0
        default:
            return completionHandler(.cancel)
        }
        if !FileManager.default.fileExists(atPath: Self.part.path) {
            FileManager.default.createFile(atPath: Self.part.path, contents: nil)
        }
        handle = try? FileHandle(forWritingTo: Self.part)
        _ = try? handle?.seekToEnd()
        total = offer?.size ?? 0
        completionHandler(.allow)
    }

    func urlSession(_ session: URLSession, dataTask: URLSessionDataTask, didReceive data: Data) {
        do {
            try handle?.write(contentsOf: data)
        } catch {
            dataTask.cancel()
            return
        }
        have += Int64(data.count)
        // The screen moves every megabyte.
        if have - lastProgress >= 1 << 20, let offer {
            lastProgress = have
            state = .downloading(offer, have, total)
        }
    }

    func urlSession(_ session: URLSession, task: URLSessionTask, didCompleteWithError error: Error?) {
        try? handle?.close()
        handle = nil
        self.task = nil
        guard let offer else { return }
        if status == 401 && !retried {
            retried = true
            model?.app.regionRequest(region: offer.region, relogin: true) { [weak self] url, headers, error in
                self?.start(url, headers, error)
            }
            return
        }
        if status == 416 || status == -1 {
            try? FileManager.default.removeItem(at: Self.part)
            return finish(failed: "The download didn't fit the file on the phone. Try again.")
        }
        if let error {
            let cancelled = (error as? URLError)?.code == .cancelled
            model?.app.log(event: "region", keys: ["state", "have"], values: [cancelled ? "paused" : "failed", KotlinLong(value: have)])
            return finish(failed: cancelled ? nil : "The download stopped. It goes on from where it stopped when you try again.")
        }
        guard status == 200 || status == 206 else {
            return finish(failed: "The server answered \(status).")
        }
        // Kept only once its SHA-256 is the one in the server's list.
        guard Self.sha256(of: Self.part) == offer.sha256 else {
            try? FileManager.default.removeItem(at: Self.part)
            model?.app.log(event: "region", keys: ["state", "have"], values: ["failed", KotlinLong(value: have)])
            return finish(failed: "The map that came wasn't the one the server listed. Try again.")
        }
        let target = Self.dir.appendingPathComponent("region.pmtiles")
        try? FileManager.default.removeItem(at: target)
        do {
            try FileManager.default.moveItem(at: Self.part, to: target)
        } catch {
            return finish(failed: "The map couldn't be kept on the phone.")
        }
        defaults.set(offer.id, forKey: "region_id")
        defaults.set(offer.name, forKey: "region_name")
        model?.app.log(event: "region", keys: ["state", "size"], values: ["done", KotlinLong(value: offer.size)])
        version += 1
        finish(failed: nil)
    }

    private func finish(failed: String?) {
        if let failed {
            state = .failed(failed)
        } else {
            state = .idle
        }
        offer = nil
        if background != .invalid {
            UIApplication.shared.endBackgroundTask(background)
            background = .invalid
        }
    }

    /** The file's SHA-256 as base64url without padding, as the core gives a region's. */
    private static func sha256(of url: URL) -> String? {
        guard let h = try? FileHandle(forReadingFrom: url) else { return nil }
        defer { try? h.close() }
        var hasher = SHA256()
        while let chunk = try? h.read(upToCount: 1 << 20), !chunk.isEmpty {
            hasher.update(data: chunk)
        }
        return Data(hasher.finalize()).base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }
}
