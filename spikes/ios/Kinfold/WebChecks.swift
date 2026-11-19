// SPDX-License-Identifier: GPL-3.0-or-later WITH LicenseRef-Kinfold-AppStore-Exception
//
// Spike 5's page (spikes/web) in this phone's WebKit, the engine Safari uses. The app carries the
// page, reference/js and the vectors (scripts/copy-web.sh) and serves them to its web view under
// a scheme of its own, on localhost, which WebKit counts as a secure context: WebCrypto works
// there, and nothing is fetched from the network.

import SwiftUI
import WebKit

enum WebChecks {
    static let scheme = "kinfold-web"
    static let page = URL(string: "\(scheme)://localhost/spikes/web/index.html")!

    /// The web view that last loaded the page, for --checks to read.
    @MainActor static weak var current: WKWebView?

    @MainActor static func makeWebView() -> WKWebView {
        let configuration = WKWebViewConfiguration()
        configuration.setURLSchemeHandler(BundledFiles(), forURLScheme: scheme)
        let view = WKWebView(frame: .zero, configuration: configuration)
        // Safari's Web Inspector on the Mac can look in.
        view.isInspectable = true
        view.load(URLRequest(url: page))
        current = view
        return view
    }

    /// The page's verdict and output once it has finished, or nil while it runs.
    @MainActor static func result(of view: WKWebView) async -> (ok: Bool, text: String)? {
        let script = """
            (() => {
              const v = document.getElementById('verdict');
              if (!v || !v.className) return '';
              return JSON.stringify([v.className, v.textContent, document.getElementById('browser').textContent, document.getElementById('out').textContent]);
            })()
            """
        guard let json = try? await view.evaluateJavaScript(script) as? String, !json.isEmpty,
              let parts = try? JSONDecoder().decode([String].self, from: Data(json.utf8)), parts.count == 4
        else { return nil }
        return (parts[0] == "pass", [parts[2], parts[1], "", parts[3]].joined(separator: "\n"))
    }
}

/// Serves the app's copy of the page, and nothing outside it.
@MainActor final class BundledFiles: NSObject, WKURLSchemeHandler {
    private let root = Bundle.main.bundleURL.appendingPathComponent("web", isDirectory: true).standardizedFileURL
    private static let types = ["html": "text/html", "mjs": "text/javascript", "js": "text/javascript", "json": "application/json"]

    func webView(_ webView: WKWebView, start task: any WKURLSchemeTask) {
        guard let url = task.request.url else { return }
        let file = root.appendingPathComponent(String(url.path.drop(while: { $0 == "/" }))).standardizedFileURL
        guard file.path.hasPrefix(root.path + "/"), let data = try? Data(contentsOf: file) else {
            task.didReceive(HTTPURLResponse(url: url, statusCode: 404, httpVersion: "HTTP/1.1", headerFields: ["Content-Length": "0"])!)
            task.didFinish()
            return
        }
        let headers = [
            "Content-Type": Self.types[file.pathExtension] ?? "application/octet-stream",
            "Content-Length": String(data.count),
            "Cache-Control": "no-store",
        ]
        task.didReceive(HTTPURLResponse(url: url, statusCode: 200, httpVersion: "HTTP/1.1", headerFields: headers)!)
        if task.request.httpMethod != "HEAD" {
            task.didReceive(data)
        }
        task.didFinish()
    }

    func webView(_ webView: WKWebView, stop task: any WKURLSchemeTask) {}
}

struct SpikeWebView: UIViewRepresentable {
    func makeUIView(context: Context) -> WKWebView { WebChecks.makeWebView() }

    func updateUIView(_ view: WKWebView, context: Context) {}
}

struct WebChecksView: View {
    var body: some View {
        SpikeWebView()
            .navigationTitle("Vectors in WebKit")
            .navigationBarTitleDisplayMode(.inline)
    }
}
