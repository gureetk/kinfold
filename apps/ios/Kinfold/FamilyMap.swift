// SPDX-License-Identifier: GPL-3.0-or-later WITH LicenseRef-Kinfold-AppStore-Exception
//
// The family on a map: MapLibre Native, drawing from files on the phone and nothing else.

import KinfoldCore
import MapLibre
import SwiftUI
import UIKit

/**
 * Each person's latest position as a dot with their initials, with their name and how long ago
 * beside it. The style is apps/maps' (inside the app, under assets/), with its world map at every
 * zoom and the family's region on top of it from zoom 7 when one is on the phone. No style, tile
 * or font is fetched from anywhere while the map is drawn.
 */
struct FamilyMap: UIViewRepresentable {
    let people: [Person]
    let region: URL?
    let version: Int
    let log: (String, [String], [Any]) -> Void

    func makeCoordinator() -> Coordinator {
        Coordinator(log: log)
    }

    func makeUIView(context: Context) -> MLNMapView {
        MLNLoggingConfiguration.shared.loggingLevel = .error
        let view = MLNMapView(frame: .zero, styleURL: Self.styleURL(region: region, version: version))
        view.delegate = context.coordinator
        view.logoView.isHidden = true
        view.attributionButton.isHidden = true
        view.compassView.isHidden = true
        view.isRotateEnabled = false
        view.isPitchEnabled = false
        context.coordinator.region = region != nil
        context.coordinator.started = Date()
        context.coordinator.version = version
        context.coordinator.log("map", ["state"], ["ready"])
        return view
    }

    func updateUIView(_ view: MLNMapView, context: Context) {
        let c = context.coordinator
        c.people = people
        if c.version != version {
            c.version = version
            c.region = region != nil
            c.started = Date()
            view.styleURL = Self.styleURL(region: region, version: version)
        } else {
            c.show(view)
        }
    }

    /** The style with its placeholders filled in (apps/maps/README.md), written where the map can read it. */
    static func styleURL(region: URL?, version: Int) -> URL? {
        guard let assets = Bundle.main.url(forResource: "assets", withExtension: nil),
              let raw = try? String(contentsOf: assets.appendingPathComponent("style.json"), encoding: .utf8) else { return nil }
        func file(_ url: URL) -> String {
            var s = URL(fileURLWithPath: url.path).absoluteString
            while s.hasSuffix("/") { s.removeLast() }
            return s
        }
        var text = raw
            .replacingOccurrences(of: "pmtiles://KINFOLD_WORLD", with: "pmtiles://" + file(assets.appendingPathComponent("world.pmtiles")))
            .replacingOccurrences(of: "KINFOLD_GLYPHS", with: file(assets.appendingPathComponent("glyphs")))
        if let region {
            text = text.replacingOccurrences(of: "pmtiles://KINFOLD_REGION", with: "pmtiles://" + file(region))
        } else if let data = text.data(using: .utf8),
                  var style = try? JSONSerialization.jsonObject(with: data) as? [String: Any] {
            // Without a region, its source and the layers that use it go.
            if var sources = style["sources"] as? [String: Any] {
                sources.removeValue(forKey: "region")
                style["sources"] = sources
            }
            if let layers = style["layers"] as? [[String: Any]] {
                style["layers"] = layers.filter { ($0["source"] as? String) != "region" }
            }
            if let out = try? JSONSerialization.data(withJSONObject: style), let s = String(data: out, encoding: .utf8) {
                text = s
            }
        }
        let out = FileManager.default.urls(for: .cachesDirectory, in: .userDomainMask)[0].appendingPathComponent("style-\(version)-\(region == nil ? 0 : 1).json")
        do {
            try text.write(to: out, atomically: true, encoding: .utf8)
        } catch {
            return nil
        }
        return out
    }

    final class Coordinator: NSObject, MLNMapViewDelegate {
        let log: (String, [String], [Any]) -> Void
        var people: [Person] = []
        var region = false
        var version = 0
        var started = Date()
        private var styled = false
        private var first = false
        private var count = 0
        private var lastAt = Date.distantPast
        private var lastZoom = -1
        private var fitted = false

        init(log: @escaping (String, [String], [Any]) -> Void) {
            self.log = log
        }

        func mapView(_ mapView: MLNMapView, didFinishLoading style: MLNStyle) {
            let source = MLNShapeSource(identifier: "family", features: [], options: nil)
            style.addSource(source)

            let dot = MLNCircleStyleLayer(identifier: "family_dot", source: source)
            dot.circleRadius = NSExpression(forConstantValue: 14)
            dot.circleColor = NSExpression(forConstantValue: UIColor(red: 0xE8 / 255, green: 0x70 / 255, blue: 0x1F / 255, alpha: 1))
            dot.circleStrokeColor = NSExpression(forConstantValue: UIColor.white)
            dot.circleStrokeWidth = NSExpression(forConstantValue: 2)
            style.addLayer(dot)

            let initials = MLNSymbolStyleLayer(identifier: "family_initials", source: source)
            initials.text = NSExpression(forKeyPath: "initials")
            initials.textFontNames = NSExpression(forConstantValue: ["Noto Sans Medium"])
            initials.textFontSize = NSExpression(forConstantValue: 12)
            initials.textColor = NSExpression(forConstantValue: UIColor.white)
            initials.textAllowsOverlap = NSExpression(forConstantValue: true)
            initials.textIgnoresPlacement = NSExpression(forConstantValue: true)
            style.addLayer(initials)

            let label = MLNSymbolStyleLayer(identifier: "family_label", source: source)
            label.text = NSExpression(forKeyPath: "label")
            label.textFontNames = NSExpression(forConstantValue: ["Noto Sans Medium"])
            label.textFontSize = NSExpression(forConstantValue: 12)
            label.textColor = NSExpression(forConstantValue: UIColor(red: 0x1E / 255, green: 0x21 / 255, blue: 0x30 / 255, alpha: 1))
            label.textHaloColor = NSExpression(forConstantValue: UIColor.white)
            label.textHaloWidth = NSExpression(forConstantValue: 1.5)
            label.textAnchor = NSExpression(forConstantValue: "top")
            label.textOffset = NSExpression(forConstantValue: NSValue(cgVector: CGVector(dx: 0, dy: 1.4)))
            style.addLayer(label)

            styled = true
            first = true
            count = 0
            log("map", ["state", "region", "took_ms"], ["style_loaded", KotlinBoolean(value: region), KotlinLong(value: Int64(Date().timeIntervalSince(started) * 1000))])
            show(mapView)
        }

        /** Puts the family on the map, and fits the camera to them once. */
        func show(_ mapView: MLNMapView) {
            guard styled, let source = mapView.style?.source(withIdentifier: "family") as? MLNShapeSource else { return }
            let now = Date().timeIntervalSince1970 * 1000
            var coordinates: [CLLocationCoordinate2D] = []
            var features: [MLNShape & MLNFeature] = []
            for p in people {
                guard let s = p.seen else { continue }
                let c = CLLocationCoordinate2D(latitude: Double(s.latE7) / 1e7, longitude: Double(s.lonE7) / 1e7)
                let f = MLNPointFeature()
                f.coordinate = c
                f.attributes = ["initials": Self.initials(p.name), "label": (p.name ?? "Someone") + " · " + Self.ago(now - Double(s.ts))]
                features.append(f)
                coordinates.append(c)
            }
            source.shape = MLNShapeCollectionFeature(shapes: features)
            guard !fitted, let firstCoordinate = coordinates.first else { return }
            fitted = true
            if coordinates.count == 1 {
                mapView.setCenter(firstCoordinate, zoomLevel: 14, animated: false)
                return
            }
            var sw = firstCoordinate
            var ne = firstCoordinate
            for c in coordinates {
                sw.latitude = min(sw.latitude, c.latitude)
                sw.longitude = min(sw.longitude, c.longitude)
                ne.latitude = max(ne.latitude, c.latitude)
                ne.longitude = max(ne.longitude, c.longitude)
            }
            mapView.setVisibleCoordinateBounds(MLNCoordinateBounds(sw: sw, ne: ne), edgePadding: UIEdgeInsets(top: 60, left: 60, bottom: 60, right: 60), animated: false, completionHandler: nil)
            if mapView.zoomLevel > 15 { mapView.setZoomLevel(15, animated: false) }
        }

        // The log gets counts only, so it shows that the files were read and drawn without saying
        // where the map was: when a style first draws in full, then when the map comes to rest at
        // another whole zoom level or after half a minute, ten times a style at most.

        func mapViewDidFinishRenderingMap(_ mapView: MLNMapView, fullyRendered: Bool) {
            if fullyRendered && first { record(mapView, "rendered") }
        }

        func mapViewDidBecomeIdle(_ mapView: MLNMapView) {
            let zoom = Int(mapView.zoomLevel)
            if !first && count >= 1 && count < 10 && (zoom != lastZoom || Date().timeIntervalSince(lastAt) >= 30) {
                record(mapView, "idle")
            }
        }

        func mapViewDidFailLoadingMap(_ mapView: MLNMapView, withError error: Error) {
            // The reason is left out: it can name a tile, and a tile says where the map was.
            log("map", ["state"], ["failed"])
        }

        private func record(_ mapView: MLNMapView, _ state: String) {
            first = false
            count += 1
            lastAt = Date()
            lastZoom = Int(mapView.zoomLevel)
            let ids = (mapView.style?.layers ?? []).map(\.identifier)
            func features(_ prefix: String) -> Int64 {
                let layers = Set(ids.filter { $0.hasPrefix(prefix) })
                return layers.isEmpty ? 0 : Int64(mapView.visibleFeatures(in: mapView.bounds, styleLayerIdentifiers: layers).count)
            }
            log("map", ["state", "region", "took_ms", "world_features", "region_features", "zoom"], [
                state,
                KotlinBoolean(value: region),
                KotlinLong(value: Int64(Date().timeIntervalSince(started) * 1000)),
                KotlinLong(value: features("world_")),
                KotlinLong(value: features("region_")),
                KotlinLong(value: Int64(lastZoom)),
            ])
        }

        static func initials(_ name: String?) -> String {
            let words = (name ?? "").split(separator: " ").prefix(2)
            let s = words.compactMap { $0.first.map(String.init) }.joined().uppercased()
            return s.isEmpty ? "?" : s
        }

        static func ago(_ ms: Double) -> String {
            let minutes = Int(ms / 60_000)
            if minutes < 1 { return "now" }
            if minutes < 60 { return "\(minutes) min" }
            let hours = minutes / 60
            if hours < 24 { return "\(hours) h" }
            return "\(hours / 24) d"
        }
    }
}
