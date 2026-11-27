// SPDX-License-Identifier: GPL-3.0-or-later WITH LicenseRef-Kinfold-AppStore-Exception
package ca.gureet.kinfold.map

import android.content.Context
import android.graphics.RectF
import android.os.SystemClock
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import androidx.compose.ui.viewinterop.AndroidView
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.LifecycleEventObserver
import androidx.lifecycle.compose.LocalLifecycleOwner
import ca.gureet.kinfold.Kinfold
import ca.gureet.kinfold.core.app.Person
import ca.gureet.kinfold.ui.ago
import ca.gureet.kinfold.ui.initials
import org.json.JSONArray
import org.json.JSONObject
import org.maplibre.android.MapLibre
import org.maplibre.android.camera.CameraUpdateFactory
import org.maplibre.android.geometry.LatLng
import org.maplibre.android.geometry.LatLngBounds
import org.maplibre.android.log.Logger
import org.maplibre.android.maps.MapLibreMap
import org.maplibre.android.maps.MapView
import org.maplibre.android.maps.Style
import org.maplibre.android.style.expressions.Expression.get
import org.maplibre.android.style.layers.CircleLayer
import org.maplibre.android.style.layers.PropertyFactory
import org.maplibre.android.style.layers.SymbolLayer
import org.maplibre.android.style.sources.GeoJsonSource

/**
 * The family on the map: each person's latest position, as a dot with their initials and a label
 * with their name and its age. The map is drawn from files on the phone only (`apps/maps`): the
 * world map inside the app, and the region downloaded from the server. It asks no server for
 * tiles, so nothing learns what anyone looks at.
 */
@Composable
fun FamilyMap(people: List<Person>, nowMs: Long, modifier: Modifier = Modifier) {
    val context = LocalContext.current
    val lifecycle = LocalLifecycleOwner.current.lifecycle
    val regionVersion by Maps.changed.collectAsState()
    val view = remember { mapView(context) }
    var map by remember { mutableStateOf<MapLibreMap?>(null) }
    var style by remember { mutableStateOf<Style?>(null) }
    var fitted by remember { mutableStateOf(false) }

    DisposableEffect(lifecycle) {
        val observer = LifecycleEventObserver { _, event ->
            when (event) {
                Lifecycle.Event.ON_START -> view.onStart()
                Lifecycle.Event.ON_RESUME -> view.onResume()
                Lifecycle.Event.ON_PAUSE -> view.onPause()
                Lifecycle.Event.ON_STOP -> view.onStop()
                else -> {}
            }
        }
        lifecycle.addObserver(observer)
        onDispose {
            lifecycle.removeObserver(observer)
            view.onDestroy()
        }
    }
    val render = remember { RenderLog() }
    LaunchedEffect(view) {
        view.getMapAsync {
            // MapLibre hands over the map once it has a surface to draw on, which needs the screen.
            Kinfold.log.write("map", "state" to "ready")
            setUp(it)
            render.watch(view, it)
            map = it
        }
    }
    // The style again whenever the region on the phone changes.
    LaunchedEffect(map, regionVersion) {
        val m = map ?: return@LaunchedEffect
        val region = Maps.file()
        val started = SystemClock.elapsedRealtime()
        style = null
        m.setStyle(Style.Builder().fromJson(styleJson(context, region))) {
            addFamily(it)
            style = it
            Kinfold.log.write("map", "state" to "style_loaded", "region" to (region != null), "took_ms" to SystemClock.elapsedRealtime() - started)
            render.styled(region != null, started)
        }
    }
    LaunchedEffect(style, people, nowMs / 30_000) {
        val s = style ?: return@LaunchedEffect
        s.getSourceAs<GeoJsonSource>(FAMILY)?.setGeoJson(geoJson(people, nowMs))
        val m = map ?: return@LaunchedEffect
        if (!fitted) fitted = fit(m, people)
    }
    Box(modifier) {
        AndroidView(factory = { view })
        // The data's credit, which the ODbL asks for, always on the map (plan §11).
        Text(
            if (Maps.file() != null) "© OpenStreetMap contributors · Natural Earth" else "Made with Natural Earth",
            style = MaterialTheme.typography.labelSmall,
            color = Color(0xFF4A463F),
            modifier = Modifier.align(Alignment.BottomEnd).padding(4.dp).background(Color(0xB3FFFFFF)).padding(horizontal = 4.dp, vertical = 1.dp),
        )
    }
}

private fun mapView(context: Context): MapView {
    MapLibre.getInstance(context)
    // MapLibre logs what it draws; the app's own log says what matters, without places.
    Logger.setVerbosity(Logger.ERROR)
    return MapView(context).apply { onCreate(null) }
}

private fun setUp(m: MapLibreMap) {
    m.uiSettings.apply {
        isAttributionEnabled = false
        isLogoEnabled = false
        isCompassEnabled = true
        isRotateGesturesEnabled = false
        isTiltGesturesEnabled = false
    }
    m.setMaxZoomPreference(17.0)
}

/**
 * The style in `assets/style.json` (apps/maps/style.py) pointed at the files: the world map and
 * the glyphs inside the app, and [region] if there is one. Without a region, its source and its
 * layers come out.
 */
private fun styleJson(context: Context, region: java.io.File?): String {
    val text = context.assets.open("style.json").use { it.readBytes().decodeToString() }
        .replace("pmtiles://KINFOLD_WORLD", "pmtiles://asset://world.pmtiles")
        .replace("KINFOLD_GLYPHS", "asset://glyphs")
    val style = JSONObject(if (region != null) text.replace("pmtiles://KINFOLD_REGION", "pmtiles://file://" + region.absolutePath) else text)
    if (region == null) {
        style.getJSONObject("sources").remove("region")
        val layers = style.getJSONArray("layers")
        val kept = JSONArray()
        for (i in 0 until layers.length()) {
            val l = layers.getJSONObject(i)
            if (l.optString("source") != "region") kept.put(l)
        }
        style.put("layers", kept)
    }
    return style.toString()
}

private fun addFamily(s: Style) {
    s.addSource(GeoJsonSource(FAMILY, """{"type":"FeatureCollection","features":[]}"""))
    s.addLayer(
        CircleLayer("family_dot", FAMILY).withProperties(
            PropertyFactory.circleRadius(15f),
            PropertyFactory.circleColor(get("color")),
            PropertyFactory.circleStrokeColor("#FFFFFF"),
            PropertyFactory.circleStrokeWidth(3f),
        ),
    )
    s.addLayer(
        SymbolLayer("family_initials", FAMILY).withProperties(
            PropertyFactory.textField(get("initials")),
            PropertyFactory.textFont(arrayOf("Noto Sans Medium")),
            PropertyFactory.textSize(13f),
            PropertyFactory.textColor("#FFFFFF"),
            PropertyFactory.textAllowOverlap(true),
            PropertyFactory.textIgnorePlacement(true),
        ),
    )
    s.addLayer(
        SymbolLayer("family_label", FAMILY).withProperties(
            PropertyFactory.textField(get("label")),
            PropertyFactory.textFont(arrayOf("Noto Sans Medium")),
            PropertyFactory.textSize(12f),
            PropertyFactory.textColor("#1E2130"),
            PropertyFactory.textHaloColor("#FFFFFF"),
            PropertyFactory.textHaloWidth(2f),
            PropertyFactory.textOffset(arrayOf(0f, 2.2f)),
            PropertyFactory.textAllowOverlap(true),
        ),
    )
}

/** The family as GeoJSON, for the map only: positions never go to the log. */
private fun geoJson(people: List<Person>, nowMs: Long): String {
    val features = JSONArray()
    for (p in people) {
        val s = p.seen ?: continue
        val stale = nowMs - s.ts > STALE_MS
        features.put(
            JSONObject()
                .put("type", "Feature")
                .put("geometry", JSONObject().put("type", "Point").put("coordinates", JSONArray().put(s.lonE7 / 1e7).put(s.latE7 / 1e7)))
                .put(
                    "properties",
                    JSONObject()
                        .put("initials", initials(p.name))
                        .put("label", (if (p.isMe) "You" else p.name ?: "Someone") + " · " + ago(nowMs, s.ts))
                        .put("color", if (stale) "#9E978C" else if (p.isMe) "#1E2130" else "#E8701F"),
                ),
        )
    }
    return JSONObject().put("type", "FeatureCollection").put("features", features).toString()
}

/** Shows everyone who has a position, once; after that the person moves the map. Whether it did. */
private fun fit(m: MapLibreMap, people: List<Person>): Boolean {
    val points = people.mapNotNull { p -> p.seen?.let { LatLng(it.latE7 / 1e7, it.lonE7 / 1e7) } }
    when {
        points.isEmpty() -> return false
        points.size == 1 -> m.moveCamera(CameraUpdateFactory.newLatLngZoom(points[0], 14.0))
        else -> m.moveCamera(CameraUpdateFactory.newLatLngBounds(LatLngBounds.Builder().includes(points).build(), 120))
    }
    return true
}

/**
 * Logs how the map draws, as counts only, so the log shows that the files were read and drawn
 * without saying where the map was: when a style first draws in full, and then when the map comes
 * to rest after moving to another whole zoom level or after half a minute, ten times a style at
 * most, how many features it drew from the world map and from the region. Failures to load or
 * draw are logged as they come.
 */
private class RenderLog {
    private var region = false
    private var started = 0L
    private var count = 0
    private var lastAt = 0L
    private var lastZoom = -1
    private var first = false

    fun styled(region: Boolean, started: Long) {
        this.region = region
        this.started = started
        count = 0
        first = true
    }

    fun watch(view: MapView, m: MapLibreMap) {
        view.addOnDidFinishRenderingMapListener { fully -> if (fully && first) log(view, m, "rendered") }
        view.addOnDidBecomeIdleListener {
            val now = SystemClock.elapsedRealtime()
            val zoom = m.cameraPosition.zoom.toInt()
            if (!first && count in 1 until 10 && (zoom != lastZoom || now - lastAt >= 30_000)) log(view, m, "idle")
        }
        // The reason is left out: it can name a tile, and a tile says where the map was.
        view.addOnDidFailLoadingMapListener { Kinfold.log.write("map", "state" to "failed") }
        view.addOnGlyphsErrorListener { _, _, _ -> Kinfold.log.write("map", "state" to "glyphs_failed") }
    }

    private fun log(view: MapView, m: MapLibreMap, state: String) {
        first = false
        count++
        lastAt = SystemClock.elapsedRealtime()
        lastZoom = m.cameraPosition.zoom.toInt()
        val rect = RectF(0f, 0f, view.width.toFloat(), view.height.toFloat())
        val layers = m.style?.layers?.map { it.id } ?: emptyList()
        fun features(prefix: String): Int {
            val ids = layers.filter { it.startsWith(prefix) }.toTypedArray()
            return if (ids.isEmpty()) 0 else m.queryRenderedFeatures(rect, *ids).size
        }
        Kinfold.log.write(
            "map",
            "state" to state,
            "region" to region,
            "took_ms" to lastAt - started,
            "world_features" to features("world_"),
            "region_features" to features("region_"),
            "zoom" to m.cameraPosition.zoom.toInt(),
        )
    }
}

private const val FAMILY = "family"

/** A position older than this is drawn grey. */
private const val STALE_MS = 60 * 60_000L
