// SPDX-License-Identifier: GPL-3.0-or-later WITH LicenseRef-Kinfold-AppStore-Exception
package ca.gureet.kinfold.share

import android.Manifest
import android.annotation.SuppressLint
import android.content.Context
import android.content.pm.PackageManager
import android.hardware.Sensor
import android.hardware.SensorManager
import android.hardware.TriggerEvent
import android.hardware.TriggerEventListener
import android.location.Location
import android.location.LocationListener
import android.location.LocationManager
import android.location.LocationRequest
import android.os.Build
import android.os.Bundle
import android.os.Handler
import android.os.HandlerThread
import android.os.SystemClock
import ca.gureet.kinfold.Kinfold
import java.util.concurrent.Executor
import kotlin.math.max
import kotlin.math.roundToLong

/**
 * The location engine: Android's own location service, with its fused provider where
 * the phone has one (Android 12 and later) and GPS and network otherwise; never Google Play
 * services. [Motion] decides the mode, and with it how often fixes come; when the phone is still,
 * fixes stop and the significant-motion sensor wakes the engine. Each fix goes to [onFix].
 */
class Locator(private val context: Context, private val onFix: (Fix, Step, Location) -> Unit) : LocationListener {
    private val lm = context.getSystemService(LocationManager::class.java)
    private val sensors = context.getSystemService(SensorManager::class.java)
    private val motionSensor: Sensor? = sensors.getDefaultSensor(Sensor.TYPE_SIGNIFICANT_MOTION)
    private val thread = HandlerThread("kinfold-locator").apply { start() }
    private val handler = Handler(thread.looper)
    private val executor = Executor { handler.post(it) }
    private val motion = Motion()

    private val trigger = object : TriggerEventListener() {
        override fun onTrigger(event: TriggerEvent?) {
            handler.post {
                Kinfold.log.write("motion")
                if (motion.motionDetected()) apply("motion")
            }
        }
    }

    /** The mode now. */
    val mode: Mode get() = motion.mode

    fun start() {
        handler.post { apply("start") }
    }

    /** Fixes every 5 seconds for [forMs], each one uploaded: the answer to a live-view request. */
    fun live(forMs: Long) {
        handler.post {
            if (motion.live(SystemClock.elapsedRealtime(), forMs)) apply("live")
            handler.postDelayed({ tick() }, forMs + 500)
        }
    }

    /** Ends live updates whose time is up, whether or not a fix came. */
    fun tick() {
        handler.post { if (motion.tick(SystemClock.elapsedRealtime())) apply("live_end") }
    }

    fun stop() {
        handler.post {
            lm.removeUpdates(this)
            motionSensor?.let { sensors.cancelTriggerSensor(trigger, it) }
            thread.quitSafely()
        }
    }

    /** Asks Android for what the mode needs, and nothing more. */
    private fun apply(why: String) {
        val m = motion.mode
        lm.removeUpdates(this)
        motionSensor?.let { sensors.cancelTriggerSensor(trigger, it) }
        if (context.checkSelfPermission(Manifest.permission.ACCESS_FINE_LOCATION) != PackageManager.PERMISSION_GRANTED) {
            Kinfold.log.write("engine", "mode" to m.name.lowercase(), "why" to why, "error" to "no location permission")
            return
        }
        if (m == Mode.STILL) {
            val sensor = motionSensor
            if (sensor != null && sensors.requestTriggerSensor(trigger, sensor)) {
                Kinfold.log.write("engine", "mode" to "still", "why" to why, "wake" to "significant_motion")
                return
            }
            // No motion sensor: a cheap fix every few minutes instead.
            request(STILL_FALLBACK_MS, highAccuracy = false, m, why)
        } else {
            request(m.intervalMs, highAccuracy = true, m, why)
        }
    }

    @SuppressLint("MissingPermission") // checked in apply()
    private fun request(intervalMs: Long, highAccuracy: Boolean, m: Mode, why: String) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            val provider = if (lm.hasProvider(LocationManager.FUSED_PROVIDER)) LocationManager.FUSED_PROVIDER else LocationManager.GPS_PROVIDER
            val quality = if (highAccuracy) LocationRequest.QUALITY_HIGH_ACCURACY else LocationRequest.QUALITY_LOW_POWER
            val request = LocationRequest.Builder(intervalMs).setQuality(quality).setMinUpdateIntervalMillis(intervalMs / 2).build()
            lm.requestLocationUpdates(provider, request, executor, this)
            Kinfold.log.write("engine", "mode" to m.name.lowercase(), "why" to why, "provider" to provider, "interval_ms" to intervalMs)
        } else {
            val wanted = if (highAccuracy) {
                listOf(LocationManager.GPS_PROVIDER, LocationManager.NETWORK_PROVIDER)
            } else {
                listOf(LocationManager.NETWORK_PROVIDER)
            }
            var providers = wanted.filter { lm.isProviderEnabled(it) }
            if (providers.isEmpty()) providers = listOf(LocationManager.GPS_PROVIDER)
            for (p in providers) lm.requestLocationUpdates(p, intervalMs, 0f, this, thread.looper)
            Kinfold.log.write("engine", "mode" to m.name.lowercase(), "why" to why, "provider" to providers.joinToString("+"), "interval_ms" to intervalMs)
        }
    }

    override fun onLocationChanged(location: Location) {
        val fix = Fix(
            atMs = location.elapsedRealtimeNanos / 1_000_000,
            latE7 = (location.latitude * 1e7).roundToLong(),
            lonE7 = (location.longitude * 1e7).roundToLong(),
            accM = if (location.hasAccuracy()) max(1L, location.accuracy.roundToLong()) else 1_000L,
            spdCms = if (location.hasSpeed()) (location.speed * 100).roundToLong() else null,
        )
        val step = motion.add(fix)
        if (step.changed) apply("fix")
        onFix(fix, step, location)
    }

    // Before Android 11 these have no default, so they must be here.
    @Deprecated("Android stopped calling it in version 10")
    override fun onStatusChanged(provider: String?, status: Int, extras: Bundle?) {}

    override fun onProviderEnabled(provider: String) {
        Kinfold.log.write("provider", "name" to provider, "on" to true)
    }

    override fun onProviderDisabled(provider: String) {
        Kinfold.log.write("provider", "name" to provider, "on" to false)
    }

    companion object {
        const val STILL_FALLBACK_MS = 5 * 60_000L

        fun isMock(location: Location): Boolean =
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) location.isMock else @Suppress("DEPRECATION") location.isFromMockProvider
    }
}
