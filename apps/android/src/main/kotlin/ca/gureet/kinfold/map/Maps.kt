// SPDX-License-Identifier: GPL-3.0-or-later WITH LicenseRef-Kinfold-AppStore-Exception
package ca.gureet.kinfold.map

import android.os.SystemClock
import ca.gureet.kinfold.Kinfold
import ca.gureet.kinfold.core.client.Region
import ca.gureet.kinfold.core.client.downloadRegion
import ca.gureet.kinfold.core.client.regions
import ca.gureet.kinfold.core.wire.Base64Url
import ca.gureet.kinfold.share.Wakelocks
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Job
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.launch
import java.io.File

/**
 * The family's map region (API.md §13): listed by the server, downloaded whole, checked against
 * its SHA-256, and kept on the phone, so that the map is drawn from the phone and the server
 * never learns what anyone looks at. One region at a time. A download that stops resumes where
 * it was, unless the server replaced the region meanwhile.
 */
object Maps {
    sealed interface State {
        data object Idle : State

        data object Listing : State

        /** What the server offers, and the region on the phone, if any. */
        data class Offer(val regions: List<Region>) : State

        data class Downloading(val region: Region, val done: Long, val total: Long) : State

        data class Failed(val message: String) : State
    }

    private val state = MutableStateFlow<State>(State.Idle)
    val ui: StateFlow<State> get() = state

    /** Bumped when the region on the phone changes, so the map loads its style again. */
    private val version = MutableStateFlow(0)
    val changed: StateFlow<Int> get() = version

    private var job: Job? = null

    private val dir: File get() = File(Kinfold.context.filesDir, "maps").apply { mkdirs() }

    /** The region's file on the phone, once whole and checked. */
    fun file(): File? = File(dir, FILE).takeIf { it.isFile && Kinfold.regionId != null }

    private fun part(): File = File(dir, "$FILE.part")

    fun list() {
        if (job?.isActive == true) return
        state.value = State.Listing
        job = Kinfold.scope.launch {
            state.value = try {
                val c = Kinfold.loadClient() ?: error("this phone isn't set up")
                State.Offer(c.regions().regions)
            } catch (e: CancellationException) {
                throw e
            } catch (e: Exception) {
                Kinfold.log.write("region", "state" to "list_failed", "error" to Kinfold.describe(e))
                State.Failed("Couldn't ask the server for its maps: " + Kinfold.describe(e))
            }
        }
    }

    /** Downloads [region], resuming a part already on the phone if it was the same file. */
    fun download(region: Region) {
        if (job?.isActive == true) return
        state.value = State.Downloading(region, 0, region.size)
        job = Kinfold.scope.launch {
            val sha = Base64Url.encode(region.sha256.toByteArray())
            val part = part()
            // A part from another region, or from a version the server has since replaced, can't be resumed.
            if (Kinfold.regionSha != sha) part.delete()
            Kinfold.regionSha = sha
            val started = SystemClock.elapsedRealtime()
            val from = if (part.isFile) part.length() else 0L
            Kinfold.log.write("region", "state" to "downloading", "size" to region.size, "from" to from)
            val wake = Wakelocks.hold(Kinfold.context, "region", 60 * 60_000L)
            try {
                val c = Kinfold.loadClient() ?: error("this phone isn't set up")
                c.downloadRegion(region) { url, headers ->
                    Kinfold.transport.download(url, headers, part, region.sha256.toByteArray(), region.etag) { done, total ->
                        state.value = State.Downloading(region, done, if (total > 0) total else region.size)
                    }
                }
                val whole = File(dir, FILE)
                if (!part.renameTo(whole)) error("couldn't keep the region's file")
                Kinfold.regionId = region.id
                Kinfold.regionName = region.name
                val ms = SystemClock.elapsedRealtime() - started
                Kinfold.log.write("region", "state" to "done", "size" to region.size, "from" to from, "took_ms" to ms)
                version.value++
                state.value = State.Idle
            } catch (e: CancellationException) {
                Kinfold.log.write("region", "state" to "paused", "have" to part.length())
                state.value = State.Idle
                throw e
            } catch (e: Exception) {
                Kinfold.log.write("region", "state" to "failed", "have" to part.length(), "error" to Kinfold.describe(e))
                state.value = State.Failed("The download stopped: " + Kinfold.describe(e) + ". Try again to carry on.")
            } finally {
                Wakelocks.release(wake)
            }
        }
    }

    /** Stops a download; what came so far stays, to resume. */
    fun pause() {
        job?.cancel()
    }

    /** Takes the region off the phone; the map falls back to the world map inside the app. */
    fun remove() {
        job?.cancel()
        File(dir, FILE).delete()
        part().delete()
        Kinfold.regionId = null
        Kinfold.regionName = null
        Kinfold.regionSha = null
        Kinfold.log.write("region", "state" to "removed")
        version.value++
        state.value = State.Idle
    }

    private const val FILE = "region.pmtiles"
}
