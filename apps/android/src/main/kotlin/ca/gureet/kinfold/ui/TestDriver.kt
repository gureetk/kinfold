// SPDX-License-Identifier: GPL-3.0-or-later WITH LicenseRef-Kinfold-AppStore-Exception
package ca.gureet.kinfold.ui

import android.content.Intent
import android.util.Log
import ca.gureet.kinfold.Kinfold
import ca.gureet.kinfold.core.rendezvous.Invite
import ca.gureet.kinfold.map.Maps
import ca.gureet.kinfold.share.SharingService
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/**
 * In a test build only (emulator-test.sh), the steps a person takes on the screen, from the intent
 * that starts the app, so that a script can drive it through adb:
 *
 * - `--es setup CODE`: set up from the server's setup code and found the circle, then make an
 *   invite and print it to logcat (tag `kinfold-test`); with `--ez admit true`, let in the first
 *   person who asks, as if the safety codes matched;
 * - `--es invite CODE`: join with that invite, agreeing to its terms;
 * - `--es name NAME` and `--es circle NAME`: the names to use;
 * - `--ez watch true`: agree to silence watches;
 * - `--ez region true`: download the first map region the server offers;
 * - `--ez share true`: turn sharing on.
 *
 * A build for the phones has none of this: [Kinfold.isTestBuild] is false there.
 */
object TestDriver {
    fun run(activity: MainActivity, intent: Intent?) {
        if (!Kinfold.isTestBuild || intent == null) return
        val setup = intent.getStringExtra("setup")
        val invite = intent.getStringExtra("invite")
        val name = intent.getStringExtra("name") ?: "Test phone"
        val circle = intent.getStringExtra("circle") ?: "Test family"
        val admit = intent.getBooleanExtra("admit", false)
        val watch = intent.getBooleanExtra("watch", false)
        val share = intent.getBooleanExtra("share", false)
        val region = intent.getBooleanExtra("region", false)
        if (setup == null && invite == null && !share) return
        Kinfold.scope.launch {
            try {
                if (setup != null) {
                    Flows.setUp(setup, name, circle)
                    finished()
                    if (watch) Kinfold.family.setWatchConsent(true)
                    val pending = Kinfold.family.invite() ?: error("no invite")
                    Log.i(TAG, "invite ${pending.code}")
                    if (admit) {
                        launch {
                            repeat(300) {
                                val asks = Kinfold.family.pollAsks()
                                if (asks.isNotEmpty()) {
                                    Kinfold.family.allow(asks.first())
                                    return@launch
                                }
                                delay(2_000)
                            }
                        }
                    }
                }
                if (invite != null) {
                    Flows.join(Invite.fromCode(invite), name)
                    finished()
                    if (watch) Kinfold.family.setWatchConsent(true)
                }
                if (share) withContext(Dispatchers.Main) { SharingService.turnOn(activity) }
                if (region) {
                    Maps.list()
                    val offer = Maps.ui.first { it is Maps.State.Offer || it is Maps.State.Failed }
                    val first = (offer as? Maps.State.Offer)?.regions?.firstOrNull() ?: error("no region on offer")
                    Maps.download(first)
                }
            } catch (e: Exception) {
                Kinfold.log.write("test", "state" to "failed", "error" to Kinfold.describe(e))
            }
        }
    }

    private suspend fun finished() {
        val end = Flows.state.first { it is Flows.Progress.Done || it is Flows.Progress.Failed }
        if (end is Flows.Progress.Failed) error(end.message)
    }

    private const val TAG = "kinfold-test"
}
