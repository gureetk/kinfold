// SPDX-License-Identifier: GPL-3.0-or-later WITH LicenseRef-Kinfold-AppStore-Exception
package ca.gureet.kinfold.ui

import ca.gureet.kinfold.Kinfold
import ca.gureet.kinfold.core.client.Joined
import ca.gureet.kinfold.core.client.join
import ca.gureet.kinfold.core.identity.SafetyCode
import ca.gureet.kinfold.core.rendezvous.Invite
import ca.gureet.kinfold.share.Connection
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Job
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.launch

/**
 * The two ways into a family, which outlive the screen that starts them: setting up from the
 * server's setup code and founding the circle, and joining with an invite. Each runs in the app's
 * scope, so turning the phone or leaving the app doesn't stop it.
 */
object Flows {
    sealed interface Progress {
        data object Idle : Progress

        data class Working(val what: String) : Progress

        /** Waiting for the inviter to let this phone in, with the safety code both screens show. */
        data class Waiting(val inviter: String, val safetyCode: String) : Progress

        data class Done(val joined: Joined?) : Progress

        data class Failed(val message: String) : Progress
    }

    private val progress = MutableStateFlow<Progress>(Progress.Idle)
    val state: StateFlow<Progress> get() = progress
    private var job: Job? = null

    fun reset() {
        if (progress.value !is Progress.Working && progress.value !is Progress.Waiting) progress.value = Progress.Idle
    }

    /** From the server's setup code (PROTOCOL.md §13.1): the account, then the family's circle. */
    fun setUp(code: String, myName: String, circleName: String) {
        if (job?.isActive == true) return
        progress.value = Progress.Working("Checking your server")
        job = Kinfold.scope.launch {
            try {
                val c = Kinfold.setUp(code)
                Kinfold.log.write("setup", "state" to "done", "server_features" to c.features.size)
                progress.value = Progress.Working("Creating $circleName")
                Kinfold.family.create(c, myName, circleName)
                Connection.kick()
                progress.value = Progress.Done(null)
            } catch (e: CancellationException) {
                throw e
            } catch (e: Exception) {
                Kinfold.log.write("setup", "state" to "failed", "error" to Kinfold.describe(e))
                progress.value = Progress.Failed(explain(e))
            }
        }
    }

    /** Founds a circle on a phone that is set up but in none, as after a setup that stopped half way. */
    fun create(myName: String, circleName: String) {
        if (job?.isActive == true) return
        progress.value = Progress.Working("Creating $circleName")
        job = Kinfold.scope.launch {
            try {
                val c = Kinfold.loadClient() ?: error("this phone isn't set up")
                c.start()
                Kinfold.family.create(c, myName, circleName)
                Connection.kick()
                progress.value = Progress.Done(null)
            } catch (e: CancellationException) {
                throw e
            } catch (e: Exception) {
                Kinfold.log.write("circle", "state" to "failed", "error" to Kinfold.describe(e))
                progress.value = Progress.Failed(explain(e))
            }
        }
    }

    /**
     * Joins with [invite] (PROTOCOL.md §9.2), once the person has seen its terms and agreed. The
     * inviter's phone lets this one in after comparing the safety code shown here.
     */
    fun join(invite: Invite, myName: String) {
        if (job?.isActive == true) return
        progress.value = Progress.Working("Connecting to the family's server")
        job = Kinfold.scope.launch {
            val family = Kinfold.family
            family.joining = true
            try {
                family.setMyName(myName)
                val c = Kinfold.forInvite(invite)
                val code = SafetyCode.code(c.p, c.keys.identity.publicKey, invite.inviterIkPub.toByteArray())
                progress.value = Progress.Waiting(invite.inviterName.ifBlank { "the inviter" }, code)
                val joined = c.join(invite, myName, timeoutMs = JOIN_WAIT_MS)
                Kinfold.log.write("joined", "details_matched" to joined.detailsMatched)
                family.joining = false
                family.started(c)
                Connection.kick()
                progress.value = Progress.Done(joined)
            } catch (e: CancellationException) {
                throw e
            } catch (e: Exception) {
                Kinfold.log.write("join", "state" to "failed", "error" to Kinfold.describe(e))
                progress.value = Progress.Failed(explain(e))
            } finally {
                family.joining = false
            }
        }
    }

    fun cancel() {
        job?.cancel()
        progress.value = Progress.Idle
    }

    private fun explain(e: Exception): String {
        val m = e.message ?: ""
        return when {
            m.contains("declined") -> "The inviter didn't let this phone in."
            m.contains("no answer") -> "Nobody let this phone in in time. Ask for a new invite."
            m.contains("another server") -> "That invite is for another server than the one this phone uses."
            e is java.io.IOException || e::class.simpleName == "TransportException" -> "Couldn't reach the family's server. Check the connection and try again."
            else -> "That didn't work: " + Kinfold.describe(e)
        }
    }

    /** How long a join waits for the inviter's phone. */
    private const val JOIN_WAIT_MS = 15 * 60_000L
}
