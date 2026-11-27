// SPDX-License-Identifier: GPL-3.0-or-later WITH LicenseRef-Kinfold-AppStore-Exception
package ca.gureet.kinfold.core.app

import ca.gureet.kinfold.core.Reason
import ca.gureet.kinfold.core.client.ClientListener
import ca.gureet.kinfold.core.client.Delivery
import ca.gureet.kinfold.core.client.ServerEvent
import ca.gureet.kinfold.core.client.SilenceAlert
import ca.gureet.kinfold.core.client.StreamChange
import ca.gureet.kinfold.core.push.PushReceipt
import ca.gureet.kinfold.core.wire.Bytes

/** What the client tells an app, sent on to [family], the log, and the app's own [hooks]. */
class FamilyEvents(private val family: Family, private val host: FamilyHost, private val hooks: FamilyHooks) : ClientListener {
    override suspend fun delivered(delivery: Delivery) {
        val live = family.onDelivery(delivery, sharing = hooks.sharing())
        if (live != null) hooks.live(live)
    }

    override suspend fun refused(circleId: Bytes?, reason: Reason) {
        log("refused", "reason" to reason.toString())
    }

    override suspend fun silence(alert: SilenceAlert) {
        val (title, text) = family.silence(alert)
        hooks.silenceAlert(alert.watchedDevice.hashCode(), title, text)
    }

    override suspend fun event(event: ServerEvent) {
        when (event) {
            is ServerEvent.JoinRequest -> {
                val asks = family.pollAsks()
                if (asks.isNotEmpty()) hooks.joinRequest(asks.first().ask.name)
            }
            is ServerEvent.WatchEnded -> family.watchEnded(event.watchedDevice, event.reason)
            is ServerEvent.Removed -> {
                log("removed", "seq" to event.seq)
                family.refresh()
            }
            is ServerEvent.Notice -> log("notice", "code" to event.code)
            else -> log("event", "type" to event::class.simpleName)
        }
    }

    override suspend fun stream(change: StreamChange) {
        hooks.stream(change)
    }

    override suspend fun logChanged(circleId: Bytes, seq: Long) {
        log("log", "seq" to seq)
        family.logChanged()
    }

    override suspend fun pushDropped(reason: PushReceipt.Drop) {
        log("push_dropped", "reason" to reason.toString())
    }

    override suspend fun failed(what: String, error: Throwable) {
        log("failed", "what" to what, "error" to describe(error))
    }

    private fun log(event: String, vararg fields: Pair<String, Any?>) = host.log(event, fields.toList())
}
