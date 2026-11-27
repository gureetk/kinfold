// SPDX-License-Identifier: GPL-3.0-or-later WITH LicenseRef-Kinfold-AppStore-Exception
package ca.gureet.kinfold.family

import ca.gureet.kinfold.Kinfold
import ca.gureet.kinfold.core.Reason
import ca.gureet.kinfold.core.client.ClientListener
import ca.gureet.kinfold.core.client.Delivery
import ca.gureet.kinfold.core.client.ServerEvent
import ca.gureet.kinfold.core.client.SilenceAlert
import ca.gureet.kinfold.core.client.StreamChange
import ca.gureet.kinfold.core.push.PushReceipt
import ca.gureet.kinfold.core.wire.Bytes
import ca.gureet.kinfold.share.Connection
import ca.gureet.kinfold.share.Notifications
import ca.gureet.kinfold.share.SharingService
import ca.gureet.kinfold.ui.MainActivity

/** What the client tells the app, sent on to the family, the connection, the sharing service and the log. */
object Events : ClientListener {
    override suspend fun delivered(delivery: Delivery) {
        val live = Kinfold.family.onDelivery(delivery, sharing = SharingService.running)
        if (live != null) SharingService.live(live)
    }

    override suspend fun refused(circleId: Bytes?, reason: Reason) {
        Kinfold.log.write("refused", "reason" to reason.toString())
    }

    override suspend fun silence(alert: SilenceAlert) {
        val (title, text) = Kinfold.family.silence(alert)
        Notifications.alert(Kinfold.context, alert.watchedDevice.hashCode(), title, text)
    }

    override suspend fun event(event: ServerEvent) {
        when (event) {
            is ServerEvent.JoinRequest -> {
                val asks = Kinfold.family.pollAsks()
                if (asks.isNotEmpty() && !MainActivity.visible) Notifications.joinRequest(Kinfold.context, asks.first().ask.name)
            }
            is ServerEvent.WatchEnded -> Kinfold.family.watchEnded(event.watchedDevice, event.reason)
            is ServerEvent.Removed -> {
                Kinfold.log.write("removed", "seq" to event.seq)
                Kinfold.family.refresh()
            }
            is ServerEvent.Notice -> Kinfold.log.write("notice", "code" to event.code)
            else -> Kinfold.log.write("event", "type" to event::class.simpleName)
        }
    }

    override suspend fun stream(change: StreamChange) {
        Connection.changed(change)
        SharingService.show()
    }

    override suspend fun logChanged(circleId: Bytes, seq: Long) {
        Kinfold.log.write("log", "seq" to seq)
        Kinfold.family.logChanged()
    }

    override suspend fun pushDropped(reason: PushReceipt.Drop) {
        Kinfold.log.write("push_dropped", "reason" to reason.toString())
    }

    override suspend fun failed(what: String, error: Throwable) {
        Kinfold.log.write("failed", "what" to what, "error" to Kinfold.describe(error))
    }
}
