// SPDX-License-Identifier: GPL-3.0-or-later WITH LicenseRef-Kinfold-AppStore-Exception
package ca.gureet.kinfold.family

import ca.gureet.kinfold.Kinfold
import ca.gureet.kinfold.core.app.FamilyHooks
import ca.gureet.kinfold.core.client.StreamChange
import ca.gureet.kinfold.share.Connection
import ca.gureet.kinfold.share.Notifications
import ca.gureet.kinfold.share.SharingService
import ca.gureet.kinfold.ui.MainActivity

/** What the core's family events ask of this app: the sharing service, notifications and the connection. */
object Events : FamilyHooks {
    override fun sharing(): Boolean = SharingService.running

    override fun live(forMs: Long) = SharingService.live(forMs)

    override fun silenceAlert(id: Int, title: String, text: String) = Notifications.alert(Kinfold.context, id, title, text)

    override fun joinRequest(name: String) {
        if (!MainActivity.visible) Notifications.joinRequest(Kinfold.context, name)
    }

    override fun stream(change: StreamChange) {
        Connection.changed(change)
        SharingService.show()
    }
}
