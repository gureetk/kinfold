// SPDX-License-Identifier: GPL-3.0-or-later WITH LicenseRef-Kinfold-AppStore-Exception
package ca.gureet.kinfold.core.app

import ca.gureet.kinfold.core.client.Client
import ca.gureet.kinfold.core.client.StreamChange
import ca.gureet.kinfold.core.client.Storage

/**
 * What [Family] needs from the app it runs in: the device's client, a place for its sealed
 * records, the person's choice on silence watches, the log, and the time.
 */
interface FamilyHost {
    /** The device's client, loaded when first needed; null before the phone is set up. */
    suspend fun client(): Client?

    /** Whether a device has been set up on this phone. */
    fun hasDevice(): Boolean

    /** Where the family's records go, as `app-family`. The app seals what it keeps there: it holds names and positions. */
    val storage: Storage

    /** The name this phone gives itself in a profile's device list, such as its make and model. */
    fun deviceName(): String

    /**
     * Whether the person agreed that the circle's other adults may be told when this phone goes
     * quiet (PROTOCOL.md §14.1): null until they have answered.
     */
    var watchConsent: Boolean?

    /** Writes one line to the app's log ([LogLines]): never a coordinate, a key, a name or an address. */
    fun log(event: String, fields: List<Pair<String, Any?>>)

    /** Trusted time in milliseconds (PROTOCOL.md §8.4), or the phone's clock before there is a client. */
    fun now(): ULong

    /** [ms], a time today or lately, as the phone shows a time of day. */
    fun timeOfDay(ms: Long): String
}

/** What [FamilyEvents] asks the app to do. Plain calls, so that an app in any language can make them. */
interface FamilyHooks {
    /** Whether the phone shares its location now: a live-view request is honoured only then (§8.2). */
    fun sharing(): Boolean

    /** Answers a live-view request: frequent updates for [forMs] milliseconds. */
    fun live(forMs: Long)

    /** Shows an alert that a phone this account watches has gone quiet (§14.1); [id] tells one phone's alert from another's. */
    fun silenceAlert(id: Int, title: String, text: String)

    /** Someone is waiting on this phone's invite: [name] is the name they gave. */
    fun joinRequest(name: String)

    /** The stream to the server opened, closed or failed (API.md §7). */
    fun stream(change: StreamChange)
}
