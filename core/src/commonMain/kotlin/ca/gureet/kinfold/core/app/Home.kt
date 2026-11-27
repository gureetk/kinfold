// SPDX-License-Identifier: GPL-3.0-or-later WITH LicenseRef-Kinfold-AppStore-Exception
package ca.gureet.kinfold.core.app

import ca.gureet.kinfold.core.client.Client
import ca.gureet.kinfold.core.client.Storage
import ca.gureet.kinfold.core.client.Transport
import ca.gureet.kinfold.core.crypto.Primitives
import ca.gureet.kinfold.core.rendezvous.Invite
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlin.concurrent.Volatile

/** What only the app can tell the core. Plain calls, so that an app in any language can answer them. */
interface Platform {
    /** Whether a device has been set up on this phone. */
    fun hasDevice(): Boolean

    /** The name this phone gives itself in a profile's device list, such as its make and model. */
    fun deviceName(): String

    /** The person's answer on silence watches (PROTOCOL.md §14.1): null until they have answered. */
    var watchConsent: Boolean?

    /** Writes one line to the app's log, formatted by [LogLines]. */
    fun log(event: String, fields: List<Pair<String, Any?>>)

    /** [ms] as the phone shows a time of day. */
    fun timeOfDay(ms: Long): String

    /** The phone's own clock in milliseconds, for the time before there is a client. */
    fun wallMs(): Long
}

/**
 * The core as an app holds it: the device's client, loaded, set up or registered from an invite
 * and handed the app's listener, and the family as this phone knows it. Both apps keep one.
 */
class Home(val p: Primitives, val transport: Transport, val storage: Storage, private val platform: Platform, hooks: FamilyHooks) {
    private val lock = Mutex()

    /** The device's client, once loaded or set up. */
    @Volatile
    var client: Client? = null
        private set

    private val host = object : FamilyHost {
        override suspend fun client(): Client? = loadClient()

        override fun hasDevice(): Boolean = platform.hasDevice()

        override val storage: Storage get() = this@Home.storage

        override fun deviceName(): String = platform.deviceName()

        override var watchConsent: Boolean?
            get() = platform.watchConsent
            set(v) {
                platform.watchConsent = v
            }

        override fun log(event: String, fields: List<Pair<String, Any?>>) = platform.log(event, fields)

        override fun now(): ULong = this@Home.now()

        override fun timeOfDay(ms: Long): String = platform.timeOfDay(ms)
    }

    /** The family as this phone knows it: people, names, positions, watches. */
    val family: Family = Family(host)

    /** What the client tells the app: through [family] to the app's hooks. */
    private val listener = FamilyEvents(family, host, hooks)

    /** Trusted time once there is a client (PROTOCOL.md §8.4), the phone's clock before. */
    fun now(): ULong = client?.clock?.now() ?: platform.wallMs().toULong()

    /** The device set up before, or null if this phone hasn't been set up. Not started yet. */
    suspend fun loadClient(): Client? = lock.withLock {
        client ?: Client.load(p, transport, storage)?.also {
            it.listener = listener
            client = it
        }
    }

    /** Sets the phone up as a new account from the server's setup code (`kinfold setup`, PROTOCOL.md §13.1). */
    suspend fun setUp(code: String): Client = lock.withLock {
        check(client == null && !platform.hasDevice()) { "this phone is set up already" }
        Client.setUp(p, transport, storage, code.trim()).also {
            it.listener = listener
            client = it
        }
    }

    /** Sets the phone up from an invite, registering with the token it carries (PROTOCOL.md §9.2), or loads the device set up before. */
    suspend fun forInvite(invite: Invite): Client = lock.withLock {
        val c = client ?: Client.load(p, transport, storage)?.also {
            it.listener = listener
            it.start()
        } ?: Client.forInvite(p, transport, storage, invite)
        c.listener = listener
        client = c
        c
    }
}
