// SPDX-License-Identifier: GPL-3.0-or-later WITH LicenseRef-Kinfold-AppStore-Exception
package ca.gureet.kinfold

import android.app.Application
import android.content.Context
import android.content.SharedPreferences
import android.os.Build
import android.util.Log
import ca.gureet.kinfold.core.app.Family
import ca.gureet.kinfold.core.app.FamilyEvents
import ca.gureet.kinfold.core.app.FamilyHost
import ca.gureet.kinfold.core.client.Client
import ca.gureet.kinfold.core.client.ClientListener
import ca.gureet.kinfold.core.client.OkHttpTransport
import ca.gureet.kinfold.core.client.Storage
import ca.gureet.kinfold.core.crypto.Primitives
import ca.gureet.kinfold.core.crypto.TinkCrypto
import ca.gureet.kinfold.core.rendezvous.Invite
import ca.gureet.kinfold.core.wire.Base64Url
import ca.gureet.kinfold.core.wire.Bytes
import ca.gureet.kinfold.family.Events
import ca.gureet.kinfold.log.EventLog
import ca.gureet.kinfold.share.Notifications
import ca.gureet.kinfold.share.Probes
import ca.gureet.kinfold.store.AppStorage
import ca.gureet.kinfold.store.KeystoreSealer
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import java.io.File
import java.util.Base64

class KinfoldApp : Application() {
    override fun onCreate() {
        super.onCreate()
        Kinfold.init(this)
    }
}

/**
 * What the app's parts share: the core and the device's client, the storage it keeps, the log,
 * the family as this phone knows it, and the few settings the person chooses.
 */
object Kinfold {
    lateinit var context: Context
        private set
    lateinit var log: EventLog
        private set
    private lateinit var prefs: SharedPreferences

    val p: Primitives by lazy { Primitives(TinkCrypto()) }

    /** A test build trusts only its test server's certificate (build.gradle.kts). */
    val transport: OkHttpTransport by lazy {
        if (isTestBuild) OkHttpTransport.trusting(Base64.getDecoder().decode(BuildConfig.TEST_CA)) else OkHttpTransport()
    }

    /** A build for the emulator test, which trusts a test server's certificate. */
    val isTestBuild: Boolean get() = BuildConfig.TEST_CA.isNotEmpty()

    /** The client's files and the app's own, the secret ones sealed with a key in the Keystore. */
    val storage: AppStorage by lazy { AppStorage(File(context.filesDir, "kinfold"), KeystoreSealer()) }

    /** For work that outlives a screen: setting up, joining, sending, exporting. */
    val scope = CoroutineScope(SupervisorJob() + Dispatchers.Default)
    private val lock = Mutex()

    @Volatile
    var client: Client? = null
        private set

    /** The family as this phone knows it: people, names, positions, watches (the core's [Family]). */
    val family: Family by lazy { Family(Host) }

    /** What the client tells the app, through the family to [Events]. */
    private val listener: ClientListener by lazy { FamilyEvents(family, Host, Events) }

    /** What the core's family needs from this app. */
    private object Host : FamilyHost {
        override suspend fun client(): Client? = loadClient()

        override fun hasDevice(): Boolean = Kinfold.storage.hasDevice()

        override val storage: Storage get() = Kinfold.storage

        override fun deviceName(): String = Kinfold.deviceName()

        override var watchConsent: Boolean?
            get() = Kinfold.watchConsent
            set(v) {
                Kinfold.watchConsent = v
            }

        override fun log(event: String, fields: List<Pair<String, Any?>>) = Kinfold.log.write(event, fields)

        override fun now(): ULong = Kinfold.now()

        override fun timeOfDay(ms: Long): String = Kinfold.timeOfDay(ms)
    }

    fun init(app: Application) {
        context = app
        prefs = app.getSharedPreferences("kinfold", Context.MODE_PRIVATE)
        log = EventLog(File(app.filesDir, "logs"), if (isTestBuild) { line -> Log.i("kinfold", line) } else null) { now() }
        Notifications.channels(app)
        log.write("process", "state" to "start", "sdk" to Build.VERSION.SDK_INT)
        Probes.logExits(app)
    }

    /** Trusted time once there is a client (PROTOCOL.md §8.4), the phone's clock before. */
    fun now(): ULong = client?.clock?.now() ?: System.currentTimeMillis().toULong()

    /** The device set up before, or null if this phone hasn't been set up. Not started yet. */
    suspend fun loadClient(): Client? = lock.withLock {
        client ?: Client.load(p, transport, storage)?.also {
            it.listener = listener
            client = it
        }
    }

    /** Sets the phone up as a new account from the server's setup code (`kinfold setup`, PROTOCOL.md §13.1). */
    suspend fun setUp(code: String): Client = lock.withLock {
        check(client == null && !storage.hasDevice()) { "this phone is set up already" }
        Client.setUp(p, transport, storage, code.trim()).also {
            it.listener = listener
            client = it
        }
    }

    /** Sets the phone up from an invite, registering with the token it carries (PROTOCOL.md §9.2). */
    suspend fun forInvite(invite: Invite): Client = lock.withLock {
        val c = client ?: Client.load(p, transport, storage)?.also {
            it.listener = listener
            it.start()
        } ?: Client.forInvite(p, transport, storage, invite)
        c.listener = listener
        client = c
        c
    }

    /** The name this phone gives itself in a profile's device list: its make and model. */
    fun deviceName(): String = "${Build.MANUFACTURER} ${Build.MODEL}"

    /** The map region on the phone, by its ID on the server, or null. */
    var regionId: String?
        get() = prefs.getString("region_id", null)
        set(v) = prefs.edit().putString("region_id", v).apply()

    /** The region's name and SHA-256 (base64url), for the screen and to resume its download. */
    var regionName: String?
        get() = prefs.getString("region_name", null)
        set(v) = prefs.edit().putString("region_name", v).apply()

    var regionSha: String?
        get() = prefs.getString("region_sha", null)
        set(v) = prefs.edit().putString("region_sha", v).apply()

    /** Whether the person has turned sharing on; the watchdog and a reboot keep it going until they stop it. */
    var sharing: Boolean
        get() = prefs.getBoolean("sharing", false)
        set(v) = prefs.edit().putBoolean("sharing", v).apply()

    /**
     * Whether the person agreed that the circle's other adults may be told when this phone goes
     * quiet (PROTOCOL.md §14.1): null until they have answered.
     */
    var watchConsent: Boolean?
        get() = if (prefs.contains("watch_consent")) prefs.getBoolean("watch_consent", false) else null
        set(v) = prefs.edit().apply { if (v == null) remove("watch_consent") else putBoolean("watch_consent", v) }.apply()

    /** The newest process exit already logged (ApplicationExitInfo), in the phone's clock. */
    var exitLoggedAt: Long
        get() = prefs.getLong("exit_logged_at", 0)
        set(v) = prefs.edit().putLong("exit_logged_at", v).apply()

    /** How often the stream pings: often enough to notice a dead connection, rarely enough to let the radio sleep. */
    const val PING_MS = 240_000L

    fun id(b: Bytes): String = Base64Url.encode(b.toByteArray())

    /** An error, for the log and the screen, without addresses (the core's [ca.gureet.kinfold.core.app.describe]). */
    fun describe(e: Throwable): String = ca.gureet.kinfold.core.app.describe(e)

    /** [ms] as the phone shows a time of day. */
    fun timeOfDay(ms: Long): String =
        java.time.format.DateTimeFormatter.ofLocalizedTime(java.time.format.FormatStyle.SHORT)
            .format(java.time.Instant.ofEpochMilli(ms).atZone(java.time.ZoneId.systemDefault()))
}
