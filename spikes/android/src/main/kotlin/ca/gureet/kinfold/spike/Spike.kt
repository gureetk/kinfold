// SPDX-License-Identifier: GPL-3.0-or-later WITH LicenseRef-Kinfold-AppStore-Exception
package ca.gureet.kinfold.spike

import android.app.Application
import android.content.Context
import android.content.SharedPreferences
import android.os.Build
import android.util.Log
import ca.gureet.kinfold.core.client.Client
import ca.gureet.kinfold.core.client.Joined
import ca.gureet.kinfold.core.client.OkHttpTransport
import ca.gureet.kinfold.core.client.Transport
import ca.gureet.kinfold.core.client.join
import ca.gureet.kinfold.core.crypto.Primitives
import ca.gureet.kinfold.core.crypto.TinkCrypto
import ca.gureet.kinfold.core.rendezvous.Invite
import ca.gureet.kinfold.core.wire.Base64Url
import ca.gureet.kinfold.core.wire.Bytes
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import java.io.File
import java.util.Base64

class SpikeApp : Application() {
    override fun onCreate() {
        super.onCreate()
        Spike.init(this)
    }
}

/** What the app's parts share: the core and the client, the log, and the few settings the spike tunes. */
object Spike {
    lateinit var context: Context
        private set
    lateinit var log: EventLog
        private set
    private lateinit var prefs: SharedPreferences

    val p: Primitives by lazy { Primitives(TinkCrypto()) }

    /** A test build trusts only its test server's certificate (build.gradle.kts). */
    val transport: Transport by lazy {
        if (isTestBuild) OkHttpTransport.trusting(Base64.getDecoder().decode(BuildConfig.TEST_CA)) else OkHttpTransport()
    }

    /** A build for the emulator test, which trusts a test server's certificate. */
    val isTestBuild: Boolean get() = BuildConfig.TEST_CA.isNotEmpty()

    private val storage: AppStorage by lazy { AppStorage(File(context.filesDir, "kinfold")) }

    /** For work that outlives a screen: joining, loading the device, exporting. */
    val scope = CoroutineScope(SupervisorJob() + Dispatchers.Default)
    private val lock = Mutex()

    @Volatile
    var client: Client? = null
        private set

    fun init(app: Application) {
        context = app
        prefs = app.getSharedPreferences("spike", Context.MODE_PRIVATE)
        log = EventLog(File(app.filesDir, "logs"), if (isTestBuild) { line -> Log.i("kinfold", line) } else null) { now() }
    }

    /** Trusted time once there is a client (PROTOCOL.md §8.4), the phone's clock before. */
    fun now(): ULong = client?.clock?.now() ?: System.currentTimeMillis().toULong()

    /** The device set up before, or null if the phone hasn't joined yet. */
    suspend fun loadClient(): Client? = lock.withLock { client ?: Client.load(p, transport, storage)?.also { client = it } }

    /**
     * Sets the phone up from an invite, with the registration token it carries, and joins its
     * circle: the harness lets it in (PROTOCOL.md §9). A phone set up before joins with its own keys.
     */
    suspend fun join(code: String): Joined {
        val invite = Invite.fromCode(code.trim())
        val c = lock.withLock {
            val loaded = client ?: Client.load(p, transport, storage)
            if (loaded != null) loaded.also { it.start() } else Client.forInvite(p, transport, storage, invite)
        }
        client = c
        return c.join(invite, deviceName(), timeoutMs = 600_000L)
    }

    /** What the phone calls itself in the circle: its make, model and Android version. */
    fun deviceName(): String = "${Build.MANUFACTURER} ${Build.MODEL} (Android ${Build.VERSION.RELEASE})"

    /** Whether the person has started sharing; the watchdog and a reboot keep it going until they stop it. */
    var sharing: Boolean
        get() = prefs.getBoolean("sharing", false)
        set(v) = prefs.edit().putBoolean("sharing", v).apply()

    /** The stream's ping interval, which the spike tunes. */
    var pingS: Int
        get() = prefs.getInt("ping_s", PINGS[1])
        set(v) = prefs.edit().putInt("ping_s", v).apply()

    /** When the phone last granted its watch, in trusted time. */
    var grantedAt: Long
        get() = prefs.getLong("granted_at", 0)
        set(v) = prefs.edit().putLong("granted_at", v).apply()

    /** When the phone last sent its name, in trusted time, and the name it sent. */
    var profileAt: Long
        get() = prefs.getLong("profile_at", 0)
        set(v) = prefs.edit().putLong("profile_at", v).apply()
    var profileName: String?
        get() = prefs.getString("profile_name", null)
        set(v) = prefs.edit().putString("profile_name", v).apply()

    /** The newest process exit already logged (ApplicationExitInfo), in the phone's clock. */
    var exitLoggedAt: Long
        get() = prefs.getLong("exit_logged_at", 0)
        set(v) = prefs.edit().putLong("exit_logged_at", v).apply()

    /** The ping intervals the screen cycles through, in seconds. */
    val PINGS = listOf(60, 240, 600, 1_200)

    fun id(b: Bytes): String = Base64Url.encode(b.toByteArray())

    fun describe(e: Throwable): String = e::class.java.simpleName + (e.message?.let { ": " + it.take(200) } ?: "")
}
