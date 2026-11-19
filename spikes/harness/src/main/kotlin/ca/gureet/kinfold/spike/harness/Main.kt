// SPDX-License-Identifier: GPL-3.0-or-later WITH LicenseRef-Kinfold-AppStore-Exception
package ca.gureet.kinfold.spike.harness

import ca.gureet.kinfold.core.client.Admitted
import ca.gureet.kinfold.core.client.Client
import ca.gureet.kinfold.core.client.JdkTransport
import ca.gureet.kinfold.core.client.Transport
import ca.gureet.kinfold.core.client.admit
import ca.gureet.kinfold.core.client.createCircle
import ca.gureet.kinfold.core.client.invite
import ca.gureet.kinfold.core.client.pendingInvites
import ca.gureet.kinfold.core.client.watches
import ca.gureet.kinfold.core.crypto.Primitives
import ca.gureet.kinfold.core.crypto.TinkCrypto
import ca.gureet.kinfold.core.wire.Base64Url
import ca.gureet.kinfold.core.wire.Bytes
import kotlinx.coroutines.delay
import kotlinx.coroutines.runBlocking
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.Paths
import java.time.Instant
import kotlin.system.exitProcess

private const val USAGE = """kinfold-harness: the other family member for Kinfold's spikes

  kinfold-harness setup CODE [--circle NAME]   set up from a setup code (kinfold setup) and create the test circle
  kinfold-harness invite [--valid 24h] [--wait] print an invite code for a phone, while run runs or not;
                                                --wait lets the phone in here, only when run isn't running
  kinfold-harness run [options]                 stay in the circle: let phones in, register their watches, ask for
                                                their location and send alerts on a schedule, and log what happens
      --locate-every 30m   live-view requests to each phone, with locate (0 for none)
      --alert-every 3h     alerts to the circle, with notify (0 for none)
      --alert evt|sos      the alert's payload type
      --ping 60s           how often the stream pings
  kinfold-harness status                        the circle's devices, the watches, the open invites
  kinfold-harness report [--since 7d]           a summary of the logs against the spikes' targets

Every command takes --data DIR, where the harness keeps its keys and logs (default: ./harness-data,
or KINFOLD_HARNESS_DATA). The keys in it can read the test circle: keep it private, and delete it
after the spikes. The logs hold times, delays and distances, never a position. --cacert FILE trusts
only that certificate, for a test server with a certificate of its own.
"""

/** The command line's options: `--name value` pairs and flags, and the words before them. */
private class Args(argv: List<String>) {
    val words = ArrayList<String>()
    private val opts = HashMap<String, String?>()

    init {
        var i = 0
        while (i < argv.size) {
            val a = argv[i]
            if (a.startsWith("--")) {
                val name = a.removePrefix("--")
                if (name in FLAGS) opts[name] = null else opts[name] = argv.getOrNull(++i) ?: fail("--$name needs a value")
            } else {
                words.add(a)
            }
            i++
        }
    }

    fun has(name: String) = name in opts

    fun string(name: String): String? = opts[name]

    fun duration(name: String, default: Long): Long = opts[name]?.let { parseDuration(it) ?: fail("--$name: a duration such as 45s, 30m, 3h or 7d") } ?: default

    companion object {
        val FLAGS = setOf("wait", "quiet")
    }
}

/** `45s`, `30m`, `3h`, `7d`, or `0`, in milliseconds. */
fun parseDuration(text: String): Long? {
    if (text == "0") return 0
    val n = text.dropLast(1).toLongOrNull() ?: return null
    return when (text.last()) {
        's' -> n * 1_000
        'm' -> n * 60_000
        'h' -> n * 3_600_000
        'd' -> n * 86_400_000
        else -> null
    }
}

private fun fail(message: String): Nothing {
    System.err.println(message)
    exitProcess(2)
}

private val p = Primitives(TinkCrypto())

/** The JDK's trusted certificates, or only the one --cacert names. */
private var cacert: Path? = null

private fun transport(): Transport = cacert?.let { JdkTransport.trusting(Files.readAllBytes(it)) } ?: JdkTransport()

fun main(argv: Array<String>) {
    val command = argv.firstOrNull() ?: fail(USAGE)
    val args = Args(argv.drop(1))
    val data = Paths.get(args.string("data") ?: System.getenv("KINFOLD_HARNESS_DATA") ?: "harness-data")
    cacert = args.string("cacert")?.let { Paths.get(it) }
    try {
        runBlocking {
            when (command) {
                "setup" -> setup(data, args)
                "invite" -> invite(data, args)
                "run" -> run(data, args)
                "status" -> status(data)
                "report" -> print(report(data.resolve("logs"), System.currentTimeMillis() - args.duration("since", 7 * 86_400_000L)))
                "help", "--help", "-h" -> print(USAGE)
                else -> fail(USAGE)
            }
        }
    } catch (e: Exception) {
        System.err.println("kinfold-harness $command: ${e.message ?: e::class.simpleName}")
        exitProcess(1)
    }
}

private suspend fun setup(data: Path, args: Args) {
    val code = args.words.firstOrNull() ?: fail("setup needs the setup code that kinfold setup prints")
    val storage = FileStorage(data)
    if (storage.read("device") != null) fail("$data already holds a device; give another --data")
    val client = Client.setUp(p, transport(), storage, code)
    val circle = client.createCircle(args.string("circle") ?: "Spikes")
    println("Set up on ${client.serverUrl} as device ${id(client.keys.deviceId)}, and created the circle ${id(circle)}.")
    println("Next: kinfold-harness invite, for each phone.")
}

private suspend fun loaded(data: Path): Pair<Client, Bytes> {
    val client = Client.load(p, transport(), FileStorage(data)) ?: fail("$data holds no device: run kinfold-harness setup first")
    val circle = client.circles().singleOrNull() ?: fail("$data's device isn't in exactly one circle")
    return client to circle
}

private suspend fun invite(data: Path, args: Args) {
    val (client, circle) = loaded(data)
    // Not start(): a running `run` keeps the circle's log, and two processes mustn't both write it.
    client.checkServer()
    val validMs = args.duration("valid", 86_400_000L)
    val name = client.state(circle)?.name ?: "Spikes"
    val pending = client.invite(circle, name, "Kinfold harness", validMs.toULong())
    if (pending.invite.regToken.size == 0) {
        println("Note: the server mints no registration tokens with invites. Run kinfold settings --member-tokens on, or give the phone a token from kinfold token create.")
    }
    println("Invite for one phone, valid for ${validMs / 3_600_000} h. Paste it into the spike app:\n\n${pending.code}\n")
    if (!args.has("wait")) {
        println("A running kinfold-harness run lets the phone in. Or run this with --wait.")
        return
    }
    println("Waiting for the phone...")
    var admitted: Admitted? = null
    while (admitted == null) {
        admitted = client.admit(pending)
        if (admitted == null) delay(2_000)
    }
    println("Let in ${admitted.name} (device ${id(admitted.deviceId)}).")
}

private suspend fun run(data: Path, args: Args) {
    val (client, circle) = loaded(data)
    val schedule = Schedule(
        locateEveryMs = args.duration("locate-every", 30 * Schedule.MINUTE),
        alertEveryMs = args.duration("alert-every", 3 * Schedule.HOUR),
        alertType = args.string("alert") ?: "evt",
        pingMs = args.duration("ping", Client.DEFAULT_PING_MS),
    )
    if (schedule.alertType != "evt" && schedule.alertType != "sos") fail("--alert is evt or sos")
    Harness(client, circle, EventLog(data.resolve("logs"), echo = !args.has("quiet")), schedule).run()
}

private suspend fun status(data: Path) {
    val (client, circle) = loaded(data)
    client.checkServer()
    val state = client.state(circle) ?: fail("not in the circle")
    println("Server ${client.serverUrl}, circle ${id(circle)} \"${state.name}\" at entry ${state.seq}, epoch ${state.epoch}.")
    println("This device: ${id(client.keys.deviceId)}")
    for (m in state.members.values) {
        println("Member ${id(m.accountId)}${if (m.admin) " (admin)" else ""}:")
        for (d in m.devices.values) println("  ${d.kind.name.lowercase()} ${id(d.id)}")
    }
    val watches = client.watches(circle)
    println(if (watches.isEmpty()) "No watches." else "Watches:")
    for (w in watches) println("  ${id(w.watchedDevice)} watched by ${id(w.watcherAccount)} after ${w.afterMin} min, until ${Instant.ofEpochMilli(w.notAfter.toLong())}")
    for (i in client.pendingInvites()) println("Open invite ${id(i.inviteId)}, until ${Instant.ofEpochMilli(i.invite.expiresAt.toLong())}")
}

private fun id(b: Bytes): String = Base64Url.encode(b.toByteArray())
