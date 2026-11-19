// SPDX-License-Identifier: GPL-3.0-or-later WITH LicenseRef-Kinfold-AppStore-Exception
package ca.gureet.kinfold.spike

import android.Manifest
import android.app.Activity
import android.app.ActivityManager
import android.content.ClipData
import android.content.ClipboardManager
import android.content.Intent
import android.content.pm.PackageManager
import android.graphics.Typeface
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.os.PowerManager
import android.provider.Settings
import android.view.View
import android.view.WindowInsets
import android.widget.Button
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import android.widget.Toast
import kotlinx.coroutines.launch
import java.io.File
import java.time.LocalDate
import java.time.ZoneOffset

/**
 * The spike's one screen, in plain Android views: join the test circle with the harness's invite,
 * grant what sharing needs, start or stop it, tune the stream's ping, and export the log.
 */
class MainActivity : Activity() {
    private lateinit var status: TextView
    private lateinit var events: TextView
    private lateinit var code: EditText
    private val ui = Handler(Looper.getMainLooper())
    private val refresh = object : Runnable {
        override fun run() {
            show()
            ui.postDelayed(this, 2_000)
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val pad = (16 * resources.displayMetrics.density).toInt()
        val column = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(pad, pad, pad, pad)
        }
        column.addView(TextView(this).apply {
            text = "Kinfold spike 2: Android without Google push"
            textSize = 18f
            setTypeface(typeface, Typeface.BOLD)
        })
        status = TextView(this).apply {
            textSize = 14f
            setTextIsSelectable(true)
        }
        column.addView(status)
        code = EditText(this).apply {
            hint = "Invite code from the harness"
            maxLines = 4
        }
        column.addView(code)
        column.addView(button("Paste the invite") { paste() })
        column.addView(button("Join the test circle") { join() })
        column.addView(button("1. Allow notifications") { allowNotifications() })
        column.addView(button("2. Allow location") { ask(Manifest.permission.ACCESS_FINE_LOCATION, Manifest.permission.ACCESS_COARSE_LOCATION) })
        column.addView(button("3. Allow location all the time") { allowBackground() })
        column.addView(button("4. Don't optimize the battery for this app") { askExemption() })
        column.addView(button("Start sharing") { startSharing() })
        column.addView(button("Stop sharing") { stopSharing() })
        column.addView(button("Ping interval: next") { nextPing() })
        column.addView(button("App info: the manufacturer's battery settings") { appInfo() })
        column.addView(button("Export the log") { export() })
        events = TextView(this).apply {
            textSize = 11f
            typeface = Typeface.MONOSPACE
            setTextIsSelectable(true)
        }
        column.addView(events)
        // Android 15 and later draw apps under the system bars; keep the content clear of them.
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            column.setOnApplyWindowInsetsListener { v, insets ->
                val bars = insets.getInsets(WindowInsets.Type.systemBars() or WindowInsets.Type.ime())
                v.setPadding(pad + bars.left, pad + bars.top, pad + bars.right, pad + bars.bottom)
                insets
            }
        }
        setContentView(ScrollView(this).apply { addView(column) })
        if (savedInstanceState == null) testHook()
    }

    /**
     * In a test build only (emulator-test.sh): `--es invite CODE` joins with that invite, and
     * `--ez share true` then starts sharing, so that a script can drive the app through adb.
     */
    private fun testHook() {
        if (!Spike.isTestBuild) return
        val invite = intent.getStringExtra("invite")
        val share = intent.getBooleanExtra("share", false)
        if (invite == null && !share) return
        Spike.scope.launch {
            try {
                if (invite != null) Spike.log.write("joined", "details_matched" to Spike.join(invite).detailsMatched)
                if (share) runOnUiThread { startSharing() }
            } catch (e: Exception) {
                Spike.log.write("join_failed", "error" to Spike.describe(e))
            }
        }
    }

    override fun onResume() {
        super.onResume()
        ui.post(refresh)
    }

    override fun onPause() {
        ui.removeCallbacks(refresh)
        super.onPause()
    }

    private fun button(label: String, action: () -> Unit): View = Button(this).apply {
        text = label
        isAllCaps = false
        setOnClickListener { action() }
    }

    private fun show() {
        Spike.scope.launch {
            val c = Spike.loadClient()
            val circle = c?.circles()?.firstOrNull()
            val circleName = circle?.let { c.state(it)?.name }
            val pm = getSystemService(PowerManager::class.java)
            val text = buildString {
                if (Spike.isTestBuild) appendLine("TEST BUILD: trusts a test server's certificate")
                appendLine("Phone: ${Spike.deviceName()}")
                appendLine(
                    when {
                        circleName != null -> "Circle: $circleName"
                        c != null -> "Set up, not in a circle yet"
                        else -> "Not joined: paste the harness's invite"
                    },
                )
                appendLine("Sharing: " + if (Spike.sharing) "on" else "off")
                appendLine(SharingService.status)
                appendLine("Location: " + locationState())
                appendLine("Notifications: " + if (notificationsAllowed()) "allowed" else "not allowed")
                appendLine("Battery optimization: " + if (pm.isIgnoringBatteryOptimizations(packageName)) "off for this app" else "on (ask to turn it off)")
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                    val restricted = getSystemService(ActivityManager::class.java).isBackgroundRestricted
                    appendLine("Background restricted: " + if (restricted) "yes (lift it in App info)" else "no")
                }
                append("Ping every ${Spike.pingS} s; heartbeat after 25 minutes without an upload")
            }
            val lines = Spike.log.recent().asReversed().joinToString("\n")
            runOnUiThread {
                status.text = text
                events.text = lines
            }
        }
    }

    private fun granted(permission: String): Boolean = checkSelfPermission(permission) == PackageManager.PERMISSION_GRANTED

    private fun locationState(): String = when {
        !granted(Manifest.permission.ACCESS_FINE_LOCATION) -> "not allowed"
        Build.VERSION.SDK_INT < Build.VERSION_CODES.Q -> "allowed (all the time on this Android)"
        granted(Manifest.permission.ACCESS_BACKGROUND_LOCATION) -> "allowed all the time"
        else -> "allowed while in use only"
    }

    private fun notificationsAllowed(): Boolean =
        Build.VERSION.SDK_INT < Build.VERSION_CODES.TIRAMISU || granted(Manifest.permission.POST_NOTIFICATIONS)

    private fun ask(vararg permissions: String) {
        requestPermissions(permissions, 1)
    }

    private fun allowNotifications() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) ask(Manifest.permission.POST_NOTIFICATIONS) else toast("Nothing to allow on this Android")
    }

    private fun allowBackground() {
        when {
            Build.VERSION.SDK_INT < Build.VERSION_CODES.Q -> toast("Nothing more to allow on this Android")
            !granted(Manifest.permission.ACCESS_FINE_LOCATION) -> toast("Allow location first")
            // Android asks this one separately, and from 11 on, in its settings: choose "Allow all the time".
            else -> ask(Manifest.permission.ACCESS_BACKGROUND_LOCATION)
        }
    }

    private fun askExemption() {
        startActivity(Intent(Settings.ACTION_REQUEST_IGNORE_BATTERY_OPTIMIZATIONS, Uri.parse("package:$packageName")))
    }

    private fun appInfo() {
        startActivity(Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS, Uri.parse("package:$packageName")))
    }

    private fun paste() {
        val clip = getSystemService(ClipboardManager::class.java).primaryClip
        val text = clip?.takeIf { it.itemCount > 0 }?.getItemAt(0)?.coerceToText(this)?.toString()
        if (text.isNullOrBlank()) toast("The clipboard is empty") else code.setText(text.trim())
    }

    private fun join() {
        val text = code.text.toString()
        if (text.isBlank()) {
            toast("Paste the invite code first")
            return
        }
        toast("Joining; the harness lets the phone in")
        Spike.scope.launch {
            try {
                val joined = Spike.join(text)
                Spike.log.write("joined", "details_matched" to joined.detailsMatched)
                runOnUiThread {
                    code.setText("")
                    toast("Joined. Now allow what sharing needs, then start it.")
                }
            } catch (e: Exception) {
                Spike.log.write("join_failed", "error" to Spike.describe(e))
                runOnUiThread { toast("Joining failed: " + Spike.describe(e)) }
            }
        }
    }

    private fun startSharing() {
        if (!granted(Manifest.permission.ACCESS_FINE_LOCATION)) {
            toast("Allow location first")
            return
        }
        Spike.sharing = true
        Spike.log.write("sharing", "on" to true)
        SharingService.start(this, "started in the app")
        Watchdog.schedule(this)
    }

    private fun stopSharing() {
        Spike.sharing = false
        Spike.log.write("sharing", "on" to false)
        Watchdog.cancel(this)
        stopService(Intent(this, SharingService::class.java))
    }

    private fun nextPing() {
        val next = Spike.PINGS[(Spike.PINGS.indexOf(Spike.pingS) + 1) % Spike.PINGS.size]
        Spike.pingS = next
        Spike.log.write("ping", "s" to next)
        if (Spike.sharing) SharingService.start(this, SharingService.RESTREAM)
        toast("Ping every $next s")
    }

    /** One file of every day's log, shared through the share sheet. */
    private fun export() {
        Spike.scope.launch {
            val dir = LogProvider.exportDir(cacheDir).apply {
                mkdirs()
                listFiles()?.forEach { it.delete() }
            }
            val model = Build.MODEL.replace(Regex("[^A-Za-z0-9]+"), "-").trim('-').ifEmpty { "phone" }
            val name = "kinfold-spike2-$model-${LocalDate.now(ZoneOffset.UTC)}.jsonl"
            File(dir, name).outputStream().use { out ->
                for (f in Spike.log.files()) f.inputStream().use { it.copyTo(out) }
            }
            val uri = LogProvider.uri(name)
            val send = Intent(Intent.ACTION_SEND)
                .setType("application/json")
                .putExtra(Intent.EXTRA_STREAM, uri)
                .addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
            send.clipData = ClipData.newRawUri(name, uri)
            runOnUiThread { startActivity(Intent.createChooser(send, "Export the spike's log")) }
        }
    }

    private fun toast(text: String) {
        Toast.makeText(this, text, Toast.LENGTH_LONG).show()
    }
}
