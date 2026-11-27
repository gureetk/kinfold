// SPDX-License-Identifier: GPL-3.0-or-later WITH LicenseRef-Kinfold-AppStore-Exception
package ca.gureet.kinfold.ui

import android.Manifest
import android.content.Intent
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.provider.Settings
import androidx.activity.ComponentActivity
import androidx.activity.compose.BackHandler
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateListOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import ca.gureet.kinfold.Kinfold
import ca.gureet.kinfold.core.rendezvous.Invite
import ca.gureet.kinfold.log.Export
import ca.gureet.kinfold.share.Connection
import ca.gureet.kinfold.share.Health
import ca.gureet.kinfold.share.SharingService
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/** Where the person is in the app. */
sealed interface Screen {
    data object Start : Screen

    data object SetUpScan : Screen

    data class SetUpDetails(val code: String) : Screen

    data object JoinScan : Screen

    data class JoinTerms(val invite: Invite) : Screen

    data object Joining : Screen

    data object Home : Screen

    data object ShowInvite : Screen

    data object Health : Screen

    data object Settings : Screen

    data object LiveAsks : Screen

    data object Maps : Screen
}

/**
 * The app's one activity, in Compose with Material 3. It keeps the connection open while it is in
 * front of the person, and asks for the permissions sharing needs when they choose to grant them.
 */
class MainActivity : ComponentActivity() {
    private val stack = mutableStateListOf<Screen>()

    /** Bumped when the person comes back from a settings screen, so the health checks are read again. */
    var resumed by mutableStateOf(0)
        private set

    private val permissions = registerForActivityResult(ActivityResultContracts.RequestMultiplePermissions()) { result ->
        Kinfold.log.write("permission", *result.map { (k, v) -> k.substringAfterLast('.').lowercase() to v }.toTypedArray())
        resumed++
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        enableEdgeToEdge()
        super.onCreate(savedInstanceState)
        Kinfold.log.write("app", "state" to "opened", "why" to (intent?.action ?: "unknown"), "restored" to (savedInstanceState != null))
        if (stack.isEmpty()) stack.add(if (Kinfold.storage.hasDevice()) Screen.Home else Screen.Start)
        setContent { KinfoldTheme { App() } }
        if (savedInstanceState == null) TestDriver.run(this, intent)
    }

    override fun onStart() {
        super.onStart()
        visible = true
        Connection.acquire(OWNER)
    }

    override fun onResume() {
        super.onResume()
        resumed++
    }

    override fun onStop() {
        visible = false
        Connection.release(OWNER)
        super.onStop()
    }

    @Composable
    private fun App() {
        val family by Kinfold.family.ui.collectAsState()
        val flow by Flows.state.collectAsState()
        val screen = stack.lastOrNull() ?: Screen.Start
        BackHandler(enabled = stack.size > 1) { back() }
        when (screen) {
            Screen.Start -> StartScreen(onSetUp = { go(Screen.SetUpScan) }, onJoin = { go(Screen.JoinScan) })
            Screen.SetUpScan -> ScanScreen(
                title = "Scan your server's setup code",
                hint = "On the server, run kinfold setup. It prints a QR code, and the same code as text beginning with KFS0.",
                prefix = "KFS0",
                resumed = resumed,
                camera = ::cameraAllowed,
                askCamera = { ask(Manifest.permission.CAMERA) },
                onBack = ::back,
                onCode = { replace(Screen.SetUpDetails(it)) },
            )
            is Screen.SetUpDetails -> SetUpScreen(flow, onBack = ::back, onSetUp = { name, circle -> Flows.setUp(screen.code, name, circle) }, onDone = { home(); go(Screen.Health) })
            Screen.JoinScan -> ScanScreen(
                title = "Scan the invite",
                hint = "On a family member's phone, open Kinfold and choose Invite. Scan the code it shows.",
                prefix = "KFI0",
                resumed = resumed,
                camera = ::cameraAllowed,
                askCamera = { ask(Manifest.permission.CAMERA) },
                onBack = ::back,
                onCode = { code -> invite(code)?.let { replace(Screen.JoinTerms(it)) } },
            )
            is Screen.JoinTerms -> JoinTermsScreen(screen.invite, family.myName, onBack = ::back, onJoin = { name ->
                Flows.join(screen.invite, name)
                replace(Screen.Joining)
            })
            Screen.Joining -> JoiningScreen(flow, onCancel = { Flows.cancel(); back() }, onDone = { home(); go(Screen.Health) })
            Screen.Home -> HomeScreen(
                family,
                resumed,
                onInvite = { go(Screen.ShowInvite) },
                onHealth = { go(Screen.Health) },
                onSettings = { go(Screen.Settings) },
                onMaps = { go(Screen.Maps) },
                onLive = { Kinfold.scope.launch { Kinfold.family.askForLive(it) } },
                onWatchAnswer = { on -> Kinfold.scope.launch { Kinfold.family.setWatchConsent(on) } },
                onJoin = { go(Screen.JoinScan) },
            )
            Screen.ShowInvite -> InviteScreen(family, onBack = ::back)
            Screen.Health -> HealthScreen(resumed, onBack = ::back, onFix = ::fix, onSharing = ::toggleSharing)
            Screen.Settings -> SettingsScreen(
                family,
                onBack = ::back,
                onLiveAsks = { go(Screen.LiveAsks) },
                onExport = ::export,
            )
            Screen.LiveAsks -> LiveAsksScreen(family, onBack = ::back)
            Screen.Maps -> MapsScreen(onBack = ::back)
        }
    }

    private fun go(s: Screen) {
        stack.add(s)
    }

    private fun replace(s: Screen) {
        if (stack.isNotEmpty()) stack.removeAt(stack.lastIndex)
        stack.add(s)
    }

    private fun back() {
        if (stack.size > 1) stack.removeAt(stack.lastIndex) else finish()
    }

    /** The family's home screen alone on the stack: where getting in ends. */
    internal fun home() {
        Flows.reset()
        stack.clear()
        stack.add(Screen.Home)
    }

    private fun invite(code: String): Invite? = try {
        Invite.fromCode(code.trim())
    } catch (_: Exception) {
        null
    }

    private fun cameraAllowed(): Boolean = checkSelfPermission(Manifest.permission.CAMERA) == PackageManager.PERMISSION_GRANTED

    private fun ask(vararg p: String) = permissions.launch(arrayOf(*p))

    private fun fix(f: Health.Fix) {
        when (f) {
            Health.Fix.LOCATION_SETTINGS -> startActivity(Intent(Settings.ACTION_LOCATION_SOURCE_SETTINGS))
            Health.Fix.LOCATION -> ask(Manifest.permission.ACCESS_FINE_LOCATION, Manifest.permission.ACCESS_COARSE_LOCATION)
            // Android asks for this one on its own, and from Android 11 in its settings: Allow all the time.
            Health.Fix.BACKGROUND_LOCATION -> ask(Manifest.permission.ACCESS_BACKGROUND_LOCATION)
            Health.Fix.NOTIFICATIONS -> if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU && checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED) {
                ask(Manifest.permission.POST_NOTIFICATIONS)
            } else {
                startActivity(Intent(Settings.ACTION_APP_NOTIFICATION_SETTINGS).putExtra(Settings.EXTRA_APP_PACKAGE, packageName))
            }
            // Android's guidance lists apps that keep families safe among those that may ask.
            Health.Fix.BATTERY -> startActivity(Intent(Settings.ACTION_REQUEST_IGNORE_BATTERY_OPTIMIZATIONS, Uri.parse("package:$packageName")))
            Health.Fix.APP_INFO -> startActivity(Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS, Uri.parse("package:$packageName")))
            Health.Fix.SHARING -> toggleSharing(true)
        }
    }

    private fun toggleSharing(on: Boolean) {
        if (on) {
            if (checkSelfPermission(Manifest.permission.ACCESS_FINE_LOCATION) != PackageManager.PERMISSION_GRANTED) {
                ask(Manifest.permission.ACCESS_FINE_LOCATION, Manifest.permission.ACCESS_COARSE_LOCATION)
                return
            }
            SharingService.turnOn(this)
        } else {
            SharingService.turnOff(this)
        }
        resumed++
    }

    private fun export() {
        Kinfold.scope.launch {
            val chooser = Export.intent(this@MainActivity)
            withContext(Dispatchers.Main) { startActivity(chooser) }
        }
    }

    companion object {
        private const val OWNER = "screen"

        /** Whether the app is in front of the person, so a notice can wait for the screen instead. */
        @Volatile
        var visible = false
            private set
    }
}
