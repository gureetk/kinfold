// SPDX-License-Identifier: GPL-3.0-or-later WITH LicenseRef-Kinfold-AppStore-Exception
package ca.gureet.kinfold.ui

import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableLongStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.graphics.painter.BitmapPainter
import androidx.compose.ui.graphics.FilterQuality
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import ca.gureet.kinfold.Kinfold
import ca.gureet.kinfold.core.wire.Bytes
import ca.gureet.kinfold.family.Ask
import ca.gureet.kinfold.family.FamilyState
import ca.gureet.kinfold.family.Person
import ca.gureet.kinfold.map.FamilyMap
import ca.gureet.kinfold.map.Maps
import ca.gureet.kinfold.qr.Qr
import ca.gureet.kinfold.share.Health
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlin.math.abs

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun HomeScreen(
    family: FamilyState,
    resumed: Int,
    onInvite: () -> Unit,
    onHealth: () -> Unit,
    onSettings: () -> Unit,
    onMaps: () -> Unit,
    onLive: (Bytes) -> Unit,
    onWatchAnswer: (Boolean) -> Unit,
    onJoin: () -> Unit,
) {
    val context = LocalContext.current
    var menu by remember { mutableStateOf(false) }
    val me = family.people.firstOrNull { it.isMe }
    val healthy = remember(resumed, family) { Health.allGood(context) }
    val now by ticking()
    val flow by Flows.state.collectAsState()
    val mapVersion by Maps.changed.collectAsState()
    val hasRegion = remember(mapVersion) { Maps.file() != null }
    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text(family.circleName ?: "Kinfold") },
                actions = {
                    if (me?.admin == true) TextButton(onClick = onInvite) { Text("Invite") }
                    Box {
                        TextButton(onClick = { menu = true }) { Text("More") }
                        DropdownMenu(expanded = menu, onDismissRequest = { menu = false }) {
                            DropdownMenuItem(text = { Text("Sharing health") }, onClick = { menu = false; onHealth() })
                            DropdownMenuItem(text = { Text("Map of your area") }, onClick = { menu = false; onMaps() })
                            DropdownMenuItem(text = { Text("Settings") }, onClick = { menu = false; onSettings() })
                        }
                    }
                },
            )
        },
    ) { inner ->
        Column(Modifier.padding(inner).fillMaxSize()) {
            if (family.circleId == null) {
                Column(Modifier.verticalScroll(rememberScrollState()).padding(20.dp), verticalArrangement = Arrangement.spacedBy(16.dp)) {
                    NoFamily(family, flow, onJoin)
                }
                return@Column
            }
            FamilyMap(family.people, now, Modifier.fillMaxWidth().weight(1f))
            Column(
                Modifier.fillMaxWidth().heightIn(max = 360.dp).verticalScroll(rememberScrollState()).padding(horizontal = 16.dp, vertical = 12.dp),
                verticalArrangement = Arrangement.spacedBy(12.dp),
            ) {
                if (!Kinfold.sharing || !healthy) {
                    Card(
                        onClick = onHealth,
                        modifier = Modifier.fillMaxWidth(),
                        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.primaryContainer),
                    ) {
                        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
                            Text(if (!Kinfold.sharing) "You're not sharing your location" else "Sharing needs attention", style = MaterialTheme.typography.titleMedium)
                            Text(if (!Kinfold.sharing) "Tap to turn sharing on." else "Something sharing depends on is off. Tap to see what.")
                        }
                    }
                }
                if (Kinfold.watchConsent == null && family.people.size > 1) {
                    Card(Modifier.fillMaxWidth()) {
                        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                            Text("Tell your family if your phone goes quiet?", style = MaterialTheme.typography.titleMedium)
                            Text(
                                "If your phone stops sending updates for an hour, your server tells the other adults. It sees only when updates arrive. " +
                                    "You can turn this off at any time in Settings.",
                            )
                            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                                Button(onClick = { onWatchAnswer(true) }) { Text("Yes") }
                                OutlinedButton(onClick = { onWatchAnswer(false) }) { Text("Not now") }
                            }
                        }
                    }
                }
                if (!hasRegion) {
                    Card(onClick = onMaps, modifier = Modifier.fillMaxWidth()) {
                        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
                            Text("Download the map of your area", style = MaterialTheme.typography.titleMedium)
                            Text("For streets and places. It's kept on this phone, so your server never sees where you look.")
                        }
                    }
                }
                for (p in family.people) PersonCard(p, now, onLive)
                if (family.people.size <= 1 && me?.admin == true) {
                    Text("Nobody else is here yet. Tap Invite and have them scan the code with Kinfold.", style = MaterialTheme.typography.bodyMedium)
                }
            }
        }
    }
    AsksDialog(family.asks)
}

/** A phone that is set up but in no circle: one that left, or whose setup or join stopped half way. */
@Composable
private fun NoFamily(family: FamilyState, flow: Flows.Progress, onJoin: () -> Unit) {
    var name by remember { mutableStateOf(family.myName ?: "") }
    var circle by remember { mutableStateOf("Family") }
    when (flow) {
        is Flows.Progress.Working, is Flows.Progress.Waiting -> {
            Text("Getting in…")
            Progress(flow)
            return
        }
        else -> {}
    }
    Text("This phone isn't in a family.", style = MaterialTheme.typography.titleMedium)
    Button(onClick = onJoin, modifier = Modifier.fillMaxWidth()) { Text("Join a family") }
    Text("Or found one, with this phone as its first member:")
    NameField(name, { name = it }, "Your name")
    NameField(circle, { circle = it }, "Your family's name")
    Progress(flow)
    OutlinedButton(onClick = { Flows.create(name.trim(), circle.trim()) }, enabled = name.isNotBlank() && circle.isNotBlank(), modifier = Modifier.fillMaxWidth()) {
        Text("Create the family")
    }
}

/** The time now, once a second, for ages that count up on screen. */
@Composable
fun ticking(): androidx.compose.runtime.State<Long> {
    val t = remember { mutableLongStateOf(System.currentTimeMillis()) }
    LaunchedEffect(Unit) {
        while (true) {
            delay(1_000)
            t.longValue = System.currentTimeMillis()
        }
    }
    return t
}

@Composable
private fun PersonCard(p: Person, nowMs: Long, onLive: (Bytes) -> Unit) {
    Card(Modifier.fillMaxWidth()) {
        Row(Modifier.padding(16.dp), verticalAlignment = Alignment.CenterVertically) {
            Box(Modifier.size(44.dp).background(MaterialTheme.colorScheme.primary, CircleShape), contentAlignment = Alignment.Center) {
                Text(initials(p.name), color = MaterialTheme.colorScheme.onPrimary, style = MaterialTheme.typography.titleMedium)
            }
            Column(Modifier.weight(1f).padding(start = 14.dp), verticalArrangement = Arrangement.spacedBy(2.dp)) {
                Text((p.name ?: "Someone") + if (p.isMe) " (you)" else "", style = MaterialTheme.typography.titleMedium)
                val s = p.seen
                if (s == null) {
                    Text(if (p.heardAt != null) "No position yet · heard from ${ago(nowMs, p.heardAt)}" else "No position yet")
                } else {
                    Text(listOfNotNull(ago(nowMs, s.ts), "±${s.accM} m", s.bat?.let { "$it% battery" + if (s.charging == true) ", charging" else "" }).joinToString(" · "))
                }
                if (p.watchedByMe) Text("You'll hear if their phone goes quiet.", style = MaterialTheme.typography.bodySmall)
            }
            if (!p.isMe) TextButton(onClick = { onLive(p.accountId) }) { Text("Refresh") }
        }
    }
}

/** Someone waiting to be let in: their name, and the safety code to compare with their screen. */
@Composable
private fun AsksDialog(asks: List<Ask>) {
    val ask = asks.firstOrNull() ?: return
    val scope = rememberCoroutineScope()
    var busy by remember(ask) { mutableStateOf(false) }
    AlertDialog(
        onDismissRequest = {},
        title = { Text("${ask.ask.name.ifBlank { "Someone" }} is asking to join") },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Text("Check that their phone shows this same safety code before you let them in:")
                SafetyCodeText(ask.safetyCode)
                Text("They'll see where everyone in the family is, and everyone will see them.", style = MaterialTheme.typography.bodySmall)
            }
        },
        confirmButton = {
            Button(enabled = !busy, onClick = {
                busy = true
                scope.launch { tryHard("letting them in") { Kinfold.family.allow(ask) } }
            }) { Text("Let them in") }
        },
        dismissButton = {
            TextButton(enabled = !busy, onClick = {
                busy = true
                scope.launch { tryHard("declining") { Kinfold.family.decline(ask) } }
            }) { Text("Decline") }
        },
    )
}

/** Runs [block] in the app's scope, so it finishes even if the screen goes, and logs a failure. */
suspend fun tryHard(what: String, block: suspend () -> Unit) {
    Kinfold.scope.launch {
        try {
            block()
        } catch (e: Exception) {
            Kinfold.log.write("failed", "what" to what, "error" to Kinfold.describe(e))
        }
    }.join()
}

@Composable
fun InviteScreen(family: FamilyState, onBack: () -> Unit) {
    var failed by remember { mutableStateOf<String?>(null) }
    LaunchedEffect(Unit) {
        if (family.invite == null) {
            try {
                Kinfold.family.invite()
            } catch (e: Exception) {
                Kinfold.log.write("invite", "state" to "failed", "error" to Kinfold.describe(e))
                failed = "Couldn't make an invite: " + Kinfold.describe(e)
            }
        }
        // The server tells this phone when someone asks; looking now and then covers a missed event.
        while (true) {
            delay(5_000)
            try {
                Kinfold.family.pollAsks()
            } catch (_: Exception) {
            }
        }
    }
    val invite = family.invite
    Page("Invite to ${family.circleName ?: "the family"}", onBack = {
        Kinfold.family.closeInvite()
        onBack()
    }) {
        Text("On the other phone, open Kinfold, choose Join a family, and scan this code.")
        if (invite != null) {
            val bitmap = remember(invite.code) { Qr.bitmap(invite.code, 720).asImageBitmap() }
            Box(Modifier.fillMaxWidth().background(androidx.compose.ui.graphics.Color.White).padding(12.dp), contentAlignment = Alignment.Center) {
                Image(BitmapPainter(bitmap, filterQuality = FilterQuality.None), contentDescription = "The invite as a QR code", modifier = Modifier.fillMaxWidth())
            }
            Text("It works once, for the next 24 hours. When they scan it, you'll compare safety codes before letting them in.", style = MaterialTheme.typography.bodySmall)
            OutlinedButton(onClick = {
                Kinfold.scope.launch { Kinfold.family.endInvite(invite) }
                onBack()
            }) { Text("Cancel the invite") }
        } else {
            Text(failed ?: "Making the invite…")
        }
    }
    AsksDialog(family.asks)
}

fun initials(name: String?): String =
    name?.split(' ', '-')?.filter { it.isNotBlank() }?.take(2)?.joinToString("") { it.take(1).uppercase() }?.ifEmpty { null } ?: "?"

/** "just now", "5 min ago", "3 h ago", "2 days ago". */
fun ago(nowMs: Long, thenMs: Long): String {
    val d = abs(nowMs - thenMs)
    return when {
        d < 60_000 -> "just now"
        d < 3_600_000 -> "${d / 60_000} min ago"
        d < 86_400_000 -> "${d / 3_600_000} h ago"
        else -> "${d / 86_400_000} days ago"
    }
}
