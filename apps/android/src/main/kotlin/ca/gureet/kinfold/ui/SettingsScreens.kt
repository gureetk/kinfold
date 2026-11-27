// SPDX-License-Identifier: GPL-3.0-or-later WITH LicenseRef-Kinfold-AppStore-Exception
package ca.gureet.kinfold.ui

import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import ca.gureet.kinfold.Kinfold
import ca.gureet.kinfold.family.Family
import ca.gureet.kinfold.family.FamilyState
import ca.gureet.kinfold.share.Health
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch

/** Sharing health (plan §17): each thing sharing depends on, green or red, and a tap to fix a red one. */
@Composable
fun HealthScreen(resumed: Int, onBack: () -> Unit, onFix: (Health.Fix) -> Unit, onSharing: (Boolean) -> Unit) {
    val context = LocalContext.current
    var tick by remember { mutableStateOf(0) }
    LaunchedEffect(Unit) {
        while (true) {
            delay(2_000)
            tick++
        }
    }
    val checks = remember(resumed, tick) { Health.checks(context) }
    Page("Sharing health", onBack) {
        Text("Everything Kinfold needs to keep your family up to date. Tap anything red to fix it.")
        Card(Modifier.fillMaxWidth()) {
            Column {
                checks.forEachIndexed { i, c ->
                    if (i > 0) HorizontalDivider()
                    Row(
                        Modifier.fillMaxWidth().padding(14.dp).let { if (!c.ok && c.fix != null) it.clickable { onFix(c.fix) } else it },
                        verticalAlignment = Alignment.Top,
                    ) {
                        Box(
                            Modifier.padding(top = 4.dp).size(12.dp).background(
                                when {
                                    c.ok -> Brand.ok
                                    c.warningOnly -> Brand.warn
                                    else -> Brand.bad
                                },
                                CircleShape,
                            ),
                        )
                        Column(Modifier.padding(start = 12.dp).weight(1f)) {
                            Text(c.title, style = MaterialTheme.typography.titleSmall)
                            Text(c.detail, style = MaterialTheme.typography.bodySmall)
                        }
                    }
                }
            }
        }
        if (Kinfold.sharing) {
            OutlinedButton(onClick = { onSharing(false) }, modifier = Modifier.fillMaxWidth()) { Text("Turn sharing off") }
        } else {
            Button(onClick = { onSharing(true) }, modifier = Modifier.fillMaxWidth()) { Text("Turn sharing on") }
        }
    }
}

@Composable
fun SettingsScreen(family: FamilyState, onBack: () -> Unit, onLiveAsks: () -> Unit, onExport: () -> Unit) {
    var name by rememberSaveable(family.myName) { mutableStateOf(family.myName ?: "") }
    val scope = rememberCoroutineScope()
    var watch by remember { mutableStateOf(Kinfold.watchConsent == true) }
    Page("Settings", onBack) {
        Text("You", style = MaterialTheme.typography.titleMedium, color = MaterialTheme.colorScheme.primary)
        NameField(name, { name = it }, "Your name")
        OutlinedButton(
            enabled = name.isNotBlank() && name.trim() != family.myName,
            onClick = { scope.launch { tryHard("changing the name") { Kinfold.family.setMyName(name.trim()) } } },
        ) { Text("Save the name") }
        HorizontalDivider()
        Text("Silence alerts", style = MaterialTheme.typography.titleMedium, color = MaterialTheme.colorScheme.primary)
        Row(verticalAlignment = Alignment.CenterVertically) {
            Column(Modifier.weight(1f)) {
                Text("Tell the family if this phone goes quiet")
                Text(
                    "After ${Family.WATCH_AFTER_MIN} minutes without an update, your server tells the other adults. " +
                        "Turning this off ends it at once.",
                    style = MaterialTheme.typography.bodySmall,
                )
            }
            Switch(checked = watch, onCheckedChange = { on ->
                watch = on
                scope.launch { tryHard("changing the silence alerts") { Kinfold.family.setWatchConsent(on) } }
            })
        }
        HorizontalDivider()
        Text("Privacy", style = MaterialTheme.typography.titleMedium, color = MaterialTheme.colorScheme.primary)
        OutlinedButton(onClick = onLiveAsks, modifier = Modifier.fillMaxWidth()) { Text("Who asked for live updates") }
        HorizontalDivider()
        Text("Help", style = MaterialTheme.typography.titleMedium, color = MaterialTheme.colorScheme.primary)
        Text("Kinfold keeps a log of how sharing went: times, distances and connection states, never where you were. You can send it to whoever helps you.")
        OutlinedButton(onClick = onExport, modifier = Modifier.fillMaxWidth()) { Text("Export the log") }
        Kinfold.client?.let { c ->
            Text("Server: ${c.serverUrl}", style = MaterialTheme.typography.bodySmall)
        }
        if (Kinfold.isTestBuild) Text("TEST BUILD: trusts a test server's certificate only.", color = MaterialTheme.colorScheme.error)
    }
}

/** Every live-view request this phone received, newest first (PROTOCOL.md §8.2): who asked, and when. */
@Composable
fun LiveAsksScreen(family: FamilyState, onBack: () -> Unit) {
    val names = family.people.associate { it.accountId to (it.name ?: "Someone") }
    Page("Who asked for live updates", onBack) {
        if (family.liveAsks.isEmpty()) Text("Nobody has asked yet.")
        for (a in family.liveAsks) {
            Column {
                Text("${names[a.from] ?: "A former member"} · ${Family.timeOfDay(a.at)}, ${java.time.Instant.ofEpochMilli(a.at).atZone(java.time.ZoneId.systemDefault()).toLocalDate()}")
                Text(if (a.honored) "Sent live updates for a couple of minutes." else "Not answered: sharing was off, or they had asked less than a minute before.", style = MaterialTheme.typography.bodySmall)
            }
        }
    }
}
