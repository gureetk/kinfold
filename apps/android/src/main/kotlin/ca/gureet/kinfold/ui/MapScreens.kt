// SPDX-License-Identifier: GPL-3.0-or-later WITH LicenseRef-Kinfold-AppStore-Exception
package ca.gureet.kinfold.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import ca.gureet.kinfold.Kinfold
import ca.gureet.kinfold.map.Maps
import java.util.Locale

/**
 * The map of the family's area (API.md §13): the regions the server offers, one downloaded whole
 * and kept on the phone. Downloading a region tells the server which one; looking at the map
 * tells it nothing.
 */
@Composable
fun MapsScreen(onBack: () -> Unit) {
    val state by Maps.ui.collectAsState()
    val version by Maps.changed.collectAsState()
    val have = remember(version) { Maps.file() }
    LaunchedEffect(Unit) { if (state is Maps.State.Idle) Maps.list() }
    Page("Map of your area", onBack) {
        Text("The map is drawn from files on this phone. Outside the area you download, it shows the world map Kinfold comes with.")
        if (have != null) {
            Card(Modifier.fillMaxWidth()) {
                Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
                    Text(Kinfold.regionName ?: "Your area", style = MaterialTheme.typography.titleMedium)
                    Text("On this phone: ${size(have.length())}")
                    OutlinedButton(onClick = { Maps.remove() }) { Text("Remove it") }
                }
            }
        }
        when (val s = state) {
            Maps.State.Idle -> OutlinedButton(onClick = { Maps.list() }) { Text("See the maps your server offers") }
            Maps.State.Listing -> Text("Asking your server…")
            is Maps.State.Failed -> {
                Text(s.message, color = MaterialTheme.colorScheme.error)
                OutlinedButton(onClick = { Maps.list() }) { Text("Try again") }
            }
            is Maps.State.Downloading -> Card(Modifier.fillMaxWidth()) {
                Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    Text("Downloading ${s.region.name}", style = MaterialTheme.typography.titleMedium)
                    LinearProgressIndicator(progress = { if (s.total > 0) (s.done.toFloat() / s.total).coerceIn(0f, 1f) else 0f }, modifier = Modifier.fillMaxWidth())
                    Text("${size(s.done)} of ${size(s.total)}. It carries on where it stopped if you leave.")
                    OutlinedButton(onClick = { Maps.pause() }) { Text("Pause") }
                }
            }
            is Maps.State.Offer -> {
                if (s.regions.isEmpty()) {
                    Text("Your server offers no maps yet. Its operator adds one with kinfold region add.")
                }
                for (r in s.regions) {
                    Card(Modifier.fillMaxWidth()) {
                        Row(Modifier.padding(16.dp), verticalAlignment = Alignment.CenterVertically) {
                            Column(Modifier.weight(1f)) {
                                Text(r.name, style = MaterialTheme.typography.titleMedium)
                                Text(size(r.size) + if (r.id == Kinfold.regionId) " · on this phone" else "", style = MaterialTheme.typography.bodySmall)
                            }
                            Button(onClick = { Maps.download(r) }) { Text(if (r.id == Kinfold.regionId) "Update" else "Download") }
                        }
                    }
                }
                Text("A big area can take a while and use a lot of data: use Wi-Fi if you can.", style = MaterialTheme.typography.bodySmall)
            }
        }
    }
}

fun size(bytes: Long): String = when {
    bytes >= 1_000_000_000 -> String.format(Locale.getDefault(), "%.1f GB", bytes / 1e9)
    bytes >= 1_000_000 -> String.format(Locale.getDefault(), "%.0f MB", bytes / 1e6)
    else -> String.format(Locale.getDefault(), "%.0f kB", bytes / 1e3)
}
