// SPDX-License-Identifier: GPL-3.0-or-later WITH LicenseRef-Kinfold-AppStore-Exception
package ca.gureet.kinfold.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.aspectRatio
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.KeyboardCapitalization
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.viewinterop.AndroidView
import ca.gureet.kinfold.core.log.Role
import ca.gureet.kinfold.core.rendezvous.Invite
import ca.gureet.kinfold.qr.ScannerView

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun Page(title: String, onBack: (() -> Unit)?, actions: @Composable () -> Unit = {}, content: @Composable () -> Unit) {
    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text(title) },
                navigationIcon = { if (onBack != null) TextButton(onClick = onBack) { Text("Back") } },
                actions = { actions() },
            )
        },
    ) { inner ->
        Column(
            Modifier.padding(inner).fillMaxSize().verticalScroll(rememberScrollState()).padding(horizontal = 20.dp, vertical = 8.dp),
            verticalArrangement = Arrangement.spacedBy(16.dp),
        ) { content() }
    }
}

@Composable
fun StartScreen(onSetUp: () -> Unit, onJoin: () -> Unit) {
    Page("Kinfold", onBack = null) {
        Text("Your family's locations, end-to-end encrypted, on your family's own server.", style = MaterialTheme.typography.titleMedium)
        Text("Your server sees only sealed envelopes it can't open. Only the people in your family can read where you are.")
        Spacer(Modifier.height(8.dp))
        Button(onClick = onJoin, modifier = Modifier.fillMaxWidth()) { Text("Join a family") }
        Text("Someone in your family invites you: scan the code their phone shows.", style = MaterialTheme.typography.bodySmall)
        OutlinedButton(onClick = onSetUp, modifier = Modifier.fillMaxWidth()) { Text("Set up a new family") }
        Text("For the first phone on a new server: scan the setup code the server prints.", style = MaterialTheme.typography.bodySmall)
    }
}

/** The camera, or a field to type or paste the code into. Calls [onCode] with a code that starts with [prefix]. */
@Composable
fun ScanScreen(
    title: String,
    hint: String,
    prefix: String,
    resumed: Int,
    camera: () -> Boolean,
    askCamera: () -> Unit,
    onBack: () -> Unit,
    onCode: (String) -> Unit,
) {
    var typed by rememberSaveable { mutableStateOf("") }
    var error by remember { mutableStateOf<String?>(null) }
    // Read again whenever the person comes back from the permission dialog.
    val allowed = remember(resumed) { camera() }
    var key by remember { mutableStateOf(0) }
    fun take(text: String) {
        val code = text.trim()
        if (code.startsWith(prefix)) {
            error = null
            onCode(code)
        } else {
            error = "That isn't the right kind of code: it should begin with $prefix."
            key++
        }
    }
    LaunchedEffect(Unit) { if (!camera()) askCamera() }
    Page(title, onBack) {
        Text(hint)
        Box(Modifier.fillMaxWidth().aspectRatio(1f).clip(RoundedCornerShape(16.dp)), contentAlignment = Alignment.Center) {
            if (allowed) {
                androidx.compose.runtime.key(key) {
                    AndroidView(factory = { ScannerView(it) { text -> take(text) } }, modifier = Modifier.fillMaxSize())
                }
            } else {
                Column(horizontalAlignment = Alignment.CenterHorizontally, verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    Text("Kinfold needs the camera to scan the code.", textAlign = TextAlign.Center)
                    OutlinedButton(onClick = askCamera) { Text("Allow the camera") }
                }
            }
        }
        error?.let { Text(it, color = MaterialTheme.colorScheme.error) }
        OutlinedTextField(
            value = typed,
            onValueChange = { typed = it },
            label = { Text("Or type or paste the code") },
            modifier = Modifier.fillMaxWidth(),
            minLines = 2,
            textStyle = MaterialTheme.typography.bodySmall.copy(fontFamily = FontFamily.Monospace),
        )
        Button(onClick = { take(typed) }, enabled = typed.isNotBlank(), modifier = Modifier.fillMaxWidth()) { Text("Continue") }
    }
}

@Composable
fun NameField(value: String, onChange: (String) -> Unit, label: String) {
    OutlinedTextField(
        value = value,
        onValueChange = { onChange(it.take(60)) },
        label = { Text(label) },
        singleLine = true,
        keyboardOptions = KeyboardOptions(capitalization = KeyboardCapitalization.Words),
        modifier = Modifier.fillMaxWidth(),
    )
}

@Composable
fun SetUpScreen(flow: Flows.Progress, onBack: () -> Unit, onSetUp: (String, String) -> Unit, onDone: () -> Unit) {
    var name by rememberSaveable { mutableStateOf("") }
    var circle by rememberSaveable { mutableStateOf("Family") }
    LaunchedEffect(flow) { if (flow is Flows.Progress.Done) onDone() }
    Page("Set up a new family", onBack) {
        Text("This phone becomes the family's first member, and an admin who can invite the others.")
        NameField(name, { name = it }, "Your name")
        NameField(circle, { circle = it }, "Your family's name")
        Text("Your name and your family's name are encrypted: your server never sees them.", style = MaterialTheme.typography.bodySmall)
        Progress(flow)
        Button(
            onClick = { onSetUp(name.trim(), circle.trim()) },
            enabled = name.isNotBlank() && circle.isNotBlank() && flow !is Flows.Progress.Working,
            modifier = Modifier.fillMaxWidth(),
        ) { Text("Set up") }
    }
}

@Composable
fun Progress(flow: Flows.Progress) {
    when (flow) {
        is Flows.Progress.Working -> Row {
            CircularProgressIndicator(Modifier.padding(end = 12.dp))
            Text(flow.what)
        }
        is Flows.Progress.Failed -> Text(flow.message, color = MaterialTheme.colorScheme.error)
        else -> {}
    }
}

@Composable
private fun Row(content: @Composable () -> Unit) {
    androidx.compose.foundation.layout.Row(verticalAlignment = Alignment.CenterVertically) { content() }
}

/**
 * The join screen (PROTOCOL.md §9.1): the terms on offer, before anything is sent. The circle's
 * and the inviter's names come from the invite, and nothing has checked them yet.
 */
@Composable
fun JoinTermsScreen(invite: Invite, myName: String?, onBack: () -> Unit, onJoin: (String) -> Unit) {
    var name by rememberSaveable { mutableStateOf(myName ?: "") }
    val terms = try {
        invite.terms
    } catch (_: Exception) {
        null
    }
    val adult = terms?.role == Role.ADULT.code
    Page("Join ${invite.circleName.ifBlank { "a family" }}", onBack) {
        Card(Modifier.fillMaxWidth()) {
            Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
                Text(invite.circleName.ifBlank { "A family" }, style = MaterialTheme.typography.titleLarge)
                Text("Invited by ${invite.inviterName.ifBlank { "someone" }}")
                Text("These names are as the invite gives them. Check the safety code with them once you join.", style = MaterialTheme.typography.bodySmall)
            }
        }
        if (adult) {
            Text("You'll join as an adult.", style = MaterialTheme.typography.titleMedium)
            Text("Everyone in the family sees where you are while you share, and you see where they are. You can turn sharing off at any time.")
            NameField(name, { name = it }, "Your name")
            Button(onClick = { onJoin(name.trim()) }, enabled = name.isNotBlank(), modifier = Modifier.fillMaxWidth()) { Text("Join") }
        } else {
            Text(
                "This invite asks you to join with a teen's rules. This version of Kinfold can't join that way yet; ask for an adult's invite.",
                color = MaterialTheme.colorScheme.error,
            )
        }
    }
}

/** Twelve groups of five digits (PROTOCOL.md §11), in three rows so it can be read aloud. */
@Composable
fun SafetyCodeText(code: String) {
    val groups = code.chunked(5)
    Card(Modifier.fillMaxWidth()) {
        Column(Modifier.padding(16.dp), horizontalAlignment = Alignment.CenterHorizontally) {
            for (row in groups.chunked(4)) {
                Text(row.joinToString("  "), fontFamily = FontFamily.Monospace, fontWeight = FontWeight.Medium, style = MaterialTheme.typography.titleMedium)
            }
        }
    }
}

@Composable
fun JoiningScreen(flow: Flows.Progress, onCancel: () -> Unit, onDone: () -> Unit) {
    var detailsWarning by remember { mutableStateOf(false) }
    LaunchedEffect(flow) {
        if (flow is Flows.Progress.Done) {
            if (flow.joined?.detailsMatched == false) detailsWarning = true else onDone()
        }
    }
    Page("Joining", onBack = onCancel) {
        when (flow) {
            is Flows.Progress.Waiting -> {
                Text("Waiting for ${flow.inviter} to let you in.", style = MaterialTheme.typography.titleMedium)
                Text("Their phone shows a safety code. Check that it is the same as this one:")
                SafetyCodeText(flow.safetyCode)
                Text("If the codes differ, don't go on: someone may be between you.", style = MaterialTheme.typography.bodySmall)
                Row {
                    CircularProgressIndicator(Modifier.padding(end = 12.dp))
                    Text("Waiting")
                }
                OutlinedButton(onClick = onCancel) { Text("Cancel") }
            }
            is Flows.Progress.Done -> if (detailsWarning) {
                // §9.4: the entry that added this phone didn't open to the terms it accepted.
                Text("You're in, as an adult.", style = MaterialTheme.typography.titleMedium)
                Text("The family's record of your terms couldn't be read as the invite offered them, so you joined as an adult, with no rules.")
                Button(onClick = onDone) { Text("Continue") }
            }
            else -> Progress(flow)
        }
    }
}
