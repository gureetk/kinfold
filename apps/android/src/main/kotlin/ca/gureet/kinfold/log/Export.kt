// SPDX-License-Identifier: GPL-3.0-or-later WITH LicenseRef-Kinfold-AppStore-Exception
package ca.gureet.kinfold.log

import android.content.ClipData
import android.content.Context
import android.content.Intent
import android.os.Build
import ca.gureet.kinfold.Kinfold
import ca.gureet.kinfold.share.Probes
import java.io.File
import java.time.LocalDate
import java.time.ZoneOffset

/** The log, every day of it in one file, handed to the share sheet for the person to send. */
object Export {
    /** Writes the file and returns the share sheet's intent; call it off the main thread. */
    fun intent(context: Context): Intent {
        val dir = LogProvider.exportDir(context.cacheDir).apply {
            mkdirs()
            listFiles()?.forEach { it.delete() }
        }
        // The state the phone is in now, so the file says how it ends.
        Kinfold.log.write("export", *Probes.state(context))
        val model = Build.MODEL.replace(Regex("[^A-Za-z0-9]+"), "-").trim('-').ifEmpty { "phone" }
        val name = "kinfold-android-$model-${LocalDate.now(ZoneOffset.UTC)}.jsonl"
        File(dir, name).outputStream().use { out ->
            for (f in Kinfold.log.files()) f.inputStream().use { it.copyTo(out) }
        }
        val uri = LogProvider.uri(name)
        val send = Intent(Intent.ACTION_SEND)
            .setType("application/json")
            .putExtra(Intent.EXTRA_STREAM, uri)
            .addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
        send.clipData = ClipData.newRawUri(name, uri)
        return Intent.createChooser(send, "Export Kinfold's log")
    }
}
