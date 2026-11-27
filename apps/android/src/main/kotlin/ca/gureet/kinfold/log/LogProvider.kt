// SPDX-License-Identifier: GPL-3.0-or-later WITH LicenseRef-Kinfold-AppStore-Exception
package ca.gureet.kinfold.log

import android.content.ContentProvider
import android.content.ContentValues
import android.database.Cursor
import android.database.MatrixCursor
import android.net.Uri
import android.os.ParcelFileDescriptor
import android.provider.OpenableColumns
import java.io.File
import java.io.FileNotFoundException

/**
 * Hands an exported log to the app the person shares it with, read-only, and nothing else: only
 * files the export wrote, in the app's cache, and only to an app given the file's link.
 */
class LogProvider : ContentProvider() {
    override fun onCreate(): Boolean = true

    override fun getType(uri: Uri): String = "application/json"

    override fun openFile(uri: Uri, mode: String): ParcelFileDescriptor {
        if (mode != "r") throw SecurityException("read only")
        return ParcelFileDescriptor.open(file(uri), ParcelFileDescriptor.MODE_READ_ONLY)
    }

    override fun query(uri: Uri, projection: Array<out String>?, selection: String?, selectionArgs: Array<out String>?, sortOrder: String?): Cursor {
        val f = file(uri)
        val columns = projection ?: arrayOf(OpenableColumns.DISPLAY_NAME, OpenableColumns.SIZE)
        return MatrixCursor(columns, 1).apply {
            addRow(
                columns.map {
                    when (it) {
                        OpenableColumns.DISPLAY_NAME -> f.name
                        OpenableColumns.SIZE -> f.length()
                        else -> null
                    }
                },
            )
        }
    }

    override fun insert(uri: Uri, values: ContentValues?): Uri? = null

    override fun delete(uri: Uri, selection: String?, selectionArgs: Array<out String>?): Int = 0

    override fun update(uri: Uri, values: ContentValues?, selection: String?, selectionArgs: Array<out String>?): Int = 0

    private fun file(uri: Uri): File {
        val name = uri.lastPathSegment ?: throw FileNotFoundException()
        if (!NAME.matches(name)) throw FileNotFoundException(name)
        val dir = exportDir(context?.cacheDir ?: throw FileNotFoundException(name))
        return File(dir, name).takeIf { it.isFile } ?: throw FileNotFoundException(name)
    }

    companion object {
        const val AUTHORITY = "ca.gureet.kinfold.logs"
        private val NAME = Regex("[A-Za-z0-9._-]{1,120}")

        fun exportDir(cache: File): File = File(cache, "export")

        fun uri(name: String): Uri = Uri.parse("content://$AUTHORITY/$name")
    }
}
