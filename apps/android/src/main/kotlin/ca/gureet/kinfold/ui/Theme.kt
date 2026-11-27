// SPDX-License-Identifier: GPL-3.0-or-later WITH LicenseRef-Kinfold-AppStore-Exception
package ca.gureet.kinfold.ui

import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color

/** The brand's colours (plan §16): tangerine on cream, night blue in the dark. */
object Brand {
    val tangerine = Color(0xFFE8701F)
    val burnt = Color(0xFFC2550E)
    val night = Color(0xFF1E2130)
    val cream = Color(0xFFFFF6EC)
    val ok = Color(0xFF2E7D32)
    val warn = Color(0xFFB26A00)
    val bad = Color(0xFFC62828)
}

private val light = lightColorScheme(
    primary = Brand.burnt,
    onPrimary = Color.White,
    primaryContainer = Color(0xFFFFDBC8),
    onPrimaryContainer = Color(0xFF331200),
    secondary = Brand.night,
    onSecondary = Color.White,
    background = Brand.cream,
    onBackground = Brand.night,
    surface = Brand.cream,
    onSurface = Brand.night,
)

private val dark = darkColorScheme(
    primary = Brand.tangerine,
    onPrimary = Color(0xFF331200),
    primaryContainer = Color(0xFF7A3000),
    onPrimaryContainer = Color(0xFFFFDBC8),
    background = Brand.night,
    onBackground = Brand.cream,
    surface = Brand.night,
    onSurface = Brand.cream,
)

@Composable
fun KinfoldTheme(content: @Composable () -> Unit) {
    MaterialTheme(colorScheme = if (isSystemInDarkTheme()) dark else light, content = content)
}
