// SPDX-License-Identifier: GPL-3.0-or-later WITH LicenseRef-Kinfold-AppStore-Exception
package ca.gureet.kinfold.core.client

// On a server or a desktop, the monotonic clock: a machine that sleeps loses that time, which
// only shortens how long trusted time counts on from the last server time heard.
internal actual fun monotonicMillis(): Long = System.nanoTime() / 1_000_000

internal actual fun wallMillis(): Long = System.currentTimeMillis()
