// SPDX-License-Identifier: GPL-3.0-or-later WITH LicenseRef-Kinfold-AppStore-Exception
// The plugins every project here uses, declared once so that they share one class loader.
// The Android plugin compiles Kotlin itself, with the Kotlin compiler declared here.
plugins {
    kotlin("jvm") version "2.4.21" apply false
    id("com.android.application") version "9.5.1" apply false
}
