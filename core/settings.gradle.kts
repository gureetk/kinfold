// SPDX-License-Identifier: GPL-3.0-or-later WITH LicenseRef-Kinfold-AppStore-Exception
pluginManagement {
    repositories {
        // Google's repository serves only the Android build tools and test libraries
        google {
            content {
                includeGroupByRegex("com\\.android.*")
                includeGroupByRegex("androidx\\..*")
                includeGroupByRegex("com\\.google\\.android\\..*")
                includeGroup("com.google.testing.platform")
            }
        }
        mavenCentral()
    }
}
dependencyResolutionManagement {
    repositories {
        google {
            content {
                includeGroupByRegex("com\\.android.*")
                includeGroupByRegex("androidx\\..*")
                includeGroupByRegex("com\\.google\\.android\\..*")
                includeGroup("com.google.testing.platform")
            }
        }
        mavenCentral()
    }
}
rootProject.name = "kinfold-core"
