// SPDX-License-Identifier: GPL-3.0-or-later WITH LicenseRef-Kinfold-AppStore-Exception
pluginManagement {
    repositories {
        // Google's repository serves only the Android build tools and libraries
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
rootProject.name = "kinfold-spikes"

include(":harness")
include(":android")

// The shared core, built from source: a spike always runs the core of its own commit.
includeBuild("../core") {
    dependencySubstitution {
        substitute(module("ca.gureet.kinfold:core")).using(project(":"))
    }
}
