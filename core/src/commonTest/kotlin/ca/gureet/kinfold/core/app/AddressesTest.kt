// SPDX-License-Identifier: GPL-3.0-or-later WITH LicenseRef-Kinfold-AppStore-Exception
package ca.gureet.kinfold.core.app

import kotlin.test.Test
import kotlin.test.assertEquals

class AddressesTest {
    @Test
    fun takesOutWhatNamesTheServer() {
        assertEquals("Failed to connect to <host>/<ip>", withoutAddresses("Failed to connect to kinfold.example.ca/192.168.1.20:8443"))
        assertEquals("Unable to resolve host \"<host>\": No address associated with hostname", withoutAddresses("Unable to resolve host \"kinfold.home.arpa\": No address associated with hostname"))
        assertEquals("Failed to connect to /<ip>", withoutAddresses("Failed to connect to /[fd00:1234::5]:8443"))
        assertEquals("Failed to connect to /<ip>", withoutAddresses("Failed to connect to /2001:db8::1"))
        assertEquals("expected a 206 from <url>", withoutAddresses("expected a 206 from https://kinfold.example.ca:8443/tiles/bc.pmtiles"))
    }

    @Test
    fun keepsTheRest() {
        for (message in listOf("timeout", "HTTP 404 /v1/tiles", "SHA-256 mismatch after 2266498 bytes", "TLSv1.3 required", "stream closed: 1001")) {
            assertEquals(message, withoutAddresses(message))
        }
    }
}
