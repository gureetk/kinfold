// SPDX-License-Identifier: GPL-3.0-or-later WITH LicenseRef-Kinfold-AppStore-Exception
package ca.gureet.kinfold.core

import ca.gureet.kinfold.core.client.ClientException
import ca.gureet.kinfold.core.client.Regions
import ca.gureet.kinfold.core.payload.Json
import ca.gureet.kinfold.core.wire.Base64Url
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertIs
import kotlin.test.assertNull

/** The region list of API.md §13, and the one parse that reads numbers with fractions. */
class RegionsTest {
    private val sha = Base64Url.encode(ByteArray(32) { it.toByte() })

    private fun region(id: String, bbox: String = "[-139.1, 48.2, -114.0, 60.0]", sha256: String = sha) =
        """{"id": "$id", "name": "British Columbia", "bbox": $bbox, "minzoom": 0, "maxzoom": 15, "size": 1480000000, "sha256": "$sha256", "updated_at": 1794000000000}"""

    @Test
    fun readsTheServersList() {
        val r = Regions.parse("""{"regions": [${region("bc")}], "attribution": "© OpenStreetMap contributors"}""".encodeToByteArray())
        assertEquals("© OpenStreetMap contributors", r.attribution)
        val bc = r.regions.single()
        assertEquals("bc", bc.id)
        assertEquals("British Columbia", bc.name)
        assertEquals(-139.1, bc.west)
        assertEquals(60.0, bc.north)
        assertEquals(15, bc.maxZoom)
        assertEquals(1_480_000_000L, bc.size)
        assertEquals("/tiles/bc.pmtiles", bc.path)
        assertEquals("\"$sha\"", bc.etag)
    }

    @Test
    fun leavesOutRegionsItCantUse() {
        val bad = listOf(
            region("../bc"),
            region("BC"),
            region("a".repeat(33)),
            region("bc", bbox = "[1, 2, 3]"),
            region("bc", bbox = "[1, 2, 3, \"4\"]"),
            region("bc", sha256 = "AAAA"),
        )
        for (r in bad) assertEquals(emptyList(), Regions.parse("""{"regions": [$r]}""".encodeToByteArray()).regions, r)
        assertFailsWith<ClientException> { Regions.parse("[]".encodeToByteArray()) }
    }

    @Test
    fun fractionsOnlyWhereAsked() {
        // §8.1 holds for payloads and for every other answer: a number with a fraction is refused.
        assertNull(Json.parsePayload("""{"t":"loc","lat":49.5}""".encodeToByteArray()))
        assertNull(Json.parseObject("""{"v":1.5}""".encodeToByteArray(), Json.Limits.MESSAGE))
        assertIs<Json.Num>(Json.parseObject("""{"v":1.0}""".encodeToByteArray(), Json.Limits.MESSAGE)!!["v"])
        val o = Json.parseObject("""{"v":-139.1,"w":2}""".encodeToByteArray(), Json.Limits.DEGREES)!!
        assertEquals(-139.1, (o["v"] as Json.Dec).value)
        assertIs<Json.Num>(o["w"])
        assertNull(Json.parseObject("""{"v":1e400}""".encodeToByteArray(), Json.Limits.DEGREES))
    }
}
