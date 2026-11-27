// SPDX-License-Identifier: GPL-3.0-or-later WITH LicenseRef-Kinfold-AppStore-Exception
package ca.gureet.kinfold.core.client

import ca.gureet.kinfold.core.payload.Json
import ca.gureet.kinfold.core.wire.Base64Url
import ca.gureet.kinfold.core.wire.Bytes

/**
 * A map region the server offers (API.md §13): a PMTiles file an app downloads whole, checks
 * against [sha256], and draws from the phone. Its bounds are west, south, east and north in degrees.
 */
class Region(
    val id: String,
    val name: String,
    val west: Double,
    val south: Double,
    val east: Double,
    val north: Double,
    val minZoom: Int,
    val maxZoom: Int,
    val size: Long,
    val sha256: Bytes,
    val updatedAt: ULong,
) {
    /** The file's path on the server, where it is downloaded whole, never in parts. */
    val path: String get() = "/tiles/$id.pmtiles"

    /** The file's `ETag`: its SHA-256 in base64url, in quotes; a download resumes with it in `If-Range`. */
    val etag: String get() = "\"" + Base64Url.encode(sha256.toByteArray()) + "\""
}

/** What `GET /v1/tiles` answers: the regions, and the attribution a map drawn from them shows. */
class Regions(val regions: List<Region>, val attribution: String) {
    companion object {
        private val ID = Regex("[a-z0-9-]{1,32}")

        /**
         * The answer's JSON. A region whose fields are missing or malformed is left out, and so is
         * one whose `id` isn't 1 to 32 lower-case letters, digits and hyphens, since the ID goes
         * into the file's URL.
         */
        fun parse(body: ByteArray): Regions {
            val o = Json.parseObject(body, Json.Limits.DEGREES) ?: throw ClientException("the server's answer (regions) is malformed")
            val list = (o["regions"] as? Json.Arr)?.items ?: emptyList()
            val regions = list.mapNotNull { item ->
                val r = item as? Json.Obj ?: return@mapNotNull null
                val id = r.string("id")?.takeIf { ID.matches(it) } ?: return@mapNotNull null
                val bbox = (r["bbox"] as? Json.Arr)?.items?.map {
                    when (it) {
                        is Json.Num -> it.value.toDouble()
                        is Json.Dec -> it.value
                        else -> null
                    }
                }
                if (bbox == null || bbox.size != 4 || bbox.any { it == null }) return@mapNotNull null
                val sha = r.string("sha256")?.let { Base64Url.decode(it) }?.takeIf { it.size == 32 } ?: return@mapNotNull null
                Region(
                    id,
                    r.string("name") ?: id,
                    bbox[0]!!,
                    bbox[1]!!,
                    bbox[2]!!,
                    bbox[3]!!,
                    r.long("minzoom")?.toInt()?.takeIf { it in 0..30 } ?: return@mapNotNull null,
                    r.long("maxzoom")?.toInt()?.takeIf { it in 0..30 } ?: return@mapNotNull null,
                    r.long("size")?.takeIf { it >= 0 } ?: return@mapNotNull null,
                    Bytes.of(sha),
                    r.long("updated_at")?.takeIf { it >= 0 }?.toULong() ?: 0UL,
                )
            }
            return Regions(regions, o.string("attribution") ?: "© OpenStreetMap contributors")
        }
    }
}

/** The regions the server offers (API.md §13). */
suspend fun Client.regions(): Regions = authed { Regions.parse(api.tiles()) }

/** Where [region]'s file is downloaded from. */
fun Client.regionUrl(region: Region): String = serverUrl + region.path

/**
 * Downloads [region] with [download], which the platform gives: it fetches the URL whole, or from
 * where an earlier download stopped, into a file, sending the headers it is handed. Those carry
 * the session, which the server asks of every download of a region (API.md §13). The session is
 * renewed first if it is about to end, and once more if [download] throws an [ApiException] with
 * status 401.
 */
suspend fun <T> Client.downloadRegion(region: Region, download: suspend (url: String, headers: Map<String, String>) -> T): T =
    authed { download(regionUrl(region), api.sessionHeaders()) }
