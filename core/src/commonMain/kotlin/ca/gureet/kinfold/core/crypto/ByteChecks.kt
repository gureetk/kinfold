// SPDX-License-Identifier: GPL-3.0-or-later WITH LicenseRef-Kinfold-AppStore-Exception
package ca.gureet.kinfold.core.crypto

import ca.gureet.kinfold.core.wire.hexBytes

/**
 * The checks of PROTOCOL.md §3.3, made on the raw bytes before any platform sees a key or a
 * signature. Ed25519 libraries disagree about exactly these cases; with the checks in front,
 * every library the protocol targets gives the verdict the spec requires.
 */
object Ed25519Checks {
    /** The group order L = 2^252 + 27742317777372353535851937790883648493, little-endian. */
    private val L = hexBytes("edd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010")

    /** p = 2^255 − 19, little-endian. */
    private val P = hexBytes("edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f")

    private val SMALL_ORDER = listOf(
        "0000000000000000000000000000000000000000000000000000000000000000",
        "0100000000000000000000000000000000000000000000000000000000000000",
        "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
        "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
        "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
    ).map(::hexBytes)

    /**
     * An invalid key (§3.3, checks 2 and 3): `y`, the key with its top bit cleared, is not below
     * p, or is one of the five small-order values. Also true for anything but 32 bytes.
     */
    fun isInvalidKey(key: ByteArray): Boolean {
        if (key.size != 32) return true
        val y = key.copyOf()
        y[31] = (y[31].toInt() and 0x7f).toByte()
        return !lessThan(y, P) || SMALL_ORDER.any { it.contentEquals(y) }
    }

    /** Whether a signature may go to the platform: S below L, and neither the key nor R invalid. */
    fun pass(publicKey: ByteArray, signature: ByteArray): Boolean =
        signature.size == 64 &&
            lessThan(signature.copyOfRange(32, 64), L) &&
            !isInvalidKey(publicKey) &&
            !isInvalidKey(signature.copyOfRange(0, 32))
}

/** The key check of PROTOCOL.md §3.5, made before sealing to an X25519 key or accepting one. */
object X25519Checks {
    private val P = hexBytes("edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f")

    private val LOW_ORDER = listOf(
        "0000000000000000000000000000000000000000000000000000000000000000",
        "0100000000000000000000000000000000000000000000000000000000000000",
        "e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800",
        "5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157",
        "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
    ).map(::hexBytes)

    /** An invalid key: top bit set (which already puts it above p), not below p, or one of the five low-order values. */
    fun isInvalidKey(key: ByteArray): Boolean =
        key.size != 32 ||
            (key[31].toInt() and 0x80) != 0 ||
            !lessThan(key, P) ||
            LOW_ORDER.any { it.contentEquals(key) }
}

/** a < b, for two 32-byte little-endian integers. */
private fun lessThan(a: ByteArray, b: ByteArray): Boolean {
    for (i in 31 downTo 0) {
        val x = a[i].toInt() and 0xff
        val y = b[i].toInt() and 0xff
        if (x != y) return x < y
    }
    return false
}
