// SPDX-License-Identifier: GPL-3.0-or-later WITH LicenseRef-Kinfold-AppStore-Exception
package ca.gureet.kinfold.store

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.security.keystore.StrongBoxUnavailableException
import java.io.IOException
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/** Seals a file's content so that only this phone can open it; [aad] binds it to its name. */
interface Sealer {
    fun seal(plain: ByteArray, aad: ByteArray): ByteArray

    /** The content [seal] sealed; [IOException] when it doesn't open. */
    fun open(sealed: ByteArray, aad: ByteArray): ByteArray

    companion object {
        /** A sealed file: this byte, the 12-byte nonce, then the ciphertext with its tag. */
        const val FORMAT: Byte = 1
        const val NONCE = 12
        const val TAG_BITS = 128
    }
}

/**
 * AES-256-GCM under a key that lives in Android's Keystore and never leaves it: in StrongBox where
 * the phone has one, in the TEE otherwise. It works while the phone is locked, since sharing runs
 * then, and it can't be exported, backed up or moved to another phone (plan §8). The cipher is
 * the Keystore's own; the app holds no key material.
 */
class KeystoreSealer(private val alias: String = "kinfold-storage") : Sealer {
    @Volatile
    private var key: SecretKey? = null

    override fun seal(plain: ByteArray, aad: ByteArray): ByteArray {
        val c = Cipher.getInstance(TRANSFORMATION)
        c.init(Cipher.ENCRYPT_MODE, key())
        c.updateAAD(aad)
        val ct = c.doFinal(plain)
        val iv = c.iv
        check(iv.size == Sealer.NONCE) { "the Keystore chose a nonce of ${iv.size} bytes" }
        return byteArrayOf(Sealer.FORMAT) + iv + ct
    }

    override fun open(sealed: ByteArray, aad: ByteArray): ByteArray {
        if (sealed.size < 1 + Sealer.NONCE + Sealer.TAG_BITS / 8 || sealed[0] != Sealer.FORMAT) throw IOException("not a sealed file")
        val c = Cipher.getInstance(TRANSFORMATION)
        c.init(Cipher.DECRYPT_MODE, key(), GCMParameterSpec(Sealer.TAG_BITS, sealed, 1, Sealer.NONCE))
        c.updateAAD(aad)
        return try {
            c.doFinal(sealed, 1 + Sealer.NONCE, sealed.size - 1 - Sealer.NONCE)
        } catch (e: Exception) {
            throw IOException("a sealed file doesn't open", e)
        }
    }

    @Synchronized
    private fun key(): SecretKey {
        key?.let { return it }
        val ks = KeyStore.getInstance(KEYSTORE).apply { load(null) }
        val k = (ks.getKey(alias, null) as? SecretKey) ?: try {
            generate(strongBox = true)
        } catch (_: StrongBoxUnavailableException) {
            generate(strongBox = false)
        }
        key = k
        return k
    }

    private fun generate(strongBox: Boolean): SecretKey {
        val spec = KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setKeySize(256)
            .setRandomizedEncryptionRequired(true)
            .setIsStrongBoxBacked(strongBox)
            .build()
        return KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, KEYSTORE).apply { init(spec) }.generateKey()
    }

    private companion object {
        const val KEYSTORE = "AndroidKeyStore"
        const val TRANSFORMATION = "AES/GCM/NoPadding"
    }
}
