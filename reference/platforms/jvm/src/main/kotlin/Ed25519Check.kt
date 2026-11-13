// SPDX-License-Identifier: Apache-2.0

// Runs the Ed25519 edge cases of the Kinfold test vectors (`ed25519.signatures`) through the
// Ed25519 code a JVM or Android app could use, with and without the byte checks of
// PROTOCOL.md §3.3 in front, and says which of them may sit behind those checks.
//
// A library is fit only if, behind the byte checks, it returns `valid` on every vector.
// The JDK's own code, Tink's own code and Conscrypt must be fit. Bouncy Castle must be
// unfit in exactly one way: it multiplies by the cofactor, so it accepts the mixed-order
// signatures that must be refused, and no byte check can catch those. The program exits
// with status 1 when any of that stops being true.
//
// Usage: gradle run --args=path/to/kinfold-v0.json

import com.google.crypto.tink.subtle.Ed25519Verify
import com.google.gson.JsonParser
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters
import org.bouncycastle.crypto.signers.Ed25519Signer
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.conscrypt.Conscrypt
import java.io.File
import java.math.BigInteger
import java.security.GeneralSecurityException
import java.security.KeyFactory
import java.security.Provider
import java.security.Security
import java.security.Signature
import java.security.spec.X509EncodedKeySpec
import kotlin.system.exitProcess

class Vector(
    val name: String,
    val pub: ByteArray,
    val msg: ByteArray,
    val sig: ByteArray,
    val valid: Boolean,
    val cofactored: Boolean,
)

fun unhex(s: String): ByteArray = ByteArray(s.length / 2) { s.substring(2 * it, 2 * it + 2).toInt(16).toByte() }

// ---- the byte checks of PROTOCOL.md §3.3 ----

val L: BigInteger = BigInteger.TWO.pow(252) + BigInteger("27742317777372353535851937790883648493")
val P: BigInteger = BigInteger.TWO.pow(255) - BigInteger.valueOf(19)
val SMALL_ORDER: List<ByteArray> = listOf(
    "0000000000000000000000000000000000000000000000000000000000000000",
    "0100000000000000000000000000000000000000000000000000000000000000",
    "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
    "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
    "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
).map(::unhex)

fun littleEndian(b: ByteArray) = BigInteger(1, b.reversedArray())

// Checks 2 and 3, on a public key or on R.
fun pointRejected(enc: ByteArray): Boolean {
    val y = enc.copyOf()
    y[31] = (y[31].toInt() and 0x7f).toByte()
    return littleEndian(y) >= P || SMALL_ORDER.any { it.contentEquals(y) }
}

fun byteChecksPass(pub: ByteArray, sig: ByteArray): Boolean =
    pub.size == 32 && sig.size == 64 &&
        littleEndian(sig.copyOfRange(32, 64)) < L && // check 1
        !pointRejected(pub) && !pointRejected(sig.copyOfRange(0, 32))

// ---- the implementations ----

class Impl(val name: String, val mustBeFit: Boolean, val verify: (pub: ByteArray, msg: ByteArray, sig: ByteArray) -> Boolean)

// The DER prefix of an Ed25519 SubjectPublicKeyInfo (RFC 8410); the raw 32-byte key follows it.
val SPKI_PREFIX = unhex("302a300506032b6570032100")

// A JCA provider's "Ed25519". Getting the factory and signature objects must work (a missing
// algorithm stops the program); a key the provider won't decode, or an exception while
// verifying, counts as a refusal.
fun jca(provider: Provider): (ByteArray, ByteArray, ByteArray) -> Boolean {
    KeyFactory.getInstance("Ed25519", provider)
    Signature.getInstance("Ed25519", provider)
    return { pub, msg, sig ->
        try {
            val key = KeyFactory.getInstance("Ed25519", provider).generatePublic(X509EncodedKeySpec(SPKI_PREFIX + pub))
            Signature.getInstance("Ed25519", provider).run {
                initVerify(key)
                update(msg)
                verify(sig)
            }
        } catch (e: GeneralSecurityException) {
            false
        } catch (e: IllegalArgumentException) {
            false
        }
    }
}

// Tink's own Java code. (Ed25519Verify.create and keysets hand verification to an installed
// Conscrypt provider when there is one, so on Android they run the platform's code.)
fun tink(pub: ByteArray, msg: ByteArray, sig: ByteArray): Boolean =
    try {
        Ed25519Verify(pub).verify(sig, msg)
        true
    } catch (e: GeneralSecurityException) {
        false
    } catch (e: IllegalArgumentException) {
        false
    }

// Bouncy Castle's lightweight API, which Android apps also reach directly.
fun bouncyCastleLightweight(pub: ByteArray, msg: ByteArray, sig: ByteArray): Boolean =
    try {
        Ed25519Signer().run {
            init(false, Ed25519PublicKeyParameters(pub, 0))
            update(msg, 0, msg.size)
            verifySignature(sig)
        }
    } catch (e: IllegalArgumentException) {
        false
    }

fun main(args: Array<String>) {
    val path = args.firstOrNull() ?: "../../../spec/vectors/kinfold-v0.json"
    val root = JsonParser.parseString(File(path).readText()).asJsonObject
    val vectors = root.getAsJsonObject("ed25519").getAsJsonArray("signatures").map {
        val o = it.asJsonObject
        Vector(
            name = o["name"].asString,
            pub = unhex(o["pub"].asString),
            msg = unhex(o["msg"].asString),
            sig = unhex(o["sig"].asString),
            valid = o["valid"].asBoolean,
            cofactored = o["cofactored"]?.asBoolean ?: false,
        )
    }
    val toRefuse = vectors.count { !it.valid }
    // What a verifier that multiplies by the cofactor gets wrong behind the byte checks.
    val cofactorFlaw = vectors.filter { it.cofactored && !it.valid }.map { it.name }.toSet()

    val bc = BouncyCastleProvider()
    val conscrypt = Conscrypt.newProvider()
    val conscryptVersion = Conscrypt.version().let { "${it.major()}.${it.minor()}.${it.patch()}" }
    val impls = listOf(
        Impl("JDK ${System.getProperty("java.version")} (SunEC)", true, jca(Security.getProvider("SunEC"))),
        Impl("Tink ${com.google.crypto.tink.Version.TINK_VERSION} (its own code)", true, ::tink),
        Impl("Conscrypt $conscryptVersion (BoringSSL)", true, jca(conscrypt)),
        Impl("Bouncy Castle ${bc.versionStr} (JCA provider)", false, jca(bc)),
        Impl("Bouncy Castle ${bc.versionStr} (lightweight API)", false, ::bouncyCastleLightweight),
    )

    println("Ed25519 edge cases: ${vectors.size} signatures, ${vectors.size - toRefuse} valid and $toRefuse to refuse")
    println()
    var ok = true
    for (impl in impls) {
        val behind = vectors.filter { (byteChecksPass(it.pub, it.sig) && impl.verify(it.pub, it.msg, it.sig)) != it.valid }
        val aloneAccepts = vectors.count { !it.valid && impl.verify(it.pub, it.msg, it.sig) }
        val aloneRefusesValid = vectors.count { it.valid && !impl.verify(it.pub, it.msg, it.sig) }
        val fit = behind.isEmpty()
        val verdict = if (fit) "fit" else "NOT fit"
        println("${impl.name}: $verdict behind the byte checks (${vectors.size - behind.size}/${vectors.size} right)")
        for (v in behind) {
            println("    ${if (v.valid) "refuses" else "accepts"} ${v.name}")
        }
        println("    on its own: accepts $aloneAccepts of the $toRefuse to refuse" +
            if (aloneRefusesValid > 0) ", refuses $aloneRefusesValid valid" else "")
        val expected = if (impl.mustBeFit) fit else behind.all { !it.valid } && behind.map { it.name }.toSet() == cofactorFlaw
        if (!expected) {
            ok = false
            println(
                "    UNEXPECTED: " + if (impl.mustBeFit) "this library must return `valid` on every vector"
                else "expected exactly the cofactored signatures to be wrongly accepted: ${cofactorFlaw.sorted().joinToString()}",
            )
        }
    }
    println()
    if (!ok) {
        println("FAILED: see UNEXPECTED above")
        exitProcess(1)
    }
    println("As expected: the JDK, Tink and Conscrypt may sit behind the byte checks; Bouncy Castle may not.")
}
