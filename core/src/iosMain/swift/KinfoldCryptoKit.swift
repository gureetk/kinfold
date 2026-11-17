// SPDX-License-Identifier: GPL-3.0-or-later WITH LicenseRef-Kinfold-AppStore-Exception
//
// The core's cryptography on iOS: Apple's CryptoKit, behind an Objective-C interface. CryptoKit
// can only be called from Swift, and Kotlin/Native imports Objective-C, so this file is all the
// Swift the core has. The build compiles it into a static library for each iOS target and imports
// the header Swift writes for it (build.gradle.kts, src/iosMain/cinterop/cryptokit.def).
//
// Every function is a plain function of bytes. Where CryptoKit throws, it returns nil, or false
// for a verdict; CryptoKitCrypto.kt turns that into what the protocol says happens. The checks
// that the protocol puts in front of the platform (PROTOCOL.md §3.3, §3.5) are made in the
// common Kotlin code, not here.

import CryptoKit
import Foundation
import Security

@objc(KFCryptoKit)
public final class KFCryptoKit: NSObject {
    /// Cipher suite 0x0001's HPKE (PROTOCOL.md §3.1).
    private static var suite: HPKE.Ciphersuite {
        HPKE.Ciphersuite(kem: .Curve25519_HKDF_SHA256, kdf: .HKDF_SHA256, aead: .AES_GCM_256)
    }

    @objc public static func sha256(_ data: Data) -> Data {
        Data(SHA256.hash(data: data))
    }

    @objc public static func sha512(_ data: Data) -> Data {
        Data(SHA512.hash(data: data))
    }

    /// HKDF-SHA-256: Extract with the salt, then Expand with the info to the length asked for.
    @objc public static func hkdf(_ ikm: Data, salt: Data, info: Data, length: Int) -> Data {
        HKDF<SHA256>.deriveKey(inputKeyMaterial: SymmetricKey(data: ikm), salt: salt, info: info, outputByteCount: length)
            .withUnsafeBytes { Data($0) }
    }

    /// AES-GCM: the ciphertext, then the 16-byte tag.
    @objc public static func aesGcmSeal(_ key: Data, nonce: Data, plaintext: Data, aad: Data) -> Data? {
        guard let n = try? AES.GCM.Nonce(data: nonce),
              let box = try? AES.GCM.seal(plaintext, using: SymmetricKey(data: key), nonce: n, authenticating: aad)
        else { return nil }
        return box.ciphertext + box.tag
    }

    /// The plaintext, or nil when the tag doesn't verify.
    @objc public static func aesGcmOpen(_ key: Data, nonce: Data, ciphertext: Data, aad: Data) -> Data? {
        guard ciphertext.count >= 16,
              let n = try? AES.GCM.Nonce(data: nonce),
              let box = try? AES.GCM.SealedBox(nonce: n, ciphertext: ciphertext.dropLast(16), tag: ciphertext.suffix(16))
        else { return nil }
        return try? AES.GCM.open(box, using: SymmetricKey(data: key), authenticating: aad)
    }

    @objc public static func ed25519PublicKey(_ seed: Data) -> Data? {
        (try? Curve25519.Signing.PrivateKey(rawRepresentation: seed))?.publicKey.rawRepresentation
    }

    /// CryptoKit adds randomness to every signature, so signing the same message twice gives two
    /// different signatures, both valid (PROTOCOL.md §3.3).
    @objc public static func ed25519Sign(_ seed: Data, message: Data) -> Data? {
        guard let key = try? Curve25519.Signing.PrivateKey(rawRepresentation: seed) else { return nil }
        return try? key.signature(for: message)
    }

    /// CryptoKit's own verdict, without the byte checks of §3.3.
    @objc public static func ed25519Verify(_ publicKey: Data, message: Data, signature: Data) -> Bool {
        guard let key = try? Curve25519.Signing.PublicKey(rawRepresentation: publicKey) else { return false }
        return key.isValidSignature(signature, for: message)
    }

    @objc public static func x25519PublicKey(_ privateKey: Data) -> Data? {
        (try? Curve25519.KeyAgreement.PrivateKey(rawRepresentation: privateKey))?.publicKey.rawRepresentation
    }

    /// One HPKE base-mode seal with empty aad (§3.5), under a fresh ephemeral key: enc ‖ ciphertext.
    @objc public static func hpkeSeal(_ publicKey: Data, info: Data, plaintext: Data) -> Data? {
        guard let key = try? Curve25519.KeyAgreement.PublicKey(rawRepresentation: publicKey),
              var sender = try? HPKE.Sender(recipientKey: key, ciphersuite: suite, info: info)
        else { return nil }
        guard let ciphertext = try? sender.seal(plaintext, authenticating: Data()) else { return nil }
        return sender.encapsulatedKey + ciphertext
    }

    /// The plaintext of a single-shot base-mode seal with empty aad, or nil if it doesn't open.
    @objc public static func hpkeOpen(_ privateKey: Data, enc: Data, info: Data, ciphertext: Data) -> Data? {
        guard let key = try? Curve25519.KeyAgreement.PrivateKey(rawRepresentation: privateKey),
              var recipient = try? HPKE.Recipient(privateKey: key, ciphersuite: suite, info: info, encapsulatedKey: enc)
        else { return nil }
        return try? recipient.open(ciphertext, authenticating: Data())
    }

    /// Bytes from the system's cryptographically secure generator (§3.6), or nil if it fails.
    @objc public static func randomBytes(_ count: Int) -> Data? {
        guard count > 0 else { return Data() }
        var bytes = Data(count: count)
        let status = bytes.withUnsafeMutableBytes { SecRandomCopyBytes(kSecRandomDefault, count, $0.baseAddress!) }
        return status == errSecSuccess ? bytes : nil
    }
}
