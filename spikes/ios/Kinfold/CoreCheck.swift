// SPDX-License-Identifier: GPL-3.0-or-later WITH LicenseRef-Kinfold-AppStore-Exception
//
// The core inside the app: the Kotlin runtime starts from KinfoldCore.xcframework, and the core
// reaches CryptoKit through its own Swift layer. Two known answers show it: SHA-256 of "abc"
// (FIPS 180-2) and the public key of RFC 8032's first Ed25519 test, with a signature that the
// core verifies.

import KinfoldCore
import SwiftUI

enum CoreCheck {
    // On the main thread, where the core's suspend functions are called from Swift.
    @MainActor static func run() async -> (ok: Bool, text: String) {
        let crypto = CryptoKitCrypto()
        do {
            let digestBytes = try await crypto.sha256(data: bytes(Array("abc".utf8)))
            let digest = hex(digestBytes)
            let sha256 = digest == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"

            let key = try await crypto.ed25519(seed: bytes(unhex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")))
            let publicKey = hex(key.publicKey) == "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
            let message = bytes(Array("kinfold".utf8))
            let signature = try await key.sign(message: message)
            let verified = try await crypto.ed25519Verify(publicKey: key.publicKey, message: message, signature: signature).boolValue

            let ok = sha256 && publicKey && verified
            let lines = [
                "SHA-256 of \"abc\": " + (sha256 ? "as FIPS 180-2 gives it" : "WRONG: \(digest)"),
                "Ed25519 public key of RFC 8032's first test: " + (publicKey ? "as the RFC gives it" : "WRONG"),
                "A signature made and verified through the core: " + (verified ? "verifies" : "DOESN'T VERIFY"),
                ok ? "The core works in this app." : "The core doesn't work in this app.",
            ]
            return (ok, lines.joined(separator: "\n"))
        } catch {
            return (false, "The core failed: \(error)")
        }
    }

    static func bytes(_ array: [UInt8]) -> KotlinByteArray {
        let k = KotlinByteArray(size: Int32(array.count))
        for (i, b) in array.enumerated() {
            k.set(index: Int32(i), value: Int8(bitPattern: b))
        }
        return k
    }

    static func hex(_ k: KotlinByteArray) -> String {
        (0..<k.size).map { String(format: "%02x", UInt8(bitPattern: k.get(index: $0))) }.joined()
    }

    static func unhex(_ s: String) -> [UInt8] {
        let chars = Array(s.utf8)
        return stride(from: 0, to: chars.count, by: 2).map { UInt8(String(decoding: chars[$0..<$0 + 2], as: UTF8.self), radix: 16)! }
    }
}

struct CoreCheckView: View {
    @State private var result: (ok: Bool, text: String)?

    var body: some View {
        ScrollView {
            Text(result?.text ?? "Running…")
                .foregroundStyle(result.map { $0.ok ? Color.green : Color.red } ?? Color.primary)
                .frame(maxWidth: .infinity, alignment: .leading)
                .padding()
        }
        .navigationTitle("The core")
        .navigationBarTitleDisplayMode(.inline)
        .task { result = await CoreCheck.run() }
    }
}
