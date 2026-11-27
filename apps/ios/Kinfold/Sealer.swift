// SPDX-License-Identifier: GPL-3.0-or-later WITH LicenseRef-Kinfold-AppStore-Exception
//
// What seals the core's secret files: the device's keys, the epoch secrets and the app's records.

import CryptoKit
import Foundation
import KinfoldCore
import Security

/**
 * AES-256-GCM from CryptoKit, under one key kept in this phone's Keychain, bound to each file's
 * name. The key is readable only on this phone, after it was first unlocked since it started (so
 * sharing works while it is locked), and never goes into a backup or onto another phone: a copy
 * of the files is unreadable elsewhere. A sealed file is a format byte (1), then CryptoKit's
 * combined box: the 12-byte nonce, the ciphertext and the 16-byte tag.
 */
final class KeychainSealer: NSObject, IosSealer {
    private static let format: UInt8 = 1
    private let key: SymmetricKey?
    /** The Keychain's answer when the key couldn't be read or made (an OSStatus), or 0. */
    let failure: Int32

    override init() {
        let loaded = Self.loadOrCreate()
        key = loaded.0
        failure = loaded.1
        super.init()
    }

    func seal(data: Data, name: String) -> Data? {
        guard let key, let box = try? AES.GCM.seal(data, using: key, authenticating: Data(name.utf8)), let combined = box.combined else { return nil }
        return Data([Self.format]) + combined
    }

    func open(data: Data, name: String) -> Data? {
        guard let key, data.first == Self.format, let box = try? AES.GCM.SealedBox(combined: data.dropFirst()) else { return nil }
        return try? AES.GCM.open(box, using: key, authenticating: Data(name.utf8))
    }

    private static let service = "ca.gureet.kinfold.storage"

    private static func loadOrCreate() -> (SymmetricKey?, Int32) {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: "key",
            kSecReturnData as String: true,
        ]
        var found: CFTypeRef?
        let read = SecItemCopyMatching(query as CFDictionary, &found)
        if read == errSecSuccess, let bytes = found as? Data, bytes.count == 32 {
            return (SymmetricKey(data: bytes), 0)
        }
        if read != errSecItemNotFound { return (nil, read) }
        let key = SymmetricKey(size: .bits256)
        let bytes = key.withUnsafeBytes { Data($0) }
        let add: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: "key",
            kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
            kSecValueData as String: bytes,
        ]
        let status = SecItemAdd(add as CFDictionary, nil)
        return status == errSecSuccess ? (key, 0) : (nil, status)
    }
}
