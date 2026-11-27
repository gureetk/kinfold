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

    override init() {
        key = Self.loadOrCreate()
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

    private static func loadOrCreate() -> SymmetricKey? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: "key",
            kSecReturnData as String: true,
        ]
        var found: CFTypeRef?
        if SecItemCopyMatching(query as CFDictionary, &found) == errSecSuccess, let bytes = found as? Data, bytes.count == 32 {
            return SymmetricKey(data: bytes)
        }
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
        return status == errSecSuccess ? key : nil
    }
}
