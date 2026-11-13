// SPDX-License-Identifier: Apache-2.0

// Runs the Ed25519 edge cases of the Kinfold test vectors (`ed25519.signatures`) through
// CryptoKit, with and without the byte checks of PROTOCOL.md §3.3 in front, and says
// whether CryptoKit may sit behind those checks: it may only if, behind them, it returns
// `valid` on every vector.
//
// On a Mac with Xcode or the Command Line Tools, from the repository root:
//
//     swift reference/platforms/cryptokit/ed25519.swift spec/vectors/kinfold-v0.json
//
// It exits with status 0 when CryptoKit may sit behind the byte checks and 1 when it may not.

import CryptoKit
import Foundation

func unhex(_ s: String) -> [UInt8] {
    var out: [UInt8] = []
    var i = s.startIndex
    while i < s.endIndex {
        let j = s.index(i, offsetBy: 2)
        out.append(UInt8(s[i..<j], radix: 16)!)
        i = j
    }
    return out
}

// ---- the byte checks of PROTOCOL.md §3.3 ----

let groupOrder = unhex("edd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010") // L, little-endian
let fieldPrime = unhex("edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f") // p = 2^255 - 19
let smallOrder = [
    "0000000000000000000000000000000000000000000000000000000000000000",
    "0100000000000000000000000000000000000000000000000000000000000000",
    "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
    "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
    "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
].map(unhex)

// a < b, both read as 32-byte little-endian integers.
func lessThan(_ a: [UInt8], _ b: [UInt8]) -> Bool {
    for i in stride(from: 31, through: 0, by: -1) where a[i] != b[i] {
        return a[i] < b[i]
    }
    return false
}

// Checks 2 and 3, on a public key or on R.
func pointRejected(_ encoding: [UInt8]) -> Bool {
    var y = encoding
    y[31] &= 0x7f
    return !lessThan(y, fieldPrime) || smallOrder.contains(y)
}

func byteChecksPass(publicKey: [UInt8], signature: [UInt8]) -> Bool {
    guard publicKey.count == 32, signature.count == 64 else { return false }
    return lessThan(Array(signature[32..<64]), groupOrder) // check 1
        && !pointRejected(publicKey)
        && !pointRejected(Array(signature[0..<32]))
}

// ---- CryptoKit ----

func word(_ accepts: Bool) -> String { accepts ? "accept" : "refuse" }

// A key CryptoKit won't import counts as a refusal.
func cryptoKitAccepts(publicKey: [UInt8], message: [UInt8], signature: [UInt8]) -> Bool {
    guard let key = try? Curve25519.Signing.PublicKey(rawRepresentation: publicKey) else { return false }
    return key.isValidSignature(signature, for: message)
}

func run(path: String) throws -> Bool {
    let data = try Data(contentsOf: URL(fileURLWithPath: path))
    guard let root = try JSONSerialization.jsonObject(with: data) as? [String: Any],
          let ed25519 = root["ed25519"] as? [String: Any],
          let vectors = ed25519["signatures"] as? [[String: Any]]
    else {
        print("\(path) has no ed25519.signatures")
        exit(2)
    }

    print("CryptoKit on macOS \(ProcessInfo.processInfo.operatingSystemVersionString)")
    print("\(vectors.count) Ed25519 edge cases from \(path)")
    print("")
    print("name".padding(toLength: 34, withPad: " ", startingAt: 0) + "valid   alone   behind the checks")
    var wrongBehind: [String] = []
    var toRefuse = 0
    var acceptedAlone = 0
    var validRefusedAlone = 0
    for vector in vectors {
        let name = vector["name"] as! String
        let publicKey = unhex(vector["pub"] as! String)
        let message = unhex(vector["msg"] as! String)
        let signature = unhex(vector["sig"] as! String)
        let valid = vector["valid"] as! Bool

        let alone = cryptoKitAccepts(publicKey: publicKey, message: message, signature: signature)
        let behind = byteChecksPass(publicKey: publicKey, signature: signature) && alone
        if valid {
            if !alone { validRefusedAlone += 1 }
        } else {
            toRefuse += 1
            if alone { acceptedAlone += 1 }
        }
        if behind != valid { wrongBehind.append(name) }
        let column = name.padding(toLength: 34, withPad: " ", startingAt: 0)
        let mark = behind == valid ? "" : "   <- WRONG"
        print("\(column)\(word(valid))  \(word(alone))  \(word(behind))\(mark)")
    }
    print("")
    let refusedValid = validRefusedAlone > 0 ? " and refuses \(validRefusedAlone) valid ones" : ""
    print("On its own CryptoKit accepts \(acceptedAlone) of the \(toRefuse) signatures to refuse\(refusedValid).")
    if wrongBehind.isEmpty {
        print("RESULT: CryptoKit may sit behind the byte checks (\(vectors.count)/\(vectors.count) right).")
        return true
    }
    print("RESULT: CryptoKit may NOT sit behind the byte checks. Wrong on: \(wrongBehind.joined(separator: ", "))")
    return false
}

let arguments = CommandLine.arguments
let path = arguments.count > 1 ? arguments[1] : "spec/vectors/kinfold-v0.json"
do {
    exit(try run(path: path) ? 0 : 1)
} catch {
    print("error: \(error)")
    exit(2)
}
