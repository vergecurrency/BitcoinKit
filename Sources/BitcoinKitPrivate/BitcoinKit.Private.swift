import Foundation
import CryptoKit
import secp256k1
import CommonCrypto
import CryptoSwift
import Foundation

// MARK: - Constants
private let SHA1_DIGEST_LENGTH = 20
private let SHA256_DIGEST_LENGTH = 32
private let SHA512_DIGEST_LENGTH = 64

// MARK: - Hash Functions
public class _Hash {
    public static func sha1(_ data: Data) -> Data {
        var hash = [UInt8](repeating: 0, count: SHA1_DIGEST_LENGTH)
        data.withUnsafeBytes { bytes in
            _ = CC_SHA1(bytes.baseAddress, CC_LONG(data.count), &hash)
        }
        return Data(hash)
    }

    public static func sha256(_ data: Data) -> Data {
        var hash = [UInt8](repeating: 0, count: SHA256_DIGEST_LENGTH)
        data.withUnsafeBytes { bytes in
            _ = CC_SHA256(bytes.baseAddress, CC_LONG(data.count), &hash)
        }
        return Data(hash)
    }

    public static func ripemd160(_ data: Data) -> Data {
    let bytes = [UInt8](data)               // convert Data to [UInt8]
    let hash = RIPEMD160().calculate(for: bytes)  // CryptoSwift RIPEMD160
    return Data(hash)                       // convert back to Data
}


    public static func sha256ripemd160(_ data: Data) -> Data {
        return ripemd160(sha256(data))
    }

    public static func hmacsha512(_ data: Data, key: Data) -> Data {
        var hash = [UInt8](repeating: 0, count: SHA512_DIGEST_LENGTH)
        data.withUnsafeBytes { dbytes in
            key.withUnsafeBytes { kbytes in
                _ = CCHmac(
                    CCHmacAlgorithm(kCCHmacAlgSHA512),
                    kbytes.baseAddress, kbytes.count,
                    dbytes.baseAddress, dbytes.count,
                    &hash
                )
            }
        }
        return Data(hash)
    }
}

// MARK: - Public Key Derivation
public class _SwiftKey {
    public static func computePublicKey(fromPrivateKey privateKey: Data, compression: Bool) -> Data? {
        guard privateKey.count == 32 else { return nil }
        guard let context = secp256k1_context_create(UInt32(SECP256K1_CONTEXT_SIGN)) else { return nil }
        defer { secp256k1_context_destroy(context) }

        var pubkey = secp256k1_pubkey()
        let success = privateKey.withUnsafeBytes { ptr -> Int32 in
            guard let base = ptr.baseAddress?.assumingMemoryBound(to: UInt8.self) else { return 0 }
            return secp256k1_ec_pubkey_create(context, &pubkey, base)
        }
        guard success == 1 else { return nil }

        let flags = compression ? UInt32(SECP256K1_EC_COMPRESSED) : UInt32(SECP256K1_EC_UNCOMPRESSED)
        var pointData = Data(count: compression ? 33 : 65)
        var outputLength = pointData.count
        let serializeSuccess = pointData.withUnsafeMutableBytes { mutableBytes -> Int32 in
            guard let base = mutableBytes.baseAddress?.assumingMemoryBound(to: UInt8.self) else { return 0 }
            return secp256k1_ec_pubkey_serialize(context, base, &outputLength, &pubkey, flags)
        }
        guard serializeSuccess == 1 else { return nil }
        pointData.count = outputLength
        return pointData
    }
}

// MARK: - HD Key (BIP32)
public class _HDKey {
    public let privateKey: Data?
    public let publicKey: Data
    public let chainCode: Data
    public let depth: UInt8
    public let fingerprint: UInt32
    public let childIndex: UInt32

    public init(privateKey: Data?, publicKey: Data, chainCode: Data, depth: UInt8, fingerprint: UInt32, childIndex: UInt32) {
        self.privateKey = privateKey
        self.publicKey = publicKey
        self.chainCode = chainCode
        self.depth = depth
        self.fingerprint = fingerprint
        self.childIndex = childIndex
    }

    public func derived(at index: UInt32, hardened: Bool) -> _HDKey? {
        let hardenedIndex = hardened ? (0x80000000 | index) : index
        guard index < 0x80000000 else { return nil }

        guard let context = secp256k1_context_create(UInt32(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY)) else { return nil }
        defer { secp256k1_context_destroy(context) }

        var data = Data()
        if hardened {
            guard let privateKey = privateKey else { return nil }
            data.append(0)
            data.append(privateKey)
        } else {
            data.append(publicKey)
        }

        var childIndexBE = hardenedIndex.bigEndian
        data.append(Data(bytes: &childIndexBE, count: MemoryLayout<UInt32>.size))

        let digest = _Hash.hmacsha512(data, key: self.chainCode)
        let secretTweak = digest[0..<32]
        let chainCodeTweak = digest[32..<64]

        var resultPrivateKey: Data?
        var resultPublicKey: Data = Data(count: 33)

        if let privateKey = self.privateKey {
            // Private key derivation
            var newSecret = Data(count: 32)
            var carry: UInt64 = 0
            for i in (0..<32).reversed() {
                let sum = UInt64(privateKey[i]) + UInt64(secretTweak[i]) + carry
                newSecret[i] = UInt8(sum & 0xFF)
                carry = sum >> 8
            }
            if carry != 0 || _HDKey.isPrivateKeyInvalid(newSecret) {
                return nil
            }
            resultPrivateKey = newSecret
            guard let pub = _SwiftKey.computePublicKey(fromPrivateKey: newSecret, compression: true) else { return nil }
            resultPublicKey = pub
        } else {
            // Public key derivation (non-hardened only)
            guard !hardened else { return nil }
            var pubkey = secp256k1_pubkey()
            let parseResult = publicKey.withUnsafeBytes { ptr -> Int32 in
                guard let base = ptr.baseAddress?.assumingMemoryBound(to: UInt8.self) else { return 0 }
                return secp256k1_ec_pubkey_parse(context, &pubkey, base, publicKey.count)
            }
            guard parseResult == 1 else { return nil }

            let tweakResult = secretTweak.withUnsafeBytes { ptr -> Int32 in
                guard let base = ptr.baseAddress?.assumingMemoryBound(to: UInt8.self) else { return 0 }
                return secp256k1_ec_pubkey_tweak_add(context, &pubkey, base)
            }
            guard tweakResult == 1 else { return nil }

            var outputLen = resultPublicKey.count
            let serializeResult = resultPublicKey.withUnsafeMutableBytes { buffer -> Int32 in
                guard let base = buffer.baseAddress?.assumingMemoryBound(to: UInt8.self) else { return 0 }
                return secp256k1_ec_pubkey_serialize(context, base, &outputLen, &pubkey, UInt32(SECP256K1_EC_COMPRESSED))
            }
            guard serializeResult == 1 else { return nil }
            resultPublicKey.count = outputLen
        }

        let fingerprintData = _Hash.sha256ripemd160(self.publicKey)
        let fingerprint = fingerprintData.withUnsafeBytes { ptr -> UInt32 in
            guard let base = ptr.baseAddress else { return 0 }
            return base.load(as: UInt32.self)
        }

        return _HDKey(
            privateKey: resultPrivateKey,
            publicKey: resultPublicKey,
            chainCode: chainCodeTweak,
            depth: self.depth + 1,
            fingerprint: fingerprint,
            childIndex: hardenedIndex
        )
    }

    private static func isPrivateKeyInvalid(_ key: Data) -> Bool {
        let order: [UInt8] = [
            0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
            0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFE,
            0xBA,0xAE,0xDC,0xE6,0xAF,0x48,0xA0,0x3B,
            0xBF,0xD2,0x5E,0x8C,0xD0,0x36,0x41,0x41
        ]
        for i in 0..<32 {
            if key[i] > order[i] { return true }
            if key[i] < order[i] { break }
        }
        return false
    }
}

// MARK: - Elliptic Curve Operations
public class _EllipticCurve {
    public static func multiplyECPointX(_ ecPointX: Data, andECPointY ecPointY: Data, withScalar scalar: Data) -> Data? {
        guard ecPointX.count == 32, ecPointY.count == 32 else { return nil }
        guard let context = secp256k1_context_create(UInt32(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY)) else { return nil }
        defer { secp256k1_context_destroy(context) }

        var compressed = Data([0x02]) + ecPointX
        if ecPointY.last! % 2 == 1 { compressed[0] = 0x03 }

        var pubkey = secp256k1_pubkey()
        let parseResult = compressed.withUnsafeBytes { ptr -> Int32 in
            guard let base = ptr.baseAddress?.assumingMemoryBound(to: UInt8.self) else { return 0 }
            return secp256k1_ec_pubkey_parse(context, &pubkey, base, compressed.count)
        }
        guard parseResult == 1 else { return nil }

        let tweakResult = scalar.withUnsafeBytes { ptr -> Int32 in
            guard let base = ptr.baseAddress?.assumingMemoryBound(to: UInt8.self) else { return 0 }
            return secp256k1_ec_pubkey_tweak_mul(context, &pubkey, base)
        }
        guard tweakResult == 1 else { return nil }

        var output = Data(count: 65)
        var outputLen = 65
        let serializeResult = output.withUnsafeMutableBytes { buffer -> Int32 in
            guard let base = buffer.baseAddress?.assumingMemoryBound(to: UInt8.self) else { return 0 }
            return secp256k1_ec_pubkey_serialize(context, base, &outputLen, &pubkey, UInt32(SECP256K1_EC_UNCOMPRESSED))
        }
        guard serializeResult == 1 else { return nil }
        output.count = outputLen
        return output
    }

    public static func decodePointOnCurve(forCompressedPublicKey publicKeyCompressed: Data) -> Data? {
        guard let context = secp256k1_context_create(UInt32(SECP256K1_CONTEXT_VERIFY)) else { return nil }
        defer { secp256k1_context_destroy(context) }

        var pubkey = secp256k1_pubkey()
        let parseResult = publicKeyCompressed.withUnsafeBytes { ptr -> Int32 in
            guard let base = ptr.baseAddress?.assumingMemoryBound(to: UInt8.self) else { return 0 }
            return secp256k1_ec_pubkey_parse(context, &pubkey, base, publicKeyCompressed.count)
        }
        guard parseResult == 1 else { return nil }

        var output = Data(count: 65)
        var outputLen = 65
        let serializeResult = output.withUnsafeMutableBytes { buffer -> Int32 in
            guard let base = buffer.baseAddress?.assumingMemoryBound(to: UInt8.self) else { return 0 }
            return secp256k1_ec_pubkey_serialize(context, base, &outputLen, &pubkey, UInt32(SECP256K1_EC_UNCOMPRESSED))
        }
        guard serializeResult == 1 else { return nil }
        output.count = outputLen
        return output
    }
}


/// A standalone, pure Swift implementation of RIPEMD-160.
/// Used in Bitcoin for hash160 = RIPEMD160(SHA256(pubKey))
/// Pure-Swift RIPEMD-160 implementation
/// Pure-Swift RIPEMD-160 implementation
public struct RIPEMD160 {
    public init() {}

    /// Compute RIPEMD-160 hash of input bytes.
    /// - Parameter bytes: Input data as `[UInt8]`
    /// - Returns: 20-byte hash as `[UInt8]`
    public func calculate(for bytes: [UInt8]) -> [UInt8] {
        let padded = padMessage(bytes)
        let blocks = splitIntoBlocks(padded, blockSize: 64)

        var h0: UInt32 = 0x67452301
        var h1: UInt32 = 0xEFCDAB89
        var h2: UInt32 = 0x98BADCFE
        var h3: UInt32 = 0x10325476
        var h4: UInt32 = 0xC3D2E1F0

        for block in blocks {
            let words = to32BitWords(block, littleEndian: true)

            var a = h0, b = h1, c = h2, d = h3, e = h4
            var aa = h0, bb = h1, cc = h2, dd = h3, ee = h4

            // Main rounds: implement both parallel lines (standard RIPEMD-160 algorithm)
            // We'll use indices and per-round constants/rotations from helper functions.

            // Left line
            for j in 0..<80 {
                let (jj, wordIndex, k, s) = leftParams(for: j)
                let temp = rol((a &+ f(jj, b, c, d) &+ words[wordIndex] &+ k), by: UInt32(s)) &+ e
                a = e
                e = d
                d = rol(c, by: 10)
                c = b
                b = temp
            }

            // Right line
            for j in 0..<80 {
                let (jj, wordIndex, k, s) = rightParams(for: j)
                let temp = rol((aa &+ f(jj, bb, cc, dd) &+ words[wordIndex] &+ k), by: UInt32(s)) &+ ee
                aa = ee
                ee = dd
                dd = rol(cc, by: 10)
                cc = bb
                bb = temp
            }

            // Combine results
            let t = h1 &+ c &+ dd
            h1 = h2 &+ d &+ ee
            h2 = h3 &+ e &+ aa
            h3 = h4 &+ a &+ bb
            h4 = h0 &+ b &+ cc
            h0 = t
        }

        return toBytes(h0, h1, h2, h3, h4)
    }
}

// MARK: - Helpers (private)
private extension RIPEMD160 {
    // 32-bit rotate left
    func rol(_ x: UInt32, by s: UInt32) -> UInt32 {
        return (x << s) | (x >> (32 - s))
    }

    // RIPEMD-160 boolean functions
    func f(_ j: Int, _ x: UInt32, _ y: UInt32, _ z: UInt32) -> UInt32 {
        if j < 16      { return x ^ y ^ z }
        else if j < 32 { return (x & y) | (~x & z) }
        else if j < 48 { return (x | ~y) ^ z }
        else if j < 64 { return (x & z) | (y & ~z) }
        else           { return x ^ (y | ~z) }
    }

    // Left-line and right-line parameter tables (index -> (jj, wordIndex, K, s))
    // To keep the implementation compact, compute params from tables below.
    func leftParams(for j: Int) -> (Int, Int, UInt32, Int) {
        // left word order (r) and left shifts (s) and left Ks
        let r: [Int] = [
            0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,
            7,4,13,1,10,6,15,3,12,0,9,5,2,14,11,8,
            3,10,14,4,9,15,8,1,2,7,0,6,13,11,5,12,
            1,9,11,10,0,8,12,4,13,3,7,15,14,5,6,2,
            4,0,5,9,7,12,2,10,14,1,3,8,11,6,15,13
        ]
        let s: [Int] = [
            11,14,15,12,5,8,7,9,11,13,14,15,6,7,9,8,
            7,6,8,13,11,9,7,15,7,12,15,9,11,7,13,12,
            11,13,6,7,14,9,13,15,14,8,13,6,5,12,7,5,
            11,12,14,15,14,15,9,8,9,14,5,6,8,6,5,12,
            9,15,5,11,6,8,13,12,5,12,13,14,11,8,5,6
        ]
        let K: [UInt32] = [
            0x00000000, 0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xA953FD4E
        ]
        let kIndex = j < 16 ? 0 : (j < 32 ? 1 : (j < 48 ? 2 : (j < 64 ? 3 : 4)))
        return (j, r[j], K[kIndex], s[j])
    }

    func rightParams(for j: Int) -> (Int, Int, UInt32, Int) {
        // right word order (r') and right shifts (s') and right Ks
        let rr: [Int] = [
            5,14,7,0,9,2,11,4,13,6,15,8,1,10,3,12,
            6,11,3,7,0,13,5,10,14,15,8,12,4,9,1,2,
            15,5,1,3,7,14,6,9,11,8,12,2,10,0,4,13,
            8,6,4,1,3,11,15,0,5,12,2,13,9,7,10,14,
            12,15,10,4,1,5,8,7,6,2,13,14,0,3,9,11
        ]
        let ss: [Int] = [
            8,9,9,11,13,15,15,5,7,7,8,11,14,14,12,6,
            9,13,15,7,12,8,9,11,7,7,12,7,6,15,13,11,
            9,7,15,11,8,6,6,14,12,13,5,14,13,13,7,5,
            15,5,8,11,14,14,6,14,6,9,12,9,12,5,15,8,
            8,5,12,9,12,5,14,6,8,13,6,5,15,13,11,11
        ]
        let KK: [UInt32] = [
            0x50A28BE6, 0x5C4DD124, 0x6D703EF3, 0x00000000, 0x00000000
        ]
        let kIndex = j < 16 ? 0 : (j < 32 ? 1 : (j < 48 ? 2 : (j < 64 ? 3 : 4)))
        return (j, rr[j], KK[kIndex], ss[j])
    }

    // Convert byte array to 32-bit words (little-endian)
    func to32BitWords(_ bytes: [UInt8], littleEndian: Bool) -> [UInt32] {
        var words = [UInt32](repeating: 0, count: bytes.count / 4)
        for i in 0..<words.count {
            let base = i * 4
            if littleEndian {
                words[i] = UInt32(bytes[base]) |
                           (UInt32(bytes[base + 1]) << 8) |
                           (UInt32(bytes[base + 2]) << 16) |
                           (UInt32(bytes[base + 3]) << 24)
            } else {
                words[i] = (UInt32(bytes[base]) << 24) |
                           (UInt32(bytes[base + 1]) << 16) |
                           (UInt32(bytes[base + 2]) << 8) |
                           UInt32(bytes[base + 3])
            }
        }
        return words
    }

    func splitIntoBlocks(_ data: [UInt8], blockSize: Int) -> [[UInt8]] {
        var blocks: [[UInt8]] = []
        var i = 0
        while i + blockSize <= data.count {
            blocks.append(Array(data[i..<i+blockSize]))
            i += blockSize
        }
        return blocks
    }

    func padMessage(_ message: [UInt8]) -> [UInt8] {
        var padded = message
        let bitLength = UInt64(message.count) * 8

        padded.append(0x80)

        while padded.count % 64 != 56 {
            padded.append(0x00)
        }

        let low = UInt32(bitLength & 0xFFFFFFFF)
        let high = UInt32((bitLength >> 32) & 0xFFFFFFFF)

        padded += toBytes(low, littleEndian: true)
        padded += toBytes(high, littleEndian: true)

        return padded
    }

    // MARK: - Byte Conversion Helpers (Safe & Non-Recursive)
func toBytes(_ value: UInt32, littleEndian: Bool = true) -> [UInt8] {
    if littleEndian {
        return [
            UInt8(value & 0xff),
            UInt8((value >> 8) & 0xff),
            UInt8((value >> 16) & 0xff),
            UInt8((value >> 24) & 0xff)
        ]
    } else {
        return [
            UInt8((value >> 24) & 0xff),
            UInt8((value >> 16) & 0xff),
            UInt8((value >> 8) & 0xff),
            UInt8(value & 0xff)
        ]
    }
}

/// Convert one or more UInt32s into bytes (calls the single version, no recursion)
func toBytes(_ values: UInt32..., littleEndian: Bool = true) -> [UInt8] {
    var out: [UInt8] = []
    for v in values {
        out.append(contentsOf: toBytes(v, littleEndian: littleEndian))
    }
    return out
}

}
