//
//  BitcoinKit.Private.swift
//  BitcoinKit
//
//  Created by Yusuke Ito on 03/24/18.
//  Copyright © 2018 Yusuke Ito. All rights reserved.
//

import Foundation
import CryptoKit
import secp256k1

public class _Hash {
    public static func sha1(_ data: Data) -> Data {
        return Data(Insecure.SHA1.hash(data: data))
    }
    
    public static func sha256(_ data: Data) -> Data {
        return Data(SHA256.hash(data: data))
    }
    public static func ripemd160(_ data: Data) -> Data {
        return Data(RIPEMD160().calculate(for: [UInt8](data)))
    }
    
    static func sha256ripemd160(_ data: Data) -> Data {
        return ripemd160(sha256(data))
    }
    
    public static func hmacsha512(_ data: Data, key: Data) -> Data {
        return hmacSha512(data, key: key)
    }

    static func hmacSha512(_ data: Data, key: Data) -> Data {
        let key = SymmetricKey(data: key)
        return Data(HMAC<SHA512>.authenticationCode(for: data, using: key))
    }
}

public class _Key {
    public static func computePublicKey(fromPrivateKey privateKey: Data, compression: Bool) -> Data {
        guard let ctx = secp256k1_context_create(UInt32(SECP256K1_CONTEXT_SIGN)) else {
            return Data()
        }
        defer { secp256k1_context_destroy(ctx) }

        var pubkey = secp256k1_pubkey()
        let created = privateKey.withUnsafeBytes {
            secp256k1_ec_pubkey_create(ctx, &pubkey, $0)
        }
        guard created == 1 else {
            return Data()
        }

        let outputLength = compression ? 33 : 65
        var output = Data(count: outputLength)
        var serializedLength = outputLength
        let flags = compression ? UInt32(SECP256K1_EC_COMPRESSED) : UInt32(SECP256K1_EC_UNCOMPRESSED)
        let serialized = output.withUnsafeMutableBytes {
            secp256k1_ec_pubkey_serialize(ctx, $0, &serializedLength, &pubkey, flags)
        }
        guard serialized == 1 else {
            return Data()
        }

        output.count = serializedLength
        return output
    }
    public static func deriveKey(_ password: Data, salt: Data, iterations:Int, keyLength: Int) -> Data {
        let hmacLength = 64
        let blockCount = Int(ceil(Double(keyLength) / Double(hmacLength)))
        var derived = Data()

        for blockIndex in 1...blockCount {
            var blockSalt = salt
            blockSalt.append(UInt8((blockIndex >> 24) & 0xff))
            blockSalt.append(UInt8((blockIndex >> 16) & 0xff))
            blockSalt.append(UInt8((blockIndex >> 8) & 0xff))
            blockSalt.append(UInt8(blockIndex & 0xff))

            var u = _Hash.hmacSha512(blockSalt, key: password)
            var block = [UInt8](u)

            for _ in 1..<iterations {
                u = _Hash.hmacSha512(u, key: password)
                for i in 0..<hmacLength {
                    block[i] ^= u[i]
                }
            }

            derived.append(contentsOf: block)
        }

        return derived.prefix(keyLength)
    }
}

public class _HDKey {
    public let privateKey: Data?
    public let publicKey: Data?
    public let chainCode: Data
    public let depth: UInt8
    public let fingerprint: UInt32
    public let childIndex: UInt32
    
    public init(privateKey: Data?, publicKey: Data?, chainCode: Data, depth: UInt8, fingerprint: UInt32, childIndex: UInt32) {
        self.privateKey = privateKey
        self.publicKey = publicKey
        self.chainCode = chainCode
        self.depth = depth
        self.fingerprint = fingerprint
        self.childIndex = childIndex
    }
    public func derived(at index: UInt32, hardened: Bool) -> _HDKey? {
        var data = Data()
        if hardened {
            data.append(0) // padding
            data += privateKey ?? Data()
        } else {
            data += publicKey ?? Data()
        }
        
        var childIndex = UInt32(hardened ? (0x80000000 | index) : index).bigEndian
        data.append(UnsafeBufferPointer(start: &childIndex, count: 1))
        let digest = _Hash.hmacsha512(data, key: self.chainCode)
        let derivedPrivateKey = digest[0..<32]
        let derivedChainCode = digest[32..<(32+32)]

        guard let ctx = secp256k1_context_create(UInt32(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY)) else {
            return nil
        }
        defer { secp256k1_context_destroy(ctx) }
        
        if let privateKey = self.privateKey {
            var derived = privateKey
            let tweaked = derived.withUnsafeMutableBytes { derivedPtr in
                derivedPrivateKey.withUnsafeBytes { tweakPtr in
                    secp256k1_ec_privkey_tweak_add(ctx, derivedPtr, tweakPtr)
                }
            }
            guard tweaked == 1 else {
                return nil
            }

            let fingerprintData = _Hash.sha256ripemd160(publicKey ?? Data())
            let fingerprintArray = fingerprintData.withUnsafeBytes {
                [UInt32](UnsafeBufferPointer(start: $0, count: fingerprintData.count))
            }
            return _HDKey(privateKey: derived,
                               publicKey: _Key.computePublicKey(fromPrivateKey: derived, compression: true),
                               chainCode: derivedChainCode,
                               depth: depth + 1,
                               fingerprint: fingerprintArray[0],
                               childIndex: childIndex)
        } else if let publicKey = self.publicKey {
            var parsedKey = secp256k1_pubkey()
            let parsed = publicKey.withUnsafeBytes {
                secp256k1_ec_pubkey_parse(ctx, &parsedKey, $0, publicKey.count)
            }
            guard parsed == 1 else {
                return nil
            }

            let tweaked = derivedPrivateKey.withUnsafeBytes {
                secp256k1_ec_pubkey_tweak_add(ctx, &parsedKey, $0)
            }
            guard tweaked == 1 else {
                return nil
            }

            var result = Data(count: 33)
            var resultLength = 33
            let serialized = result.withUnsafeMutableBytes {
                secp256k1_ec_pubkey_serialize(ctx, $0, &resultLength, &parsedKey, UInt32(SECP256K1_EC_COMPRESSED))
            }
            guard serialized == 1 else {
                return nil
            }
            result.count = resultLength

            let fingerprintData = _Hash.sha256ripemd160(publicKey)
            let fingerprintArray = fingerprintData.withUnsafeBytes {
                [UInt32](UnsafeBufferPointer(start: $0, count: fingerprintData.count))
            }
            return _HDKey(privateKey: nil,
                          publicKey: result,
                          chainCode: derivedChainCode,
                          depth: depth + 1,
                          fingerprint: fingerprintArray[0],
                          childIndex: childIndex)
        } else {
            return nil
        }
    }
}

public class _Crypto {
    public static func signMessage(_ data: Data, withPrivateKey privateKey: Data) throws -> Data {
        let ctx = secp256k1_context_create(UInt32(SECP256K1_CONTEXT_SIGN))!
        defer { secp256k1_context_destroy(ctx) }
        
        let signature = UnsafeMutablePointer<secp256k1_ecdsa_signature>.allocate(capacity: 1)
        defer { signature.deallocate() }
        let status = data.withUnsafeBytes { (ptr: UnsafePointer<UInt8>) in
            privateKey.withUnsafeBytes { secp256k1_ecdsa_sign(ctx, signature, ptr, $0, nil, nil) }
        }
        guard status == 1 else { throw CryptoError.signFailed }
        
        let normalizedsig = UnsafeMutablePointer<secp256k1_ecdsa_signature>.allocate(capacity: 1)
        defer { normalizedsig.deallocate() }
        secp256k1_ecdsa_signature_normalize(ctx, normalizedsig, signature)
        
        var length: size_t = 128
        var der = Data(count: length)
        guard der.withUnsafeMutableBytes({ return secp256k1_ecdsa_signature_serialize_der(ctx, $0, &length, normalizedsig) }) == 1 else { throw CryptoError.noEnoughSpace }
        der.count = length
        
        return der
    }
    
    public static func verifySignature(_ signature: Data, message: Data, publicKey: Data) throws -> Bool {
        let ctx = secp256k1_context_create(UInt32(SECP256K1_CONTEXT_VERIFY))!
        defer { secp256k1_context_destroy(ctx) }
        
        let signaturePointer = UnsafeMutablePointer<secp256k1_ecdsa_signature>.allocate(capacity: 1)
        defer { signaturePointer.deallocate() }
        guard signature.withUnsafeBytes({ secp256k1_ecdsa_signature_parse_der(ctx, signaturePointer, $0, signature.count) }) == 1 else {
            throw CryptoError.signatureParseFailed
        }
        
        let pubkeyPointer = UnsafeMutablePointer<secp256k1_pubkey>.allocate(capacity: 1)
        defer { pubkeyPointer.deallocate() }
        guard publicKey.withUnsafeBytes({ secp256k1_ec_pubkey_parse(ctx, pubkeyPointer, $0, publicKey.count) }) == 1 else {
            throw CryptoError.publicKeyParseFailed
        }
        
        guard message.withUnsafeBytes ({ secp256k1_ecdsa_verify(ctx, signaturePointer, $0, pubkeyPointer) }) == 1 else {
            return false
        }
        
        return true
    }
    
    public enum CryptoError: Error {
        case signFailed
        case noEnoughSpace
        case signatureParseFailed
        case publicKeyParseFailed
    }
}
