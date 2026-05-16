//
//  Crypto.swift
//
//  Copyright © 2018 Kishikawa Katsumi
//  Copyright © 2018 BitcoinKit developers
//
//  Permission is hereby granted, free of charge, to any person obtaining a copy
//  of this software and associated documentation files (the "Software"), to deal
//  in the Software without restriction, including without limitation the rights
//  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
//  copies of the Software, and to permit persons to whom the Software is
//  furnished to do so, subject to the following conditions:
//
//  The above copyright notice and this permission notice shall be included in
//  all copies or substantial portions of the Software.
//
//  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
//  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
//  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
//  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
//  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
//  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
//  THE SOFTWARE.
//

import Foundation
#if BitcoinKitXcode
import BitcoinKit.Private
#else
import BitcoinKitPrivate
#endif
import Foundation
import secp256k1

enum _Crypto {
    static func signMessage(_ message: Data, withPrivateKey privateKey: Data) throws -> Data {
        // Create context
        guard let context = secp256k1_context_create(UInt32(SECP256K1_CONTEXT_SIGN)) else {
            throw CryptoError.signFailed
        }
        defer { secp256k1_context_destroy(context) }

        // Hash message before signing
        let hash = Crypto.sha256(message)

        var signature = secp256k1_ecdsa_signature()
        let signResult = hash.withUnsafeBytes { hashPtr in
            privateKey.withUnsafeBytes { privKeyPtr in
                secp256k1_ecdsa_sign(context, &signature, hashPtr.bindMemory(to: UInt8.self).baseAddress!, privKeyPtr.bindMemory(to: UInt8.self).baseAddress!, nil, nil)
            }
        }

        guard signResult == 1 else {
            throw CryptoError.signFailed
        }

        // Serialize compact
        var compactSig = Data(repeating: 0, count: 64)
        var outputLen: size_t = 64
        compactSig.withUnsafeMutableBytes { compactPtr in
            secp256k1_ecdsa_signature_serialize_compact(context, compactPtr.bindMemory(to: UInt8.self).baseAddress!, &signature)
        }
        return compactSig
    }

    static func verifySignature(_ signature: Data, message: Data, publicKey: Data) throws -> Bool {
        guard let context = secp256k1_context_create(UInt32(SECP256K1_CONTEXT_VERIFY)) else {
            throw CryptoError.signatureParseFailed
        }
        defer { secp256k1_context_destroy(context) }

        let hash = Crypto.sha256(message)
        var sig = secp256k1_ecdsa_signature()
        var pubkey = secp256k1_pubkey()

        let parseSig = signature.withUnsafeBytes {
            secp256k1_ecdsa_signature_parse_compact(context, &sig, $0.bindMemory(to: UInt8.self).baseAddress!)
        }
        guard parseSig == 1 else { throw CryptoError.signatureParseFailed }

        let parsePub = publicKey.withUnsafeBytes {
            secp256k1_ec_pubkey_parse(context, &pubkey, $0.bindMemory(to: UInt8.self).baseAddress!, publicKey.count)
        }
        guard parsePub == 1 else { throw CryptoError.publicKeyParseFailed }

        let verifyResult = hash.withUnsafeBytes {
            secp256k1_ecdsa_verify(context, &sig, $0.bindMemory(to: UInt8.self).baseAddress!, &pubkey)
        }

        return verifyResult == 1
    }
}

public struct Crypto {
    public static func sha1(_ data: Data) -> Data {
        return _Hash.sha1(data)
    }

    public static func sha256(_ data: Data) -> Data {
        return _Hash.sha256(data)
    }

    public static func sha256sha256(_ data: Data) -> Data {
        return sha256(sha256(data))
    }

    public static func ripemd160(_ data: Data) -> Data {
        return _Hash.ripemd160(data)
    }

    public static func sha256ripemd160(_ data: Data) -> Data {
        return ripemd160(sha256(data))
    }

    public static func hmacsha512(data: Data, key: Data) -> Data {
        return _Hash.hmacsha512(data, key: key)
    }

    public static func sign(_ data: Data, privateKey: PrivateKey) throws -> Data {
        #if BitcoinKitXcode
        return _Crypto.signMessage(data, withPrivateKey: privateKey.data)
        #else
        return try _Crypto.signMessage(data, withPrivateKey: privateKey.data)
        #endif
    }

    public static func verifySignature(_ signature: Data, message: Data, publicKey: Data) throws -> Bool {
        #if BitcoinKitXcode
        return _Crypto.verifySignature(signature, message: message, publicKey: publicKey)
        #else
        return try _Crypto.verifySignature(signature, message: message, publicKey: publicKey)
        #endif
    }

    public static func verifySigData(for tx: Transaction, inputIndex: Int, utxo: TransactionOutput, sigData: Data, pubKeyData: Data) throws -> Bool {
        // Hash type is one byte tacked on to the end of the signature. So the signature shouldn't be empty.
        guard !sigData.isEmpty else {
            throw ScriptMachineError.error("SigData is empty.")
        }
        // Extract hash type from the last byte of the signature.
        let helper: SignatureHashHelper
        if let hashType = BCHSighashType(rawValue: sigData.last!) {
            helper = BCHSignatureHashHelper(hashType: hashType)
        } else if let hashType = BTCSighashType(rawValue: sigData.last!) {
            helper = BTCSignatureHashHelper(hashType: hashType)
        } else {
            throw ScriptMachineError.error("Unknown sig hash type")
        }
        // Strip that last byte to have a pure signature.
        let sighash: Data = helper.createSignatureHash(of: tx, for: utxo, inputIndex: inputIndex)
        let signature: Data = sigData.dropLast()

        return try Crypto.verifySignature(signature, message: sighash, publicKey: pubKeyData)
    }
}

public enum CryptoError: Error {
    case signFailed
    case noEnoughSpace
    case signatureParseFailed
    case publicKeyParseFailed
}
