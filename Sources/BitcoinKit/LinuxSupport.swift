//
//  LinuxSupport.swift
//  BitcoinKit
//
//  Created by Yusuke Ito on 3/25/18.
//
import Foundation

// Linux missing implementaion
#if !os(macOS) && !os(iOS) && !os(tvOS) && !os(watchOS)
let errSecSuccess: Int32 = 0
let kSecRandomDefault = 0

func SecRandomCopyBytes(_ a: Int, _ count: Int, _ ptr: UnsafeMutableRawPointer) -> Int32 {
    var generator = SystemRandomNumberGenerator()
    let bytes = (0..<count).map { _ in UInt8.random(in: .min ... .max, using: &generator) }
    bytes.withUnsafeBytes {
        ptr.copyMemory(from: $0.baseAddress!, byteCount: count)
    }
    return errSecSuccess
}
#endif
