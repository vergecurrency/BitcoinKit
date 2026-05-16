//
//  BitArray.swift
//  BitcoinKit
//
//  Updated for Swift 5.10+ compatibility
//

import Foundation

public struct BitArray: Hashable, RangeReplaceableCollection {

    // MARK: - Properties
    private var bits: [Int]

    // MARK: - Initializers

    /// Empty BitArray
    public init() {
        self.bits = []
    }

    /// From [Int]
    public init(bits: [Int]) {
        self.bits = bits
    }

    /// From Data
    public init(data: Data) {
        self.init(bytes: [UInt8](data))
    }

    /// From bytes array with optional bit count
    public init(bytes: [UInt8], bitCount: Int? = nil) {
        var tempBits: [Int] = []
        for byte in bytes {
            for i in 0..<8 {
                let bit = (byte >> (7 - i)) & 1
                tempBits.append(Int(bit))
            }
        }
        if let bitCount = bitCount, bitCount < tempBits.count {
            tempBits = Array(tempBits.prefix(bitCount))
        }
        self.bits = tempBits
    }

    /// Repeating value
    public init(repeating repeatedValue: Bool, count: Int) {
        self.bits = Array(repeating: repeatedValue ? 1 : 0, count: count)
    }

    // MARK: - Collection Conformance
    public typealias Element = Bool
    public typealias Index = Int

    public var startIndex: Index { bits.startIndex }
    public var endIndex: Index { bits.endIndex }

    public func index(after i: Index) -> Index { bits.index(after: i) }

    public subscript(position: Index) -> Element {
        get { bits[position] == 1 }
        set { bits[position] = newValue ? 1 : 0 }
    }

    // MARK: - RangeReplaceableCollection
    public mutating func replaceSubrange<C>(
        _ subrange: Range<Int>,
        with newElements: C
    ) where C: Collection, C.Element == Bool {
        // Remove old range
        let rangeCount = subrange.count
        for _ in 0..<rangeCount {
            _ = remove(at: subrange.lowerBound)
        }
        // Insert new elements
        var insertionIndex = subrange.lowerBound
        for element in newElements {
            insert(element, at: insertionIndex)
            insertionIndex += 1
        }
    }

    // MARK: - Mutating Methods
    public mutating func append(_ newElement: Bool) {
        bits.append(newElement ? 1 : 0)
    }

    public mutating func insert(_ newElement: Bool, at i: Index) {
        bits.insert(newElement ? 1 : 0, at: i)
    }

    @discardableResult
    public mutating func remove(at i: Index) -> Bool {
        let removed = bits.remove(at: i)
        return removed == 1
    }

    public mutating func removeAll(keepingCapacity keepCapacity: Bool = false) {
        bits.removeAll(keepingCapacity: keepCapacity)
    }

    // MARK: - Utilities
    public var count: Int { bits.count }
    public var isEmpty: Bool { bits.isEmpty }

    public mutating func toggle(at index: Int) {
        bits[index] = bits[index] == 1 ? 0 : 1
    }

    public func toBytes() -> [UInt8] {
        var bytes: [UInt8] = []
        var byte: UInt8 = 0
        for (index, bit) in bits.enumerated() {
            byte |= UInt8(bit) << (7 - (index % 8))
            if index % 8 == 7 {
                bytes.append(byte)
                byte = 0
            }
        }
        if bits.count % 8 != 0 {
            bytes.append(byte)
        }
        return bytes
    }
}
extension BitArray {
    /// Returns a string of "0" and "1" representing all bits in order
    public var binaryString: String {
        return bits.map { $0 == 1 ? "1" : "0" }.joined()
    }
}
extension BitArray {

    /// Return first `count` bits
    public func prefix(maxCount count: Int) -> BitArray {
        return BitArray(bits: Array(bits.prefix(count)))
    }

    /// Return all but last `count` bits
    public func prefix(subtractFromCount count: Int) -> BitArray {
        return BitArray(bits: Array(bits.prefix(bits.count - count)))
    }

    /// Return last `count` bits
    public func suffix(maxCount count: Int) -> BitArray {
        return BitArray(bits: Array(bits.suffix(count)))
    }
}
extension BitArray {
    /// Initialize from array of UInt11
    init(_ elements: [UInt11]) {
        // Convert each UInt11 to 11-bit binary string and concatenate
        let binaryString = elements.map { $0.binaryString }.joined()
        
        // Convert binary string to bits array
        var tempBits: [Int] = []
        for char in binaryString {
            if char == "0" {
                tempBits.append(0)
            } else {
                tempBits.append(1)
            }
        }
        self.bits = tempBits
    }
}
extension BitArray {
    /// Splits BitArray into chunks of given size
    func splitIntoChunks(ofSize size: Int) -> [BitArray] {
        precondition(size > 0, "Chunk size must be greater than zero")

        var chunks: [BitArray] = []
        var start = 0

        while start < bits.count {
            let end = Swift.min(start + size, bits.count)
            let chunkBits = Array(bits[start..<end])
            chunks.append(BitArray(bits: chunkBits))
            start += size
        }

        return chunks
    }
}

extension BitArray {

    /// Convert BitArray to [UInt8]
    public func asBytesArray() -> [UInt8] {
        let numBits = bits.count
        let numBytes = (numBits + 7) / 8
        var bytes = [UInt8](repeating: 0, count: numBytes)

        for (index, bit) in bits.enumerated() where bit == 1 {
            bytes[index / 8] |= UInt8(1 << (7 - index % 8))
        }

        return bytes
    }

    /// Convert BitArray to Data
    public func asData() -> Data {
        return Data(asBytesArray())
    }
}
