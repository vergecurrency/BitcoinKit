import Foundation

struct RIPEMD160 {
    private static let messageLeft = [
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
        7, 4, 13, 1, 10, 6, 15, 3, 12, 0, 9, 5, 2, 14, 11, 8,
        3, 10, 14, 4, 9, 15, 8, 1, 2, 7, 0, 6, 13, 11, 5, 12,
        1, 9, 11, 10, 0, 8, 12, 4, 13, 3, 7, 15, 14, 5, 6, 2,
        4, 0, 5, 9, 7, 12, 2, 10, 14, 1, 3, 8, 11, 6, 15, 13
    ]

    private static let messageRight = [
        5, 14, 7, 0, 9, 2, 11, 4, 13, 6, 15, 8, 1, 10, 3, 12,
        6, 11, 3, 7, 0, 13, 5, 10, 14, 15, 8, 12, 4, 9, 1, 2,
        15, 5, 1, 3, 7, 14, 6, 9, 11, 8, 12, 2, 10, 0, 4, 13,
        8, 6, 4, 1, 3, 11, 15, 0, 5, 12, 2, 13, 9, 7, 10, 14,
        12, 15, 10, 4, 1, 5, 8, 7, 6, 2, 13, 14, 0, 3, 9, 11
    ]

    private static let rotateLeft = [
        11, 14, 15, 12, 5, 8, 7, 9, 11, 13, 14, 15, 6, 7, 9, 8,
        7, 6, 8, 13, 11, 9, 7, 15, 7, 12, 15, 9, 11, 7, 13, 12,
        11, 13, 6, 7, 14, 9, 13, 15, 14, 8, 13, 6, 5, 12, 7, 5,
        11, 12, 14, 15, 14, 15, 9, 8, 9, 14, 5, 6, 8, 6, 5, 12,
        9, 15, 5, 11, 6, 8, 13, 12, 5, 12, 13, 14, 11, 8, 5, 6
    ]

    private static let rotateRight = [
        8, 9, 9, 11, 13, 15, 15, 5, 7, 7, 8, 11, 14, 14, 12, 6,
        9, 13, 15, 7, 12, 8, 9, 11, 7, 7, 12, 7, 6, 15, 13, 11,
        9, 7, 15, 11, 8, 6, 6, 14, 12, 13, 5, 14, 13, 13, 7, 5,
        15, 5, 8, 11, 14, 14, 6, 14, 6, 9, 12, 9, 12, 5, 15, 8,
        8, 5, 12, 9, 12, 5, 14, 6, 8, 13, 6, 5, 15, 13, 11, 11
    ]

    func calculate(for bytes: [UInt8]) -> [UInt8] {
        let padded = pad(bytes)
        var h0: UInt32 = 0x67452301
        var h1: UInt32 = 0xefcdab89
        var h2: UInt32 = 0x98badcfe
        var h3: UInt32 = 0x10325476
        var h4: UInt32 = 0xc3d2e1f0

        for offset in stride(from: 0, to: padded.count, by: 64) {
            let block = Array(padded[offset..<offset + 64])
            let words = block.toLittleEndianWords()

            var al = h0, bl = h1, cl = h2, dl = h3, el = h4
            var ar = h0, br = h1, cr = h2, dr = h3, er = h4

            for j in 0..<80 {
                let tl = rotateLeft(
                    al &+ f(j, bl, cl, dl) &+ words[Self.messageLeft[j]] &+ constantLeft(j),
                    by: Self.rotateLeft[j]
                ) &+ el
                al = el
                el = dl
                dl = rotateLeft(cl, by: 10)
                cl = bl
                bl = tl

                let tr = rotateLeft(
                    ar &+ f(79 - j, br, cr, dr) &+ words[Self.messageRight[j]] &+ constantRight(j),
                    by: Self.rotateRight[j]
                ) &+ er
                ar = er
                er = dr
                dr = rotateLeft(cr, by: 10)
                cr = br
                br = tr
            }

            let t = h1 &+ cl &+ dr
            h1 = h2 &+ dl &+ er
            h2 = h3 &+ el &+ ar
            h3 = h4 &+ al &+ br
            h4 = h0 &+ bl &+ cr
            h0 = t
        }

        return h0.littleEndianBytes + h1.littleEndianBytes + h2.littleEndianBytes + h3.littleEndianBytes + h4.littleEndianBytes
    }

    private func f(_ j: Int, _ x: UInt32, _ y: UInt32, _ z: UInt32) -> UInt32 {
        if j < 16 { return x ^ y ^ z }
        if j < 32 { return (x & y) | (~x & z) }
        if j < 48 { return (x | ~y) ^ z }
        if j < 64 { return (x & z) | (y & ~z) }
        return x ^ (y | ~z)
    }

    private func constantLeft(_ j: Int) -> UInt32 {
        switch j {
        case 0..<16: return 0x00000000
        case 16..<32: return 0x5a827999
        case 32..<48: return 0x6ed9eba1
        case 48..<64: return 0x8f1bbcdc
        default: return 0xa953fd4e
        }
    }

    private func constantRight(_ j: Int) -> UInt32 {
        switch j {
        case 0..<16: return 0x50a28be6
        case 16..<32: return 0x5c4dd124
        case 32..<48: return 0x6d703ef3
        case 48..<64: return 0x7a6d76e9
        default: return 0x00000000
        }
    }

    private func rotateLeft(_ value: UInt32, by amount: Int) -> UInt32 {
        return (value << UInt32(amount)) | (value >> UInt32(32 - amount))
    }

    private func pad(_ bytes: [UInt8]) -> [UInt8] {
        var padded = bytes
        let bitLength = UInt64(bytes.count * 8)
        padded.append(0x80)
        while padded.count % 64 != 56 {
            padded.append(0)
        }
        padded += bitLength.littleEndianBytes
        return padded
    }
}

private extension Array where Element == UInt8 {
    func toLittleEndianWords() -> [UInt32] {
        var words = [UInt32]()
        for i in stride(from: 0, to: count, by: 4) {
            words.append(
                UInt32(self[i]) |
                UInt32(self[i + 1]) << 8 |
                UInt32(self[i + 2]) << 16 |
                UInt32(self[i + 3]) << 24
            )
        }
        return words
    }
}

private extension UInt32 {
    var littleEndianBytes: [UInt8] {
        return [
            UInt8(self & 0xff),
            UInt8((self >> 8) & 0xff),
            UInt8((self >> 16) & 0xff),
            UInt8((self >> 24) & 0xff)
        ]
    }
}

private extension UInt64 {
    var littleEndianBytes: [UInt8] {
        return [
            UInt8(self & 0xff),
            UInt8((self >> 8) & 0xff),
            UInt8((self >> 16) & 0xff),
            UInt8((self >> 24) & 0xff),
            UInt8((self >> 32) & 0xff),
            UInt8((self >> 40) & 0xff),
            UInt8((self >> 48) & 0xff),
            UInt8((self >> 56) & 0xff)
        ]
    }
}
