//
//  Network.swift
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


// MARK: - Network Base Class
open class Network {
    @available(*, deprecated, renamed: "mainnetBCH")
    public static let mainnet: Network = BCHMainnet()
    @available(*, deprecated, renamed: "testnetBCH")
    public static let testnet: Network = BCHTestnet()

    public static let mainnetBCH: Network = BCHMainnet()
    public static let testnetBCH: Network = BCHTestnet()
    public static let mainnetBTC: Network = BTCMainnet()
    public static let testnetBTC: Network = BTCTestnet()

    // XVG networks
    public static let mainnetXVG: Network = XVGMainnet()
    public static let testnetXVG: Network = XVGTestnet()

    /// Network name i.e. livenet/testnet
    open var name: String { fatalError("Network.name must be implemented.") }
    /// Network alias i.e. mainnet/regtest
    open var alias: String { fatalError("Network.alias must be implemented.") }
    /// Address Scheme
    open var scheme: String { fatalError("Network.scheme must be implemented.") }
    /// BIP44 CoinType
    open var coinType: CoinType { fatalError("Network.coinType must be implemented.") }

    /// pubkeyhash version byte
    open var pubkeyhash: UInt8 { fatalError("Network.pubkeyhash must be implemented.") }
    /// privatekey version byte
    open var privatekey: UInt8 { fatalError("Network.privatekey must be implemented.") }
    /// scripthash version byte
    open var scripthash: UInt8 { fatalError("Network.scripthash must be implemented.") }
    /// xpubkey version byte
    open var xpubkey: UInt32 { fatalError("Network.xpubkey must be implemented.") }
    /// xprivkey version byte
    open var xprivkey: UInt32 { fatalError("Network.xprivkey must be implemented.") }

    /// Network magic
    open var magic: UInt32 { fatalError("Network.magic must be implemented.") }
    /// Port number
    open var port: UInt32 { fatalError("Network.port must be implemented.") }
    /// DNS seeds
    open var dnsSeeds: [String] { fatalError("Network.dnsSeeds must be implemented.") }
    /// Checkpoints to IBD
    open var checkpoints: [Checkpoint] { fatalError("Network.checkpoints must be implemented.") }
    /// Genesis Block
    open var genesisBlock: Data { fatalError("Network.genesisBlock must be implemented.") }

    fileprivate init() {}
}

extension Network: Equatable {
    public static func ==(lhs: Network, rhs: Network) -> Bool {
        return lhs.name == rhs.name
            && lhs.pubkeyhash == rhs.pubkeyhash
            && lhs.privatekey == rhs.privatekey
            && lhs.scripthash == rhs.scripthash
            && lhs.xpubkey == rhs.xpubkey
            && lhs.xprivkey == rhs.xprivkey
            && lhs.magic == rhs.magic
            && lhs.port == rhs.port
    }
}

public struct Checkpoint {
    public let height: Int32
    public let hash: Data
    public let timestamp: UInt32
    public let target: UInt32
}

// MARK: - Bitcoin Networks
public class BTCMainnet: Mainnet {
    override public var scheme: String { return "bitcoin" }
    override public var magic: UInt32 { return 0xf9beb4d9 }
    public override var coinType: CoinType { return .btc }
    override public var dnsSeeds: [String] {
        return [
            "seed.bitcoin.sipa.be",
            "dnsseed.bluematt.me",
            "dnsseed.bitcoin.dashjr.org",
            "seed.bitcoinstats.com",
            "seed.bitnodes.io",
            "bitseed.xf2.org",
            "seed.bitcoin.jonasschnelli.ch",
            "bitcoin.bloqseeds.net",
            "seed.ob1.io"
        ]
    }
}

public class BTCTestnet: Testnet {
    override public var scheme: String { return "bitcoin" }
    override public var magic: UInt32 { return 0x0b110907 }
    override public var dnsSeeds: [String] {
        return [
            "testnet-seed.bitcoin.jonasschnelli.ch",
            "testnet-seed.bluematt.me",
            "testnet-seed.bitcoin.petertodd.org",
            "testnet-seed.bitcoin.schildbach.de",
            "bitcoin-testnet.bloqseeds.net"
        ]
    }
}

// MARK: - BCH Networks
public class BCHMainnet: Mainnet {
    override public var scheme: String { return "bitcoincash" }
    override public var magic: UInt32 { return 0xe3e1f3e8 }
    public override var coinType: CoinType { return .bch }
    override public var dnsSeeds: [String] {
        return [
            "seed.bitcoinabc.org",
            "seed-abc.bitcoinforks.org",
            "btccash-seeder.bitcoinunlimited.info",
            "seed.bitprim.org",
            "seed.deadalnix.me",
            "seeder.criptolayer.net"
        ]
    }
}

public class BCHTestnet: Testnet {
    override public var scheme: String { return "bchtest" }
    override public var magic: UInt32 { return 0xf4e5f3f4 }
    override public var dnsSeeds: [String] {
        return [
            "testnet-seed.bitcoinabc.org",
            "testnet-seed-abc.bitcoinforks.org",
            "testnet-seed.bitprim.org",
            "testnet-seed.deadalnix.me",
            "testnet-seeder.criptolayer.net"
        ]
    }
}

// MARK: - XVG Networks
public class XVGMainnet: Mainnet {
    override public var name: String { return "verge-mainnet" }
    override public var alias: String { return "mainnet" }
    override public var scheme: String { return "verge" }
    public override var coinType: CoinType { return .xvg }

    override public var pubkeyhash: UInt8 { return 0x1e }
    override public var privatekey: UInt8 { return 0x9e }
    override public var scripthash: UInt8 { return 0x21 }
    override public var xpubkey: UInt32 { return 0x0488b21e }
    override public var xprivkey: UInt32 { return 0x0488ade4 }

    override public var magic: UInt32 { return 0xfabfb5da }
    override public var port: UInt32 { return 5253 }
    override public var dnsSeeds: [String] {
        return [
            "seed.verge-blockchain.com",
            "seed2.verge-blockchain.com"
        ]
    }
    override public var checkpoints: [Checkpoint] { return [] }
    override public var genesisBlock: Data {
        return Data(Data(hex: "0000000038c6d23e5b6a3f0e2f23d8b1a8e8bbf5db2f7c5b0d3f07b6d67c8c0c")!.reversed())
    }
}

public class XVGTestnet: Testnet {
    override public var name: String { return "verge-testnet" }
    override public var alias: String { return "testnet" }
    override public var scheme: String { return "verge-test" }
    public override var coinType: CoinType { return .xvg }

    override public var pubkeyhash: UInt8 { return 0x71 }
    override public var privatekey: UInt8 { return 0xf1 }
    override public var scripthash: UInt8 { return 0xc4 }
    override public var xpubkey: UInt32 { return 0x043587cf }
    override public var xprivkey: UInt32 { return 0x04358394 }

    override public var magic: UInt32 { return 0xdab5bffa }
    override public var port: UInt32 { return 51938 }
    override public var dnsSeeds: [String] {
        return [
            "testnet-seed.verge-blockchain.com"
        ]
    }
    override public var checkpoints: [Checkpoint] { return [] }
    override public var genesisBlock: Data {
        return Data(Data(hex: "000000000933ea01ad0ee984209779baaec3ced90fa3f408719526f8d77f4943")!.reversed())
    }
}

// MARK: - Mainnet/Testnet Base Classes
public class Mainnet: Network {
    override public var name: String { return "livenet" }
    override public var alias: String { return "mainnet" }
    override public var pubkeyhash: UInt8 { return 0x00 }
    override public var privatekey: UInt8 { return 0x80 }
    override public var scripthash: UInt8 { return 0x05 }
    override public var xpubkey: UInt32 { return 0x0488b21e }
    override public var xprivkey: UInt32 { return 0x0488ade4 }
    override public var port: UInt32 { return 8333 }
}

public class Testnet: Network {
    override public var name: String { return "testnet" }
    override public var alias: String { return "regtest" }
    public override var coinType: CoinType { return .testnet }
    override public var pubkeyhash: UInt8 { return 0x6f }
    override public var privatekey: UInt8 { return 0xef }
    override public var scripthash: UInt8 { return 0xc4 }
    override public var xpubkey: UInt32 { return 0x043587cf }
    override public var xprivkey: UInt32 { return 0x04358394 }
    override public var port: UInt32 { return 18_333 }
}


