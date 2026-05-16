// swift-tools-version:5.7
import PackageDescription

let package = Package(
    name: "BitcoinKit",
    platforms: [
        .iOS(.v13),
        .macOS(.v10_15)
    ],
    products: [
        .library(
            name: "BitcoinKit",
            targets: ["BitcoinKit"]
        ),
        .library(
            name: "HdWalletKit",
            targets: ["HdWalletKit"]
        )
    ],
    dependencies: [
        .package(url: "https://github.com/vapor-community/copenssl.git", exact: "1.0.0-rc.1"),
        .package(url: "https://github.com/GigaBitcoin/secp256k1.swift.git", exact: "0.10.0"),
        .package(url: "https://github.com/apple/swift-crypto.git", "1.0.0"..<"3.0.0"),
        .package(url: "https://github.com/horizontalsystems/HsCryptoKit.Swift.git", from: "1.3.0"),
        .package(url: "https://github.com/krzyzanowskim/CryptoSwift.git", from: "1.9.0")
    ],
    targets: [
        .target(
            name: "BitcoinKitPrivate",
            dependencies: [
                .product(name: "COpenSSL", package: "copenssl"),
                .product(name: "secp256k1", package: "secp256k1.swift"),
                "CryptoSwift"
            ],
            path: "Sources/BitcoinKitPrivate"
        ),
        .target(
            name: "BitcoinKit",
            dependencies: [
                "BitcoinKitPrivate",
                .product(name: "secp256k1", package: "secp256k1.swift")
            ],
            path: "Sources/BitcoinKit"
        ),
        .target(
            name: "HdWalletKit",
            dependencies: [
                .product(name: "Crypto", package: "swift-crypto"),
                .product(name: "_CryptoExtras", package: "swift-crypto"),
                .product(name: "secp256k1", package: "secp256k1.swift"),
                .product(name: "HsCryptoKit", package: "HsCryptoKit.Swift")
            ],
            path: "Sources/HdWalletKit"
        ),
        .testTarget(
            name: "BitcoinKitTests",
            dependencies: ["BitcoinKit"],
            path: "Tests/BitcoinKitTests"
        ),
        .testTarget(
            name: "HdWalletKitTests",
            dependencies: ["HdWalletKit"],
            path: "Tests/HdWalletKitTests"
        )
    ]
)
