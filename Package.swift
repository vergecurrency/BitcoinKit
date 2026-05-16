// swift-tools-version:5.7
import PackageDescription

let package = Package(
    name: "BitcoinKit",
    platforms: [
        .iOS(.v13),
        .macOS(.v10_15)
    ],
    products: [
        .library(name: "BitcoinKit", targets: ["BitcoinKit"])
    ],
    dependencies: [
        .package(url: "https://github.com/GigaBitcoin/secp256k1.swift.git", exact: "0.23.1")
    ],
    targets: [
        .target(
            name: "BitcoinKit",
            dependencies: ["BitcoinKitPrivate"]
        ),
        .target(
            name: "BitcoinKitPrivate",
            dependencies: [
                .product(name: "libsecp256k1", package: "secp256k1.swift")
            ]
        ),
        .testTarget(
            name: "BitcoinKitTests",
            dependencies: ["BitcoinKit"]
        )
    ]
)
