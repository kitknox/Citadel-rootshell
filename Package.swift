// swift-tools-version:5.9
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "Citadel",
    platforms: [
        .macOS(.v14),
        .iOS(.v17)
    ],
    products: [
        .library(
            name: "Citadel",
            targets: ["Citadel"]
        ),
    ],
    dependencies: [
        // rootshell's public fork carries the SSH algorithm and platform fixes
        // required by Citadel.
        .package(
            url: "https://github.com/kitknox/swift-nio-ssh-rootshell.git",
            exact: "0.1.0"
        ),
        .package(url: "https://github.com/apple/swift-log.git", from: "1.0.0"),
        .package(url: "https://github.com/attaswift/BigInt.git", from: "5.2.0"),
        // Pinned exactly: CMLDSA44 declares private CCryptoBoringSSL_MLDSA44_*
        // symbols and opaque struct storage sized against this release's
        // vendored BoringSSL. Re-validate the shim before moving the pin.
        .package(url: "https://github.com/apple/swift-crypto.git", exact: "3.15.1"),
        .package(url: "https://github.com/apple/swift-nio-transport-services.git", from: "1.19.0"),
        .package(url: "https://github.com/mtynior/ColorizeSwift.git", from: "1.5.0"),
    ],
    targets: [
        .target(name: "CCitadelBcrypt"),
        .target(
            name: "CSntrup761",
            cSettings: [
                .unsafeFlags(["-w"]),  // Suppress warnings in reference crypto code
            ]
        ),
        // Bridges to the ML-DSA-44 already compiled inside swift-crypto's
        // CCryptoBoringSSL (whose umbrella header doesn't expose mldsa.h).
        .target(name: "CMLDSA44"),
        .target(
            name: "Citadel",
            dependencies: [
                .target(name: "CCitadelBcrypt"),
                .target(name: "CSntrup761"),
                .target(name: "CMLDSA44"),
                .product(name: "NIOSSH", package: "swift-nio-ssh-rootshell"),
                .product(name: "NIOTransportServices", package: "swift-nio-transport-services"),
                .product(name: "Crypto", package: "swift-crypto"),
                .product(name: "_CryptoExtras", package: "swift-crypto"),
                .product(name: "BigInt", package: "BigInt"),
                .product(name: "Logging", package: "swift-log"),
            ]
        ),
        .executableTarget(
            name: "CitadelServerExample",
            dependencies: [
                "Citadel",
                .product(name: "ColorizeSwift", package: "ColorizeSwift")
            ]),
        .testTarget(
            name: "CitadelTests",
            dependencies: [
                "Citadel",
                .product(name: "NIOSSH", package: "swift-nio-ssh-rootshell"),
                .product(name: "BigInt", package: "BigInt"),
                .product(name: "Logging", package: "swift-log"),
            ],
            resources: [
                .copy("TestData"),
            ]
        ),
    ]
)
