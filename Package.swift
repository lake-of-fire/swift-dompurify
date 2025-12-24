// swift-tools-version: 6.2
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "SwiftDOMPurify",
    platforms: [
        .macOS(.v13),
        .iOS(.v15),
        .tvOS(.v16),
        .watchOS(.v9),
    ],
    products: [
        // Products define the executables and libraries a package produces, making them visible to other packages.
        .library(
            name: "SwiftDOMPurify",
            targets: ["SwiftDOMPurify"]
        ),
        .executable(
            name: "SwiftDOMPurifyBench",
            targets: ["SwiftDOMPurifyBench"]
        ),
    ],
    dependencies: [
        .package(url: "https://github.com/scinfu/SwiftSoup.git", from: "2.11.3"),
    ],
    targets: [
        // Targets are the basic building blocks of a package, defining a module or a test suite.
        // Targets can depend on other targets in this package and products from dependencies.
        .target(
            name: "SwiftDOMPurify",
            dependencies: [
                .product(name: "SwiftSoup", package: "SwiftSoup")
            ]
        ),
        .executableTarget(
            name: "SwiftDOMPurifyBench",
            dependencies: ["SwiftDOMPurify"]
        ),
        .testTarget(
            name: "SwiftDOMPurifyTests",
            dependencies: ["SwiftDOMPurify"],
            resources: [
                .copy("Fixtures")
            ]
        ),
    ]
)
