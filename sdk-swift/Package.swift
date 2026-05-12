// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "Capsule",
    platforms: [
        .iOS(.v17),
        .macOS(.v14),
    ],
    products: [
        .library(name: "Capsule",        targets: ["Capsule"]),
        .library(name: "CapsuleSkills",  targets: ["CapsuleSkills"]),
        .library(name: "CapsuleLLM",     targets: ["CapsuleLLM"]),
        .library(name: "CapsuleUI",      targets: ["CapsuleUI"]),
    ],
    dependencies: [],
    targets: [
        // Core: zero dependencies. Pure crypto + format primitives.
        .target(name: "Capsule",
                path: "Sources/Capsule"),

        // Skills: the `skills/` subtree of a capsule. Depends only on Core.
        .target(name: "CapsuleSkills",
                dependencies: ["Capsule"],
                path: "Sources/CapsuleSkills"),

        // LLM: protocols a host harness implements to wire its model and
        // a runtime that routes skill actions. Depends on Core + Skills.
        .target(name: "CapsuleLLM",
                dependencies: ["Capsule", "CapsuleSkills"],
                path: "Sources/CapsuleLLM"),

        // UI: drop-in SwiftUI components for "+ Capsule" affordances in
        // host apps. Depends on Core + Skills.
        .target(name: "CapsuleUI",
                dependencies: ["Capsule", "CapsuleSkills"],
                path: "Sources/CapsuleUI"),

        .testTarget(name: "CapsuleTests",
                    dependencies: ["Capsule", "CapsuleSkills"],
                    path: "Tests/CapsuleTests"),
    ]
)
