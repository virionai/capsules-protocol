// ExportCapsuleButton — drop-in share affordance for a built capsule.
//
// Hosts call `make(...)` with their already-built BuildResult; the button
// presents the iOS share sheet so the user can AirDrop / save / send.
// Verification is run in-process before share enables.
//
// The share-sheet machinery is UIKit-only. On macOS the type remains
// referenceable so cross-platform call sites keep compiling, but its
// `body` is an inert placeholder — hosts on macOS should use
// `NSSharingService` directly instead.

import Foundation
import SwiftUI
#if canImport(UIKit)
import UIKit
#endif
import Capsule

public struct ExportCapsuleButton: View {
    private let result: CapsuleBuilder.BuildResult
    private let label: String
    private let suggestedFileName: String

    public init(result: CapsuleBuilder.BuildResult,
                label: String = "Share .capsule",
                suggestedFileName: String? = nil)
    {
        self.result = result
        self.label = label
        self.suggestedFileName = suggestedFileName
            ?? "capsule-\(String(result.capsuleId.prefix(8))).capsule"
    }

    #if canImport(UIKit)
    @State private var sharing = false
    @State private var verification: CapsuleVerification?

    public var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack {
                Button(action: { sharing = true }) {
                    Label(label, systemImage: "square.and.arrow.up")
                }
                .disabled(verification != nil && !(verification?.ok ?? true))
                if let v = verification {
                    VerifyBadge(verification: v)
                }
            }
        }
        .onAppear {
            verification = CapsuleVerifier.verify(result.bytes)
        }
        .sheet(isPresented: $sharing) {
            ShareSheet(items: [tempURL()])
        }
    }

    private func tempURL() -> URL {
        let url = FileManager.default.temporaryDirectory
            .appendingPathComponent(suggestedFileName)
        try? result.bytes.write(to: url, options: .atomic)
        return url
    }
    #else
    // macOS / non-UIKit platforms: no share-sheet equivalent ships here.
    // Hosts should wire `NSSharingService` against `result.bytes`.
    public var body: some View {
        EmptyView()
    }
    #endif
}

#if canImport(UIKit)
private struct ShareSheet: UIViewControllerRepresentable {
    let items: [Any]
    func makeUIViewController(context: Context) -> UIActivityViewController {
        UIActivityViewController(activityItems: items, applicationActivities: nil)
    }
    func updateUIViewController(_ vc: UIActivityViewController, context: Context) {}
}
#endif
