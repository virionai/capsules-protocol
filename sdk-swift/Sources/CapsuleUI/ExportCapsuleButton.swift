// ExportCapsuleButton — drop-in share affordance for a built capsule.
//
// Hosts call `make(...)` with their already-built BuildResult; the button
// presents the iOS share sheet so the user can AirDrop / save / send.
// Verification is run in-process before share enables.

import Foundation
import SwiftUI
import UIKit
import Capsule

public struct ExportCapsuleButton: View {
    private let result: CapsuleBuilder.BuildResult
    private let label: String
    private let suggestedFileName: String
    @State private var sharing = false
    @State private var verification: CapsuleVerification?

    public init(result: CapsuleBuilder.BuildResult,
                label: String = "Share .capsule",
                suggestedFileName: String? = nil)
    {
        self.result = result
        self.label = label
        self.suggestedFileName = suggestedFileName
            ?? "capsule-\(String(result.capsuleId.prefix(8))).capsule"
    }

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
}

private struct ShareSheet: UIViewControllerRepresentable {
    let items: [Any]
    func makeUIViewController(context: Context) -> UIActivityViewController {
        UIActivityViewController(activityItems: items, applicationActivities: nil)
    }
    func updateUIViewController(_ vc: UIActivityViewController, context: Context) {}
}
