// AddCapsuleButton — drop-in "+ Capsule" affordance.
//
// Tap → file picker (UTType "public.data") → parse → callback with the
// fully parsed capsule and a verification report. Hosts wire this into
// their own UI; the button styles itself to match the host's tint and
// font but stays neutral by default.

import Foundation
import SwiftUI
import UniformTypeIdentifiers
import Capsule

public struct AddCapsuleButton: View {
    public typealias OnCapsuleOpened = (ParsedCapsule, CapsuleVerification, URL) -> Void

    private let label: String
    private let allowlist: Set<String>
    private let onOpened: OnCapsuleOpened
    @State private var picking = false
    @State private var error: String?

    public init(label: String = "+ Capsule",
                allowlist: Set<String> = [],
                onOpened: @escaping OnCapsuleOpened)
    {
        self.label = label
        self.allowlist = allowlist
        self.onOpened = onOpened
    }

    public var body: some View {
        Button(action: { picking = true }) {
            Label(label, systemImage: "plus.circle")
        }
        .fileImporter(
            isPresented: $picking,
            allowedContentTypes: [
                UTType(filenameExtension: "capsule") ?? .data,
                .zip,
                .data,
            ],
            allowsMultipleSelection: false
        ) { result in
            switch result {
            case .success(let urls):
                guard let url = urls.first else { return }
                let didStart = url.startAccessingSecurityScopedResource()
                defer { if didStart { url.stopAccessingSecurityScopedResource() } }
                do {
                    let bytes = try Data(contentsOf: url)
                    let parsed = try CapsuleReader.parse(bytes)
                    let v = CapsuleVerifier.verify(bytes, allowlist: allowlist)
                    onOpened(parsed, v, url)
                    error = nil
                } catch {
                    self.error = "\(error)"
                }
            case .failure(let err):
                self.error = "\(err)"
            }
        }
        .alert("Could not open capsule",
               isPresented: Binding(
                    get: { error != nil },
                    set: { if !$0 { error = nil } }
               )) {
            Button("OK") { error = nil }
        } message: {
            Text(error ?? "")
        }
    }
}

/// Compact verification badge a host can place beside an opened capsule.
///
/// The badge renders the VERDICT, not just `ok` (spec/results.md): an
/// `unsupported` capsule is a limitation of this verifier — another
/// implementation may verify the same bytes — so it never reads as a
/// failure. And a valid verdict is never presented without every
/// qualifier beside it: a weaker claim the author made honestly must
/// not become a stronger claim the tooling makes falsely.
public struct VerifyBadge: View {
    public let verification: CapsuleVerification
    public init(verification: CapsuleVerification) { self.verification = verification }

    private var tint: Color {
        switch verification.verdict {
        case "valid": return .green
        case "unsupported": return .orange
        default: return .red
        }
    }

    private var symbol: String {
        switch verification.verdict {
        case "valid": return "checkmark.seal.fill"
        case "unsupported": return "questionmark.circle.fill"
        default: return "exclamationmark.triangle.fill"
        }
    }

    public var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            HStack(spacing: 6) {
                Image(systemName: symbol).foregroundStyle(tint)
                Text(CapsuleResults.headline(verification)).font(.caption.bold())
            }
            .padding(.horizontal, 8).padding(.vertical, 3)
            .background(Capsule().fill(tint.opacity(0.12)))
            ForEach(verification.qualifiers, id: \.self) { qualifier in
                Text("· " + CapsuleResults.rendering(of: qualifier))
                    .font(.caption2)
                    .foregroundStyle(.secondary)
            }
        }
    }
}
