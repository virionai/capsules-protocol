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
public struct VerifyBadge: View {
    public let verification: CapsuleVerification
    public init(verification: CapsuleVerification) { self.verification = verification }
    public var body: some View {
        HStack(spacing: 6) {
            Image(systemName: verification.ok ? "checkmark.seal.fill" : "exclamationmark.triangle.fill")
                .foregroundStyle(verification.ok ? Color.green : Color.red)
            Text(verification.ok
                 ? (verification.trustedSignerCount > 0 ? "verified · trusted" : "verified")
                 : "verification failed")
                .font(.caption.bold())
        }
        .padding(.horizontal, 8).padding(.vertical, 3)
        .background(
            Capsule().fill(
                (verification.ok ? Color.green : Color.red).opacity(0.12)
            )
        )
    }
}
