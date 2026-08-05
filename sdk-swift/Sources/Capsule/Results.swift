// Renderer language for the normalized verdict surface
// (spec/results.md "Required renderer language").
//
// The verdict is the verifier's claim about the capsule, and a
// qualifier the reader never sees converts a weaker claim made honestly
// by the author into a stronger claim made falsely by the tooling —
// the trust.md threat row this vocabulary exists to close. A conforming
// renderer MUST NOT present a `valid` verdict without rendering every
// qualifier beside it, each carrying at least its normative minimum
// substring. This table is that floor, shared by every renderer in the
// lane; the phrasing AROUND each substring belongs to the renderer.

import Foundation

public enum CapsuleResults {

    /// The human rendering of one qualifier, containing that
    /// qualifier's normative minimum substring. An UNKNOWN entry — a
    /// later spec revision's name, or an `x-<vendor>-` extension — is
    /// surfaced VERBATIM and must never be treated as satisfied or
    /// ignorable (spec/results.md consumer rule).
    public static func rendering(of qualifier: String) -> String {
        switch qualifier {
        case "signer_set_unbound":
            return "the signer set is not bound by the seal (manifest.signer_commitment absent)"
        case "actor_set_unbound":
            return "chain actors are not bound to a declared participant set "
                + "(manifest.participants empty)"
        case "empty_chain_not_walked":
            return "empty chain: no events to walk; envelope anchors checked null instead"
        case "encrypted_outer_only":
            return "the content is encrypted and was not read (L2 outer only; chain deferred to L3)"
        case "version_not_accepted_by_policy":
            return "the declared format version is not in the declared accepted set of this host"
        case "trust_not_evaluated":
            return "trust not evaluated: no allowlist was supplied"
        case "no_trusted_signer":
            return "the supplied allowlist matched no signer"
        // The three lineage qualifiers arrive with the `predecessors`
        // machinery; their phrases are already normative, so a result
        // carrying one renders correctly the day this lane emits it.
        case "lineage_declared_unverified":
            return "lineage is declared, not verified in this run"
        case "lineage_mismatch":
            return "a supplied predecessor is a different sealed state of the declared predecessor"
        case "lineage_predecessor_invalid":
            return "a supplied predecessor fails its own verification"
        default:
            return qualifier
        }
    }

    /// A one-line summary of the verdict for a compact surface. Never
    /// the bare word "verified" for a qualified pass, and never the
    /// word "failed" for an `unsupported` verdict: an unknown era or an
    /// unimplemented profile is a limitation of THIS verifier, and
    /// another implementation may verify the same bytes.
    public static func headline(_ verification: CapsuleVerification) -> String {
        switch verification.verdict {
        case "valid":
            let trust = verification.trustedSignerCount > 0 ? " · trusted" : ""
            return verification.qualifiers.isEmpty ? "verified\(trust)" : "verified, with caveats\(trust)"
        case "unsupported":
            return "not verifiable by this verifier (\(verification.verdictReason ?? "unsupported"))"
        default:
            return "verification failed"
        }
    }
}
