// Capsule federation layer (non-normative reference adapter).
//
// Adds external identity (e.g. Clerk), encrypted-recipient discovery, and
// signer-role/quorum policy WITHOUT changing the portable capsule wire shape
// or making verification depend on any network service. See
// spec/federation.md and spec/profiles/clerk.md.
//
// Portability firewall (enforced by construction, not convention):
//   - Nothing here is imported by verifier.js. verifyCapsule() stays offline
//     and issuer-agnostic.
//   - Attestation verification is offline given cached issuer trust roots.
//   - Recipient-key discovery runs only at authoring time; decryption needs
//     only the recipient's local X25519 private key.

export {
  ATTESTATION_TYP,
  ATTESTATION_DOMAIN,
  signIdentityAttestation,
  verifyIdentityAttestation,
  verifyJwt,
} from "./attestation.js";

export {
  fetchIssuerMetadata,
  loadTrustRoots,
  resolveRecipientKeys,
  clerkRecipientDirectory,
} from "./discovery.js";

export { evaluateSignerPolicy } from "./policy.js";
