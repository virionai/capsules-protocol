// Issuer identity normalization, shared by the attestation and discovery
// layers.
//
// spec/federation.md "Vocabulary": an issuer is canonically identified by a
// lowercase DNS name. Fields that are URLs by convention (issuer metadata
// `issuer`, JWT `iss`) carry the origin form; fields inside signer documents
// and envelopes carry the bare DNS name. "Verifiers MUST treat the two forms
// as the same issuer after normalization (strip scheme, lowercase, drop
// trailing slash)."

/**
 * Reduce an issuer identifier — origin form (`https://acme.example/`), bare
 * DNS form (`acme.example`), or a URL under the issuer origin
 * (`https://acme.example/.well-known/jwks.json`) — to its lowercase DNS
 * identity. Returns null for anything unparseable, so callers fail closed.
 */
export function normalizeIssuer(value) {
  if (typeof value !== "string") return null;
  const trimmed = value.trim();
  if (trimmed.length === 0) return null;
  const withScheme = /^https?:\/\//i.test(trimmed) ? trimmed : `https://${trimmed}`;
  try {
    const host = new URL(withScheme).host.toLowerCase();
    return host.length > 0 ? host : null;
  } catch {
    return null;
  }
}
