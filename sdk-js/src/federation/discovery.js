// Issuer discovery and recipient-key resolution.
//
// These functions run ONLY at authoring time (sealing an encrypted capsule,
// or requesting an attestation) and at optional policy-refresh time (caching
// an issuer's trust roots). They never run during capsule verification or
// decryption. Decryption needs only the recipient's X25519 private key held
// locally — never a call to Clerk or any issuer.
//
// Every network dependency is injected (a `fetchLike` or a directory object),
// so the reference implementation and its tests run fully offline.

/**
 * Fetch and shallow-validate an issuer metadata document, conventionally at
 * `<issuer>/.well-known/capsule-issuer.json`. `fetchLike` matches the fetch
 * contract: (url) => Promise<{ ok, json() }>.
 */
export async function fetchIssuerMetadata(fetchLike, issuerBaseUrl) {
  const url = new URL("/.well-known/capsule-issuer.json", issuerBaseUrl).toString();
  const res = await fetchLike(url);
  if (!res || !res.ok) throw new Error(`issuer metadata fetch failed: ${issuerBaseUrl}`);
  const meta = await res.json();
  if (!meta.issuer) throw new Error("issuer metadata missing 'issuer'");
  if (!Array.isArray(meta.profiles)) throw new Error("issuer metadata missing 'profiles'");
  return meta;
}

/**
 * Load an issuer's trust roots (public keys) for offline attestation
 * verification. Prefers inline `trust_roots.jwks`; otherwise fetches
 * `trust_roots.jwks_uri`. The result is cacheable and small.
 */
export async function loadTrustRoots(metadata, fetchLike) {
  const tr = metadata.trust_roots ?? {};
  if (tr.jwks) return tr.jwks;
  if (tr.jwks_uri) {
    const res = await fetchLike(tr.jwks_uri);
    if (!res || !res.ok) throw new Error(`jwks fetch failed: ${tr.jwks_uri}`);
    return await res.json();
  }
  throw new Error("issuer metadata has no trust_roots.jwks or jwks_uri");
}

/**
 * Resolve recipient X25519 public keys for encryption from a key directory.
 *
 * `directory` is any object exposing `lookup(identifier) =>
 * Promise<string|null>` returning a 64-hex X25519 public key (or null when a
 * recipient has published none). Returns
 *   { resolved: [{ identifier, x25519_public_key_hex }], missing: [identifier] }
 *
 * Callers pass `resolved[].x25519_public_key_hex` straight into
 * CapsuleBuilder.seal({ recipients }). Only resolved recipients can decrypt.
 */
export async function resolveRecipientKeys(directory, identifiers) {
  if (typeof directory?.lookup !== "function") {
    throw new Error("directory must expose lookup(identifier)");
  }
  const resolved = [];
  const missing = [];
  for (const identifier of identifiers) {
    const hex = await directory.lookup(identifier);
    if (hex && /^[0-9a-f]{64}$/.test(hex)) {
      resolved.push({ identifier, x25519_public_key_hex: hex });
    } else {
      missing.push(identifier);
    }
  }
  return { resolved, missing };
}

/**
 * A recipient key directory backed by Clerk. `clerkClient` is injected and
 * only needs a single method:
 *   getPublicMetadata(identifier) => Promise<object>
 * mapping a Clerk user id / org id / email to that principal's public
 * metadata, where the X25519 capsule key is published under `keyField`
 * (default "capsule_x25519_public_key"). This mirrors how a Clerk backend
 * exposes `publicMetadata` via the Backend API — publishing an encryption
 * key is a deliberate, non-secret directory entry.
 */
export function clerkRecipientDirectory(clerkClient, { keyField = "capsule_x25519_public_key" } = {}) {
  if (typeof clerkClient?.getPublicMetadata !== "function") {
    throw new Error("clerkClient must expose getPublicMetadata(identifier)");
  }
  return {
    async lookup(identifier) {
      const meta = await clerkClient.getPublicMetadata(identifier);
      const hex = meta?.[keyField];
      return typeof hex === "string" ? hex.toLowerCase() : null;
    },
  };
}
