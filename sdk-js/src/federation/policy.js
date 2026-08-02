// Signer-role and quorum policy, evaluated as an offline overlay on top of a
// verifyCapsule() result plus verified identity attestations.
//
// This does NOT change what "valid math" means. It answers a separate,
// host-owned question: given the signers whose keys are cryptographically
// valid AND whose identities are attested by a trusted issuer, is the host's
// authorization policy satisfied? A host with no policy simply skips this.

/**
 * evaluateSignerPolicy(verifyResult, attestedSigners, policy, options)
 *
 * verifyResult    the object returned by verifyCapsule()
 * attestedSigners [{ capsule_id, signer_public_key, signer_role, subject }] —
 *                 the verified identity claims of attestations already
 *                 checked with verifyIdentityAttestation(); pass each
 *                 result's `identity.claims` (non-null only when the
 *                 attestation verified)
 * policy          {
 *                   issuer,                       // informational
 *                   required: [
 *                     { role, org_role?, quorum = 1 }
 *                   ]
 *                 }
 * options         { capsuleId }  REQUIRED — the capsule these attestations
 *                 must be bound to. Matching a signer by public key alone
 *                 makes a cross-capsule replay invisible at this layer.
 *
 * Returns { satisfied, matched: [...], unmet: [...], errors: [...] }.
 *
 * A signer counts toward a requirement only if its key is a trusted signer in
 * verifyResult (valid signature + on the allowlist) AND covered by an
 * attestation bound to THIS capsule_id matching the required role (and
 * org_role, when specified).
 */
export function evaluateSignerPolicy(verifyResult, attestedSigners, policy, options = {}) {
  if (typeof options.capsuleId !== "string" || options.capsuleId.length === 0) {
    throw new TypeError(
      "evaluateSignerPolicy requires options.capsuleId: an attestation counts only for the capsule it was bound to (spec/federation.md)",
    );
  }
  const errors = [];
  const required = policy?.required ?? [];

  const trustedKeys = new Set(
    (verifyResult?.envelope?.signers ?? [])
      .filter((s) => s.valid && s.trusted)
      .map((s) => s.public_key.toLowerCase()),
  );

  const attestByKey = new Map();
  for (const a of attestedSigners ?? []) {
    if (!a?.signer_public_key) continue;
    const key = a.signer_public_key.toLowerCase();
    // Cross-capsule replay: an attestation whose binding names a different
    // capsule proves nothing here, however valid its signature.
    if (a.capsule_id !== options.capsuleId) {
      errors.push(
        `policy: attestation for signer ${key} is bound to capsule_id ` +
          `${a.capsule_id ?? "(none)"}, not ${options.capsuleId}`,
      );
      continue;
    }
    attestByKey.set(key, a);
  }

  const matched = [];
  const unmet = [];
  for (const req of required) {
    const quorum = req.quorum ?? 1;
    const hits = [];
    for (const key of trustedKeys) {
      const att = attestByKey.get(key);
      if (!att) continue;
      if (att.signer_role !== req.role) continue;
      if (req.org_role && att.subject?.org_role !== req.org_role) continue;
      hits.push({ signer_public_key: key, subject: att.subject });
    }
    if (hits.length >= quorum) {
      matched.push({ requirement: req, signers: hits });
    } else {
      unmet.push({ requirement: req, have: hits.length, need: quorum });
    }
  }

  if (unmet.length > 0) {
    for (const u of unmet) {
      errors.push(
        `policy: role '${u.requirement.role}'` +
          (u.requirement.org_role ? ` (org_role '${u.requirement.org_role}')` : "") +
          ` needs ${u.need} trusted+attested signer(s), have ${u.have}`,
      );
    }
  }

  // An attestation bound to another capsule is a strong negative signal
  // (spec/federation.md "Failure reporting": attestation_rejected), so it
  // fails the policy even when the remaining signers satisfy every
  // requirement.
  return { satisfied: unmet.length === 0 && errors.length === 0, matched, unmet, errors };
}
