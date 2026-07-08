// Signer-role and quorum policy, evaluated as an offline overlay on top of a
// verifyCapsule() result plus verified identity attestations.
//
// This does NOT change what "valid math" means. It answers a separate,
// host-owned question: given the signers whose keys are cryptographically
// valid AND whose identities are attested by a trusted issuer, is the host's
// authorization policy satisfied? A host with no policy simply skips this.

/**
 * evaluateSignerPolicy(verifyResult, attestedSigners, policy)
 *
 * verifyResult    the object returned by verifyCapsule()
 * attestedSigners [{ signer_public_key, signer_role, subject }] — the claims
 *                 of attestations already verified with
 *                 verifyIdentityAttestation() (ok === true only)
 * policy          {
 *                   issuer,                       // informational
 *                   required: [
 *                     { role, org_role?, quorum = 1 }
 *                   ]
 *                 }
 *
 * Returns { satisfied, matched: [...], unmet: [...], errors: [...] }.
 *
 * A signer counts toward a requirement only if its key is both a trusted
 * signer in verifyResult (valid signature + on the allowlist) AND covered by
 * an attestation matching the required role (and org_role, when specified).
 */
export function evaluateSignerPolicy(verifyResult, attestedSigners, policy) {
  const errors = [];
  const required = policy?.required ?? [];

  const trustedKeys = new Set(
    (verifyResult?.envelope?.signers ?? [])
      .filter((s) => s.valid && s.trusted)
      .map((s) => s.public_key.toLowerCase()),
  );

  const attestByKey = new Map();
  for (const a of attestedSigners ?? []) {
    if (a?.signer_public_key) attestByKey.set(a.signer_public_key.toLowerCase(), a);
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

  return { satisfied: unmet.length === 0, matched, unmet, errors };
}
