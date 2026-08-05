# Capsule v0.7 — Python SDK

Independent Python implementation of the Capsule v0.7 portable,
signed, verifiable work-artifact format. Sibling to the
[JS reference SDK](../sdk-js/) and the [Rust verifier](../verifier-rust/);
same wire format, same verification semantics, same ergonomics.

Prototype, not production. See [../spec/](../spec/) for the protocol.

## Add it to your app

Not yet published to PyPI. Install from a checkout of this repository:

```sh
pip install /path/to/capsules-protocol/sdk-py
# or for development:  pip install -e /path/to/capsules-protocol/sdk-py
```

Requirements: Python >= 3.11. The only runtime dependency is
[`cryptography`](https://pypi.org/project/cryptography/) (Ed25519,
X25519, HKDF-SHA256, ChaCha20-Poly1305).

## Quickstart

Create, save, verify, and read a capsule. This flow is pinned by
`tests/test_dx.py`, so it cannot silently rot:

```python
from capsule import CapsuleBuilder, CapsuleReader, generate_ed25519, verify_capsule

# 1. One keypair for your app (persist keys.private_key_hex somewhere
#    safe; in a real app you generate this once, not per capsule).
keys = generate_ed25519()

# 2. Build and seal a capsule: a portable, signed unit of work.
builder = CapsuleBuilder(originator=keys)  # or {"public_key": ..., "label": "MyApp"}
builder.set_program("# Quarterly report\n\nDraft written by Alice, reviewed by AI.\n")
builder.append_event({"actor": "human:alice", "action": "wrote_draft"})
builder.append_event({"actor": "ai:assistant", "action": "suggested_edits", "payload": {"count": 3}})
data = builder.seal(signers=keys)

with open("quickstart.capsule", "wb") as f:
    f.write(data)

# 3. Anywhere else (another process, another machine): open and verify.
#    The allowlist is your trust decision — which signer keys you accept.
with open("quickstart.capsule", "rb") as f:
    file_bytes = f.read()

result = verify_capsule(file_bytes, allowlist=[keys.public_key_hex])
print("verified:", result["ok"])                        # True — math checks out
print("trusted signers:", result["trusted_signer_count"])  # 1 — and you trust the key

# 4. Read the contents.
reader = CapsuleReader.from_bytes(file_bytes)
print("capsule id:", reader.manifest()["id"])
print(reader.program())
for event in reader.events():
    print(f"event {event['seq']}: {event['actor']} {event['action']}")
```

Sensible defaults keep the happy path short: `created_at` and `seal()`'s
`signed_at` default to now, while event timestamps inherit `created_at`.
Pass both values explicitly for reproducible builds. Events default to
`kind="observation"` / `target="capsule"`, and a signer's role defaults to
`"originator"`, and `verify_capsule()` never raises: unopenable input, a
malformed manifest, and a malformed chain all come back as a fail-closed
result (`ok: False`) with the reason in `errors`.

## Keys: hex or bytes, your choice

Every place the API takes a key accepts either a hex string (any case)
or 32 raw bytes — including the keypair objects from
`generate_ed25519()` / `generate_x25519()` as-is:

```python
keys = generate_ed25519()
# keys = Ed25519KeyPair(public_key=b"...", private_key=b"...",
#                       public_key_hex="...", private_key_hex="...")

CapsuleBuilder(originator=keys)                      # keypair object
CapsuleBuilder(originator={"public_key": "b440d9e6..."})  # hex
builder.seal(signers=keys)                           # role defaults to "originator"
builder.seal(signers=[{"role": "reviewer", "public_key": pub_hex, "private_key": priv_hex}])
verify_capsule(data, allowlist=[keys.public_key])     # bytes
verify_capsule(data, allowlist=[keys.public_key_hex]) # hex
```

The wire format stays lowercase hex regardless of input form.

Persist the private key (e.g. `keys.private_key_hex`) in your secret
store; publish the public key to whoever needs to verify your capsules.
The allowlist is a *trust policy*, not cryptography — `result["ok"]`
says the math checks out; `result["trusted_signer_count"]` says a
signer is one you accept (see [../spec/trust.md](../spec/trust.md)).
Treat a capsule as good when
`result["ok"] and result["trusted_signer_count"] >= 1` (or your own
stricter policy).

## The verdict surface: what a report must not hide

Every result also carries the normalized vocabulary of
[../spec/results.md](../spec/results.md), derived from the facts above:

```python
result["verdict"]         # "valid" | "invalid" | "unsupported"
result["verdict_reason"]  # non-null iff "unsupported": unsupported_version_newer,
                          # unsupported_version_older, unsupported_profile,
                          # unsupported_capability
result["qualifiers"]      # e.g. ["signer_set_unbound", "trust_not_evaluated"]
```

`result["ok"] == (result["verdict"] == "valid")` is an invariant.
`"unsupported"` names a limitation of *this verifier* — an unknown era
or a profile it does not implement — never corruption: route the capsule
to an implementation that has the rules. `qualifiers` names the weaker
claims a `valid` verdict rests on (an unbound signer set, an unwalked
empty chain, an unread encrypted body, no allowlist consulted, a custody
claim that was declared but not verified); a conforming renderer MUST
show every one of them beside the verdict, so "verified" never means
more than the capsule actually claimed. The emitted set is the ten names
of [../spec/results.md](../spec/results.md), always in that order — bare
strings only: payload-carrying facts stay in their own channels
(`result["lineage"]`, `result["profile"]`, `result["format_version"]`).

`result["profile"]` is the profile declaration channel
([../spec/profiles.md](../spec/profiles.md)): `observed` /
`observed_version` (the declaration as read, reported even on refusal),
`declared`, `effective` / `effective_version` (the profile actually
applied — absence means `v0.6-suite`/`1.0`, permanently), `supported`,
`status`, and `accepted_by_policy`. Host policy is reported and never
decided: `verify_capsule(data, accept_versions=[...],
accept_profiles=[...])` fills in the two `accepted_by_policy` facts
without changing `ok`.

## Encrypt for specific recipients

Pass `recipients` at seal time to encrypt the capsule body
(ChaCha20-Poly1305; per-recipient X25519 key wrap). Anyone can still
verify the outer signatures (L2); only recipients can decrypt and fully
verify the content (L3):

```python
from capsule import generate_x25519

recipient = generate_x25519()  # recipient generates; shares public_key_hex

data = builder.seal(signers=keys, recipients=[recipient.public_key_hex])

# Recipient side:
outer = CapsuleReader.from_bytes(data)
l2 = verify_capsule(outer, allowlist=[keys.public_key_hex])  # no key needed
inner = outer.decrypt(recipient)  # keypair object works as-is
l3 = verify_capsule(inner, allowlist=[keys.public_key_hex],
                    outer_envelope=outer.envelope())
print(inner.program())
```

The reader `decrypt()` returns remembers the layer it came out of, so
the L3 inner/outer lineage equality (spec/lineage.md) runs on this
recipe with no extra argument. Pass `outer_manifest=outer.manifest()`
only when you verify raw decrypted BYTES instead of that reader.

## Continue someone else's capsule (lineage / rewrap)

You cannot seal under another originator's identity — and you don't
need to. A successor capsule declares the exact sealed artifact it
continues from (`manifest.predecessors`,
[../spec/lineage.md](../spec/lineage.md)), carries the content files
forward byte-identically, and starts a fresh chain under YOUR key:

```python
from capsule import CapsuleBuilder, rewrap_capsule, generate_ed25519, verify_capsule

bob = generate_ed25519()

# One-call custody transfer:
wrap = rewrap_capsule(alice_bytes, originator=bob)
wrap["bytes"], wrap["capsule_id"], wrap["predecessor_entry"]

# Or continue the work before sealing:
builder = CapsuleBuilder.continue_from(
    alice_bytes,
    originator={"public_key": bob.public_key_hex, "label": "Bob"},
    participants=[{"actor_id": "human:bob", "role": "custodian"}],
)
builder.append_event({"actor": "human:bob", "action": "continued"})
sealed = builder.seal(signers=bob)

# Verify the custody claim by supplying the predecessor bytes:
result = verify_capsule(sealed, predecessors=[alice_bytes])
result["lineage"]  # {"declared", "ok", "verified_depth", "entries": [...]}
```

The declaration is the successor's ONE-WAY claim — the predecessor's
originator has not countersigned it — and linkage is report-only:
supplying the wrong file changes `result["lineage"]`, never
`result["ok"]`. Merges: `builder.declare_predecessor(other_parent_bytes)`
once per parent; an archivist holding hashes but not bytes uses
`builder.declare_predecessor_entry({...})`. Refusals (tampered /
unknown-era / encrypted / alternate-profile predecessors) raise
`PredecessorError` with a machine-readable `.reason`.

An unclean custody claim also reaches the verdict surface above:
`lineage_declared_unverified`, `lineage_mismatch` and
`lineage_predecessor_invalid` are qualifiers 8-10 — a `valid` verdict
whose custody claim a renderer must not hide.

## Develop

```sh
cd sdk-py
pip install -e ".[dev]"
pytest                         # full suite, incl. registry + parity lanes
ruff check src tests           # lint
ruff format --check src tests  # formatter check
```

## Parity and conformance

- `tests/test_spec_registry.py` consumes the language-neutral outcome
  registries (`spec/vectors/tamper-detection/`, `malformed-layout/`,
  `lineage/`, `profile-declaration/`, `result-vocabulary/`, …) and the
  byte-level `signing-input.json` pins directly.
- `tests/test_parity_jssdk.py` runs both directions: Python verifies
  JS-built fixtures, and JS verifies Python-built capsules via a Node
  subprocess.
- `tests/test_rewrap.py` adds the lineage derivation-parity pin: the
  six-member entry this lane derives from a checked-in predecessor is
  JSON-equal to the one the JS reference lane sealed into the successor
  fixture (cross-era and zero-event corners included).

## Module map (mirrors `sdk-js/src/`)

| Python | JS reference | Responsibility |
|---|---|---|
| `capsule.canonical` | `sdk-js/src/canonical.js` | JCS RFC 8785, SHA-256, hex |
| `capsule.crypto` | `sdk-js/src/crypto.js` | Ed25519, X25519, HKDF-SHA256, ChaCha20-Poly1305 |
| `capsule.keys` | `sdk-js/src/keys.js` | API-boundary key-input normalization |
| `capsule.zip_io` | `sdk-js/src/zip.js` | Deterministic STORED ZIP + safety |
| `capsule.pith` | `sdk-js/src/pith.js` | Narrative-field normalizer |
| `capsule.chain` | `sdk-js/src/chain.js` | Event hashing + chain verify |
| `capsule.manifest` | `sdk-js/src/manifest.js` | Manifest, capsule_id, content_index, `predecessors` grammar |
| `capsule.lineage` | `sdk-js/src/lineage.js` | Lineage standalone checks + report-only linkage walk |
| `capsule.envelope` | `sdk-js/src/envelope.js` | Envelope build + sign + verify |
| `capsule.builder` | `sdk-js/src/builder.js` | CapsuleBuilder (plain + encrypted multi-recipient) |
| `capsule.reader` | `sdk-js/src/reader.js` | CapsuleReader (plain + decrypt) |
| `capsule.profiles` | `sdk-js/src/profiles.js` | Supported-profile table + the open-stage profile gate |
| `capsule.verifier` | `sdk-js/src/verifier.js` | verify_capsule (L2 plain, L2 encrypted-aware, L3) |

## License

MIT. See [../LICENSE](../LICENSE).
