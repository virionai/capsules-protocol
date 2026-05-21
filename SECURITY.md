# Security Policy

## Reporting a vulnerability

Until Capsule reaches a published v1 specification, report suspected
security issues as GitHub issues in this repository:

- Open a new issue: <https://github.com/virionai/capsules-protocol/issues>
- Use a clear title such as `security: verifier accepts mismatched manifest hash`.
- Include the affected SDK / spec version, reproducer steps or test vector,
  and your assessment of impact.

Do not post private keys, live credentials, private customer data, or
weaponized exploit payloads in a public issue. If the report requires
sensitive material, open the issue with a minimal public reproduction and
state that a private artifact is available on request.

## Disclosure

During the pre-v1 period, security issues are handled in the open by default
so the protocol design can be reviewed and corrected publicly. We will:

1. Acknowledge receipt within five business days.
2. Confirm the vulnerability (or push back with rationale) within
   fifteen business days.
3. Work in the issue or linked PR on a fix, test, and spec clarification.
4. Credit you in the release notes and CHANGELOG, unless you prefer
   to remain anonymous.

After v1 is published, this policy will move to a private coordinated
disclosure process.

## Scope

In scope:

- The Capsule v0.6 format and its specification (`spec/`).
- Reference SDKs in this repository (`sdk-js/`, `sdk-py/`,
  `sdk-kotlin/`, `sdk-swift/`).
- The Rust verifier (`verifier-rust/`) and CLI (`cli/`).
- The conformance harness (`tools/run-conformance.mjs`).

We deeply appreciate your work — thank you for keeping Capsule users
safe.
