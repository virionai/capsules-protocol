# Security Policy

## Reporting a vulnerability

Please **do not** open a public GitHub issue for a suspected security
vulnerability. Email instead:

- **Primary:** `security@virion.ai`
- **Fallback (if the above bounces):** `josh@virion.ai`

Include enough detail to reproduce: affected SDK / spec version,
reproducer steps or test vector, and your assessment of impact.

A PGP key for encrypted reports is TBD. Until it is published, please
do not include exploit payloads or sensitive proof-of-concept material
in the initial email; we will coordinate a secure channel before you
send anything sensitive.

## Disclosure

We follow a **90-day coordinated disclosure** default. The clock starts
when we acknowledge your report. We will:

1. Acknowledge receipt within five business days.
2. Confirm the vulnerability (or push back with rationale) within
   fifteen business days.
3. Work with you on a fix and a coordinated public disclosure date,
   normally within ninety days of acknowledgement.
4. Credit you in the release notes and CHANGELOG, unless you prefer
   to remain anonymous.

If we have not responded within five business days, please re-send
the report and CC `josh@virion.ai`. If we have not shipped a fix or
agreed on an extended timeline within ninety days, you may disclose
publicly.

## Scope

In scope:

- The Capsule v0.6 format and its specification (`spec/`).
- Reference SDKs in this repository (`sdk-js/`, `sdk-py/`,
  `sdk-kotlin/`, `sdk-swift/`).
- The Rust verifier (`verifier-rust/`) and CLI (`CLI/`).
- The conformance harness (`tools/run-conformance.mjs`).

Out of scope:

- Example capsules in the sibling
  [`virionai/capsules-examples`](https://github.com/virionai/capsules-examples)
  repo — please report those there.
- Issues in third-party dependencies; please report upstream first.

We deeply appreciate your work — thank you for keeping Capsule users
safe.
