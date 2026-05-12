# Capsule v0.6 conformance report

**Generated:** 2026-05-12T02:47:04.589Z  
**Node:** v22.14.0  
**Platform:** darwin  
**Harness:** v0.1.0  
**Overall status:** PASS · 7/7 targets passed · 1.5s total

## Targets

### [PASS] sdk-js — @capsule/sdk-v0.6-prototype
- Language: javascript · Kind: sdk
- Test command: `npm test` (cwd: `sdk`)
- Install: skipped (cached) · Test duration: 214ms · Exit code: 0
- Tests: 20 passed of 20
- Note: install skipped: node_modules present and lockfile unchanged

### [PASS] example-symptom-tracker — symptom-tracker
- Language: javascript · Kind: example
- Test command: `npm test` (cwd: `examples/symptom-tracker`)
- Install: skipped (cached) · Test duration: 174ms · Exit code: 0
- Sealed capsule: 6,986 bytes (`examples/symptom-tracker/output/symptom-tracker.capsule`)
- Note: install skipped: node_modules present and lockfile unchanged

### [PASS] example-medical-journal — medical-journal
- Language: javascript · Kind: example
- Test command: `npm test` (cwd: `examples/medical-journal`)
- Install: skipped (cached) · Test duration: 179ms · Exit code: 0
- Sealed capsule: 18,918 bytes (`examples/medical-journal/output/medical-journal.capsule`)
- Note: install skipped: node_modules present and lockfile unchanged

### [PASS] example-tamper-detection — tamper-detection
- Language: javascript · Kind: example
- Test command: `npm run build && npm run verify` (cwd: `examples/tamper-detection`)
- Install: skipped (cached) · Test duration: 317ms · Exit code: 0
- Sealed capsule: 4,493 bytes (`examples/tamper-detection/output/clean.capsule`)
- Note: install skipped: node_modules present and lockfile unchanged

### [PASS] example-business-dr — business-dr
- Language: javascript · Kind: example
- Test command: `npm test` (cwd: `examples/business-dr`)
- Install: skipped (cached) · Test duration: 208ms · Exit code: 0
- Sealed capsule: 25,386 bytes (`examples/business-dr/output/business-dr-plain.capsule`)
- Note: install skipped: node_modules present and lockfile unchanged

### [PASS] example-family-dr — family-dr
- Language: javascript · Kind: example
- Test command: `npm test` (cwd: `examples/family-dr`)
- Install: skipped (cached) · Test duration: 186ms · Exit code: 0
- Sealed capsule: 35,167 bytes (`examples/family-dr/output/family-dr.capsule`)
- Note: install skipped: node_modules present and lockfile unchanged

### [PASS] example-town-dr — town-dr
- Language: javascript · Kind: example
- Test command: `npm test` (cwd: `examples/town-dr`)
- Install: skipped (cached) · Test duration: 186ms · Exit code: 0
- Sealed capsule: 36,778 bytes (`examples/town-dr/output/town-dr.capsule`)
- Note: install skipped: node_modules present and lockfile unchanged
