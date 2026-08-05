// Vector-driven check that object-member ordering matches the normative
// JCS vectors in spec/vectors/jcs-key-order.json.
//
// RFC 8785 §3.2.3 sorts members on their UTF-16 code-unit sequences. This
// lane gets that for free — `a < b` on a JS string IS UTF-16 order — so
// these vectors are the oracle's own regression pin. Mirrors the Python
// test_jcs_key_order_registry, the Rust jcs_key_order_registry, the Swift
// testJcsKeyOrderRegistry, and the Kotlin jcsKeyOrderRegistry.

import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

import { bytesToHex, jcs, sha256 } from "../src/canonical.js";

const here = dirname(fileURLToPath(import.meta.url));
const vectorsPath = join(here, "..", "..", "spec", "vectors", "jcs-key-order.json");

test("JCS object-member ordering matches spec vectors", () => {
  const { vectors } = JSON.parse(readFileSync(vectorsPath, "utf8"));
  assert.ok(vectors.length > 0, "vector file is empty");
  for (const v of vectors) {
    const obj = {};
    v.keys.forEach((k, i) => {
      obj[k] = i;
    });
    const canonical = jcs(obj);
    assert.equal(bytesToHex(canonical), v.canonical_utf8_hex, v.name);
    assert.equal(bytesToHex(sha256(canonical)), v.sha256_hex, v.name);
    const order = Object.keys(JSON.parse(Buffer.from(canonical).toString("utf8")));
    assert.deepEqual(order, v.expected_key_order, v.name);
  }
});
