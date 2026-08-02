import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

import { jcs } from "../src/canonical.js";

const here = dirname(fileURLToPath(import.meta.url));
const vectorsPath = join(here, "..", "..", "spec", "vectors", "jcs-numbers.json");

test("JCS number serialization matches spec vectors", () => {
  const { vectors } = JSON.parse(readFileSync(vectorsPath, "utf8"));
  assert.ok(vectors.length > 0, "vector file is empty");
  for (const { ieee_hex, expected, accepted } of vectors) {
    const value = Buffer.from(ieee_hex, "hex").readDoubleBE(0);
    if (accepted === false) {
      // Outside the I-JSON acceptance boundary (spec/canonicalization.md):
      // `expected` records the layout Number::toString would produce, but
      // the value must never reach a canonical serialization.
      assert.throws(
        () => jcs(value),
        /integer outside IEEE-754 exact range/,
        `bits ${ieee_hex} must be rejected (would serialize as ${expected})`,
      );
      continue;
    }
    const got = Buffer.from(jcs(value)).toString("utf8");
    assert.equal(got, expected, `bits ${ieee_hex}`);
  }
});
