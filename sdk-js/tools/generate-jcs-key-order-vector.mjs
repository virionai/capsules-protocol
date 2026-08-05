#!/usr/bin/env node
// generate-jcs-key-order-vector.mjs
//
// Emits spec/vectors/jcs-key-order.json: normative object-member ordering
// vectors for RFC 8785 section 3.2.3, which sorts members on their UTF-16
// code-unit sequences.
//
// UTF-16 order is NOT Unicode code-point order. They disagree whenever a
// supplementary-plane key (>= U+10000, whose UTF-16 lead surrogate is
// 0xD800..0xDBFF) meets a BMP key in U+E000..U+FFFF: by code point the BMP
// key sorts first, by UTF-16 code units the supplementary key does. They
// also disagree with any normalization- or collation-aware comparator
// (e.g. Swift's `String <`), which reports canonically equivalent keys as
// equal and leaves their order unspecified.
//
// The reference lane (the `canonicalize` npm package used by
// sdk-js/src/canonical.js) is the oracle. Regeneration is an intentional
// spec change; review the byte-level diff.

import { writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { bytesToHex, jcs, sha256 } from "../src/canonical.js";

const __dirname = dirname(fileURLToPath(import.meta.url));
const VECTORS = join(__dirname, "..", "..", "spec", "vectors");

// Keys are spelled by code point so this source file stays pure ASCII and
// no key depends on how an editor re-encodes invisible characters.
const cp = (...codes) => String.fromCodePoint(...codes);

// Each case lists keys in *input* order. The object under test maps each
// key to its 0-based index in that list, so the serialized values make the
// resulting member order readable with no number-format interplay.
const CASES = [
  {
    name: "ascii-basic",
    note: "Sanity: plain ASCII keys, out of order on input.",
    keys: ["b", "a", "c"],
  },
  {
    name: "empty-and-prefix",
    note: "Empty key sorts first; a proper prefix sorts before its extension.",
    keys: ["aa", "", "a", "ab"],
  },
  {
    name: "escaped-chars-sort-on-raw-code-units",
    note:
      "Keys order by RAW code units, not by their escaped JSON spelling: " +
      "U+0001 < U+0022 (quote) < U+005C (backslash) < U+007E (tilde).",
    keys: [cp(0x7e), cp(0x5c), cp(0x22), cp(0x01)],
  },
  {
    name: "supplementary-vs-high-bmp",
    note:
      "THE divergence case, and the negative witness for code-point order. " +
      "U+1F600 encodes as D83D DE00, so it sorts BELOW U+E000 and U+FFFF in " +
      "UTF-16 order and ABOVE them in code-point order.",
    keys: [cp(0xffff), cp(0x1f600), cp(0xe000), "z"],
  },
  {
    name: "surrogate-boundary",
    note:
      "U+D7FF is the last BMP scalar below the surrogate block; U+10000 is " +
      "the first supplementary scalar (D800 DC00) and must sort between " +
      "U+D7FF and U+E000.",
    keys: [cp(0xe000), cp(0x10000), cp(0xd7ff)],
  },
  {
    name: "supplementary-vs-supplementary",
    note:
      "Two supplementary keys order by lead surrogate then trail surrogate, " +
      "which here agrees with code-point order.",
    keys: [cp(0x1f600), cp(0x10000), cp(0x10ffff)],
  },
  {
    name: "canonically-equivalent-keys-are-distinct",
    note:
      "Negative witness for collation-aware comparators. U+0065 U+0301 and " +
      "precomposed U+00E9 are distinct JSON members and must NOT compare " +
      "equal. UTF-16 puts 0x0065 before 0x00E9. A normalization- or " +
      "collation-aware comparator calls them equal and leaves the order " +
      "unspecified.",
    keys: [cp(0x00e9), cp(0x0065, 0x0301), "f"],
  },
  {
    name: "cjk-and-private-use",
    note:
      "Mixed BMP blocks plus a supplementary CJK ideograph (U+20000 -> " +
      "D840 DC00), which must sort below every U+E000..U+FFFF key.",
    keys: [cp(0xfb00), cp(0x20000), cp(0x4e00), cp(0xf8ff), "A"],
  },
];

function buildObject(keys) {
  const obj = {};
  keys.forEach((k, i) => {
    obj[k] = i;
  });
  return obj;
}

async function main() {
  const vectors = CASES.map((c) => {
    const canonical = jcs(buildObject(c.keys));
    const parsed = JSON.parse(Buffer.from(canonical).toString("utf8"));
    return {
      name: c.name,
      note: c.note,
      keys: c.keys,
      expected_key_order: Object.keys(parsed),
      canonical_utf8_hex: bytesToHex(canonical),
      sha256_hex: bytesToHex(sha256(canonical)),
    };
  });

  const doc = {
    meta: { kind: "jcs-key-order" },
    description:
      "RFC 8785 section 3.2.3 object-member ordering vectors. For each entry, " +
      "build a JSON object whose members are `keys` (in any insertion order), " +
      "each mapped to the integer index it has in `keys`, canonicalize it, and " +
      "reproduce `canonical_utf8_hex` byte-for-byte. Members MUST be sorted on " +
      "their UTF-16 code-unit sequences: not Unicode code-point order (the two " +
      "disagree once a supplementary-plane key meets a key in U+E000..U+FFFF) " +
      "and not a normalization- or collation-aware order (which can call " +
      "canonically equivalent keys equal). `expected_key_order` is the same " +
      "information in readable form; `sha256_hex` is SHA-256 over the bytes in " +
      "`canonical_utf8_hex`. The same ordering governs `content_index.files` " +
      "(a JSON array, so its order is inside the hashed bytes) and ZIP entry " +
      "order.",
    oracle:
      "Node.js with the `canonicalize` npm package, via sdk-js/src/canonical.js " +
      "(the JavaScript reference lane). Generated by " +
      "sdk-js/tools/generate-jcs-key-order-vector.mjs.",
    vectors,
  };

  // Emit pure ASCII. String#split("") yields UTF-16 code units, so
  // surrogate halves are escaped individually -- the six-character
  // backslash-u spelling every JSON parser recombines. Keeps the
  // checked-in vector file readable in diffs and immune to editor
  // re-encoding.
  const ascii = JSON.stringify(doc, null, 2)
    .split("")
    .map((ch) => {
      const code = ch.charCodeAt(0);
      return code > 0x7f ? "\\u" + code.toString(16).padStart(4, "0") : ch;
    })
    .join("");

  const out = join(VECTORS, "jcs-key-order.json");
  await writeFile(out, ascii + "\n", "utf8");
  console.log(`wrote ${out} (${vectors.length} vectors)`);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
