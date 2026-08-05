// Pith — authoring-layer normalizer for capsule narrative fields.
//
// This is a *normalizer*, not "compression" in the
// information-theoretic sense. It deterministically rewrites a small
// grammar of narrative fields (whitespace normalization, first-N
// sentences, word-boundary truncation with ellipsis) so that cold-
// reading LLMs absorb a consistent, terse context faster.
//
// The discipline is the product. The reference implementation is a
// helper for the discipline. An LLM applying Pith *style* produces
// richer compression than this library can; this library guarantees
// that fields written without LLM judgment still come out terse and
// regular.
//
// Pith is OPT-IN at the builder: pass { pith: true } to the
// CapsuleBuilder constructor (or per event) to have appendEvent()
// normalize the narrative payload fields below. An author who writes
// prose gets their prose — lossy normalization is never a default,
// because the rewrite lands inside the hash chain where the original
// is not preserved (ROADMAP: Pith is an authoring/profile discipline,
// not a protocol requirement). When normalization DID change a field,
// the builder records it in the event's `pith_normalized_fields`
// member (spec/chain.md), so the rewrite is discoverable, not silent.
//
// Narrative fields the normalizer targets:
//   - payload.summary
//   - payload.statement
//   - payload.note
//   - payload.open_items[].item
//   - payload.decisions[].text
//   - payload.milestones[].text
//
// MEANING PRESERVATION. The v0.6 splitter treated every [.!?] as a
// sentence boundary, so a dot inside an identifier (ledger.entry_audit)
// or a decimal (12.4k) fragmented the sentence, burned the sentence
// budget, and silently deleted trailing sentences — technical prose
// was corrupted inside the hash chain. The scanner below only ends a
// sentence at a terminator that is followed by whitespace (or end of
// input), never mid-token, and errs toward keeping text: dropping a
// real boundary merges two sentences (more text survives); inventing
// one deletes content. Selection cuts the original string at sentence
// ends — kept text is byte-identical to the input.

import { CURRENT_VERSION } from "./versions.js";

// Pith is versioned with the spec (never a separate literal — a second
// copy is exactly how a bump leaves a stale era behind).
export const PITH_VERSION = CURRENT_VERSION;
const DEFAULT_MAX_CHARS = 280;
const DEFAULT_MAX_SENTENCES = 3;
const ELLIPSIS = "…";

/**
 * compressText(input, options) -> { text, changed, version }
 *
 * options:
 *   maxChars:     number (default 280) — output length cap, including ellipsis
 *   maxSentences: number (default 3)   — sentences kept before length cap
 */
export function compressText(input, options = {}) {
  if (typeof input !== "string") {
    throw new TypeError("compressText: input must be a string");
  }
  const maxChars = positiveIntegerOrDefault(options.maxChars, DEFAULT_MAX_CHARS);
  const maxSentences = positiveIntegerOrDefault(options.maxSentences, DEFAULT_MAX_SENTENCES);

  const normalized = normalizeWhitespace(input);
  const trimmed = firstSentences(normalized, maxSentences);
  const text = truncateAtWordBoundary(trimmed, maxChars);

  return {
    text,
    changed: text !== input,
    version: PITH_VERSION,
  };
}

/**
 * Deep-clone `payload`, normalize the known narrative fields, and report
 * which top-level payload members actually changed.
 *
 * Returns { payload, normalizedFields } where normalizedFields is a list
 * of paths in the spec/chain.md payload-path grammar ("payload.summary",
 * "payload.open_items", ...) naming exactly the members whose text the
 * normalizer rewrote. Non-narrative fields (numbers, IDs, hashes, JSON
 * structures) are preserved verbatim and never reported.
 */
export function normalizeEventPayload(payload, options = {}) {
  const copy = cloneJson(payload);
  const normalizedFields = [];
  if (!isRecord(copy)) return { payload: copy, normalizedFields };
  for (const key of ["summary", "statement", "note"]) {
    if (compressStringField(copy, key, options)) normalizedFields.push(`payload.${key}`);
  }
  for (const [listKey, textKey] of [
    ["open_items", "item"],
    ["decisions", "text"],
    ["milestones", "text"],
  ]) {
    if (compressTextListField(copy, listKey, textKey, options)) {
      normalizedFields.push(`payload.${listKey}`);
    }
  }
  return { payload: copy, normalizedFields };
}

/**
 * Return a deep-cloned copy of `payload` with known narrative fields
 * normalized. Non-narrative fields (numbers, IDs, hashes, JSON
 * structures) are preserved verbatim. (normalizeEventPayload without
 * the change report.)
 */
export function compressEventPayload(payload, options = {}) {
  return normalizeEventPayload(payload, options).payload;
}

// ---------- internals ----------

function normalizeWhitespace(input) {
  return input
    .replace(/\r\n?/g, "\n")
    .split("\n")
    .map((line) => line.replace(/[\t ]+/g, " ").trim())
    .filter((line) => line.length > 0)
    .join(" ");
}

// Fullwidth terminators end a sentence unconditionally: they never
// appear inside identifiers, decimals, or abbreviations.
const CJK_TERMINATORS = new Set(["。", "！", "？", "｡"]); // 。 ！ ？ ｡
// Closing quotes/brackets that stay attached to the sentence they close.
const SENTENCE_CLOSERS = new Set(['"', "'", ")", "]", "}", "»", "’", "”"]);
// Opening punctuation stripped from a token before the abbreviation check.
const TOKEN_OPENERS = new Set(['"', "'", "(", "[", "{", "«", "‘", "“"]);
// Common abbreviations whose trailing dot is not a sentence boundary.
// Kept deliberately small and technical-prose-oriented; a miss merely
// merges two sentences (keeps more text), never deletes content.
const ABBREVIATIONS = new Set([
  "e.g", "i.e", "eg", "ie", "etc", "vs", "cf", "ca", "al", "approx",
  "no", "nr", "fig", "figs", "eq", "sec", "ver", "rev", "resp",
  "dr", "mr", "mrs", "ms", "prof", "st", "jr", "sr", "dept", "inc", "ltd", "co",
]);

const LOWERCASE_LETTER = /\p{Ll}/u;

function isWhitespace(ch) {
  return /\s/u.test(ch);
}

/**
 * Exclusive end offsets of each sentence in `input` (whitespace-
 * normalized text). A sentence ends at:
 *   - a fullwidth CJK terminator (plus any attached closers), always; or
 *   - an ASCII [.!?]+ run (plus any attached closers) that is followed
 *     by whitespace or end of input, where the next non-space character
 *     is not a lowercase letter, and — for a single '.' — the preceding
 *     token is neither a known abbreviation nor a single-letter initial.
 * A dot inside a token (identifier, decimal, version, URL) is never
 * followed by whitespace, so it can never end a sentence.
 */
function sentenceEndOffsets(input) {
  const offsets = [];
  const n = input.length;
  let i = 0;
  while (i < n) {
    const ch = input[i];
    if (CJK_TERMINATORS.has(ch)) {
      let j = i + 1;
      while (j < n && (CJK_TERMINATORS.has(input[j]) || SENTENCE_CLOSERS.has(input[j]))) j++;
      offsets.push(j);
      i = j;
      continue;
    }
    if (ch === "." || ch === "!" || ch === "?") {
      let j = i + 1;
      while (j < n && (input[j] === "." || input[j] === "!" || input[j] === "?")) j++;
      const runLength = j - i;
      let k = j;
      while (k < n && SENTENCE_CLOSERS.has(input[k])) k++;
      if (k < n && !isWhitespace(input[k])) {
        i = j; // mid-token dot (a.b, 12.4, v0.7, example.com) — not a boundary
        continue;
      }
      let m = k;
      while (m < n && isWhitespace(input[m])) m++;
      if (m < n && LOWERCASE_LETTER.test(String.fromCodePoint(input.codePointAt(m)))) {
        i = j; // lowercase continuation — err toward keeping one sentence
        continue;
      }
      if (runLength === 1 && ch === "." && precedingTokenBlocksBoundary(input, i)) {
        i = j; // abbreviation ("e.g.", "etc.") or initial ("J.")
        continue;
      }
      offsets.push(k);
      i = k;
      continue;
    }
    i++;
  }
  if (offsets.length === 0 || offsets[offsets.length - 1] < n) {
    offsets.push(n); // trailing unterminated text is the final sentence
  }
  return offsets;
}

/** True when the token ending at `dotIndex` is an abbreviation or initial. */
function precedingTokenBlocksBoundary(input, dotIndex) {
  let start = dotIndex;
  while (start > 0 && !isWhitespace(input[start - 1])) start--;
  let token = input.slice(start, dotIndex);
  while (token.length > 0 && TOKEN_OPENERS.has(token[0])) token = token.slice(1);
  if (token.length === 0) return false;
  if (/^[A-Z]$/.test(token)) return true; // "J." in "J. Smith"
  return ABBREVIATIONS.has(token.toLowerCase());
}

function firstSentences(input, maxSentences) {
  if (input.length === 0) return input;
  const ends = sentenceEndOffsets(input);
  if (ends.length <= maxSentences) return input;
  // Cut the ORIGINAL string at the Nth sentence end: kept text is
  // byte-identical to the input (no re-joining, no inserted spaces).
  return input.slice(0, ends[maxSentences - 1]).trimEnd();
}

function truncateAtWordBoundary(input, maxChars) {
  if (input.length <= maxChars) return input;
  // maxChars is a positive integer and ELLIPSIS is one UTF-16 code unit,
  // so this branch is only reachable with maxChars === 1: there is no room
  // for content, only the ellipsis itself.
  if (maxChars <= ELLIPSIS.length) return ELLIPSIS;

  const limit = maxChars - ELLIPSIS.length;
  const prefix = sliceAtCodePointBoundary(input, limit);
  const trimmedPrefix = prefix.trimEnd();
  const lastSpace = trimmedPrefix.lastIndexOf(" ");
  const minimumUsefulBoundary = Math.floor(limit * 0.6);
  const bounded =
    prefix.length !== trimmedPrefix.length
      ? trimmedPrefix
      : lastSpace >= minimumUsefulBoundary
        ? trimmedPrefix.slice(0, lastSpace)
        : trimmedPrefix;
  const cleaned = bounded.replace(/[\s,;:.!?-]+$/u, "");
  return `${cleaned.length > 0 ? cleaned : trimmedPrefix}${ELLIPSIS}`;
}

/**
 * `input.slice(0, limit)` cuts UTF-16 code units. When the code unit at
 * `limit - 1` is a high surrogate its low surrogate lives at `limit`, so a
 * naive slice ends in a lone surrogate — text that is no longer well-formed
 * Unicode and that the JCS acceptance boundary rejects at seal time
 * (spec/canonicalization.md). Drop the straddling unit instead.
 *
 * `limit` is always >= 1 here because the maxChars <= ELLIPSIS.length case
 * returns earlier.
 */
function sliceAtCodePointBoundary(input, limit) {
  if (limit >= input.length) return input;
  const unit = input.charCodeAt(limit - 1);
  if (unit >= 0xd800 && unit <= 0xdbff) return input.slice(0, limit - 1);
  return input.slice(0, limit);
}

function positiveIntegerOrDefault(value, fallback) {
  return Number.isInteger(value) && value > 0 ? value : fallback;
}

/** Normalize record[key] in place; true when the text actually changed. */
function compressStringField(record, key, options) {
  if (typeof record[key] !== "string") return false;
  const before = record[key];
  record[key] = compressText(before, options).text;
  return record[key] !== before;
}

/** Normalize entry[textKey] across a list; true when any entry changed. */
function compressTextListField(record, listKey, textKey, options) {
  const list = record[listKey];
  if (!Array.isArray(list)) return false;
  let changed = false;
  for (const entry of list) {
    if (isRecord(entry) && compressStringField(entry, textKey, options)) changed = true;
  }
  return changed;
}

function cloneJson(value) {
  if (Array.isArray(value)) return value.map((entry) => cloneJson(entry));
  if (isRecord(value)) {
    const out = {};
    for (const [k, v] of Object.entries(value)) out[k] = cloneJson(v);
    return out;
  }
  return value;
}

function isRecord(value) {
  if (value === null || typeof value !== "object") return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}
