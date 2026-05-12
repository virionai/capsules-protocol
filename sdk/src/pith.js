// Pith — context-style discipline for capsule narrative fields.
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
// Applied automatically by CapsuleBuilder.appendEvent() to event
// payload fields commonly used for narrative:
//   - payload.summary
//   - payload.statement
//   - payload.note
//   - payload.open_items[].item
//   - payload.decisions[].text
//   - payload.milestones[].text
//
// Pass { pith: false } to appendEvent() to opt out, or call
// compressEventPayload() / compressText() directly.

export const PITH_VERSION = "0.6";
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
 * Return a deep-cloned copy of `payload` with known narrative fields
 * normalized. Non-narrative fields (numbers, IDs, hashes, JSON
 * structures) are preserved verbatim.
 */
export function compressEventPayload(payload, options = {}) {
  const copy = cloneJson(payload);
  if (!isRecord(copy)) return copy;
  compressStringField(copy, "summary", options);
  compressStringField(copy, "statement", options);
  compressStringField(copy, "note", options);
  compressTextListField(copy, "open_items", "item", options);
  compressTextListField(copy, "decisions", "text", options);
  compressTextListField(copy, "milestones", "text", options);
  return copy;
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

function firstSentences(input, maxSentences) {
  if (input.length === 0) return input;
  const matches = input.match(/[^.!?]+(?:[.!?]+|$)/g);
  if (!matches) return input;
  const sentences = matches.map((s) => s.trim()).filter((s) => s.length > 0);
  if (sentences.length <= maxSentences) return input;
  return sentences.slice(0, maxSentences).join(" ");
}

function truncateAtWordBoundary(input, maxChars) {
  if (input.length <= maxChars) return input;
  if (maxChars <= ELLIPSIS.length) return ELLIPSIS.slice(0, maxChars);

  const limit = maxChars - ELLIPSIS.length;
  const prefix = input.slice(0, limit);
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

function positiveIntegerOrDefault(value, fallback) {
  return Number.isInteger(value) && value > 0 ? value : fallback;
}

function compressStringField(record, key, options) {
  if (typeof record[key] !== "string") return;
  record[key] = compressText(record[key], options).text;
}

function compressTextListField(record, listKey, textKey, options) {
  const list = record[listKey];
  if (!Array.isArray(list)) return;
  for (const entry of list) {
    if (isRecord(entry)) compressStringField(entry, textKey, options);
  }
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
