// Deterministic ZIP packing/unpacking via JSZip.
// Determinism is achieved by sorted paths and fixed timestamps.
//
// We reject unsafe entries on read: absolute paths, ".." segments,
// NUL bytes, symlinks, duplicate entry names, and non-STORED
// compression. ZIP-slip protection plus parser-differential protection
// (JSZip alone would silently inflate DEFLATE entries and let the last
// duplicate name win, so those checks run over the raw central
// directory before JSZip parses anything).

import JSZip from "jszip";

const FIXED_DATE = new Date(Date.UTC(1980, 0, 1, 0, 0, 0));
const MAX_ENTRIES = 10_000;
const MAX_TOTAL_BYTES = 1024 * 1024 * 1024; // 1 GiB

const EOCD_SIG = 0x06054b50; // end of central directory
const CDH_SIG = 0x02014b50; // central directory file header
const EOCD_MIN = 22; // EOCD size with empty comment
const MAX_COMMENT = 0xffff;

/**
 * Minimal raw central-directory scan, independent of JSZip.
 *
 * Returns [{ name, method, externalAttrs }] for every central-directory
 * record (including directory markers). Throws on structural problems:
 * missing/truncated EOCD or central directory, and ZIP64 sentinel values
 * (a capsule can never legitimately need ZIP64 under the 10,000-entry /
 * 1 GiB caps, so ZIP64 is rejected fail-closed rather than parsed).
 */
export function scanCentralDirectory(bytes) {
  const buf = Buffer.isBuffer(bytes)
    ? bytes
    : ArrayBuffer.isView(bytes)
      ? Buffer.from(bytes.buffer, bytes.byteOffset, bytes.byteLength)
      : Buffer.from(bytes);
  if (buf.length < EOCD_MIN) throw new Error("zip scan: too small to be a zip");

  // The EOCD is the LAST record; scan back over a possible trailing comment.
  let eocd = -1;
  const lowest = Math.max(0, buf.length - EOCD_MIN - MAX_COMMENT);
  for (let p = buf.length - EOCD_MIN; p >= lowest; p--) {
    if (buf.readUInt32LE(p) === EOCD_SIG) {
      eocd = p;
      break;
    }
  }
  if (eocd < 0) throw new Error("zip scan: end-of-central-directory not found");

  const totalEntries = buf.readUInt16LE(eocd + 10);
  const cdSize = buf.readUInt32LE(eocd + 12);
  const cdOffset = buf.readUInt32LE(eocd + 16);
  if (totalEntries === 0xffff || cdSize === 0xffffffff || cdOffset === 0xffffffff) {
    throw new Error("zip scan: ZIP64 archives are not supported");
  }
  if (totalEntries > MAX_ENTRIES) {
    throw new Error(`zip scan: too many entries (${totalEntries})`);
  }
  if (cdOffset + cdSize > eocd) {
    throw new Error("zip scan: central directory extends past EOCD");
  }

  const entries = [];
  let p = cdOffset;
  for (let i = 0; i < totalEntries; i++) {
    if (p + 46 > buf.length || buf.readUInt32LE(p) !== CDH_SIG) {
      throw new Error(`zip scan: truncated or malformed central directory at record ${i}`);
    }
    const method = buf.readUInt16LE(p + 10);
    const nameLen = buf.readUInt16LE(p + 28);
    const extraLen = buf.readUInt16LE(p + 30);
    const commentLen = buf.readUInt16LE(p + 32);
    const externalAttrs = buf.readUInt32LE(p + 38);
    if (p + 46 + nameLen > buf.length) {
      throw new Error(`zip scan: truncated entry name at record ${i}`);
    }
    const name = buf.toString("utf8", p + 46, p + 46 + nameLen);
    entries.push({ name, method, externalAttrs });
    p += 46 + nameLen + extraLen + commentLen;
  }
  return entries;
}

/**
 * Fail-closed strictness pass over the raw central directory. Rejects:
 *   - duplicate entry names (parser-differential: readers disagree on
 *     which copy wins, so a signed capsule must never contain one)
 *   - unsafe paths, checked on the RAW stored name (JSZip sanitizes
 *     names on load, which would hide e.g. a leading slash from the
 *     post-load check)
 *   - non-STORED compression (spec/format.md: STORED only)
 *   - symlink entries (Unix mode bits in external attrs)
 */
function assertStrictEntries(bytes) {
  const entries = scanCentralDirectory(bytes);
  const seen = new Set();
  for (const e of entries) {
    if (seen.has(e.name)) throw new Error(`zip unpack: duplicate entry: ${e.name}`);
    seen.add(e.name);
    assertSafePath(e.name);
    if (e.name.endsWith("/")) continue; // directory marker
    if (e.method !== 0) {
      throw new Error(`zip unpack: only STORED supported, got method ${e.method}: ${e.name}`);
    }
    const mode = (e.externalAttrs >>> 16) & 0xffff;
    if ((mode & 0o170000) === 0o120000) {
      throw new Error(`zip entry is a symlink: ${e.name}`);
    }
  }
}

/** files: Map<string, Uint8Array|Buffer>; returns Uint8Array (ZIP bytes). */
export async function packZip(files) {
  if (files.size > MAX_ENTRIES) throw new Error(`zip pack: too many entries (${files.size})`);
  const zip = new JSZip();
  const sorted = [...files.entries()].sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0));
  for (const [path, bytes] of sorted) {
    assertSafePath(path);
    zip.file(path, Buffer.from(bytes), {
      date: FIXED_DATE,
      createFolders: false,
      // STORED, no compression
      compression: "STORE",
    });
  }
  const out = await zip.generateAsync({
    type: "uint8array",
    compression: "STORE",
    streamFiles: false,
    platform: "UNIX",
  });
  return out;
}

/** bytes: Uint8Array; returns Map<path, Uint8Array> (sorted by path). */
export async function unpackZip(bytes) {
  assertStrictEntries(bytes);
  const zip = await JSZip.loadAsync(bytes, { checkCRC32: true });
  const out = new Map();
  let total = 0;
  let count = 0;
  const entries = Object.entries(zip.files);
  if (entries.length > MAX_ENTRIES) throw new Error(`zip unpack: too many entries (${entries.length})`);
  // Sort for stable iteration order
  entries.sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0));
  for (const [path, entry] of entries) {
    if (entry.dir) continue;
    assertSafePath(path);
    const data = await entry.async("uint8array");
    total += data.length;
    count += 1;
    if (count > MAX_ENTRIES) throw new Error("zip unpack: entry-count limit exceeded");
    if (total > MAX_TOTAL_BYTES) throw new Error("zip unpack: total-size limit exceeded");
    out.set(path, data);
  }
  return out;
}

function assertSafePath(p) {
  if (typeof p !== "string" || p.length === 0) throw new Error("zip path: empty or non-string");
  if (p.includes("\0")) throw new Error(`zip path contains NUL: ${JSON.stringify(p)}`);
  if (p.startsWith("/") || /^[A-Za-z]:[\\/]/.test(p)) {
    throw new Error(`zip path is absolute: ${p}`);
  }
  for (const segment of p.split(/[\\/]/)) {
    if (segment === "..") throw new Error(`zip path has parent traversal: ${p}`);
  }
}
