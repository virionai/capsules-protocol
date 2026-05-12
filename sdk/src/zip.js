// Deterministic ZIP packing/unpacking via JSZip.
// Determinism is achieved by sorted paths and fixed timestamps.
//
// We reject unsafe entries on read: absolute paths, ".." segments,
// NUL bytes, symlinks. ZIP-slip protection.

import JSZip from "jszip";

const FIXED_DATE = new Date(Date.UTC(1980, 0, 1, 0, 0, 0));
const MAX_ENTRIES = 10_000;
const MAX_TOTAL_BYTES = 1024 * 1024 * 1024; // 1 GiB

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
