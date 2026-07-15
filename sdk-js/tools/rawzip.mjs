// rawzip.mjs — minimal raw ZIP writer for crafting HOSTILE test archives.
//
// The production packer (src/zip.js packZip) refuses to write unsafe
// entries, so strictness tests and the malformed-layout vector generator
// need a writer with no guardrails: duplicate names, parent-traversal and
// absolute paths, DEFLATE compression, symlink mode bits. Never use this
// to produce a real capsule.

import { deflateRawSync } from "node:zlib";

const LFH_SIG = 0x04034b50;
const CDH_SIG = 0x02014b50;
const EOCD_SIG = 0x06054b50;

// Fixed DOS timestamp: 1980-01-01T00:00:00 (the ZIP epoch), matching the
// deterministic packer.
const DOS_TIME = 0;
const DOS_DATE = (0 << 9) | (1 << 5) | 1;

const CRC_TABLE = (() => {
  const t = new Uint32Array(256);
  for (let n = 0; n < 256; n++) {
    let c = n;
    for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    t[n] = c >>> 0;
  }
  return t;
})();

function crc32(buf) {
  let c = 0xffffffff;
  for (let i = 0; i < buf.length; i++) c = CRC_TABLE[(c ^ buf[i]) & 0xff] ^ (c >>> 8);
  return (c ^ 0xffffffff) >>> 0;
}

/**
 * Write a ZIP from entry descriptors, verbatim and in order:
 *   { name: string, data: Buffer|Uint8Array|string,
 *     method?: 0 (STORED, default) | 8 (DEFLATE),
 *     mode?: number  // Unix mode bits for external attrs, e.g. 0o120777
 *   }
 * Returns Buffer of the archive bytes. No path safety, no dedup.
 */
export function writeRawZip(entries) {
  const locals = [];
  const centrals = [];
  let offset = 0;

  for (const e of entries) {
    const nameBytes = Buffer.from(e.name, "utf8");
    const data = Buffer.isBuffer(e.data) ? e.data : Buffer.from(e.data ?? "");
    const method = e.method ?? 0;
    const crc = crc32(data);
    const body = method === 8 ? deflateRawSync(data) : data;
    const extAttrs = e.mode !== undefined ? (e.mode << 16) >>> 0 : 0;

    const lfh = Buffer.alloc(30);
    lfh.writeUInt32LE(LFH_SIG, 0);
    lfh.writeUInt16LE(20, 4); // version needed
    lfh.writeUInt16LE(0, 6); // flags
    lfh.writeUInt16LE(method, 8);
    lfh.writeUInt16LE(DOS_TIME, 10);
    lfh.writeUInt16LE(DOS_DATE, 12);
    lfh.writeUInt32LE(crc, 14);
    lfh.writeUInt32LE(body.length, 18);
    lfh.writeUInt32LE(data.length, 22);
    lfh.writeUInt16LE(nameBytes.length, 26);
    lfh.writeUInt16LE(0, 28); // extra len
    locals.push(lfh, nameBytes, body);

    const cdh = Buffer.alloc(46);
    cdh.writeUInt32LE(CDH_SIG, 0);
    cdh.writeUInt16LE((3 << 8) | 20, 4); // made by: Unix, v2.0
    cdh.writeUInt16LE(20, 6); // version needed
    cdh.writeUInt16LE(0, 8); // flags
    cdh.writeUInt16LE(method, 10);
    cdh.writeUInt16LE(DOS_TIME, 12);
    cdh.writeUInt16LE(DOS_DATE, 14);
    cdh.writeUInt32LE(crc, 16);
    cdh.writeUInt32LE(body.length, 20);
    cdh.writeUInt32LE(data.length, 24);
    cdh.writeUInt16LE(nameBytes.length, 28);
    cdh.writeUInt16LE(0, 30); // extra len
    cdh.writeUInt16LE(0, 32); // comment len
    cdh.writeUInt16LE(0, 34); // disk number
    cdh.writeUInt16LE(0, 36); // internal attrs
    cdh.writeUInt32LE(extAttrs, 38);
    cdh.writeUInt32LE(offset, 42);
    centrals.push(cdh, nameBytes);

    offset += 30 + nameBytes.length + body.length;
  }

  const cd = Buffer.concat(centrals);
  const eocd = Buffer.alloc(22);
  eocd.writeUInt32LE(EOCD_SIG, 0);
  eocd.writeUInt16LE(0, 4); // disk number
  eocd.writeUInt16LE(0, 6); // cd start disk
  eocd.writeUInt16LE(entries.length, 8);
  eocd.writeUInt16LE(entries.length, 10);
  eocd.writeUInt32LE(cd.length, 12);
  eocd.writeUInt32LE(offset, 16);
  eocd.writeUInt16LE(0, 20); // comment len

  return Buffer.concat([...locals, cd, eocd]);
}
