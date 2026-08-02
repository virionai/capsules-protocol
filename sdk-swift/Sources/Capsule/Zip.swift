// Deterministic ZIP STORED writer + minimal reader. Mirrors the JavaScript
// reference SDK so the bytes produced here verify under verifyCapsule.

import Foundation

public enum CapsuleZip {
    private static let DOS_TIME: UInt16 = 0
    private static let DOS_DATE: UInt16 = 0x0021 // 1980-01-01
    private static let MAX_ENTRIES = 10_000
    private static let EOCD_MIN = 22
    private static let MAX_COMMENT = 0xFFFF
    private static let EOCD_SIG: UInt32 = 0x0605_4b50
    private static let CDH_SIG: UInt32 = 0x0201_4b50
    private static let LFH_SIG: UInt32 = 0x0403_4b50

    public static func pack(_ files: [(path: String, data: Data)]) -> Data {
        precondition(files.count <= MAX_ENTRIES, "zip: too many entries")
        let entries = files.sorted { $0.path < $1.path }
        for e in entries { try! assertSafePath(e.path) }
        var out = Data()
        var localOffsets: [UInt32] = []
        for e in entries {
            let nameBytes = Data(e.path.utf8)
            let crc = crc32(e.data)
            localOffsets.append(UInt32(out.count))
            // Local file header
            out.append(le32(0x04034b50))
            out.append(le16(20))           // version needed
            out.append(le16(0))            // flags
            out.append(le16(0))            // compression (STORED)
            out.append(le16(DOS_TIME))
            out.append(le16(DOS_DATE))
            out.append(le32(crc))
            out.append(le32(UInt32(e.data.count)))
            out.append(le32(UInt32(e.data.count)))
            out.append(le16(UInt16(nameBytes.count)))
            out.append(le16(0))            // extra field length
            out.append(nameBytes)
            out.append(e.data)
        }
        let cdStart = UInt32(out.count)
        var cdSize: UInt32 = 0
        for (i, e) in entries.enumerated() {
            let nameBytes = Data(e.path.utf8)
            let crc = crc32(e.data)
            let cdEntryStart = out.count
            out.append(le32(0x02014b50))
            out.append(le16(20))           // version made by
            out.append(le16(20))           // version needed
            out.append(le16(0))            // flags
            out.append(le16(0))            // compression
            out.append(le16(DOS_TIME))
            out.append(le16(DOS_DATE))
            out.append(le32(crc))
            out.append(le32(UInt32(e.data.count)))
            out.append(le32(UInt32(e.data.count)))
            out.append(le16(UInt16(nameBytes.count)))
            out.append(le16(0))            // extra
            out.append(le16(0))            // comment length
            out.append(le16(0))            // disk number
            out.append(le16(0))            // internal attrs
            out.append(le32(0))            // external attrs
            out.append(le32(localOffsets[i]))
            out.append(nameBytes)
            cdSize += UInt32(out.count - cdEntryStart)
        }
        // EOCD
        out.append(le32(0x06054b50))
        out.append(le16(0))
        out.append(le16(0))
        out.append(le16(UInt16(entries.count)))
        out.append(le16(UInt16(entries.count)))
        out.append(le32(cdSize))
        out.append(le32(cdStart))
        out.append(le16(0))
        return out
    }

    /// Unpack a STORED-only ZIP.
    ///
    /// This function NEVER traps on input bytes. Every offset taken from
    /// the archive is attacker-controlled, so each one is bounds-checked
    /// before it indexes the byte array: a Swift out-of-range subscript is
    /// a `fatalError`, which no `do`/`catch` in `CapsuleVerifier` can
    /// contain, and would take the host process down with it. All
    /// structural violations throw `CapsuleError.malformed`.
    ///
    /// Mirrors `scanCentralDirectory` in `sdk-js/src/zip.js`: the central
    /// directory is walked by its declared byte size (not by the
    /// attacker-controlled EOCD record count) and ZIP64 sentinels are
    /// refused outright.
    public static func unpack(_ bytes: Data) throws -> [(path: String, data: Data)] {
        let b = [UInt8](bytes)
        guard b.count >= EOCD_MIN else { throw CapsuleError.malformed("zip too small") }

        // The EOCD is the LAST record; scan back over a possible trailing
        // comment. A signature-shaped byte sequence inside the comment is
        // not an EOCD unless its declared comment length lands exactly at
        // end-of-file.
        var eocd = -1
        let lowest = max(0, b.count - EOCD_MIN - MAX_COMMENT)
        var scan = b.count - EOCD_MIN
        while scan >= lowest {
            if peek32(b, scan) == EOCD_SIG,
               let commentLen = peek16(b, scan + 20),
               scan + EOCD_MIN + Int(commentLen) == b.count
            {
                eocd = scan
                break
            }
            scan -= 1
        }
        guard eocd >= 0 else { throw CapsuleError.malformed("zip: EOCD not found") }
        // Two EOCD signatures make the archive ambiguous across readers
        // (which record wins is library-dependent). Fail closed, as sdk-js
        // does, rather than pick one.
        var q = b.count - 4
        while q > eocd {
            if peek32(b, q) == EOCD_SIG {
                throw CapsuleError.malformed("zip: multiple end-of-central-directory records")
            }
            q -= 1
        }

        let cdCount = Int(try read16(b, eocd + 10))
        let cdSize = Int(try read32(b, eocd + 12))
        let cdOffset = Int(try read32(b, eocd + 16))
        // ZIP64 sentinels: a capsule can never legitimately need ZIP64
        // under the 10,000-entry / 1 GiB caps, so refuse rather than parse.
        guard cdCount != 0xFFFF, cdSize != 0xFFFF_FFFF, cdOffset != 0xFFFF_FFFF else {
            throw CapsuleError.malformed("zip: ZIP64 archives are not supported")
        }
        // Central-directory geometry must close exactly on the EOCD; this
        // is what makes every subsequent record offset in-bounds.
        guard cdOffset <= eocd, cdSize <= eocd, cdOffset + cdSize == eocd else {
            throw CapsuleError.malformed("zip: central directory does not end at EOCD")
        }

        let cdEnd = eocd
        var out: [(String, Data)] = []
        var p = cdOffset
        while p < cdEnd {
            guard p + 46 <= cdEnd else {
                throw CapsuleError.malformed(
                    "zip: truncated central-directory record \(out.count)")
            }
            let sig = try read32(b, p)
            guard sig == CDH_SIG else {
                throw CapsuleError.malformed("zip: bad CD signature at record \(out.count)")
            }
            let compression = try read16(b, p + 10)
            let compSize = Int(try read32(b, p + 20))
            let uncompSize = Int(try read32(b, p + 24))
            let nameLen = Int(try read16(b, p + 28))
            let extraLen = Int(try read16(b, p + 30))
            let commentLen = Int(try read16(b, p + 32))
            let localOff = Int(try read32(b, p + 42))
            guard compression == 0 else {
                throw CapsuleError.malformed("zip: only STORED supported")
            }
            guard compSize == uncompSize else {
                throw CapsuleError.malformed("zip: STORED size mismatch")
            }
            guard compSize != 0xFFFF_FFFF, localOff != 0xFFFF_FFFF else {
                throw CapsuleError.malformed("zip: ZIP64 archives are not supported")
            }
            let next = p + 46 + nameLen + extraLen + commentLen
            guard next <= cdEnd else {
                throw CapsuleError.malformed(
                    "zip: truncated central-directory record \(out.count)")
            }
            let name = String(decoding: b[(p + 46)..<(p + 46 + nameLen)], as: UTF8.self)
            try assertSafePath(name)
            p = next

            // Local header + entry data must live entirely before the
            // central directory.
            guard localOff + 30 <= cdOffset else {
                throw CapsuleError.malformed("zip: local header out of range for \(name)")
            }
            let lfhSig = try read32(b, localOff)
            guard lfhSig == LFH_SIG else {
                throw CapsuleError.malformed("zip: bad LFH signature for \(name)")
            }
            let lfhNameLen = Int(try read16(b, localOff + 26))
            let lfhExtraLen = Int(try read16(b, localOff + 28))
            let dataOff = localOff + 30 + lfhNameLen + lfhExtraLen
            guard dataOff <= cdOffset, compSize <= cdOffset - dataOff else {
                throw CapsuleError.malformed("zip: entry data out of range for \(name)")
            }
            out.append((name, Data(b[dataOff..<(dataOff + compSize)])))
        }
        return out
    }

    private static func assertSafePath(_ p: String) throws {
        guard !p.isEmpty else { throw CapsuleError.malformed("zip path: empty") }
        guard !p.contains("\0") else { throw CapsuleError.malformed("zip path: NUL") }
        guard !p.hasPrefix("/") else { throw CapsuleError.malformed("zip path: absolute") }
        for seg in p.split(whereSeparator: { $0 == "/" || $0 == "\\" }) {
            if seg == ".." { throw CapsuleError.malformed("zip path traversal") }
        }
    }

    // CRC-32 (poly 0xEDB88320) — standard ZIP CRC.
    private static let crcTable: [UInt32] = {
        var t = [UInt32](repeating: 0, count: 256)
        for n in 0..<256 {
            var c: UInt32 = UInt32(n)
            for _ in 0..<8 {
                c = (c & 1) != 0 ? (0xEDB88320 ^ (c >> 1)) : (c >> 1)
            }
            t[n] = c
        }
        return t
    }()
    public static func crc32(_ data: Data) -> UInt32 {
        var crc: UInt32 = 0xFFFFFFFF
        for b in data {
            crc = (crc >> 8) ^ crcTable[Int((crc ^ UInt32(b)) & 0xFF)]
        }
        return crc ^ 0xFFFFFFFF
    }

    private static func le16(_ v: UInt16) -> Data {
        Data([UInt8(v & 0xFF), UInt8((v >> 8) & 0xFF)])
    }
    private static func le32(_ v: UInt32) -> Data {
        Data([
            UInt8(v & 0xFF),
            UInt8((v >> 8) & 0xFF),
            UInt8((v >> 16) & 0xFF),
            UInt8((v >> 24) & 0xFF),
        ])
    }
    /// Bounds-checked little-endian reads. `peek*` return nil out of
    /// range (used by the EOCD scan, where misses are expected); `read*`
    /// throw, so a crafted offset surfaces as a malformed-capsule error
    /// instead of an array trap.
    private static func peek16(_ b: [UInt8], _ off: Int) -> UInt16? {
        guard off >= 0, off + 2 <= b.count else { return nil }
        return UInt16(b[off]) | (UInt16(b[off + 1]) << 8)
    }
    private static func peek32(_ b: [UInt8], _ off: Int) -> UInt32? {
        guard off >= 0, off + 4 <= b.count else { return nil }
        return UInt32(b[off])
            | (UInt32(b[off + 1]) << 8)
            | (UInt32(b[off + 2]) << 16)
            | (UInt32(b[off + 3]) << 24)
    }
    private static func read16(_ b: [UInt8], _ off: Int) throws -> UInt16 {
        guard let v = peek16(b, off) else {
            throw CapsuleError.malformed("zip: read past end of archive at \(off)")
        }
        return v
    }
    private static func read32(_ b: [UInt8], _ off: Int) throws -> UInt32 {
        guard let v = peek32(b, off) else {
            throw CapsuleError.malformed("zip: read past end of archive at \(off)")
        }
        return v
    }
}

public enum CapsuleError: Error, CustomStringConvertible {
    case malformed(String)
    case verification(String)
    public var description: String {
        switch self {
        case .malformed(let m): return "Capsule malformed: \(m)"
        case .verification(let m): return "Capsule verification failed: \(m)"
        }
    }
}
