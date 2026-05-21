// Deterministic ZIP STORED writer + minimal reader. Mirrors the JavaScript
// reference SDK so the bytes produced here verify under verifyCapsule.

import Foundation

public enum CapsuleZip {
    private static let DOS_TIME: UInt16 = 0
    private static let DOS_DATE: UInt16 = 0x0021 // 1980-01-01
    private static let MAX_ENTRIES = 10_000

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

    public static func unpack(_ bytes: Data) throws -> [(path: String, data: Data)] {
        guard bytes.count >= 22 else { throw CapsuleError.malformed("zip too small") }
        // Find EOCD signature scanning from the end.
        var eocd = -1
        let sig: [UInt8] = [0x50, 0x4b, 0x05, 0x06]
        let bytesArr = [UInt8](bytes)
        if bytesArr.count >= 22 {
            var i = bytesArr.count - 22
            while i >= 0 {
                if bytesArr[i] == sig[0] && bytesArr[i+1] == sig[1] &&
                   bytesArr[i+2] == sig[2] && bytesArr[i+3] == sig[3] {
                    eocd = i; break
                }
                i -= 1
            }
        }
        guard eocd >= 0 else { throw CapsuleError.malformed("zip: EOCD not found") }
        let cdCount = Int(read16(bytesArr, eocd + 10))
        let cdOffset = Int(read32(bytesArr, eocd + 16))
        var p = cdOffset
        var out: [(String, Data)] = []
        for _ in 0..<cdCount {
            guard read32(bytesArr, p) == 0x02014b50 else {
                throw CapsuleError.malformed("zip: bad CD signature")
            }
            let compression = read16(bytesArr, p + 10)
            let compSize = Int(read32(bytesArr, p + 20))
            let uncompSize = Int(read32(bytesArr, p + 24))
            let nameLen = Int(read16(bytesArr, p + 28))
            let extraLen = Int(read16(bytesArr, p + 30))
            let commentLen = Int(read16(bytesArr, p + 32))
            let localOff = Int(read32(bytesArr, p + 42))
            guard compression == 0 else { throw CapsuleError.malformed("zip: only STORED supported") }
            guard compSize == uncompSize else { throw CapsuleError.malformed("zip: STORED size mismatch") }
            let name = String(decoding: Array(bytesArr[(p + 46)..<(p + 46 + nameLen)]), as: UTF8.self)
            try assertSafePath(name)
            p += 46 + nameLen + extraLen + commentLen

            guard read32(bytesArr, localOff) == 0x04034b50 else {
                throw CapsuleError.malformed("zip: bad LFH signature")
            }
            let lfhNameLen = Int(read16(bytesArr, localOff + 26))
            let lfhExtraLen = Int(read16(bytesArr, localOff + 28))
            let dataOff = localOff + 30 + lfhNameLen + lfhExtraLen
            let data = Data(bytesArr[dataOff..<(dataOff + compSize)])
            out.append((name, data))
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
    private static func read16(_ b: [UInt8], _ off: Int) -> UInt16 {
        UInt16(b[off]) | (UInt16(b[off + 1]) << 8)
    }
    private static func read32(_ b: [UInt8], _ off: Int) -> UInt32 {
        UInt32(b[off])
            | (UInt32(b[off + 1]) << 8)
            | (UInt32(b[off + 2]) << 16)
            | (UInt32(b[off + 3]) << 24)
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
