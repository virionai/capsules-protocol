//! Deterministic STORED-only ZIP reader with safety checks.
//!
//! This is the read side of `sdk-js/src/zip.js`. The verifier reads `.capsule`
//! containers (which are ZIP archives) and must reject any entry that
//! violates the spec's safety properties:
//!
//! - empty / NUL-byte / absolute / drive-letter / parent-traversal paths
//! - symlink entries (Unix mode bits set to symlink)
//! - non-STORED compression (we only honor uncompressed entries; everything
//!   else makes archive bytes a function of the compressor's version, which
//!   defeats the spec's content-only-determinism contract)
//!
//! In addition, the reader caps the number of entries and total uncompressed
//! size so that a hostile capsule cannot exhaust memory. Per-entry
//! pre-allocation is also bounded — see the comment in [`unpack_zip`] near
//! the call to `read_to_end` — so that an attacker-declared `size()` of e.g.
//! `u64::MAX` cannot trick us into reserving multi-GiB ahead of read.
//!
//! On success, [`unpack_zip`] returns a [`BTreeMap`] keyed by path. The
//! `BTreeMap` is the contract: callers depend on stable, sorted iteration to
//! recompute hashes deterministically.
//!
//! See `spec/format.md` § "Container properties" for the canonical statement
//! of these rules.

use std::collections::BTreeMap;
use std::io::{Cursor, Read};

use thiserror::Error;
use zip::read::ZipArchive;
use zip::CompressionMethod;

/// Maximum number of entries the reader will accept. Mirrors the JS SDK.
pub const MAX_ENTRIES: usize = 10_000;

/// Maximum total uncompressed bytes the reader will accept. Mirrors the JS
/// SDK: 1 GiB. Enforced as data is read so a small archive header cannot
/// trick us into pre-allocating more than this bound.
pub const MAX_TOTAL_BYTES: u64 = 1024 * 1024 * 1024;

/// Why a path was rejected by the safety predicate.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum PathReason {
    /// Empty path string.
    #[error("path is empty")]
    Empty,
    /// Path contains a NUL byte.
    #[error("path contains a NUL byte")]
    NulByte,
    /// Path is absolute: starts with `/`, or matches `^[A-Za-z]:[\\/]`
    /// (Windows drive-letter form).
    #[error("path is absolute")]
    Absolute,
    /// Some path segment is `..`, which would let the entry escape its
    /// extraction root (ZIP-slip).
    #[error("path contains parent-traversal segment")]
    ParentTraversal,
    /// Entry's Unix mode marks it as a symlink.
    #[error("entry is a symlink")]
    Symlink,
}

/// Errors returned by [`unpack_zip`].
#[derive(Debug, Error)]
pub enum ZipError {
    /// Archive header / central-directory could not be parsed, or some other
    /// generic structural failure from the underlying ZIP library.
    #[error("invalid zip container: {0}")]
    InvalidContainer(String),

    /// Entry path failed [`PathReason`]'s safety predicate.
    #[error("unsafe zip entry path {path:?}: {reason}")]
    UnsafePath { path: String, reason: PathReason },

    /// Entry uses a compression method other than STORED (method 0). The raw
    /// 16-bit ZIP method code is included for diagnostics.
    #[error("unsupported compression for {path:?}: method {method}")]
    UnsupportedCompression { path: String, method: u16 },

    /// More than `MAX_ENTRIES` entries in the archive.
    #[error("too many entries: {0} (max {MAX_ENTRIES})")]
    TooManyEntries(usize),

    /// Total uncompressed bytes exceeds `MAX_TOTAL_BYTES`.
    #[error("archive too large: {total} bytes (max {MAX_TOTAL_BYTES})")]
    TooLarge { total: u64 },

    /// I/O error from the inner reader.
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

/// Validate `path` against the safety predicate. Returns a typed reason on
/// the first violation. Mirrors `assertSafePath` in `sdk-js/src/zip.js`.
fn check_safe_path(path: &str) -> Result<(), PathReason> {
    if path.is_empty() {
        return Err(PathReason::Empty);
    }
    if path.contains('\0') {
        return Err(PathReason::NulByte);
    }
    if path.starts_with('/') || is_drive_letter_absolute(path) {
        return Err(PathReason::Absolute);
    }
    for segment in path.split(['/', '\\']) {
        if segment == ".." {
            return Err(PathReason::ParentTraversal);
        }
    }
    Ok(())
}

/// Match the regex `^[A-Za-z]:[\\/]` from the JS reference. Pure ASCII so
/// byte indexing is safe.
fn is_drive_letter_absolute(path: &str) -> bool {
    let bytes = path.as_bytes();
    bytes.len() >= 3
        && bytes[0].is_ascii_alphabetic()
        && bytes[1] == b':'
        && (bytes[2] == b'/' || bytes[2] == b'\\')
}

/// Map a [`CompressionMethod`] back to its 16-bit ZIP method code, for use
/// in error reporting only.
///
/// `CompressionMethod::to_u16` is marked `#[deprecated]` in zip 5.1 — the
/// crate's preferred way to compare methods is via the named `Self`
/// constants, which we already do for the actual `Stored` check. For
/// diagnostic output, however, we want the wire-format method number
/// (e.g. 8 for DEFLATE), and the deprecated accessor is still the only
/// public API that returns it. Wrapping the call in `#[allow(deprecated)]`
/// keeps clippy's `-D warnings` setting from rejecting the build.
#[allow(deprecated)]
fn compression_method_code(method: CompressionMethod) -> u16 {
    method.to_u16()
}

/// Read every entry of a STORED-only ZIP archive, sorted by path.
///
/// On success the returned [`BTreeMap`] contains one (path, bytes) pair per
/// non-directory entry. Sorted iteration is guaranteed by `BTreeMap`. On any
/// safety violation, compression mismatch, or limit overflow, an error is
/// returned and no partial state escapes.
pub fn unpack_zip(bytes: &[u8]) -> Result<BTreeMap<String, Vec<u8>>, ZipError> {
    let cursor = Cursor::new(bytes);
    let mut archive = ZipArchive::new(cursor)
        .map_err(|e| ZipError::InvalidContainer(e.to_string()))?;

    let total_entries = archive.len();
    if total_entries > MAX_ENTRIES {
        return Err(ZipError::TooManyEntries(total_entries));
    }

    let mut out: BTreeMap<String, Vec<u8>> = BTreeMap::new();
    let mut total_bytes: u64 = 0;

    for i in 0..total_entries {
        let mut entry = archive
            .by_index(i)
            .map_err(|e| ZipError::InvalidContainer(e.to_string()))?;
        let name = entry.name().to_string();

        // Skip pure directory markers: name ends with `/` and zero size.
        // We deliberately do NOT use `entry.is_dir()` alone, since the JS
        // reference treats directory-ness as a name suffix; pairing it with
        // size==0 keeps the contract identical to JS.
        if name.ends_with('/') && entry.size() == 0 {
            continue;
        }

        // Reject symlinks before any other check that needs the body, because
        // is_symlink() looks at mode bits and tells us this entry is not a
        // regular file.
        if entry.is_symlink() {
            return Err(ZipError::UnsafePath {
                path: name,
                reason: PathReason::Symlink,
            });
        }

        if let Err(reason) = check_safe_path(&name) {
            return Err(ZipError::UnsafePath { path: name, reason });
        }

        let method = entry.compression();
        if method != CompressionMethod::Stored {
            return Err(ZipError::UnsupportedCompression {
                path: name,
                method: compression_method_code(method),
            });
        }

        // Decoding-time enforcement: read into a Vec<u8>, observing total.
        //
        // The declared `entry.size()` and `entry.compressed_size()` come from
        // the central directory, which is attacker-controllable. A hostile
        // archive could claim `size = u64::MAX` and force a multi-GiB
        // pre-allocation even though the actual STORED body is tiny. To
        // defend against that, we cap the *initial* allocation at the
        // smallest of:
        //   * declared uncompressed size,
        //   * declared compressed size (for STORED, equal to uncompressed in
        //     a well-formed archive — using it as a structural sanity check),
        //   * the remaining MAX_TOTAL_BYTES budget,
        //   * an absolute 16 MiB cap on the initial allocation.
        // The `Vec` will still grow if the actual body exceeds the initial
        // capacity; the post-read `total_bytes` check below enforces the
        // global limit on what we actually accepted.
        let declared = entry.size();
        if declared > MAX_TOTAL_BYTES {
            return Err(ZipError::TooLarge {
                total: declared,
            });
        }
        const INITIAL_CAP_LIMIT: u64 = 16 * 1024 * 1024;
        let remaining = MAX_TOTAL_BYTES.saturating_sub(total_bytes);
        let initial_cap = declared
            .min(entry.compressed_size())
            .min(remaining)
            .min(INITIAL_CAP_LIMIT) as usize;
        let mut buf = Vec::with_capacity(initial_cap);
        entry.read_to_end(&mut buf).map_err(ZipError::Io)?;

        // Note: there is no in-loop `file_count > MAX_ENTRIES` re-check here.
        // The outer `for i in 0..total_entries` already iterates a count that
        // was bounded by `MAX_ENTRIES` before the loop began (see the
        // `archive.len()` check above), so the inner check would be dead.
        total_bytes = total_bytes.saturating_add(buf.len() as u64);
        if total_bytes > MAX_TOTAL_BYTES {
            return Err(ZipError::TooLarge { total: total_bytes });
        }

        out.insert(name, buf);
    }

    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use zip::write::{SimpleFileOptions, ZipWriter};

    /// Build an in-memory ZIP from `(path, body, method)` triples. Used by
    /// the synthetic-corpus tests below.
    fn make_zip(entries: &[(&str, &[u8], CompressionMethod)]) -> Vec<u8> {
        let buf = Cursor::new(Vec::<u8>::new());
        let mut zw = ZipWriter::new(buf);
        for (name, body, method) in entries {
            let opts = SimpleFileOptions::default().compression_method(*method);
            zw.start_file(*name, opts).expect("start_file");
            zw.write_all(body).expect("write_all");
        }
        zw.finish().expect("finish").into_inner()
    }

    #[test]
    fn opens_real_clean_capsule() {
        // Resolve the JS-produced fixture from CARGO_MANIFEST_DIR. The
        // canonicalize() call also asserts the path actually exists.
        let bytes = crate::test_support::clean_capsule_bytes();
        let map = unpack_zip(&bytes).expect("clean.capsule must parse");

        for required in [
            "manifest.json",
            "program.md",
            "chain/events.jsonl",
            "provenance/envelope.json",
        ] {
            assert!(
                map.contains_key(required),
                "expected {required} in capsule; got keys: {:?}",
                map.keys().collect::<Vec<_>>()
            );
        }

        // Sanity: manifest.json must be valid JSON. We do not validate
        // schema here; that lands in Task 4.
        let manifest_bytes = map.get("manifest.json").expect("manifest present");
        let _: serde_json::Value =
            serde_json::from_slice(manifest_bytes).expect("manifest.json parses as JSON");
    }

    #[test]
    fn rejects_parent_traversal() {
        let bytes = make_zip(&[("../escape.txt", b"oops", CompressionMethod::Stored)]);
        let err = unpack_zip(&bytes).expect_err("must reject ..");
        match err {
            ZipError::UnsafePath {
                reason: PathReason::ParentTraversal,
                path,
            } => {
                assert_eq!(path, "../escape.txt");
            }
            other => panic!("expected ParentTraversal, got {other:?}"),
        }
    }

    #[test]
    fn rejects_absolute_path() {
        let bytes = make_zip(&[("/etc/passwd", b"root:x:0:0", CompressionMethod::Stored)]);
        let err = unpack_zip(&bytes).expect_err("must reject absolute");
        match err {
            ZipError::UnsafePath {
                reason: PathReason::Absolute,
                path,
            } => {
                assert_eq!(path, "/etc/passwd");
            }
            other => panic!("expected Absolute, got {other:?}"),
        }
    }

    #[test]
    fn rejects_drive_letter_absolute() {
        let bytes = make_zip(&[(r"C:\foo", b"win", CompressionMethod::Stored)]);
        let err = unpack_zip(&bytes).expect_err("must reject drive-letter absolute");
        match err {
            ZipError::UnsafePath {
                reason: PathReason::Absolute,
                path,
            } => {
                assert_eq!(path, r"C:\foo");
            }
            other => panic!("expected Absolute (drive-letter), got {other:?}"),
        }
    }

    #[test]
    fn rejects_nul_byte_path() {
        // The zip writer is happy to emit NULs in names; if a future zip
        // version starts rejecting this at write time, we'd need to hand-
        // assemble the bytes. The current zip 5.1 path goes through fine.
        let bytes = make_zip(&[("bad\0name.txt", b"x", CompressionMethod::Stored)]);
        let err = unpack_zip(&bytes).expect_err("must reject NUL byte");
        match err {
            ZipError::UnsafePath {
                reason: PathReason::NulByte,
                ..
            } => {}
            other => panic!("expected NulByte, got {other:?}"),
        }
    }

    #[test]
    fn rejects_deflate_compression() {
        let bytes = make_zip(&[(
            "compressed.bin",
            // make body big enough that the writer doesn't degrade to STORED
            &vec![0u8; 1024],
            CompressionMethod::Deflated,
        )]);
        let err = unpack_zip(&bytes).expect_err("must reject deflate");
        match err {
            ZipError::UnsupportedCompression { path, method } => {
                assert_eq!(path, "compressed.bin");
                // Method 8 is DEFLATE per the ZIP spec.
                assert_eq!(method, 8);
            }
            other => panic!("expected UnsupportedCompression, got {other:?}"),
        }
    }

    #[test]
    fn rejects_too_many_entries() {
        // MAX_ENTRIES + 1. Use empty bodies to keep the test fast.
        let buf = Cursor::new(Vec::<u8>::new());
        let mut zw = ZipWriter::new(buf);
        let opts = SimpleFileOptions::default().compression_method(CompressionMethod::Stored);
        let count = MAX_ENTRIES + 1;
        for i in 0..count {
            // Fixed-width name keeps the central directory predictable.
            zw.start_file(format!("e/{i:08}.bin"), opts).expect("start_file");
        }
        let bytes = zw.finish().expect("finish").into_inner();

        let err = unpack_zip(&bytes).expect_err("must reject too many");
        match err {
            ZipError::TooManyEntries(n) => assert_eq!(n, count),
            other => panic!("expected TooManyEntries, got {other:?}"),
        }
    }

    #[test]
    fn returns_sorted_paths() {
        // Insert in c, a, b order; iteration must come back a, b, c.
        let bytes = make_zip(&[
            ("c", b"3", CompressionMethod::Stored),
            ("a", b"1", CompressionMethod::Stored),
            ("b", b"2", CompressionMethod::Stored),
        ]);
        let map = unpack_zip(&bytes).expect("ok");
        let keys: Vec<&str> = map.keys().map(|s| s.as_str()).collect();
        assert_eq!(keys, vec!["a", "b", "c"]);
    }

    #[test]
    fn small_entry_bounded_initial_allocation() {
        // Best-effort guard for the bounded pre-allocation invariant.
        //
        // A hostile capsule could declare `size = u64::MAX` to force a
        // multi-GiB pre-allocation. The `zip` crate's writer always sets
        // `size` honestly when we drive it through `start_file` /
        // `write_all`, so we cannot directly synthesize the attack archive
        // through the writer API without hand-assembling ZIP bytes. Instead,
        // we verify the *upper bound* the implementation guarantees: even if
        // the central-directory `size()` were huge, the per-entry initial
        // allocation must not exceed 16 MiB (the `INITIAL_CAP_LIMIT` constant
        // used inside `unpack_zip`). For a small entry like this one, the
        // returned `Vec`'s capacity will be small — but more importantly, it
        // is provably below the 16 MiB ceiling.
        //
        // If a future refactor accidentally drops the `min(INITIAL_CAP_LIMIT)`
        // cap and re-introduces `Vec::with_capacity(declared as usize)`, this
        // test will still pass for honest small entries — the real defense
        // lives in the code review of `zip_reader.rs`. We keep this test
        // anyway as documentation of the invariant and to catch the
        // *opposite* regression: the cap accidentally being applied to
        // healthy small reads in a way that prevents `read_to_end` from
        // completing.
        let body = vec![0xab_u8; 4];
        let bytes = make_zip(&[("small.bin", &body, CompressionMethod::Stored)]);
        let map = unpack_zip(&bytes).expect("small archive must parse");
        let buf = map.get("small.bin").expect("entry present");
        assert_eq!(buf.as_slice(), body.as_slice());
        // The Vec was either grown by `read_to_end` or pre-sized to a value
        // that is itself bounded by INITIAL_CAP_LIMIT (16 MiB). Either way,
        // it cannot exceed 16 MiB for a 4-byte body.
        assert!(
            buf.capacity() <= 16 * 1024 * 1024,
            "capacity {} exceeds 16 MiB bound for a 4-byte entry",
            buf.capacity()
        );
    }

    #[test]
    fn safe_path_predicate_unit_cases() {
        // Spot-check the predicate directly. The full ZIP-slip cases live in
        // the integration-style tests above; this one is just to keep the
        // helper honest.
        assert!(check_safe_path("ok.txt").is_ok());
        assert!(check_safe_path("a/b/c.txt").is_ok());
        assert_eq!(check_safe_path(""), Err(PathReason::Empty));
        assert_eq!(check_safe_path("a\0b"), Err(PathReason::NulByte));
        assert_eq!(check_safe_path("/abs"), Err(PathReason::Absolute));
        assert_eq!(check_safe_path("c:/win"), Err(PathReason::Absolute));
        assert_eq!(check_safe_path(r"D:\win"), Err(PathReason::Absolute));
        // Drive-letter pattern requires *exactly* `[A-Za-z]:[\\/]`. A bare
        // colon is not a drive-letter case and should pass.
        assert!(check_safe_path("not:absolute").is_ok());
        assert_eq!(
            check_safe_path("a/../b"),
            Err(PathReason::ParentTraversal)
        );
        // Backslash is also a separator on Windows ZIPs in the wild; the
        // predicate must catch parent traversal across either.
        assert_eq!(
            check_safe_path(r"a\..\b"),
            Err(PathReason::ParentTraversal)
        );
    }
}
