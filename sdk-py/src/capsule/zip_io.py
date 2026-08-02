"""Deterministic STORED-only ZIP with safety checks. Mirrors sdk/src/zip.js."""

from __future__ import annotations

import io
import zipfile
from collections.abc import Mapping

# Entry order is this container's determinism guarantee, and it must be the
# same order every other lane uses. Acyclic: canonical.py imports only
# hashlib, math and typing.
from .canonical import utf16_sort_key

MAX_ENTRIES = 10_000
MAX_TOTAL_BYTES = 1024 * 1024 * 1024  # 1 GiB
_FIXED_DATE = (1980, 1, 1, 0, 0, 0)

# ZIP record signatures and layout constants, mirroring sdk-js/src/zip.js.
_EOCD_SIG = 0x06054B50  # end of central directory
_CDH_SIG = 0x02014B50  # central directory file header
_LFH_SIG = 0x04034B50  # local file header
_EOCD_MIN = 22  # EOCD size with empty comment
_MAX_COMMENT = 0xFFFF
# DOS "directory" attribute. Some readers (JSZip) decide directory-ness from
# this bit rather than from the trailing "/" in the name.
_DOS_DIR_ATTR = 0x10


class UnsafeZipPathError(ValueError):
    """Raised when a ZIP entry's path would escape, contain a NUL, or be absolute."""


def _assert_safe_path(p: str) -> None:
    if not isinstance(p, str) or len(p) == 0:
        raise UnsafeZipPathError("zip path: empty or non-string")
    if "\x00" in p:
        raise UnsafeZipPathError(f"zip path contains NUL: {p!r}")
    if p.startswith("/"):
        raise UnsafeZipPathError(f"zip path is absolute: {p}")
    if len(p) >= 2 and p[1] == ":":
        raise UnsafeZipPathError(f"zip path is absolute: {p}")
    for segment in p.replace("\\", "/").split("/"):
        if segment == "..":
            raise UnsafeZipPathError(f"zip path has parent traversal: {p}")


def _read_u16(data: bytes, at: int) -> int:
    return int.from_bytes(data[at : at + 2], "little")


def _read_u32(data: bytes, at: int) -> int:
    return int.from_bytes(data[at : at + 4], "little")


def _read_local_name(data: bytes, offset: int, index: int) -> str:
    """Read the file name out of the LOCAL file header at ``offset``.

    Some ZIP readers (JSZip in the JS reference lane) re-key entries by the
    name in the local header rather than the central directory. Reading it
    here lets the scan require the two to agree, so no reader can be shown a
    different entry set.
    """
    if offset + 30 > len(data) or _read_u32(data, offset) != _LFH_SIG:
        raise ValueError(f"zip scan: missing local file header for record {index}")
    name_len = _read_u16(data, offset + 26)
    end = offset + 30 + name_len
    if end > len(data):
        raise ValueError(f"zip scan: truncated local file header for record {index}")
    return data[offset + 30 : end].decode("utf-8", "replace")


def _scan_central_directory(data: bytes) -> set[str]:
    """Fail-closed scan of the RAW central directory; the authoritative entry set.

    Ports ``scanCentralDirectory`` + ``assertStrictEntries`` from
    ``sdk-js/src/zip.js``. CPython's ``zipfile`` sanitizes/keeps-last on load
    and locates the EOCD by scanning for the last signature, so the container
    rules must be enforced against the raw bytes before ``zipfile`` parses
    anything. Returns the set of non-directory entry names the archive admits.

    Rejects: a missing/ambiguous/trailing-byte end-of-central-directory
    record, ZIP64 sentinels, count/offset mismatches, duplicate names, unsafe
    paths, local/central name disagreement, ambiguous directory markers,
    non-STORED compression, and symlink entries.
    """
    n = len(data)
    if n < _EOCD_MIN:
        raise ValueError("zip scan: too small to be a zip")

    # The EOCD is the LAST record; scan back over a possible trailing comment.
    # A signature-shaped byte sequence is only an EOCD if its declared comment
    # length lands exactly at end-of-file. A trailing byte therefore prevents a
    # match, and the container is rejected rather than deferred to a more
    # permissive locator.
    eocd = -1
    lowest = max(0, n - _EOCD_MIN - _MAX_COMMENT)
    p = n - _EOCD_MIN
    while p >= lowest:
        if _read_u32(data, p) == _EOCD_SIG and p + _EOCD_MIN + _read_u16(data, p + 20) == n:
            eocd = p
            break
        p -= 1
    if eocd < 0:
        raise ValueError("zip scan: end-of-central-directory not found")

    # Reject any later EOCD signature so this scan cannot select a different
    # directory from a parser that searches by the last signature occurrence.
    q = n - 4
    while q > eocd:
        if _read_u32(data, q) == _EOCD_SIG:
            raise ValueError("zip scan: multiple end-of-central-directory records")
        q -= 1

    total_entries = _read_u16(data, eocd + 10)
    cd_size = _read_u32(data, eocd + 12)
    cd_offset = _read_u32(data, eocd + 16)
    if total_entries == 0xFFFF or cd_size == 0xFFFFFFFF or cd_offset == 0xFFFFFFFF:
        raise ValueError("zip scan: ZIP64 archives are not supported")
    if total_entries > MAX_ENTRIES:
        raise ValueError(f"zip scan: too many entries ({total_entries})")
    cd_end = cd_offset + cd_size
    if cd_end != eocd:
        raise ValueError("zip scan: central directory does not end at EOCD")

    # Walk the directory by its byte size, not the attacker-controlled EOCD
    # record count; cross-check the declared count only after consuming it.
    entries: list[tuple[str, str, int, int, int, int]] = []
    p = cd_offset
    while p < cd_end:
        i = len(entries)
        if p + 46 > cd_end or _read_u32(data, p) != _CDH_SIG:
            raise ValueError(
                f"zip scan: truncated or malformed central directory at record {i}"
            )
        method = _read_u16(data, p + 10)
        compressed_size = _read_u32(data, p + 20)
        size = _read_u32(data, p + 24)
        name_len = _read_u16(data, p + 28)
        extra_len = _read_u16(data, p + 30)
        comment_len = _read_u16(data, p + 32)
        external_attrs = _read_u32(data, p + 38)
        local_header_offset = _read_u32(data, p + 42)
        nxt = p + 46 + name_len + extra_len + comment_len
        if nxt > cd_end:
            raise ValueError(f"zip scan: truncated central-directory record {i}")
        name = data[p + 46 : p + 46 + name_len].decode("utf-8", "replace")
        local_name = _read_local_name(data, local_header_offset, i)
        entries.append(
            (name, local_name, method, compressed_size, size, external_attrs)
        )
        if len(entries) > MAX_ENTRIES:
            raise ValueError(f"zip scan: too many entries ({len(entries)})")
        p = nxt
    if len(entries) != total_entries:
        raise ValueError(
            "zip scan: central-directory entry count mismatch "
            f"(EOCD {total_entries}, actual {len(entries)})"
        )

    seen: set[str] = set()
    expected: set[str] = set()
    for name, local_name, method, compressed_size, size, external_attrs in entries:
        if name in seen:
            raise ValueError(f"zip unpack: duplicate entry: {name}")
        seen.add(name)
        _assert_safe_path(name)
        # The central directory is authoritative. A reader that keys entries by
        # the LOCAL header name sees a different set, so require equality.
        if local_name != name:
            raise ValueError(
                "zip unpack: local/central name mismatch: "
                f"central {name!r}, local {local_name!r}"
            )
        is_dir_name = name.endswith("/")
        # JSZip derives directory-ness from the DOS attribute bit, not the
        # name, so a dir-bit entry with a plain file name is dropped there
        # while zipfile/unzip extract it as a file.
        if external_attrs & _DOS_DIR_ATTR and not is_dir_name:
            raise ValueError(
                f"zip unpack: directory attribute on non-directory name: {name}"
            )
        if is_dir_name:
            # A "/"-terminated name carrying content is the mirror image of
            # the same differential: readers that key on the name drop it.
            if size != 0 or compressed_size != 0:
                raise ValueError(f"zip unpack: directory marker with nonzero size: {name}")
            continue
        if method != 0:
            raise ValueError(
                f"zip unpack: only STORED supported, got method {method}: {name}"
            )
        mode = (external_attrs >> 16) & 0xFFFF
        if mode and (mode & 0o170000) == 0o120000:
            raise UnsafeZipPathError(f"zip entry is a symlink: {name}")
        expected.add(name)
    return expected


def pack_zip(files: Mapping[str, bytes]) -> bytes:
    """Pack a mapping of path → bytes into a deterministic STORED ZIP."""
    if len(files) > MAX_ENTRIES:
        raise ValueError(f"zip pack: too many entries ({len(files)})")
    sorted_items = sorted(files.items(), key=lambda kv: utf16_sort_key(kv[0]))
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_STORED) as zf:
        for path, data in sorted_items:
            _assert_safe_path(path)
            zi = zipfile.ZipInfo(filename=path, date_time=_FIXED_DATE)
            zi.compress_type = zipfile.ZIP_STORED
            zi.external_attr = 0  # default file attrs; symlink bit unset
            zf.writestr(zi, bytes(data))
    return buf.getvalue()


def unpack_zip(data: bytes) -> dict[str, bytes]:
    """Unpack a STORED-only ZIP, applying safety + size caps.

    The raw central-directory scan is the single authoritative source of the
    entry set. It runs first and rejects every shape that lets two ZIP parsers
    disagree; ``unpack_zip`` then extracts with ``zipfile`` and asserts that
    the set it produced is exactly the set the scan admitted.
    """
    expected = _scan_central_directory(data)
    out: dict[str, bytes] = {}
    total = 0
    with zipfile.ZipFile(io.BytesIO(data)) as zf:
        for zi in sorted(zf.infolist(), key=lambda x: utf16_sort_key(x.filename)):
            if zi.filename.endswith("/"):
                continue  # directory marker (scan already validated its shape)
            if zi.filename not in expected:
                raise ValueError(
                    f"zip unpack: entry not in central directory: {zi.filename}"
                )
            payload = zf.read(zi)
            total += len(payload)
            if total > MAX_TOTAL_BYTES:
                raise ValueError("zip unpack: total-size limit exceeded")
            out[zi.filename] = payload
    # Every central-directory file entry must have been extracted. A name the
    # scan admitted but zipfile dropped is the smuggling direction of the same
    # parser differential.
    if len(out) != len(expected):
        missing = ", ".join(sorted(n for n in expected if n not in out))
        raise ValueError(f"zip unpack: central-directory entry not extracted: {missing}")
    return out
