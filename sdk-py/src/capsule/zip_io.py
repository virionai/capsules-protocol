"""Deterministic STORED-only ZIP with safety checks. Mirrors sdk/src/zip.js."""

from __future__ import annotations

import io
import zipfile
from collections.abc import Mapping

MAX_ENTRIES = 10_000
MAX_TOTAL_BYTES = 1024 * 1024 * 1024  # 1 GiB
_FIXED_DATE = (1980, 1, 1, 0, 0, 0)


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


def pack_zip(files: Mapping[str, bytes]) -> bytes:
    """Pack a mapping of path → bytes into a deterministic STORED ZIP."""
    if len(files) > MAX_ENTRIES:
        raise ValueError(f"zip pack: too many entries ({len(files)})")
    sorted_items = sorted(files.items(), key=lambda kv: kv[0])
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
    """Unpack a STORED-only ZIP, applying safety + size caps."""
    out: dict[str, bytes] = {}
    total = 0
    with zipfile.ZipFile(io.BytesIO(data)) as zf:
        infos = zf.infolist()
        if len(infos) > MAX_ENTRIES:
            raise ValueError(f"zip unpack: too many entries ({len(infos)})")
        # Duplicate entry names are a parser differential (readers disagree
        # on which copy wins), so a signed capsule must never contain one.
        seen: set[str] = set()
        for zi in infos:
            if zi.filename in seen:
                raise ValueError(f"zip unpack: duplicate entry: {zi.filename}")
            seen.add(zi.filename)
        for zi in sorted(infos, key=lambda x: x.filename):
            if zi.is_dir():
                continue
            _assert_safe_path(zi.filename)
            if zi.compress_type != zipfile.ZIP_STORED:
                raise ValueError(
                    f"zip unpack: only STORED supported, got compress_type={zi.compress_type}"
                )
            # Reject symlinks: high 16 bits of external_attr carry the
            # POSIX file mode; symlink mode is 0o120000.
            mode = (zi.external_attr >> 16) & 0xFFFF
            if mode and (mode & 0o170000) == 0o120000:
                raise UnsafeZipPathError(f"zip entry is a symlink: {zi.filename}")
            payload = zf.read(zi)
            total += len(payload)
            if total > MAX_TOTAL_BYTES:
                raise ValueError("zip unpack: total-size limit exceeded")
            out[zi.filename] = payload
    return out
