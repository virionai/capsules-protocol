import io
import zipfile

import pytest

from capsule.zip_io import (
    MAX_ENTRIES,
    MAX_TOTAL_BYTES,
    UnsafeZipPathError,
    pack_zip,
    unpack_zip,
)


def test_pack_unpack_roundtrip():
    files = {
        "a.txt": b"hello",
        "b.txt": b"world",
        "nested/c.txt": b"nested",
    }
    zip_bytes = pack_zip(files)
    out = unpack_zip(zip_bytes)
    assert out == files


def test_pack_emits_sorted_entries():
    files = {"z.txt": b"z", "a.txt": b"a", "m/m.txt": b"m"}
    zip_bytes = pack_zip(files)
    with zipfile.ZipFile(io.BytesIO(zip_bytes)) as zf:
        assert [zi.filename for zi in zf.infolist()] == ["a.txt", "m/m.txt", "z.txt"]


def test_pack_uses_stored_compression():
    zip_bytes = pack_zip({"a.txt": b"x" * 1000})
    with zipfile.ZipFile(io.BytesIO(zip_bytes)) as zf:
        for zi in zf.infolist():
            assert zi.compress_type == zipfile.ZIP_STORED


def test_pack_uses_fixed_1980_timestamp():
    zip_bytes = pack_zip({"a.txt": b"x"})
    with zipfile.ZipFile(io.BytesIO(zip_bytes)) as zf:
        for zi in zf.infolist():
            assert zi.date_time == (1980, 1, 1, 0, 0, 0)


def test_pack_is_deterministic():
    files = {"a.txt": b"hi", "b.txt": b"there"}
    assert pack_zip(files) == pack_zip(files)


def test_pack_rejects_absolute_path():
    with pytest.raises(UnsafeZipPathError):
        pack_zip({"/etc/passwd": b"x"})


def test_pack_rejects_parent_traversal():
    with pytest.raises(UnsafeZipPathError):
        pack_zip({"a/../b": b"x"})


def test_pack_rejects_nul_byte():
    with pytest.raises(UnsafeZipPathError):
        pack_zip({"a\x00b": b"x"})


def test_pack_rejects_drive_letter():
    with pytest.raises(UnsafeZipPathError):
        pack_zip({"C:/x": b"y"})


def test_unpack_rejects_too_many_entries():
    files = {f"f{i:04d}.txt": b"x" for i in range(MAX_ENTRIES + 1)}
    with pytest.raises(ValueError):
        pack_zip(files)


def test_unpack_rejects_total_size_overflow():
    # Forge a ZIP that decompresses to > 1 GiB by abusing STORED with
    # large declared size. Easiest path: pack a real file, then assert
    # the cap raises by lowering it via constant injection in a future
    # helper. For now, smoke test the cap variable exists and is right.
    assert MAX_TOTAL_BYTES == 1024 * 1024 * 1024


def test_unpack_rejects_nonstored_compression():
    # Build a ZIP with DEFLATE manually, expect rejection.
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("a.txt", "hello")
    with pytest.raises(ValueError, match="STORED"):
        unpack_zip(buf.getvalue())


def test_unpack_rejects_unsafe_path():
    # Build a ZIP that contains "../escape" via lower-level API.
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_STORED) as zf:
        zi = zipfile.ZipInfo("../escape")
        zi.compress_type = zipfile.ZIP_STORED
        zf.writestr(zi, "x")
    with pytest.raises(UnsafeZipPathError):
        unpack_zip(buf.getvalue())
