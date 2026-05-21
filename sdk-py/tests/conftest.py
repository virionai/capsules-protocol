"""Shared pytest fixtures + utility for JS-SDK parity."""

from __future__ import annotations

import json
import pathlib

import pytest

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
TAMPER_DIR = REPO_ROOT / "spec" / "vectors" / "tamper-detection"
TAMPER_OUT = TAMPER_DIR / "output"


@pytest.fixture(scope="session")
def tamper_fixtures() -> pathlib.Path:
    """Return shared JS parity fixtures when the vector registry exists."""
    if not (TAMPER_OUT / "clean.capsule").exists():
        pytest.skip("JS parity fixtures are not checked in yet; pending spec/vectors registry")
    return TAMPER_OUT


@pytest.fixture(scope="session")
def js_originator_pubkey(tamper_fixtures: pathlib.Path) -> str:
    keys = json.loads((tamper_fixtures / "keys.json").read_text())
    return keys["originator"]["publicKey"]
