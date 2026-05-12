"""Shared pytest fixtures + utility for JS-SDK parity."""

from __future__ import annotations

import json
import os
import pathlib
import subprocess

import pytest

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
TAMPER_DIR = REPO_ROOT / "examples" / "tamper-detection"
TAMPER_OUT = TAMPER_DIR / "output"


@pytest.fixture(scope="session")
def tamper_fixtures() -> pathlib.Path:
    """Ensure the JS tamper-detection fixtures exist; build if missing."""
    if not (TAMPER_OUT / "clean.capsule").exists():
        if os.environ.get("CAPSULE_PY_SKIP_JS_BUILD") == "1":
            pytest.skip("JS tamper fixtures missing and CAPSULE_PY_SKIP_JS_BUILD=1 set")
        subprocess.run(
            ["npm", "install", "--no-audit", "--no-fund"],
            cwd=TAMPER_DIR,
            check=True,
        )
        subprocess.run(["npm", "run", "build"], cwd=TAMPER_DIR, check=True)
    return TAMPER_OUT


@pytest.fixture(scope="session")
def js_originator_pubkey(tamper_fixtures: pathlib.Path) -> str:
    keys = json.loads((tamper_fixtures / "keys.json").read_text())
    return keys["originator"]["publicKey"]
