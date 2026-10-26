from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from typing import Dict, List

import pytest

CHALLENGES_DIR = Path(__file__).parent.parent / "challenges"
MANIFEST_PATH = CHALLENGES_DIR / "manifest.json"
ANGRSOLVE = Path(__file__).parent.parent / "angrsolve.py"


def _load_manifest() -> Dict:
    with open(MANIFEST_PATH) as f:
        return json.load(f)


def _active_entries() -> Dict[str, Dict]:
    data = _load_manifest()
    return {
        name: cfg
        for name, cfg in data.get("challenges", {}).items()
        if "skip_reason" not in cfg
    }


def _resolve_find(binary: Path, cfg: Dict) -> int:
    """Resolve a manifest find target to a rebased address (lazy angr import)."""
    import angr

    proj = angr.Project(str(binary), auto_load_libs=False)
    if "find_symbol" in cfg:
        sym = proj.loader.find_symbol(cfg["find_symbol"])
        assert sym is not None, (
            f"manifest stale: symbol {cfg['find_symbol']!r} not in {binary.name} "
            f"— update challenges/manifest.json"
        )
        return sym.rebased_addr
    rva = int(cfg["find_rva"], 16)
    addr = proj.loader.main_object.min_addr + rva
    assert _is_executable(proj, addr), (
        f"manifest stale: find_rva {cfg['find_rva']} for {binary.name} "
        f"(rebased {hex(addr)}) is not executable code — update challenges/manifest.json"
    )
    return addr


def _is_executable(proj, addr: int) -> bool:
    for seg in proj.loader.main_object.segments:
        if seg.is_executable and seg.vaddr <= addr < seg.vaddr + seg.memsize:
            return True
    # Fallback for loaders without segment info: accept addresses inside .text.
    try:
        sec = proj.loader.main_object.find_section_containing(addr)
        return sec is not None and (sec.header.sh_flags & 0x4) != 0
    except Exception:
        return False


class TestManifest:
    """Fast checks: manifest shape + targets. No solving here."""

    def test_manifest_loads(self) -> None:
        data = _load_manifest()
        assert data.get("version") == 1
        assert isinstance(data.get("challenges"), dict)
        assert len(data["challenges"]) > 0

    def test_binaries_exist(self) -> None:
        for name, cfg in _active_entries().items():
            if "skip_reason" in cfg:
                continue
            assert (CHALLENGES_DIR / name).exists(), f"missing binary: {name}"

    def test_entries_have_required_keys(self) -> None:
        for name, cfg in _active_entries().items():
            assert "args" in cfg and isinstance(cfg["args"], list), name
            assert "timeout" in cfg and cfg["timeout"] > 0, name
            assert ("find_symbol" in cfg) != ("find_rva" in cfg), (
                f"{name}: need exactly one of find_symbol / find_rva"
            )

    def test_find_targets_resolve(self) -> None:
        for name, cfg in _active_entries().items():
            addr = _resolve_find(CHALLENGES_DIR / name, cfg)
            assert isinstance(addr, int) and addr > 0

    def test_skipped_have_reasons(self) -> None:
        data = _load_manifest()
        for name, cfg in data["challenges"].items():
            if (CHALLENGES_DIR / name).exists() and name not in _active_entries():
                assert cfg.get("skip_reason"), f"{name}: skipped without reason"


@pytest.mark.slow
class TestChallengeSolves:
    @pytest.mark.parametrize(
        "name", sorted(_active_entries().keys())
    )
    def test_solves(self, name: str) -> None:
        cfg = _active_entries()[name]
        binary = CHALLENGES_DIR / name
        find_addr = _resolve_find(binary, cfg)
        cmd = [
            sys.executable, str(ANGRSOLVE), str(binary),
            "--find", hex(find_addr), *cfg["args"],
            "--no-color", "-q",
        ]
        timeout = int(cfg["timeout"]) + 120
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        except subprocess.TimeoutExpired:
            pytest.fail(f"{name}: solver exceeded {timeout}s — bump timeout in manifest.json")
        assert result.returncode == 0, (
            f"{name}: no solution (stderr: {result.stderr[-2000:]})"
        )
        assert "Solution found" in result.stdout
