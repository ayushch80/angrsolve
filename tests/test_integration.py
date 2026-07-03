from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path


def _run_angrsolve(args: list[str]) -> subprocess.CompletedProcess:
    """Run angrsolve.py with the given args and return the result."""
    cmd = [sys.executable, str(Path(__file__).parent.parent / "angrsolve.py")]
    cmd.extend(args)
    return subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        timeout=60,
    )


class TestEndToEnd:
    def test_argv_detects_solution(self, argv_binary: str) -> None:
        result = _run_angrsolve([str(argv_binary), "--find", "win", "--argv", "32", "--no-color", "-q"])
        assert result.returncode == 0
        assert "Solution found" in result.stdout

    def test_stdin_detects_solution(self, stdin_binary: str) -> None:
        result = _run_angrsolve([str(stdin_binary), "--find", "win", "--stdin", "16", "--no-color", "-q"])
        assert result.returncode == 0
        assert "Solution found" in result.stdout

    def test_file_detects_solution(self, file_binary: str) -> None:
        result = _run_angrsolve([str(file_binary), "--find", "win", "--file", "flag.txt", "16", "--no-color", "-q"])
        assert result.returncode == 0
        assert "Solution found" in result.stdout

    def test_json_output(self, argv_binary: str) -> None:
        result = _run_angrsolve([str(argv_binary), "--find", "win", "--argv", "32", "--json", "--no-color", "-q"])
        assert result.returncode == 0
        data = json.loads(result.stdout)
        assert "find_addr" in data
        assert data["argv"] is not None

    def test_no_solution_when_wrong_target(self, argv_binary: str) -> None:
        result = _run_angrsolve(
            [str(argv_binary), "--find", "0xdeadbeef", "--argv", "32", "--no-color", "-q"]
        )
        assert result.returncode == 1
        assert "No solution found" in result.stdout

    def test_save_output(self, argv_binary: str, tmp_path: Path) -> None:
        save_path = tmp_path / "payload.bin"
        result = _run_angrsolve(
            [
                str(argv_binary),
                "--find", "win",
                "--argv", "32",
                "--save", str(save_path),
                "--no-color", "-q",
            ]
        )
        assert result.returncode == 0
        assert save_path.exists()
        saved = save_path.read_bytes()
        assert b"s3cr3t" in saved

    def test_auto_avoid_does_not_prevent_solution(self, argv_binary: str) -> None:
        result = _run_angrsolve(
            [str(argv_binary), "--find", "win", "--argv", "32", "--no-color", "-q", "--auto-avoid"]
        )
        assert result.returncode == 0
        assert "Solution found" in result.stdout

    def test_unrestricted_mode_finds_solution(self, argv_binary: str) -> None:
        result = _run_angrsolve(
            [
                str(argv_binary),
                "--find", "win",
                "--argv", "32",
                "--mode", "unrestricted",
                "--no-color", "-q",
            ]
        )
        assert result.returncode == 0
        assert "Solution found" in result.stdout

    def test_multiple_find_targets(self, argv_binary: str) -> None:
        # --find win --find main — should find win first or still work
        result = _run_angrsolve(
            [str(argv_binary), "--find", "win", "--find", "main", "--argv", "32", "--no-color", "-q"]
        )
        assert result.returncode == 0
        assert "Solution found" in result.stdout
