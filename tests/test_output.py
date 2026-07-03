from __future__ import annotations

import json
import sys
from io import StringIO

import pytest

from angrsolve.output import (
    Solution,
    colorize,
    enable_color,
    format_solution_text,
    output_solution,
    print_no_solution,
)


class TestColorize:
    def test_color_enabled(self) -> None:
        enable_color(True)
        result = colorize("hello", lambda t: f"\033[92m{t}\033[0m")
        assert result == "\033[92mhello\033[0m"

    def test_color_disabled(self) -> None:
        enable_color(False)
        result = colorize("hello", lambda t: f"\033[92m{t}\033[0m")
        assert result == "hello"
        enable_color(True)  # restore


class TestSolutionToJson:
    def test_minimal(self) -> None:
        sol = Solution(find_addr=0x401234)
        data = sol.to_json()
        assert data["find_addr"] == "0x401234"
        assert data["find_name"] is None
        assert data["stdin"] is None
        assert data["argv"] is None
        assert data["files"] == {}
        assert data["active_states"] == 0

    def test_with_data(self) -> None:
        sol = Solution(
            find_addr=0x401234,
            find_name="win",
            stdin=b"hello",
            argv=b"world",
            files={"flag.txt": b"secret"},
            active_states=2,
            explored_states=10,
            timing_ms=123.4,
        )
        data = sol.to_json()
        assert data["find_name"] == "win"
        assert data["stdin"] == "68656c6c6f"
        assert data["argv"] == "776f726c64"
        assert data["files"]["flag.txt"] == "736563726574"
        assert data["active_states"] == 2
        assert data["explored_states"] == 10
        assert data["timing_ms"] == 123.4


class TestFormatSolutionText:
    def test_basic(self) -> None:
        sol = Solution(find_addr=0x401234)
        text = format_solution_text(sol)
        assert "Solution found!" in text
        assert "0x401234" in text

    def test_with_name(self) -> None:
        sol = Solution(find_addr=0x401234, find_name="win")
        text = format_solution_text(sol)
        assert "win" in text
        assert "0x401234" in text

    def test_stdin_dump(self) -> None:
        sol = Solution(find_addr=0x401234, stdin=b"hello")
        text = format_solution_text(sol)
        assert "STDIN" in text
        assert "hello" in text
        assert "68656c6c6f" in text  # hex

    def test_argv_dump(self) -> None:
        sol = Solution(find_addr=0x401234, argv=b"secret")
        text = format_solution_text(sol)
        assert "ARGV" in text
        assert "secret" in text

    def test_file_dump(self) -> None:
        sol = Solution(find_addr=0x401234, files={"flag.txt": b"data"})
        text = format_solution_text(sol)
        assert "FILE [flag.txt]" in text
        assert "data" in text

    def test_stats(self) -> None:
        sol = Solution(find_addr=0x401234, explored_states=5, active_states=1, timing_ms=100.0)
        text = format_solution_text(sol)
        assert "5" in text
        assert "1" in text
        assert "100.0" in text


class TestOutputSolution:
    def test_json_output(self, capsys: pytest.CaptureFixture[str]) -> None:
        sol = Solution(find_addr=0x401234, stdin=b"abc")
        output_solution(sol, json_mode=True)
        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert data["find_addr"] == "0x401234"

    def test_save_stdin(self, tmp_path: pytest.TempPathFactory) -> None:
        sol = Solution(find_addr=0x401234, stdin=b"payload")
        save_path = str(tmp_path / "out.bin")
        output_solution(sol, save_path=save_path)
        saved = (tmp_path / "out.bin").read_bytes()
        assert saved == b"payload"

    def test_save_argv(self, tmp_path: pytest.TempPathFactory) -> None:
        sol = Solution(find_addr=0x401234, argv=b"argv_payload")
        save_path = str(tmp_path / "out.bin")
        output_solution(sol, save_path=save_path)
        saved = (tmp_path / "out.bin").read_bytes()
        assert saved == b"argv_payload"

    def test_save_file(self, tmp_path: pytest.TempPathFactory) -> None:
        sol = Solution(find_addr=0x401234, files={"flag.txt": b"file_data"})
        save_path = str(tmp_path / "out.bin")
        output_solution(sol, save_path=save_path)
        saved = (tmp_path / "out.bin").read_bytes()
        assert saved == b"file_data"


class TestPrintNoSolution:
    def test_text(self, capsys: pytest.CaptureFixture[str]) -> None:
        print_no_solution(explored=3, timing_ms=50.0)
        captured = capsys.readouterr()
        assert "No solution found" in captured.out

    def test_json(self, capsys: pytest.CaptureFixture[str]) -> None:
        print_no_solution(explored=3, timing_ms=50.0, json_mode=True)
        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert data["error"] == "No solution found"
        assert data["explored_states"] == 3
