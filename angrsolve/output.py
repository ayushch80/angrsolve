from __future__ import annotations

import json
import sys
from dataclasses import dataclass, field, asdict
from typing import Any, Dict, List, Optional


def _green(text: str) -> str:
    return f"\033[92m{text}\033[0m"


def _cyan(text: str) -> str:
    return f"\033[96m{text}\033[0m"


def _yellow(text: str) -> str:
    return f"\033[93m{text}\033[0m"


def _dim(text: str) -> str:
    return f"\033[2m{text}\033[0m"


def _red(text: str) -> str:
    return f"\033[91m{text}\033[0m"


def _bold(text: str) -> str:
    return f"\033[1m{text}\033[0m"


COLOR_ENABLED = True


def enable_color(enabled: bool = True) -> None:
    global COLOR_ENABLED
    COLOR_ENABLED = enabled


def colorize(text: str, color_fn) -> str:
    if COLOR_ENABLED:
        return color_fn(text)
    return text


@dataclass
class Solution:
    """Holds a recovered solution."""

    find_addr: int
    find_name: Optional[str] = None
    stdin: Optional[bytes] = None
    argv: Optional[bytes] = None
    files: Dict[str, bytes] = field(default_factory=dict)
    active_states: int = 0
    explored_states: int = 0
    timing_ms: float = 0.0

    def to_json(self) -> Dict[str, Any]:
        result: Dict[str, Any] = {
            "find_addr": hex(self.find_addr),
            "find_name": self.find_name,
            "stdin": self.stdin.hex() if self.stdin else None,
            "argv": self.argv.hex() if self.argv else None,
            "files": {k: v.hex() for k, v in self.files.items()},
            "active_states": self.active_states,
            "explored_states": self.explored_states,
            "timing_ms": self.timing_ms,
        }
        return result


def format_solution_text(solution: Solution) -> str:
    lines = []
    lines.append("")
    lines.append(colorize("✓ Solution found!", _green))
    lines.append("")

    if solution.find_name:
        lines.append(f"  Target: {colorize(solution.find_name, _cyan)} ({hex(solution.find_addr)})")
    else:
        lines.append(f"  Target: {colorize(hex(solution.find_addr), _cyan)}")

    lines.append("")

    def _dump(label: str, data: bytes) -> None:
        try:
            printable = data.decode("ascii")
            printable_text = printable
        except (UnicodeDecodeError, ValueError):
            printable_text = repr(data)

        lines.append(f"  {colorize(label + ':', _bold)}")
        lines.append(f"    ASCII:  {colorize(printable_text, _yellow)}")
        lines.append(f"    HEX:    {colorize(data.hex(), _dim)}")
        lines.append(f"    Python: {colorize(repr(data), _cyan)}")
        lines.append(f"    Escaped: {colorize(data.decode('latin-1').encode('unicode_escape').decode('ascii'), _dim)}")
        lines.append("")

    if solution.stdin is not None:
        _dump("STDIN", solution.stdin)

    if solution.argv is not None:
        _dump("ARGV", solution.argv)

    for fname, data in solution.files.items():
        _dump(f"FILE [{fname}]", data)

    lines.append(colorize(f"  Explored states: {solution.explored_states}  |  "
                          f"Active states: {solution.active_states}  |  "
                          f"Time: {solution.timing_ms:.1f} ms",
                          _dim))
    lines.append("")

    return "\n".join(lines)


def output_solution(
    solution: Solution,
    json_mode: bool = False,
    save_path: Optional[str] = None,
) -> None:
    if json_mode:
        print(json.dumps(solution.to_json(), indent=2))
    else:
        print(format_solution_text(solution))

    if save_path:
        payload = None
        if solution.stdin is not None:
            payload = solution.stdin
        elif solution.argv is not None:
            payload = solution.argv
        elif solution.files:
            payload = next(iter(solution.files.values()))

        if payload is not None:
            with open(save_path, "wb") as f:
                f.write(payload)
            print(colorize(f"[*] Payload saved to {save_path}", _green), file=sys.stderr)


def print_no_solution(
    explored: int = 0,
    timing_ms: float = 0.0,
    json_mode: bool = False,
) -> None:
    if json_mode:
        print(json.dumps({"error": "No solution found", "explored_states": explored, "timing_ms": timing_ms}))
    else:
        print(colorize("✗ No solution found", _red))
        print(colorize(f"  Explored states: {explored}  |  Time: {timing_ms:.1f} ms", _dim))
