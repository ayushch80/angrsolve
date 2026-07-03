from __future__ import annotations

import re
from typing import Optional


def parse_address(value: str) -> Optional[int]:
    """Parse an address from a hex string or decimal string.

    Accepts hex prefixes like 0x, 0X, or bare hex.
    """
    value = value.strip()
    try:
        if value.startswith(("0x", "0X")):
            return int(value, 16)
        if re.match(r"^[0-9a-fA-F]+$", value):
            return int(value, 16)
        return int(value)
    except (ValueError, TypeError):
        return None


def hexdump(data: bytes, per_line: int = 16) -> str:
    """Return a hexdump-style string of *data*."""
    lines = []
    for i in range(0, len(data), per_line):
        chunk = data[i : i + per_line]
        hex_part = " ".join(f"{b:02x}" for b in chunk)
        ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"{i:08x}  {hex_part:<{per_line * 3}}  {ascii_part}")
    return "\n".join(lines)
