from __future__ import annotations

from angrsolve.utils import hexdump, parse_address


class TestParseAddress:
    def test_hex_prefix(self) -> None:
        assert parse_address("0x1234") == 0x1234

    def test_hex_prefix_caps(self) -> None:
        assert parse_address("0XABCD") == 0xABCD

    def test_bare_hex(self) -> None:
        assert parse_address("deadbeef") == 0xDEADBEEF

    def test_decimal(self) -> None:
        # Pure decimal numbers that don't look like hex still parse as hex if
        # all digits are 0-9 (valid hex). Use 0x prefix to force hex.
        assert parse_address("0x12345") == 0x12345
        assert parse_address("99999") == 0x99999  # all-hex digits

    def test_invalid(self) -> None:
        assert parse_address("zzz") is None

    def test_empty_string(self) -> None:
        assert parse_address("") is None

    def test_whitespace(self) -> None:
        assert parse_address("  0xff  ") == 0xFF


class TestHexdump:
    def test_simple(self) -> None:
        result = hexdump(b"hello")
        assert "hello" in result

    def test_multiline(self) -> None:
        data = bytes(range(32))
        result = hexdump(data, per_line=16)
        lines = result.split("\n")
        assert len(lines) == 2
        assert "00 01" in lines[0]
        assert "10 11" in lines[1]

    def test_non_printable_replaced(self) -> None:
        data = bytes([0, 1, 2, 0x41])
        result = hexdump(data, per_line=4)
        assert "..." in result
        assert "A" in result

    def test_empty(self) -> None:
        assert hexdump(b"") == ""
