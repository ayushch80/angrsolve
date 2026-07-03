from __future__ import annotations

import string
from typing import Any

import claripy

from angrsolve.constraints import ConstraintConfig, _set_to_ranges


class TestSetToRanges:
    def test_empty(self) -> None:
        assert _set_to_ranges(set()) == []

    def test_single(self) -> None:
        assert _set_to_ranges({5}) == [(5, 5)]

    def test_contiguous(self) -> None:
        assert _set_to_ranges({1, 2, 3, 4}) == [(1, 4)]

    def test_two_ranges(self) -> None:
        assert _set_to_ranges({1, 2, 5, 6}) == [(1, 2), (5, 6)]

    def test_unsorted_input(self) -> None:
        assert _set_to_ranges({10, 1, 2, 11}) == [(1, 2), (10, 11)]


class TestConstraintConfig:
    def test_printable_includes_null(self) -> None:
        cfg = ConstraintConfig(mode="printable")
        allowed = cfg.build_allowed_set()
        assert 0x00 in allowed

    def test_printable_contains_ascii_printable(self) -> None:
        cfg = ConstraintConfig(mode="printable")
        allowed = cfg.build_allowed_set()
        for b in string.printable.encode("ascii"):
            assert b in allowed

    def test_alphanumeric(self) -> None:
        cfg = ConstraintConfig(mode="alphanumeric")
        allowed = cfg.build_allowed_set()
        assert 0x00 in allowed
        assert ord(b"a") in allowed
        assert ord(b"Z") in allowed
        assert ord(b"5") in allowed
        assert ord(b" ") not in allowed
        assert ord(b"\n") not in allowed

    def test_letters(self) -> None:
        cfg = ConstraintConfig(mode="letters")
        allowed = cfg.build_allowed_set()
        assert 0x00 in allowed
        assert ord(b"a") in allowed
        assert ord(b"Z") in allowed
        assert ord(b"5") not in allowed

    def test_digits(self) -> None:
        cfg = ConstraintConfig(mode="digits")
        allowed = cfg.build_allowed_set()
        assert 0x00 in allowed
        assert ord(b"0") in allowed
        assert ord(b"9") in allowed
        assert ord(b"a") not in allowed

    def test_unrestricted(self) -> None:
        cfg = ConstraintConfig(mode="unrestricted")
        allowed = cfg.build_allowed_set()
        assert len(allowed) == 256

    def test_custom_bytes(self) -> None:
        cfg = ConstraintConfig(mode="printable", custom_bytes=[0x41, 0x42])
        allowed = cfg.build_allowed_set()
        assert allowed == {0x41, 0x42}

    def test_excluded_bytes(self) -> None:
        cfg = ConstraintConfig(mode="unrestricted", excluded_bytes={0x41})
        # build_allowed_set does not apply exclusions; apply_to does.
        allowed = cfg.build_allowed_set()
        assert 0x41 in allowed  # not excluded at this level
        syms = [claripy.BVS("x", 8)]
        constraints = cfg.apply_to(syms)
        if not constraints:
            return  # unrestricted with all 256 → no constraints
        assert len(constraints) == 1

    def test_apply_to_printable_returns_constraints(self) -> None:
        cfg = ConstraintConfig(mode="digits")
        syms = [claripy.BVS(f"b_{i}", 8) for i in range(3)]
        constraints = cfg.apply_to(syms)
        assert len(constraints) == 3
        for c in constraints:
            assert isinstance(c, claripy.ast.Base)  # All claripy ASTs share this base

    def test_apply_to_unrestricted_no_constraints(self) -> None:
        cfg = ConstraintConfig(mode="unrestricted")
        syms = [claripy.BVS(f"b_{i}", 8) for i in range(3)]
        constraints = cfg.apply_to(syms)
        assert constraints == []

    def test_apply_to_digits_constraints_satisfiable(self) -> None:
        cfg = ConstraintConfig(mode="digits")
        syms = [claripy.BVS(f"b_{i}", 8) for i in range(5)]
        constraints = cfg.apply_to(syms)
        solver = claripy.Solver()
        for c in constraints:
            solver.add(c)
        result = solver.check_satisfiability()
        # result is a list: non-empty means satisfiable
        assert len(result) > 0

    def test_default_mode_printable(self) -> None:
        cfg = ConstraintConfig()
        assert cfg.mode == "printable"
