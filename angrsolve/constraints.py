from __future__ import annotations

import string
from dataclasses import dataclass, field
from typing import List, Optional, Set, Tuple

import claripy


def _set_to_ranges(values: Set[int]) -> List[Tuple[int, int]]:
    """Convert a set of integers into a list of (lo, hi) inclusive ranges."""
    if not values:
        return []
    sorted_vals = sorted(values)
    ranges: List[Tuple[int, int]] = []
    lo = sorted_vals[0]
    hi = sorted_vals[0]
    for v in sorted_vals[1:]:
        if v == hi + 1:
            hi = v
        else:
            ranges.append((lo, hi))
            lo = v
            hi = v
    ranges.append((lo, hi))
    return ranges


@dataclass
class ConstraintConfig:
    """Configuration for byte constraints on symbolic input."""

    mode: str = "printable"
    custom_bytes: Optional[List[int]] = None
    excluded_bytes: Optional[Set[int]] = None

    def __post_init__(self) -> None:
        if self.excluded_bytes is None:
            self.excluded_bytes = set()

    def build_allowed_set(self) -> Set[int]:
        if self.custom_bytes is not None:
            return set(self.custom_bytes)
        if self.mode == "printable":
            s = set(string.printable.encode("ascii"))
            s.add(0x00)  # null terminator
            return s
        if self.mode == "alphanumeric":
            s = set(string.ascii_letters.encode("ascii") + string.digits.encode("ascii"))
            s.add(0x00)
            return s
        if self.mode == "letters":
            s = set(string.ascii_letters.encode("ascii"))
            s.add(0x00)
            return s
        if self.mode == "digits":
            s = set(string.digits.encode("ascii"))
            s.add(0x00)
            return s
        if self.mode == "unrestricted":
            return set(range(256))
        return set(string.printable.encode("ascii"))

    def apply_to(self, sym_bytes: List[claripy.BVS]) -> List[claripy.BoolV]:
        """Build efficient range-based constraints for each symbolic byte.

        Returns a list of BoolV constraints (one per byte) that constrain
        each byte to the allowed set.  Contiguous ranges are batched
        together for solver performance.
        """
        all_bytes = self.build_allowed_set()
        excluded = self.excluded_bytes or set()
        allowed = all_bytes - excluded

        if len(allowed) == 256:
            return []

        ranges = _set_to_ranges(allowed)

        constraints = []
        for bv in sym_bytes:
            if ranges:
                clause = claripy.BoolV(False)
                for lo, hi in ranges:
                    clause = claripy.Or(clause, claripy.And(bv >= lo, bv <= hi))
                constraints.append(clause)
            else:
                constraints.append(claripy.BoolV(False))
        return constraints
