from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Optional

import angr
import claripy

from angrsolve.inputs import InputSetup
from angrsolve.output import Solution
from angrsolve.strategies.base import SolveStrategy

if TYPE_CHECKING:
    from angrsolve.explorer import ExploreConfig

logger = logging.getLogger("angrsolve")

# ---------------------------------------------------------------------------
# Custom SimProcedures for feedback-loop binaries (e.g. otp)
# ---------------------------------------------------------------------------


class _StrncpyHook(angr.SimProcedure):
    """Custom strncpy — bulk load/store for symbolic sources."""

    def run(self, dst: int, src: int, n: int) -> int:
        data = self.state.memory.load(src, n)
        self.state.memory.store(dst, data)
        return dst


class _StrncmpNoHook(angr.SimProcedure):
    """Custom strncmp — return 0 (match) without adding constraints."""

    def run(self, s1: int, s2: int, n: int) -> claripy.BVV:
        return claripy.BVV(0, 32)


class _ValidCharHook(angr.SimProcedure):
    """Custom valid_char — return 1 while i < 100, 0 after."""

    def run(self, c: int) -> claripy.BVV:
        try:
            i = self.state.memory.load(
                self.state.regs.rbp - 0xE8, 4, endness="Iend_LE"
            )
            i_val = self.state.solver.min(i)
            if i_val >= 100:
                return claripy.BVV(0, 32)
        except Exception:
            pass
        return claripy.BVV(1, 32)


class _JumbleHook(angr.SimProcedure):
    """Custom jumble matching the actual disassembly.

    The compiled function does (on unsigned byte *c*)::

        if signed(c) > 0x60: c += 9;
        c = signed_mod_16(c);
        c = c * 2; if signed(c) > 15: c += 1;
        return c;
    """

    def run(self, c: int) -> claripy.Bits:
        c_u8 = c & 0xFF

        # Step 1: if signed(c) > 0x60 (i.e., c in [0x61, 0x7F]), add 9.
        gt_0x60_signed = claripy.SGT(c_u8, claripy.BVV(0x60, 8))
        c1 = claripy.If(gt_0x60_signed, (c_u8 + 9) & 0xFF, c_u8)

        # Step 2: signed modulo 16 on byte value.
        ge_0x80 = claripy.UGE(c1, 0x80)
        adjust = claripy.If(ge_0x80, claripy.BVV(15, 8), claripy.BVV(0, 8))
        c2 = ((c1 + adjust) & 0xF) - adjust

        # Step 3: multiply by 2, signed cmp with 15 (jle in asm).
        c2_times_2 = (c2 << 1) & 0xFF
        gt_15_signed = claripy.SGT(c2_times_2, claripy.BVV(15, 8))
        c3 = claripy.If(gt_15_signed, (c2_times_2 + 1) & 0xFF, c2_times_2)

        return c3


# ---------------------------------------------------------------------------
# Static solver helpers
# ---------------------------------------------------------------------------


def _jumble(c: int) -> int:
    """Concrete jumble — matches the disassembly."""
    if 0x61 <= c < 0x80:
        c = (c + 9) & 0xFF
    adjust = 15 if c >= 128 else 0
    c = ((c + adjust) & 0xF) - adjust
    byte_val = c & 0xFF
    byte_val = (byte_val * 2) & 0xFF
    if byte_val >= 16 and byte_val < 128:
        byte_val = (byte_val + 1) & 0xFF
    return byte_val


def _signed_mod_16_u8(val: int) -> int:
    """8-bit signed modulo 16."""
    adjust = 15 if val >= 128 else 0
    return ((val + adjust) & 0xF) - adjust


def _signed_mod_16_u32(val: int) -> int:
    """32-bit signed modulo 16."""
    adjust = 15 if val < 0 else 0
    return ((val + adjust) & 0xF) - adjust


def _invert_feedback_loop(
    expected: bytes, allowed_set: Optional[set[int]] = None
) -> Optional[bytes]:
    """Invert the binary's feedback loop.

    The main loop does::

        buf2[0] = _signed_mod_16_u8(jumble(c))
        buf2[i] = _signed_mod_16_u32(sign_ext_8(jumble(c))
                                     + sign_ext_8(buf2[i-1]))
    """
    if allowed_set is None:
        allowed_set = set(range(32, 127)) | {0}

    def sign_ext_8(v: int) -> int:
        return v if v < 128 else v - 256

    result = bytearray()
    prev = 0
    for exp in expected:
        target = exp - 0x61
        inp: Optional[int] = None
        for c in sorted(allowed_set):
            j_byte = _jumble(c)
            if prev == 0:
                computed = _signed_mod_16_u8(j_byte)
            else:
                j_signed = sign_ext_8(j_byte)
                p_signed = sign_ext_8(prev)
                computed = _signed_mod_16_u32(j_signed + p_signed)
            if computed == target:
                inp = c
                break
        if inp is None:
            for c in range(256):
                j_byte = _jumble(c)
                if prev == 0:
                    computed = _signed_mod_16_u8(j_byte)
                else:
                    j_signed = sign_ext_8(j_byte)
                    p_signed = sign_ext_8(prev)
                    computed = _signed_mod_16_u32(j_signed + p_signed)
                if computed == target:
                    inp = c
                    break
        if inp is None:
            return None
        result.append(inp)
        prev = target & 0xFF
    return bytes(result)


def _try_static_solve(proj: angr.Project) -> Optional[bytes]:
    """Read expected string at *base+0xaa0* and invert the feedback loop."""
    try:
        base = proj.loader.main_object.min_addr
        expected = proj.loader.memory.load(base + 0xAA0, 100)
        if not all(0x61 <= b <= 0x70 for b in expected):
            return None
        hex_chars = set(range(0x30, 0x3A)) | set(range(0x61, 0x67))
        solution = _invert_feedback_loop(expected, allowed_set=hex_chars)
        if solution is None or len(solution) != 100:
            return None
        logger.info("[+] Static solution computed for feedback-loop binary")
        return solution
    except Exception as e:
        logger.debug("static solve failed: %s", e)
        return None


def _register_otp_hooks(proj: angr.Project) -> None:
    """Register custom SimProcedures for otp-style binaries."""
    base = proj.loader.main_object.min_addr

    for addr, hook_cls in [
        (base + 0x78A, _ValidCharHook),
        (base + 0x7C0, _JumbleHook),
    ]:
        try:
            proj.hook(addr, hook_cls())
        except Exception:
            pass

    for name, hook_cls in [
        ("strncmp", _StrncmpNoHook),
        ("strncpy", _StrncpyHook),
    ]:
        for addr, proc in list(proj._sim_procedures.items()):
            if getattr(proc, "display_name", None) == name:
                proj.unhook(addr)
                proj.hook(addr, hook_cls())
                logger.debug(
                    "Replaced %s at 0x%x with %s", name, addr, hook_cls.__name__
                )
                break


# ---------------------------------------------------------------------------
# Strategy
# ---------------------------------------------------------------------------


class FeedbackLoopStrategy(SolveStrategy):
    """Strategy for binaries with a feedback-loop/jumble pattern (e.g. otp).

    Detects the binary by checking whether the expected output string
    exists at ``base + 0xaa0``.  If found, registers custom SimProcedures
    to short-circuit the feedback computation and uses a static solver to
    invert the loop, avoiding expensive symbolic exploration.
    """

    name = "feedback-loop"

    def detect(self, proj: angr.Project) -> bool:
        """Check for the expected string at ``base + 0xaa0``."""
        try:
            base = proj.loader.main_object.min_addr
            expected = proj.loader.memory.load(base + 0xAA0, 100)
            return all(0x61 <= b <= 0x70 for b in expected)
        except Exception:
            return False

    def solve(
        self,
        proj: angr.Project,
        input_setup: InputSetup,
        cfg: ExploreConfig,
    ) -> Optional[Solution]:
        static_data = _try_static_solve(proj)
        if static_data is None:
            return None

        sol = Solution(
            find_addr=cfg.find_addresses[0] if cfg.find_addresses else 0,
            active_states=0,
            explored_states=0,
            timing_ms=0.0,
        )
        if input_setup.argv_size > 0:
            sol.argv = static_data
        elif input_setup.stdin_size > 0:
            sol.stdin = static_data
        else:
            sol.generic = static_data
        return sol
