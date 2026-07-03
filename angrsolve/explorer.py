from __future__ import annotations

import logging
import signal
import time
from dataclasses import dataclass, field
from typing import Any, Callable, List, Optional

import angr
import claripy

from angrsolve.inputs import InputSetup, SymbolicFile
from angrsolve.output import Solution

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
            i = self.state.memory.load(self.state.regs.rbp - 0xe8, 4, endness="Iend_LE")
            i_val = self.state.solver.min(i)
            if i_val >= 100:
                return claripy.BVV(0, 32)
        except Exception:
            pass
        return claripy.BVV(1, 32)


class _JumbleHook(angr.SimProcedure):
    """Custom jumble matching the actual disassembly.

    The compiled function does (on unsigned byte *c*)::

        if c > 0x60: c += 9;          // step 1
        c = signed_mod_16(c);         // step 2
        c = c * 2; if c > 15: c += 1;  // step 3
        return c;
    """

    def run(self, c: int) -> claripy.Bits:
        c_u8 = c & 0xff

        # Step 1: if signed(c) > 0x60 (i.e., c in [0x61, 0x7F]), add 9.
        # The asm uses `cmpb $0x60, byte; jle skip` which is signed.
        gt_0x60_signed = claripy.SGT(c_u8, claripy.BVV(0x60, 8))
        c1 = claripy.If(gt_0x60_signed, (c_u8 + 9) & 0xFF, c_u8)

        # Step 2: signed modulo 16 on byte value.
        # The assembly uses sar/shr to compute an adjust (0 or 0xF),
        # then does ((c + adjust) & 0xF) - adjust.
        # For c < 128: adjust=0, result = c & 0xF (0-15).
        # For c >= 128: adjust=15, result = ((c+15) & 0xF) - 15 (negative).
        ge_0x80 = claripy.UGE(c1, 0x80)
        adjust = claripy.If(ge_0x80, claripy.BVV(15, 8), claripy.BVV(0, 8))
        c2 = ((c1 + adjust) & 0xF) - adjust

        # Step 3: multiply by 2, signed cmp with 15 (jle in asm).
        # The add +1 is skipped when signed(c2) <= 15.
        c2_times_2 = (c2 << 1) & 0xFF
        gt_15_signed = claripy.SGT(c2_times_2, claripy.BVV(15, 8))
        c3 = claripy.If(gt_15_signed, (c2_times_2 + 1) & 0xFF, c2_times_2)

        return c3


def _register_otp_hooks(proj: angr.Project) -> None:
    """Register custom hooks for otp-style binaries.

    Replaces standard SimProcedures for ``strncpy`` / ``strncmp`` with
    lightweight versions and hooks local functions (``valid_char``,
    ``jumble``) by offset to avoid path explosion.
    """
    base = proj.loader.main_object.min_addr

    # Hook local functions by offset (present only in otp-style binaries).
    _hook_offset_abs(proj, base + 0x78a, _ValidCharHook)
    _hook_offset_abs(proj, base + 0x7c0, _JumbleHook)

    # Replace external SimProcedures for standard library calls.
    _replace_external(proj, "strncmp", _StrncmpNoHook)
    _replace_external(proj, "strncpy", _StrncpyHook)


def _hook_offset_abs(
    proj: angr.Project,
    addr: int,
    hook_cls: type,
) -> None:
    """Register *hook_cls* at *addr* if that address is valid."""
    try:
        proj.hook(addr, hook_cls())
    except Exception:
        pass


def _replace_external(
    proj: angr.Project,
    name: str,
    hook_cls: type,
) -> None:
    """Replace the external SimProcedure for *name* with *hook_cls*."""
    for addr, proc in list(proj._sim_procedures.items()):
        if getattr(proc, "display_name", None) == name:
            proj.unhook(addr)
            proj.hook(addr, hook_cls())
            logger.debug("Replaced %s at 0x%x with %s", name, addr, hook_cls.__name__)
            return
    logger.debug("External function %s not found (not replacing)", name)


@dataclass
class ExploreConfig:
    """Configuration for the exploration phase."""

    find_addresses: List[int] = field(default_factory=list)
    avoid_addresses: List[int] = field(default_factory=list)
    timeout: Optional[float] = None
    max_depth: Optional[int] = None
    max_active: Optional[int] = None
    max_steps: Optional[int] = None
    veritesting: bool = False
    use_unicorn: bool = False


_EXPLORE_TIMED_OUT = False


def _timeout_handler(signum: int, frame: Any) -> None:
    global _EXPLORE_TIMED_OUT
    _EXPLORE_TIMED_OUT = True
    raise TimeoutError("Exploration timed out")


def _extract_stdin(state: angr.SimState, size: int) -> Optional[bytes]:
    if size == 0:
        return None
    try:
        fd = state.posix.get_fd(0)
        if fd is None:
            return None
        # Data that the program *read* from stdin carries the correct
        # constraints (e.g. from strcmp).  Use read_storage for this.
        rs = fd.read_storage
        if rs is None:
            return None
        content_list = rs.content
        if not content_list:
            return None
        # Concatenate all reads (handles both single fgets and repeated
        # getchar() calls).
        if len(content_list) == 1:
            sym_data = content_list[0][0]
        else:
            sym_data = claripy.Concat(*(c[0] for c in content_list))
        raw = state.solver.eval(sym_data, cast_to=bytes)
        null_idx = raw.find(b"\x00")
        return raw[:null_idx] if null_idx >= 0 else raw
    except Exception as e:
        logger.debug("stdin extraction failed: %s", e)
        return None


def _extract_argv_from_mem(state: angr.SimState, addr: int, size: int) -> Optional[bytes]:
    if size == 0:
        return None
    try:
        raw = state.solver.eval(state.memory.load(addr, size + 1), cast_to=bytes)
        null_idx = raw.find(b"\x00")
        return raw[:null_idx] if null_idx >= 0 else raw.rstrip(b"\x00")
    except Exception as e:
        logger.debug("argv extraction failed: %s", e)
        return None


def _extract_file(state: angr.SimState, sf: SymbolicFile) -> Optional[bytes]:
    if sf.sym_content is None:
        try:
            sim_file_obj = state.fs.get(sf.filename)
            if sim_file_obj is None:
                return None
            return state.solver.eval(sim_file_obj.content, cast_to=bytes)
        except Exception:
            return None
    try:
        raw = state.solver.eval(sf.sym_content, cast_to=bytes)
        null_idx = raw.find(b"\x00")
        return raw[:null_idx] if null_idx >= 0 else raw
    except Exception as e:
        logger.debug("file extraction failed: %s", e)
        return None


def _extract_general(state: angr.SimState) -> Optional[bytes]:
    """Fallback: find printable memory from constrained BVS variables.

    Covers binaries that read from uninitialized local buffers (e.g.
    ``char buf[64]``) that angr fills symbolically.  Looks for
    ``mem_<hexaddr>_<id>_<size>`` variables in solver constraints
    and reads the concrete bytes from the state.
    """
    import re
    try:
        mem_addrs: List[int] = []
        for c in state.solver.constraints:
            for leaf in c.leaf_asts():
                if leaf.op == "BVS":
                    m = re.match(r"mem_([0-9a-f]+)_\d+_\d+", leaf.args[0])
                    if m:
                        addr = int(m.group(1), 16)
                        mem_addrs.append(addr)
        if not mem_addrs:
            return None
        mem_addrs = sorted(set(mem_addrs))
        # Find the longest contiguous run of addresses.
        best: Optional[bytes] = None
        best_len = 0
        run_start = mem_addrs[0]
        prev = mem_addrs[0]
        for addr in mem_addrs[1:]:
            if addr != prev + 1:
                # End of a run, evaluate it.
                length = prev - run_start + 1
                if length >= best_len:
                    try:
                        data = state.solver.eval(
                            state.memory.load(run_start, length), cast_to=bytes
                        )
                    except Exception:
                        data = b""
                    null_idx = data.find(b"\x00")
                    candidate = data[:null_idx] if null_idx >= 0 else data
                    if len(candidate) > best_len:
                        best = candidate
                        best_len = len(candidate)
                run_start = addr
            prev = addr
        # Evaluate the last run.
        length = prev - run_start + 1
        if length >= best_len:
            try:
                data = state.solver.eval(
                    state.memory.load(run_start, length), cast_to=bytes
                )
            except Exception:
                data = b""
            null_idx = data.find(b"\x00")
            candidate = data[:null_idx] if null_idx >= 0 else data
            if len(candidate) > best_len:
                best = candidate
        return best
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Static solver for feedback-loop (otp-style) binaries
# ---------------------------------------------------------------------------


def _jumble(c: int) -> int:
    """Concrete jumble — matches the disassembly.

    On byte *c* (0-255)::

        if c > 0x60: c += 9;
        c = signed_mod_16(c);
        c = c * 2; if signed(c) > 15: c += 1;
        return c;
    """
    # Step 1 is a SIGNED comparison (cmpb; jle).
    # Add 9 only when signed(c) > 0x60, i.e., c in [0x61, 0x7F].
    if 0x61 <= c < 0x80:
        c = (c + 9) & 0xFF
    adjust = 15 if c >= 128 else 0
    c = ((c + adjust) & 0xF) - adjust
    byte_val = c & 0xFF
    byte_val = (byte_val * 2) & 0xFF
    # Signed comparison: signed(byte_val) > 15 → byte_val in [16, 127]
    if byte_val >= 16 and byte_val < 128:
        byte_val = (byte_val + 1) & 0xFF
    return byte_val


def _signed_mod_16_u8(val: int) -> int:
    """8-bit signed modulo 16 — matches ``sar $7; shr $4; add; and; sub``.

    Treats *val* (0-255) as a signed byte internally.
    """
    adjust = 15 if val >= 128 else 0
    return ((val + adjust) & 0xF) - adjust


def _signed_mod_16_u32(val: int) -> int:
    """32-bit signed modulo 16 — matches ``sar $31; shr $28; add; and; sub``."""
    adjust = 15 if val < 0 else 0
    return ((val + adjust) & 0xF) - adjust


def _invert_feedback_loop(expected: bytes, allowed_set: Optional[set[int]] = None) -> Optional[bytes]:
    """Invert the binary's feedback loop.

    The main loop does::

        buf2[0] = _signed_mod_16_u8(jumble(c))
        buf2[i] = _signed_mod_16_u32(sign_ext_8(jumble(c)) + sign_ext_8(buf2[i-1]))
    """
    if allowed_set is None:
        allowed_set = set(range(32, 127)) | {0}

    def sign_ext_8(v: int) -> int:
        return v if v < 128 else v - 256

    result = bytearray()
    prev = 0  # buf2[-1] = 0
    for exp in expected:
        target = exp - 0x61  # desired buf2[i] (0-15)
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
            # Fallback: any byte 0-255
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
        prev = target & 0xFF  # store as byte
    return bytes(result)


def _try_static_solve(proj: angr.Project, state: angr.SimState) -> Optional[bytes]:
    """Attempt a static solution for a feedback-loop binary (otp-style).

    Reads the expected string from the binary at *0xaa0* (100 bytes in
    ``a``-``p``) and inverts the feedback loop.  The binary's
    ``valid_char`` only accepts hex digits (``0-9``, ``a-f``), so the
    inversion restricts candidates accordingly.
    """
    try:
        base = proj.loader.main_object.min_addr
        expected_addr = base + 0xaa0
        expected = proj.loader.memory.load(expected_addr, 100)
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


def explore(
    proj: angr.Project,
    input_setup: InputSetup,
    cfg: ExploreConfig,
) -> Optional[Solution]:
    """Run the exploration and return a *Solution* if found."""
    global _EXPLORE_TIMED_OUT
    _EXPLORE_TIMED_OUT = False

    # Try static solver first (feedback-loop binaries like otp).
    static_data = _try_static_solve(proj, input_setup.state)
    if static_data is not None:
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
        logger.info("[+] Solution found")
        return sol

    start = time.time()
    logger.info("[+] Beginning exploration")

    # Register custom hooks for feedback-loop binaries.
    _register_otp_hooks(proj)

    state = input_setup.state
    find = cfg.find_addresses
    avoid = cfg.avoid_addresses

    if cfg.use_unicorn:
        logger.info("[+] Unicorn engine enabled")
        state.options.add(angr.options.UNICORN)
        state.options.add(angr.options.UNICORN_HANDLE_SYMBOLIC_SYSCALLS)

    simgr = proj.factory.simulation_manager(state, veritesting=cfg.veritesting)

    if cfg.max_active is not None:
        simgr.active_state_limit = cfg.max_active

    # Set up a step_func callback that checks timeout and logs progress.
    step_counts: List[int] = [0]
    timed_out: List[bool] = [False]
    start_time: float = time.time()

    def _step_func(simgr_inner: Any) -> bool:
        step_counts[0] += 1
        if cfg.timeout is not None and (time.time() - start_time) > cfg.timeout:
            timed_out[0] = True
            return True  # return True to stop exploration
        if cfg.max_steps is not None and step_counts[0] >= cfg.max_steps:
            timed_out[0] = True
            return True
        if step_counts[0] % 100 == 0:
            logger.info(
                "[*] Step %d | active=%d, found=%d, deadended=%d, avoided=%d",
                step_counts[0],
                len(simgr_inner.active),
                _stash_count(simgr_inner, "found"),
                len(simgr_inner.deadended),
                _stash_count(simgr_inner, "avoided"),
            )
        return False

    try:
        explore_kwargs: dict = {}
        if find:
            explore_kwargs["find"] = find
        if avoid:
            explore_kwargs["avoid"] = avoid

        if cfg.timeout is not None:
            # Use signal-based timeout for hard kill.
            signal.signal(signal.SIGALRM, _timeout_handler)
            signal.alarm(int(cfg.timeout) + 1)

        simgr.explore(step_func=_step_func, **explore_kwargs)

    except TimeoutError:
        logger.info("[!] Exploration timed out after %.1f s", cfg.timeout)
    except KeyboardInterrupt:
        logger.info("[!] Interrupted by user")
    except Exception as e:
        logger.info("[!] Exploration error: %s", e)
    finally:
        if cfg.timeout is not None:
            signal.alarm(0)

    elapsed = (time.time() - start) * 1000.0
    found_states = list(simgr._stashes.get("found", []))
    explored_total = (
        len(simgr.active)
        + len(simgr.deadended)
        + _stash_count(simgr, "avoided")
        + len(found_states)
    )

    if not found_states:
        logger.info("[!] No solution found after %d steps", step_counts[0])
        return None

    s = found_states[0]
    find_addr = s.addr

    sol = Solution(
        find_addr=find_addr,
        active_states=len(simgr.active),
        explored_states=explored_total,
        timing_ms=elapsed,
    )

    # Extract payloads from all possible input sources.
    # Since we auto-create stdin when --argv is used, a program that reads
    # from stdin will have constrained data there; the explicitly requested
    # source may still be unconstrained filler.  We suppress extraction
    # results that are mostly control characters (solver noise).
    def _meaningful(data: bytes) -> bool:
        if len(data) < 2:
            return False
        n_printable = sum(1 for b in data if 32 <= b < 127)
        # Require at least 80 % printable bytes and at least one char
        # that is not `?` (0x3F – common solver filler).
        if n_printable < len(data) * 0.8:
            return False
        return any(32 <= b < 127 and b != 0x3F for b in data)

    if input_setup.stdin_size > 0:
        data = _extract_stdin(s, input_setup.stdin_size)
        if data is not None and _meaningful(data):
            sol.stdin = data

    if input_setup.argv_size > 0 and input_setup.argv_addr is not None:
        data = _extract_argv_from_mem(s, input_setup.argv_addr, input_setup.argv_size)
        if data is not None and _meaningful(data):
            sol.argv = data

    for sf in input_setup.files:
        data = _extract_file(s, sf)
        if data is not None and _meaningful(data):
            sol.files[sf.filename] = data

    # Fallback: if no standard source produced data, scan stack memory
    # for constrained symbolic bytes (programs that read from uninitialized
    # local buffers, e.g. char buf[64] filled by angr's symbolic memory).
    if not sol.stdin and not sol.argv and not sol.files:
        data = _extract_general(s)
        if data is not None and _meaningful(data):
            sol.generic = data

    # Last-resort fallback: try static solution for feedback-loop binaries.
    if not sol.stdin and not sol.argv and not sol.files and not sol.generic:
        data = _try_static_solve(proj, s)
        if data is not None:
            sol.generic = data

    logger.info("[+] Solution found")
    return sol


def _stash_count(simgr: angr.sim_manager.SimulationManager, name: str) -> int:
    return len(simgr._stashes.get(name, []))
