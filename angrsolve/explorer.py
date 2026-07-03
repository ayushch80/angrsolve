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
        sym_data = content_list[0][0]
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


def explore(
    proj: angr.Project,
    input_setup: InputSetup,
    cfg: ExploreConfig,
) -> Optional[Solution]:
    """Run the exploration and return a *Solution* if found."""
    global _EXPLORE_TIMED_OUT
    _EXPLORE_TIMED_OUT = False

    start = time.time()
    logger.info("[+] Beginning exploration")

    state = input_setup.state
    find = cfg.find_addresses
    avoid = cfg.avoid_addresses

    if cfg.use_unicorn:
        logger.info("[+] Unicorn engine enabled")
        state.options.add(angr.options.UNICORN)
        state.options.add(angr.options.UNICORN_HANDLE_SYMBOLIC_SYSCALLS)
        state.options.add(angr.options.UNICORN_SYM_SYSCALL_RESOLVER)

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

    if input_setup.stdin_size > 0:
        data = _extract_stdin(s, input_setup.stdin_size)
        if data is not None:
            sol.stdin = data

    if input_setup.argv_size > 0 and input_setup.argv_addr is not None:
        data = _extract_argv_from_mem(s, input_setup.argv_addr, input_setup.argv_size)
        if data is not None:
            sol.argv = data

    for sf in input_setup.files:
        data = _extract_file(s, sf)
        if data is not None:
            sol.files[sf.filename] = data

    logger.info("[+] Solution found")
    return sol


def _stash_count(simgr: angr.sim_manager.SimulationManager, name: str) -> int:
    return len(simgr._stashes.get(name, []))
