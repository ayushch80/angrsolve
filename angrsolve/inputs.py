from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import List, Optional

import angr
import claripy

from angrsolve.constraints import ConstraintConfig

logger = logging.getLogger("angrsolve")


@dataclass
class InputConfig:
    """Describes one source of symbolic input."""

    source: str  # "stdin", "argv", "file"
    size: int = 128
    filename: Optional[str] = None


@dataclass
class InputSetup:
    """Carries all symbolic data and metadata for exploration."""

    state: angr.SimState
    stdin_size: int = 0
    stdin_addr: Optional[int] = None  # address where stdin content was stored
    argv_size: int = 0
    argv_addr: Optional[int] = None  # address where argv[1] content was stored
    files: List["SymbolicFile"] = field(default_factory=list)


@dataclass
class SymbolicFile:
    """Describes a symbolic file that was created."""

    filename: str
    size: int
    sym_content: Optional[claripy.Bits] = None


def _resolve_main(proj: angr.Project) -> Optional[int]:
    sym = proj.loader.find_symbol("main")
    return sym.rebased_addr if sym is not None else None


def setup_input(
    proj: angr.Project,
    inputs: List[InputConfig],
    cfg: ConstraintConfig,
) -> InputSetup:
    """Create the initial state and attach symbolic inputs."""
    stdin_size = 0
    argv_size = 0
    files: List[SymbolicFile] = []

    # Collect configuration.
    has_argv = any(inp.source == "argv" for inp in inputs)
    has_stdin = any(inp.source == "stdin" for inp in inputs)
    has_file = any(inp.source == "file" for inp in inputs)

    for inp in inputs:
        if inp.source == "argv":
            argv_size = inp.size
        elif inp.source == "stdin":
            stdin_size = inp.size
        elif inp.source == "file":
            files.append(SymbolicFile(filename=inp.filename or "", size=inp.size))

    state: angr.SimState
    argv_addr: Optional[int] = None
    stdin_addr: Optional[int] = None

    if has_argv:
        # Use call_state at main for --argv to avoid libc startup complexity.
        main_addr = _resolve_main(proj)
        if main_addr is not None:
            state = proj.factory.call_state(main_addr)
        else:
            state = proj.factory.entry_state()

        # Build symbolic argv[1].
        sym_vals = [claripy.BVS(f"argv_1_{i}", 8) for i in range(argv_size)]
        argv_string = claripy.Concat(*sym_vals, claripy.BVV(0, 8))

        # Place the string on the stack.
        stack_bv = state.regs.rsp - 0x200
        state.memory.store(stack_bv, argv_string)
        argv_addr = state.solver.eval(stack_bv)

        # Build the argv array.
        argv_array = stack_bv - 0x100
        prog_name = stack_bv + 0x50
        state.memory.store(prog_name, b"./binary\x00")
        state.memory.store(argv_array, prog_name, endness="Iend_LE")
        state.memory.store(argv_array + 8, stack_bv, endness="Iend_LE")
        state.memory.store(argv_array + 16, claripy.BVV(0, 64), endness="Iend_LE")

        state.regs.rdi = claripy.BVV(2, 64)
        state.regs.rsi = argv_array

        # Apply constraints.
        constraints = cfg.apply_to(sym_vals)
        for c in constraints:
            state.solver.add(c)

        # Always set up stdin so programs that read from stdin (fgets etc.)
        # get properly constrained symbolic data rather than unconstrained
        # filler.  This ensures strcmp constraints carry back to extraction.
        if stdin_size == 0:
            stdin_size = 128
        _create_stdin(state, stdin_size, cfg)
    else:
        state = proj.factory.entry_state()
        if has_stdin:
            _create_stdin(state, stdin_size, cfg)

    # Set up files.
    for inp in inputs:
        if inp.source == "file" and inp.filename:
            sym_content = _create_file(state, inp.filename, inp.size, cfg)
            for sf in files:
                if sf.filename == inp.filename:
                    sf.sym_content = sym_content
                    break

    return InputSetup(
        state=state,
        stdin_size=stdin_size,
        stdin_addr=stdin_addr,
        argv_size=argv_size,
        argv_addr=argv_addr,
        files=files,
    )


def _create_stdin(
    state: angr.SimState,
    size: int,
    cfg: ConstraintConfig,
) -> None:
    logger.info("[+] Creating symbolic stdin (size=%d)", size)
    sym_bytes = [claripy.BVS(f"stdin_{i}", 8) for i in range(size)]
    stdin = claripy.Concat(*sym_bytes)

    fd = state.posix.get_fd(0)
    fd.write_data(stdin)
    fd.seek(0)

    constraints = cfg.apply_to(sym_bytes)
    for c in constraints:
        state.solver.add(c)


def _create_file(
    state: angr.SimState,
    filename: str,
    size: int,
    cfg: ConstraintConfig,
) -> claripy.Bits:
    logger.info("[+] Creating symbolic file '%s' (size=%d)", filename, size)
    sym_bytes = [claripy.BVS(f"file_{filename}_{i}", 8) for i in range(size)]
    content = claripy.Concat(*sym_bytes)

    sim_file = angr.storage.file.SimFile(filename, content=content)
    state.fs.insert(filename, sim_file)

    constraints = cfg.apply_to(sym_bytes)
    for c in constraints:
        state.solver.add(c)

    return content
