# AGENTS.md — angrsolve

## Project Structure

```
angrsolve/                  # Package source
├── __init__.py             # Orchestration, logging, main()
├── cli.py                  # Argument parser and config builders
├── constraints.py          # Byte constraint modes (printable, etc.)
├── explorer.py             # Exploration engine with extract helpers
├── inputs.py               # Symbolic input setup (stdin/argv/file)
├── loader.py               # Binary loading and symbol resolution
├── output.py               # Solution output (text, JSON, save)
└── utils.py                # parse_address, hexdump
angrsolve.py                # Entry point (#!/usr/bin/env python3)
tests/                      # Test suite
├── conftest.py             # Test binary compilation fixtures
├── test_utils.py
├── test_constraints.py
├── test_cli.py
├── test_output.py
├── test_loader.py
├── test_inputs.py
├── test_explorer.py
├── test_integration.py
└── test_binaries.py               # 26 tests: compiles C → ELF → solves
AGENTS.md                   # This file
README.md
requirements.txt
```

## Build / Test / Lint Commands

```bash
# Run all tests (from project root)
pytest -v

# Run a specific test file
pytest -v tests/test_utils.py

# Run with live output (no capture)
pytest -v -s tests/test_explorer.py

# Run end-to-end tests only (slowest)
pytest -v tests/test_integration.py

# Run binary compilation tests (requires gcc)
pytest -v tests/test_binaries.py

# Run fast unit tests only (no angr dependency)
pytest -v tests/test_utils.py tests/test_constraints.py tests/test_cli.py tests/test_output.py

# Check syntax without running
python3 -m py_compile angrsolve/__init__.py angrsolve/cli.py angrsolve/constraints.py \
  angrsolve/explorer.py angrsolve/inputs.py angrsolve/loader.py angrsolve/output.py \
  angrsolve/utils.py angrsolve.py

# Run a quick smoke test
python3 angrsolve.py /tmp/test_argv_bin --find win --argv 32 --no-color -q
```

## GitHub Actions (`.github/workflows/ci.yml`)

Three parallel jobs run on every push/PR:

| Job | What it runs | Approx time |
|-----|-------------|-------------|
| `lint` | `python3 -m py_compile` on every `.py` file | 10 s |
| `unit-tests` | Fast tests (utils, constraints, cli, output) | 10 s |
| `integration-tests` | Loader, input setup, exploration + auto-created test binaries | 2 min |

## Code Conventions

- **Type hints**: Use `from __future__ import annotations` in every file. Use `Optional[X]` over `X | None` for Python < 3.10 compat.
- **Imports**: stdlib → third-party (angr, claripy) → local (`angrsolve.*`).
- **Docstrings**: Minimal. Only for public functions / classes when purpose isn't obvious.
- **Naming**: `snake_case` for functions/variables, `PascalCase` for classes, `UPPER_CASE` for constants.
- **Error handling**: Catch broad `Exception` in extraction helpers (explorer.py), log with `logger.debug`.
- **Logging**: Use `logger = logging.getLogger("angrsolve")` per module. Levels: ERROR (broken), WARNING (angr noise), INFO (progress), DEBUG (extraction failures).

## Architecture Notes

- **Binary loading**: `angr.Project(path, auto_load_libs=False)` — no libc loaded, but PLT functions get SimProcedures.
- **State creation**: `entry_state` for stdin/file only; `call_state(main_addr)` + manual stack setup for `--argv` (avoids libc startup complexity).
- **argv setup**: argv[1] string stored on stack manually; `rdi=2, rsi=argv_array`. This avoids a bug where `entry_state(args=[...])` doesn't handle symbolic BVs.
- **Exploration loop**: `simgr.explore(step_func=..., find=..., avoid=...)`. The `step_func` callback checks timeout, max_steps, and logs progress every 100 steps.
- **Stdin extraction**: Uses `fd.read_storage.content[0][0]` — data the program *consumed* (carries strcmp/etc constraints). The `.write_storage` approach does not carry backward constraints.
- **File extraction**: Saves `sym_content` reference at creation time, extracts from that after exploration. Direct `SimFile.content` access doesn't survive reads.
- **Constraints**: Range-based `claripy.And(bv >= lo, bv <= hi)` per contiguous range, not OR-chain per byte value. This avoids solver slowdown from huge OR chains.
- **Timeout**: SIGALRM-based hard kill (`signal.alarm(int(timeout) + 1)`). The `_timeout_handler` raises `TimeoutError` caught in `explore()`.

## Adding a Feature

1. Update the relevant module(s) following existing conventions
2. Add/update tests in `tests/`
3. Run `pytest -v` from project root
4. Run `python3 -m py_compile` on changed files for syntax check
5. Update README if user-facing
