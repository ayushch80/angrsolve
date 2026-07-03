# angrsolve Documentation

## Table of Contents

- [Overview](#overview)
- [Installation](#installation)
- [Usage](#usage)
- [Input Sources](#input-sources)
  - [stdin](#stdin)
  - [argv](#argv)
  - [File](#file)
- [Constraint Modes](#constraint-modes)
- [Target Specification](#target-specification)
  - [Find Targets](#find-targets)
  - [Avoid Targets](#avoid-targets)
  - [Auto-detect](#auto-detect)
- [Performance Options](#performance-options)
- [Output](#output)
  - [Text Output](#text-output)
  - [JSON Output](#json-output)
  - [Save to File](#save-to-file)
- [Logging and Verbosity](#logging-and-verbosity)
- [Examples](#examples)
  - [Basic argv](#basic-argv)
  - [Basic stdin](#basic-stdin)
  - [File-based input](#file-based-input)
  - [PIE binary](#pie-binary)
  - [Stripped binary](#stripped-binary)
  - [Integer comparison](#integer-comparison)
  - [memcmp challenge](#memcmp-challenge)
  - [Multiple checks](#multiple-checks)
  - [Custom byte constraints](#custom-byte-constraints)
  - [JSON output](#json-output)
- [Architecture](#architecture)
- [Development](#development)
  - [Running tests](#running-tests)
  - [Code conventions](#code-conventions)
  - [CI](#ci)

---

## Overview

angrsolve automates the process of finding symbolic inputs that reach a target address in a binary. It uses angr to:

1. Load the binary and resolve target addresses
2. Create symbolic input (stdin, argv, or file contents)
3. Apply byte constraints (printable ASCII by default)
4. Explore execution paths until the target is reached
5. Extract the concrete input values from the solver

It is designed for CTF reversing challenges where the goal is to provide input that passes validation checks (strcmp, memcmp, integer comparisons) to reach a success function.

---

## Installation

### Prerequisites

- **Python 3.8+**
- **angr 9.2+** (installed automatically via requirements.txt)
- **gcc** (only needed for running the binary compilation test suite)

### Install

```bash
pip install -r requirements.txt
```

Requirements file:

```
angr>=9.2,<10.0
claripy>=9.2,<10.0
pytest>=9.0
```

### Verify

```bash
python angrsolve.py --help
```

---

## Usage

```
angrsolve BINARY [OPTIONS]
```

### Positional arguments

| Argument | Description |
|----------|-------------|
| `BINARY` | Path to the ELF binary to analyze |

### All flags

| Flag | Description |
|------|-------------|
| `--find ADDR/SYM` | Target address or symbol to find (can repeat) |
| `--avoid ADDR/SYM` | Addresses/symbols to avoid (can repeat) |
| `--no-auto-avoid` | Disable automatic detection of failure functions |
| `--stdin SIZE` | Symbolic stdin buffer of SIZE bytes |
| `--argv SIZE` | Symbolic argv[1] of SIZE bytes |
| `--file NAME SIZE` | Symbolic file with name and size (can repeat) |
| `--mode MODE` | Constraint mode: `printable`, `alphanumeric`, `letters`, `digits`, `unrestricted` |
| `--unicorn` | Enable Unicorn engine for faster exploration |
| `--veritesting` | Enable veritesting for better path merging |
| `--timeout SECONDS` | Exploration timeout in seconds |
| `--max-depth N` | Maximum basic block depth |
| `--max-active N` | Maximum active states |
| `--max-steps N` | Maximum exploration steps |
| `--save FILE` | Save the payload to a file |
| `--json` | Output in JSON format |
| `--no-color` | Disable colored terminal output |
| `-v` / `-vv` / `-vvv` | Verbosity level (count-based) |
| `-q` / `--quiet` | Suppress all non-result output |

### Auto-default behavior

If no input source flag is given (`--stdin`, `--argv`, `--file`), angrsolve defaults to `--stdin 128`.

---

## Input Sources

### stdin

The program reads from stdin (via `fgets`, `read`, `scanf`, etc.).

```bash
python angrsolve.py ./chall --find win --stdin 64
```

The symbolic data is written to file descriptor 0 before exploration starts. After finding a solution, the data the program *consumed* from stdin (stored in `read_storage`) is extracted — this carries backward constraints from comparisons like `strcmp` and `memcmp`.

### argv

The program checks `argv[1]` (common in CTF challenges).

```bash
python angrsolve.py ./chall --find win --argv 32
```

For dynamically linked binaries, angrsolve uses `call_state(main_addr)` instead of `entry_state` to bypass libc startup complexity. The symbolic argv[1] string is:

1. Created as symbolic bitvectors (`BVS`)
2. Stored on the stack
3. The argv array is set up with `argv[0]` pointing to `"./binary"` and `argv[1]` pointing to the symbolic data
4. `rdi = 2` (argc), `rsi = argv_array` are set manually

When `--argv` is used, angrsolve also **always creates stdin** (128 bytes) automatically. This ensures that programs which also read from stdin get properly constrained symbolic data there. The `_meaningful()` filter in the explorer suppresses extraction results that are mostly solver noise.

### File

The program reads from a file on disk (via `fopen`/`fgets`/`fread`).

```bash
python angrsolve.py ./chall --find win --file flag.txt 256
```

Multiple symbolic files can be specified:

```bash
python angrsolve.py ./chall --find win --file key.txt 16 --file config.txt 64
```

The symbolic file is registered with angr's virtual file system before exploration. A reference to the symbolic content is saved at creation time for extraction (since `SimFile.content` access doesn't survive reads correctly after the file has been read).

### Combined inputs

You can combine multiple input sources:

```bash
python angrsolve.py ./chall --find win --stdin 32 --argv 16 --file data.txt 64
```

All sources will be explored simultaneously, and the solution will include data from whichever sources actually constrained the execution path.

---

## Constraint Modes

Byte constraints limit the values that each symbolic byte can take. This reduces the search space and ensures the solution is a valid input.

| Mode | Allowed bytes | Use case |
|------|---------------|----------|
| `printable` (default) | `string.printable` + null byte (0x00) | Standard CTF challenges |
| `alphanumeric` | `[a-zA-Z0-9]` + null byte | Password fields, alphanumeric-only checks |
| `letters` | `[a-zA-Z]` + null byte | Alphabetic passwords |
| `digits` | `[0-9]` + null byte | PIN codes, numeric input |
| `unrestricted` | All 256 byte values | Binary data, non-printable payloads |

The null byte (0x00) is included in all restricted modes because symbolic strings need a terminator to satisfy string comparison functions like `strcmp`.

### How constraints work

Constraints are applied **per byte** using range-based `claripy.And(bv >= lo, bv <= hi)` clauses. Instead of OR-ing every allowed byte value (which creates huge constraint trees that slow down the solver), contiguous ranges are batched together:

```python
# Example: digits mode allows {0x00, 0x30-0x39}
# Produces: Or(And(bv >= 0x30, bv <= 0x39), bv == 0x00)
```

This approach is significantly faster for the solver than the naive OR-per-value approach.

---

## Target Specification

### Find Targets

The `--find` flag specifies which address the exploration should try to reach. Multiple find targets can be specified:

```bash
python angrsolve.py ./chall --find win              # symbol name
python angrsolve.py ./chall --find 0x4011d6          # hex address
python angrsolve.py ./chall --find win --find flag   # multiple targets
```

If the binary is **PIE** (position-independent), hex addresses are assumed to be offsets and the base address is automatically added.

### Avoid Targets

The `--avoid` flag specifies addresses or symbols that should be avoided during exploration. If the simulation manager reaches any avoid target on a path, that path is pruned:

```bash
python angrsolve.py ./chall --find win --avoid 0x401350
python angrsolve.py ./chall --find win --avoid fail --avoid exit
python angrsolve.py ./chall --find win --no-auto-avoid  # disable auto-avoid
```

### Auto-detect

If no `--find` is given, angrsolve scans the symbol table for common success function names:

- **Find candidates**: `win`, `success`, `flag`, `print_flag`, `give_flag`, `correct`, `congratulations`

If `--auto-avoid` is enabled (default), it also scans for common failure functions:

- **Avoid candidates**: `exit`, `abort`, `__stack_chk_fail`, `fail`, `failure`, `lost`, `print_fail`, `wrong`

```bash
python angrsolve.py ./chall                    # auto-detect everything
python angrsolve.py ./chall --no-auto-avoid    # only auto-detect find targets
```

If no find target can be resolved (either from `--find` or auto-detect), angrsolve exits with an error.

---

## Performance Options

### Unicorn Engine

```bash
python angrsolve.py ./chall --find win --unicorn
```

Enables the Unicorn engine for concrete execution of non-symbolic code paths. This can dramatically speed up exploration on binaries where most of the code doesn't touch symbolic data. Requires the `unicorn` Python package.

Options enabled:

- `UNICORN` — enable unicorn
- `UNICORN_HANDLE_SYMBOLIC_SYSCALLS` — handle symbolic syscalls during unicorn execution
- `UNICORN_SYM_SYSCALL_RESOLVER` — resolve symbolic syscalls

### Veritesting

```bash
python angrsolve.py ./chall --find win --veritesting
```

Enables veritesting, which merges multiple execution paths at control-flow merges using the solver. This can reduce path explosion in binaries with many conditional branches.

### Timeout

```bash
python angrsolve.py ./chall --find win --timeout 30
```

Kills exploration after the given number of seconds. Uses a SIGALRM-based hard kill that interrupts the angr solver even if it's stuck in a long-running symbolic execution. An additional 1-second grace period is added to the timeout.

### Max Depth

```bash
python angrsolve.py ./chall --find win --max-depth 200
```

Limits the maximum number of basic blocks the exploration can traverse. Paths that exceed this depth are terminated.

### Max Active States

```bash
python angrsolve.py ./chall --find win --max-active 50
```

Limits the number of concurrently active states. When the limit is reached, the simulation manager stops forking new states, which can help with path explosion.

### Max Steps

```bash
python angrsolve.py ./chall --find win --max-steps 1000
```

Limits the total number of exploration steps (each step advances the simulation manager by one tick).

---

## Output

### Text Output

By default, angrsolve prints a formatted solution:

```
✓ Solution found!

  Target: win (0x4011d6)

  STDIN:
    ASCII:  password123
    HEX:    70617373776f7264313233
    Python: b"password123"
    Escaped: password123

  Explored states: 86  |  Active states: 0  |  Time: 1423.5 ms
```

The solution displays:

- **Target** — the address/symbol that was reached
- **STDIN** — the required stdin input (if applicable)
- **ARGV** — the required argv[1] value (if applicable)
- **FILE** — required file contents (if applicable)
- **Stats** — explored states, active states, wall-clock time

Each data source is shown in four formats:

| Format | Example |
|--------|---------|
| ASCII | `password123` |
| HEX | `70617373776f7264313233` |
| Python | `b"password123"` |
| Escaped | `password123` |

### JSON Output

```bash
python angrsolve.py ./chall --find win --stdin 64 --json
```

```json
{
  "find_addr": "0x4011d6",
  "find_name": "win",
  "stdin": "70617373776f7264313233",
  "argv": null,
  "files": {},
  "active_states": 0,
  "explored_states": 86,
  "timing_ms": 1423.5
}
```

When no solution is found:

```json
{
  "error": "No solution found",
  "explored_states": 42,
  "timing_ms": 5340.2
}
```

### Save to File

```bash
python angrsolve.py ./chall --find win --stdin 64 --save payload.bin
```

Saves the raw payload bytes to a file. The payload is chosen in priority order: stdin → argv → first file. If no payload is available, the file is not created.

---

## Logging and Verbosity

| Flag | Effect |
|------|--------|
| (default) | INFO level, shows progress every 100 steps |
| `-v` | Same as default (INFO) |
| `-vv` | DEBUG level, shows solver extraction details |
| `-vvv` | NOTSET level, shows all log messages |
| `-q` / `--quiet` | ERROR level only, suppresses all non-result output |

Third-party loggers (angr, claripy, pyvex, archinfo):

| Verbosity | Effect on third-party loggers |
|-----------|-------------------------------|
| Default | WARNING level |
| `-vv` | DEBUG level |
| `-q` | ERROR level |

---

## Examples

### Basic argv

Find the argv[1] that reaches `win`:

```bash
$ python angrsolve.py ./chall --find win --argv 32
[+] Loading binary: ./chall
[+] Target resolved: win -> 0x4011d6
[+] Creating symbolic stdin (size=128)
[+] Creating symbolic argv (size=32)
[+] Beginning exploration
[*] Step 100 | active=2, found=0, deadended=34, avoided=0
[*] Step 200 | active=1, found=0, deadended=78, avoided=0
[+] Solution found

✓ Solution found!

  Target: win (0x4011d6)

  ARGV:
    ASCII:  s3cr3t
    HEX:    733363723374
    Python: b's3cr3t'
    Escaped: s3cr3t

  Explored states: 79  |  Active states: 0  |  Time: 4234.2 ms
```

### Basic stdin

Find the stdin input that reaches `win`:

```bash
$ python angrsolve.py ./chall --find win --stdin 64
[+] Loading binary: ./chall
[+] Target resolved: win -> 0x4011d6
[+] Creating symbolic stdin (size=64)
[+] Beginning exploration
[*] Step 100 | active=12, found=0, deadended=34, avoided=2
[+] Solution found

✓ Solution found!

  Target: win (0x4011d6)

  STDIN:
    ASCII:  p4ssw0rd
    HEX:    7034737377307264
    Python: b'p4ssw0rd'
    Escaped: p4ssw0rd

  Explored states: 86  |  Active states: 8  |  Time: 1423.5 ms
```

### File-based input

Find the contents of `flag.txt` that reach `win`:

```bash
$ python angrsolve.py ./chall --find win --file flag.txt 64
[+] Loading binary: ./chall
[+] Target resolved: win -> 0x4011d6
[+] Creating symbolic file 'flag.txt' (size=64)
[+] Beginning exploration
[*] Step 100 | active=3, found=0, deadended=12, avoided=0
[+] Solution found

✓ Solution found!

  Target: win (0x4011d6)

  FILE [flag.txt]:
    ASCII:  admin:secret
    HEX:    61646d696e3a736563726574
    Python: b'admin:secret'
    Escaped: admin:secret

  Explored states: 41  |  Active states: 0  |  Time: 2134.1 ms
```

### PIE binary

PIE binaries work identically — the base address is added automatically:

```bash
$ python angrsolve.py ./chall-pie --find win --argv 32
[+] Loading binary: ./chall-pie
[+] Target resolved: win -> 0x555555555189
# ...
```

### Stripped binary

For stripped binaries, use the raw address or find it via trial:

```bash
$ python angrsolve.py ./chall-stripped --find 0x1189 --argv 32
# ...
```

Symbol-based lookups will fail on stripped binaries (the symbol table has been removed), but hex addresses and auto-detection via the `win`/`success` etc. heuristic will also fail.

### Integer comparison

Challenges that check integer values (not strings) work the same way:

```bash
$ python angrsolve.py ./chall --find win --stdin 4
```

The solver will find integer byte values that pass the check.

### memcmp challenge

For binaries using `memcmp` instead of `strcmp`:

```bash
$ python angrsolve.py ./chall --find win --argv 32
```

`memcmp` is handled symbolically the same as `strcmp` by angr's SimProcedures.

### Multiple checks

For binaries that check multiple conditions:

```bash
$ python angrsolve.py ./chall --find win --stdin 64
```

The solver automatically finds input that passes all checks simultaneously.

### Custom byte constraints

Use `--mode unrestricted` for non-printable payloads:

```bash
$ python angrsolve.py ./chall --find win --stdin 16 --mode unrestricted
```

### JSON output

Machine-readable output:

```bash
$ python angrsolve.py ./chall --find win --argv 32 --json
{
  "find_addr": "0x4011d6",
  "find_name": "win",
  "stdin": null,
  "argv": "733363723374",
  "files": {},
  "active_states": 0,
  "explored_states": 79,
  "timing_ms": 4234.2
}
```

---

## Architecture

angrsolve is organized into modules within the `angrsolve/` package:

```
angrsolve/
├── __init__.py     # Orchestration, logging setup, main()
├── cli.py          # Argparse CLI definition and config builders
├── constraints.py  # Byte constraint modes, range-based constraint generation
├── explorer.py     # Step-by-step exploration, extract helpers, solution creation
├── inputs.py       # Symbolic input creation (stdin/argv/file)
├── loader.py       # Binary loading and symbol resolution
├── output.py       # Solution formatting (text/JSON), file saving
└── utils.py        # Address parsing, hexdump utility
angrsolve.py        # Entry point (#!/usr/bin/env python3)
```

### Data flow

```
CLI args → parse_args()
              ↓
       build_input_configs() → InputConfig[]
       build_constraint_config() → ConstraintConfig
       build_explore_config() → ExploreConfig
              ↓
       load_binary() → angr.Project
              ↓
       resolve_addresses() → find/avoid address lists
       resolve_auto_symbols() → auto-detect symbols
              ↓
       setup_input() → InputSetup (SimState + symbolic data)
              ↓
       explore() → Solution or None
              ↓
       output_solution() / print_no_solution()
```

### Key design decisions

- **`call_state(main)` for argv**: Dynamically linked binaries with argv use `proj.factory.call_state(main_addr)` instead of `entry_state(args=[...])`. This avoids a bug where `entry_state` with symbolic bitvectors doesn't handle argv correctly, and also avoids the complexity of libc startup code. The argv[1] string is placed on the stack manually with `rdi`/`rsi` set appropriately.

- **Auto-created stdin for argv**: When `--argv` is used, stdin is automatically created (128 bytes). This ensures that programs which read from stdin (e.g., `fgets`) get properly constrained symbolic data. The `_meaningful()` filter in the explorer drops extraction results that are mostly solver noise, preventing garbage output.

- **Range-based constraints**: Instead of creating `Or(bv == 0x00, bv == 0x30, bv == 0x31, ...)` for every byte, contiguous ranges are batched as `Or(And(bv >= 0x30, bv <= 0x39), bv == 0x00)`. This significantly improves solver performance.

- **`read_storage` for stdin extraction**: The data the program *consumed* from stdin is stored in `fd.read_storage`. This carries backward constraints from comparisons (strcmp, memcmp, etc.). The `write_storage` approach does not carry these constraints.

- **Signal-based hard timeout**: Uses `signal.alarm()` to kill exploration if it exceeds the timeout, even if the solver is stuck in a long-running symbolic execution.

- **No Unicorn by default**: Unicorn engine is not enabled by default because it can cause issues with some binaries. Enable it explicitly with `--unicorn` for performance gains when appropriate.

---

## Development

### Running tests

```bash
# Full test suite (135 tests)
pytest -v

# Fast unit tests only (utils, constraints, cli, output)
pytest -v tests/test_utils.py tests/test_constraints.py tests/test_cli.py tests/test_output.py

# Integration tests (loader, inputs, explorer)
pytest -v tests/test_loader.py tests/test_inputs.py tests/test_explorer.py

# Binary compilation tests (requires gcc)
pytest -v tests/test_binaries.py

# End-to-end tests (slowest)
pytest -v tests/test_integration.py

# Syntax check
python3 -m py_compile angrsolve.py angrsolve/*.py

# Quick smoke test
python3 angrsolve.py /tmp/test_argv_bin --find win --argv 32 --no-color -q
```

### Code conventions

- Type hints with `from __future__ import annotations`
- Imports: stdlib → third-party → local
- `snake_case` for functions/variables, `PascalCase` for classes, `UPPER_CASE` for constants
- Minimal docstrings — only when purpose isn't obvious
- Catch broad `Exception` in extraction helpers, log with `logger.debug`
- Use `logger = logging.getLogger("angrsolve")` per module

### CI

A pre-commit hook (`.githooks/pre-commit`) runs `python3 -m py_compile` on all staged `.py` files. Enable it with:

```bash
git config core.hooksPath .githooks
```

GitHub Actions runs three parallel jobs on every push/PR:

| Job | What it runs | Approx time |
|-----|-------------|-------------|
| `lint` | `python3 -m py_compile` on all `.py` files | 10 s |
| `unit-tests` | Fast tests (utils, constraints, cli, output) | 10 s |
| `integration-tests` | Loader, input setup, exploration + compiled test binaries | 2 min |
