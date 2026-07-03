# angrsolve

A production-quality Python tool that automatically solves simple reverse engineering and CTF binaries using the [angr](https://angr.io/) symbolic execution framework.

## Installation

```bash
pip install -r requirements.txt
```

Requires Python 3.8+ and angr 9.2+.

## Usage

```bash
python angrsolve.py ./chall --find win
python angrsolve.py ./chall --find 0x4011d6
python angrsolve.py ./chall --find win --argv 64
python angrsolve.py ./chall --find win --stdin 128
python angrsolve.py ./chall --find win --file flag.txt 256
```

### Input sources

| Flag | Description |
|------|-------------|
| `--stdin SIZE` | Symbolic stdin buffer of `SIZE` bytes (default) |
| `--argv SIZE` | Symbolic `argv[1]` of `SIZE` bytes |
| `--file NAME SIZE` | Symbolic file with given name and size |

### Constraints

| Flag | Description |
|------|-------------|
| `--mode MODE` | Byte constraint mode: `printable`, `alphanumeric`, `letters`, `digits`, `unrestricted` (default: `printable`) |

### Targets

| Flag | Description |
|------|-------------|
| `--find ADDR/SYM` | Target address or symbol (can specify multiple) |
| `--avoid ADDR/SYM` | Addresses/symbols to avoid (can specify multiple) |
| `--no-auto-avoid` | Disable automatic detection of failure functions |

### Performance

| Flag | Description |
|------|-------------|
| `--unicorn` | Enable Unicorn engine for faster exploration |
| `--veritesting` | Enable veritesting for better path merging |
| `--timeout SEC` | Exploration timeout in seconds |
| `--max-depth N` | Maximum basic block depth |
| `--max-active N` | Maximum active states |

### Output

| Flag | Description |
|------|-------------|
| `--save FILE` | Save the payload to a file |
| `--json` | JSON output mode |
| `--no-color` | Disable colored output |

### Logging

| Flag | Description |
|------|-------------|
| `--verbose`, `-v` | Verbose logging |
| `--quiet`, `-q` | Suppress all non-result output |

## How it works

1. **Load** the binary with angr (`auto_load_libs=False`)
2. **Resolve** target addresses (symbols or hex)
3. **Create** symbolic input (stdin, argv, or file)
4. **Constrain** bytes (printable ASCII by default)
5. **Explore** with `simgr.step()` until the target is reached or state space is exhausted
6. **Extract** and display the concrete solution

## Project structure

```
angrsolve/
    __init__.py    — entry point, orchestration
    cli.py         — argparse CLI definition
    loader.py      — binary loading, symbol resolution
    inputs.py      — symbolic input creation
    constraints.py — byte constraints
    explorer.py    — simulation manager exploration
    output.py      — result formatting and display
    utils.py       — helper utilities
```

## Example

```bash
$ python angrsolve.py ./chall --find win --stdin 64

[+] Loading binary: ./chall
[+] Target resolved: win -> 0x4011d6
[+] Creating symbolic stdin (size=64)
[+] Beginning exploration
[*] Step 100 | active=12, found=0, deadended=34, avoided=2
[*] Step 200 | active=8, found=0, deadended=78, avoided=5
[+] Solution found

✓ Solution found!

  Target: win (0x4011d6)

  STDIN:
    ASCII:  password123
    HEX:    70617373776f7264313233
    Python: b"password123"
    Escaped: password123

  Explored states: 86  |  Active states: 8  |  Time: 1423.5 ms
```

## License

MIT
