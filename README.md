# angrsolve

A Python tool that automatically solves simple reverse engineering and CTF binaries using [angr](https://angr.io/) symbolic execution.

```bash
python angrsolve.py ./chall --find win           # auto stdin
python angrsolve.py ./chall --find win --argv 64 # argv input
python angrsolve.py ./chall --find win --stdin 128
python angrsolve.py ./chall --find win --file flag.txt 256
```

## Quick install

```bash
pip install -r requirements.txt
```

Requires Python 3.8+ and angr 9.2+. See [DOCS.md](DOCS.md) for detailed docs.

## Features

- **Input sources** — symbolic stdin, argv[1], or file contents
- **Constraint modes** — printable, alphanumeric, letters, digits, unrestricted
- **Target resolution** — symbol names, hex addresses, PIE-aware
- **Auto-detect** — find `win`/`success`/`flag`/etc. automatically
- **Avoid** — avoid failure functions (manual or auto-detected)
- **Output** — ASCII/hex/Python/escaped; JSON mode; save to file
- **Performance** — Unicorn engine, veritesting, configurable timeout/depth/active limits

## Challenges solved

| Challenge | Platform | Difficulty | Input type |
|-----------|----------|-----------|------------|
| Gatekeeper | picoCTF | medium | stdin |
| file-run2  | picoCTF | medium | argv  |

## Documentation

Full documentation and examples are in [DOCS.md](DOCS.md).
