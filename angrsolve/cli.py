from __future__ import annotations

import argparse
from typing import List, Optional

from angrsolve.constraints import ConstraintConfig
from angrsolve.explorer import ExploreConfig
from angrsolve.inputs import InputConfig


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="angrsolve",
        description="angrsolve — automatic symbolic execution solver for CTF/reversing binaries",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  angrsolve ./chall --find win\n"
            "  angrsolve ./chall --find 0x4011d6\n"
            "  angrsolve ./chall --find win --argv 64\n"
            "  angrsolve ./chall --find win --stdin 128\n"
            "  angrsolve ./chall --find win --file flag.txt 256\n"
        ),
    )

    # Required
    parser.add_argument("binary", type=str, help="Path to the ELF binary to analyze")

    # Target
    parser.add_argument(
        "--find",
        type=str,
        action="append",
        default=[],
        dest="find_targets",
        help="Address or symbol name to find (can specify multiple)",
    )
    parser.add_argument(
        "--avoid",
        type=str,
        action="append",
        default=[],
        dest="avoid_targets",
        help="Address or symbol name to avoid (can specify multiple)",
    )
    parser.add_argument(
        "--auto-avoid",
        action="store_true",
        default=True,
        help="Automatically detect and avoid failure functions (default: on)",
    )
    parser.add_argument(
        "--no-auto-avoid",
        action="store_false",
        dest="auto_avoid",
        help="Disable automatic avoid detection",
    )

    # Input sources
    parser.add_argument(
        "--stdin",
        type=int,
        metavar="SIZE",
        default=None,
        help="Create a symbolic stdin buffer of SIZE bytes",
    )
    parser.add_argument(
        "--argv",
        type=int,
        metavar="SIZE",
        default=None,
        help="Create a symbolic argv[1] of SIZE bytes",
    )
    parser.add_argument(
        "--file",
        type=str,
        nargs=2,
        metavar=("FILENAME", "SIZE"),
        action="append",
        default=[],
        dest="files",
        help="Create a symbolic file with FILENAME and SIZE bytes",
    )

    # Constraints
    parser.add_argument(
        "--mode",
        type=str,
        choices=["printable", "alphanumeric", "letters", "digits", "unrestricted"],
        default="printable",
        help="Byte constraint mode (default: printable)",
    )
    parser.add_argument(
        "--custom-bytes",
        type=str,
        default=None,
        help="Comma-separated list of allowed byte values (e.g. '0x20,0x30-0x40')",
    )

    # Performance
    parser.add_argument(
        "--unicorn",
        action="store_true",
        default=False,
        help="Enable Unicorn engine for faster exploration",
    )
    parser.add_argument(
        "--veritesting",
        action="store_true",
        default=False,
        help="Enable veritesting for better path merging",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=None,
        metavar="SECONDS",
        help="Exploration timeout in seconds",
    )
    parser.add_argument(
        "--max-depth",
        type=int,
        default=None,
        metavar="N",
        help="Maximum exploration depth (number of basic blocks)",
    )
    parser.add_argument(
        "--max-active",
        type=int,
        default=None,
        metavar="N",
        help="Maximum number of active states",
    )
    parser.add_argument(
        "--max-steps",
        type=int,
        default=None,
        metavar="N",
        help="Maximum number of exploration steps",
    )

    # Output
    parser.add_argument(
        "--save",
        type=str,
        default=None,
        metavar="FILE",
        help="Save the payload to a file",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        default=False,
        help="Output results in JSON format",
    )
    parser.add_argument(
        "--no-color",
        action="store_true",
        default=False,
        help="Disable colored terminal output",
    )

    # Logging / verbosity
    parser.add_argument(
        "--verbose",
        "-v",
        action="count",
        default=0,
        dest="verbose",
        help="Increase verbosity (repeat for more, e.g. -v, -vv, -vvv)",
    )
    parser.add_argument(
        "--quiet",
        "-q",
        action="store_true",
        default=False,
        help="Suppress all output except results",
    )

    return parser


def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    parser = build_parser()
    args = parser.parse_args(argv)

    # If no input source specified, auto-detect: prefer --stdin.
    if args.stdin is None and args.argv is None and not args.files:
        args.stdin = 128

    return args


def build_input_configs(args: argparse.Namespace) -> List[InputConfig]:
    configs: List[InputConfig] = []

    if args.stdin is not None:
        if args.stdin <= 0:
            raise ValueError(f"--stdin size must be positive, got {args.stdin}")
        configs.append(InputConfig(source="stdin", size=args.stdin))

    if args.argv is not None:
        if args.argv <= 0:
            raise ValueError(f"--argv size must be positive, got {args.argv}")
        configs.append(InputConfig(source="argv", size=args.argv))

    for fname, fsize in args.files:
        if not fname:
            raise ValueError("--file requires a non-empty filename")
        try:
            size = int(fsize)
        except ValueError:
            raise ValueError(f"Invalid file size: {fsize}")
        if size <= 0:
            raise ValueError(f"--file size must be positive, got {fsize}")
        configs.append(InputConfig(source="file", size=size, filename=fname))

    return configs


def _parse_custom_bytes(spec: str) -> List[int]:
    """Parse a spec like '0x20,0x30-0x40' into a list of byte values."""
    values: List[int] = []
    for token in spec.split(","):
        token = token.strip()
        if not token:
            continue
        try:
            if "-" in token:
                lo_s, hi_s = token.split("-", 1)
                lo, hi = int(lo_s, 0), int(hi_s, 0)
                if lo > hi:
                    raise ValueError(f"reversed range '{token}'")
                values.extend(range(lo, hi + 1))
            else:
                values.append(int(token, 0))
        except ValueError as e:
            raise ValueError(f"Invalid --custom-bytes token '{token}': {e}")
    for v in values:
        if not 0 <= v <= 255:
            raise ValueError(f"--custom-bytes value out of range 0-255: {v}")
    if not values:
        raise ValueError(f"--custom-bytes spec '{spec}' contains no byte values")
    return values


def build_constraint_config(args: argparse.Namespace) -> ConstraintConfig:
    custom_bytes = _parse_custom_bytes(args.custom_bytes) if args.custom_bytes else None
    return ConstraintConfig(mode=args.mode, custom_bytes=custom_bytes)


def build_explore_config(args: argparse.Namespace) -> ExploreConfig:
    if args.timeout is not None and args.timeout <= 0:
        raise ValueError(f"--timeout must be positive, got {args.timeout}")
    for name in ("max_depth", "max_active", "max_steps"):
        value = getattr(args, name, None)
        if value is not None and value < 1:
            raise ValueError(f"--{name.replace('_', '-')} must be >= 1, got {value}")
    return ExploreConfig(
        timeout=args.timeout,
        max_depth=args.max_depth,
        max_active=args.max_active,
        max_steps=args.max_steps,
        veritesting=args.veritesting,
        use_unicorn=args.unicorn,
    )
