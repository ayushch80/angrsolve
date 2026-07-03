from __future__ import annotations

import logging
import sys
from typing import List, Optional

from angrsolve.cli import (
    build_constraint_config,
    build_explore_config,
    build_input_configs,
    parse_args,
)
from angrsolve.explorer import explore
from angrsolve.inputs import setup_input
from angrsolve.loader import load_binary, resolve_address, resolve_addresses, resolve_auto_symbols
from angrsolve.output import enable_color, output_solution, print_no_solution


def _setup_logging(verbose: int, quiet: bool) -> None:
    if quiet:
        level = logging.ERROR
    elif verbose >= 3:
        level = logging.NOTSET
    elif verbose == 2:
        level = logging.DEBUG
    elif verbose >= 1:
        level = logging.INFO
    else:
        level = logging.INFO

    logging.basicConfig(
        level=level,
        format="%(message)s",
        stream=sys.stderr,
    )

    # Suppress noisy third-party loggers unless verbose.
    for name in ("angr", "claripy", "pyvex", "archinfo"):
        if verbose >= 2:
            logging.getLogger(name).setLevel(logging.DEBUG)
        elif quiet:
            logging.getLogger(name).setLevel(logging.ERROR)
        else:
            logging.getLogger(name).setLevel(logging.WARNING)

    if verbose >= 3:
        logging.getLogger().setLevel(logging.NOTSET)


def main(argv: Optional[List[str]] = None) -> int:
    args = parse_args(argv)

    _setup_logging(verbose=args.verbose, quiet=args.quiet)

    if args.no_color:
        enable_color(False)

    proj = load_binary(args.binary)

    # Resolve find addresses.
    find_addresses = resolve_addresses(proj, args.find_targets)

    # Resolve avoid addresses.
    avoid_addresses = resolve_addresses(proj, args.avoid_targets)

    # Auto-detect symbols if no --find was given.
    if not find_addresses:
        auto = resolve_auto_symbols(proj)
        if auto["find"]:
            find_addresses = auto["find"]
            logging.getLogger("angrsolve").info(
                "[+] Auto-detected find targets: %s",
                ", ".join(hex(a) for a in auto["find"]),
            )
        else:
            logging.getLogger("angrsolve").error(
                "No find targets specified and none auto-detected"
            )
            return 1

    if args.auto_avoid:
        auto = resolve_auto_symbols(proj)
        avoid_set = set(avoid_addresses)
        for a in auto["avoid"]:
            if a not in avoid_set:
                avoid_addresses.append(a)
                avoid_set.add(a)
        if auto["avoid"]:
            logging.getLogger("angrsolve").info(
                "[+] Auto-avoiding: %s",
                ", ".join(hex(a) for a in auto["avoid"]),
            )

    # Build configurations.
    input_configs = build_input_configs(args)
    constraint_cfg = build_constraint_config(args)
    explore_cfg = build_explore_config(args)
    explore_cfg.find_addresses = find_addresses
    explore_cfg.avoid_addresses = avoid_addresses

    # Setup symbolic inputs.
    input_setup = setup_input(proj, input_configs, constraint_cfg)

    # Run exploration.
    solution = explore(proj, input_setup, explore_cfg)

    if solution is not None:
        output_solution(solution, json_mode=args.json, save_path=args.save)
        return 0

    print_no_solution(json_mode=args.json)
    return 1


if __name__ == "__main__":
    sys.exit(main())
