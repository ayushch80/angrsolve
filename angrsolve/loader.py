from __future__ import annotations

import logging
from typing import Dict, List, Optional, Set, Union

import angr

logger = logging.getLogger("angrsolve")


def load_binary(path: str) -> angr.Project:
    """Load an ELF binary with angr.

    Sets ``auto_load_libs=False`` for performance and correctness.
    Automatically detects PIE and non-PIE binaries.
    """
    logger.info("[+] Loading binary: %s", path)
    return angr.Project(path, auto_load_libs=False)


def resolve_address(
    proj: angr.Project,
    target: Union[str, int],
) -> Optional[int]:
    """Resolve a target to a concrete address.

    *Integer targets* are returned directly (absolute addresses).
    If the binary is PIE the address is assumed to be an offset and the
    base address is added.

    *String targets* are looked up in the symbol table first.  If the
    lookup fails the string is parsed as a hex address.
    """
    is_pie = proj.loader.main_object.pic

    if isinstance(target, int):
        addr = target
        if is_pie and addr < proj.loader.main_object.max_addr:
            addr += proj.loader.main_object.min_addr
        return addr

    sym = proj.loader.find_symbol(target)
    if sym is not None:
        logger.info("[+] Target resolved: %s -> 0x%x", target, sym.rebased_addr)
        return sym.rebased_addr

    try:
        addr = int(target, 0)
    except ValueError:
        logger.error("Could not resolve target: %s", target)
        return None

    if is_pie:
        addr += proj.loader.main_object.min_addr
    logger.info("[+] Target resolved: %s -> 0x%x", target, addr)
    return addr


def resolve_auto_symbols(proj: angr.Project) -> Dict[str, int]:
    """Automatically detect common success/failure symbols.

    Looks for well-known symbol names in the binary and returns a
    mapping of category to address.
    """
    candidates: List[str] = [
        "win",
        "success",
        "flag",
        "print_flag",
        "print_flag",
        "give_flag",
        "correct",
        "congratulations",
    ]
    avoid_candidates: List[str] = [
        "exit",
        "abort",
        "__stack_chk_fail",
        "fail",
        "failure",
        "lost",
        "print_fail",
        "wrong",
    ]

    result: Dict[str, int] = {"find": [], "avoid": []}
    for name in candidates:
        sym = proj.loader.find_symbol(name)
        if sym is not None:
            result["find"].append(sym.rebased_addr)

    for name in avoid_candidates:
        sym = proj.loader.find_symbol(name)
        if sym is not None:
            result["avoid"].append(sym.rebased_addr)

    return result


def resolve_addresses(
    proj: angr.Project,
    targets: List[Union[str, int]],
) -> List[int]:
    """Resolve a list of targets to concrete addresses."""
    resolved: List[int] = []
    for t in targets:
        addr = resolve_address(proj, t)
        if addr is not None:
            resolved.append(addr)
    return resolved
