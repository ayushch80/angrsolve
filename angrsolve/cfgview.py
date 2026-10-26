"""EXPERIMENTAL interactive accordion CFG viewer.

Shows the binary's control-flow graph level by level (one terminal row per
depth).  Each row lists that depth's basic blocks; at most one node per
level is expanded — expanding a sibling collapses the previously expanded
one and resets deeper levels.  Blocks are badged live from exploration:

    ``●`` active state here   ``·`` visited   ``F`` find target
    ``A`` avoid target        ``★`` solution found here

Keys: ↑/↓ or k/j move, ←/→ or h/l siblings, Enter/Space expand,
Backspace/u collapse one level, r rebuild the graph, q abandon the run.  Exploration runs in a worker thread; the UI polls a
lock-protected snapshot so rendering never touches live angr state.
"""

from __future__ import annotations

import logging
import sys
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Set

logger = logging.getLogger("angrsolve")


# --------------------------------------------------------------------------
# Pure model (no angr, no curses — unit tested).
# --------------------------------------------------------------------------

class Accordion:
    """One expanded node per depth level.

    ``expand(level, idx)`` selects the node and drops every deeper
    expansion.  ``collapse(level)`` drops that level and below.
    """

    def __init__(self) -> None:
        self.expanded: Dict[int, int] = {}

    def expand(self, level: int, idx: int) -> None:
        self.expanded[level] = idx
        for lv in [lv for lv in self.expanded if lv > level]:
            del self.expanded[lv]

    def collapse(self, level: int) -> None:
        for lv in [lv for lv in self.expanded if lv >= level]:
            del self.expanded[lv]


def render_lines(
    entry: int, adj: Dict[int, List[int]], expanded: Dict[int, int]
) -> List[tuple]:
    """Flatten the accordion-unfolded tree into visible lines.

    Each line is (level, sib_idx, addr, last, cont) where `last` marks the
    final sibling and `cont` flags, per ancestor level, whether that
    ancestor has a following sibling (drives the vertical continuation).
    """
    lines: List[tuple] = []

    def rec(addr: int, level: int, sib_idx: int, last: bool, cont: tuple) -> None:
        lines.append((level, sib_idx, addr, last, cont))
        if expanded.get(level) == sib_idx:
            kids = adj.get(addr, [])
            for i, k in enumerate(kids):
                # A child's continuation segments describe its ancestors:
                # the parent contributes only if it has a following sibling.
                rec(k, level + 1, i, i == len(kids) - 1, cont + (not last,))

    rec(entry, 0, 0, True, ())
    return lines


def format_line(
    addr: int,
    marks: str,
    n_kids: int,
    is_expanded: bool,
    last: bool,
    cont: tuple,
    width: int,
) -> str:
    """Build the printable text for one tree line, truncated to `width`."""
    prefix = "".join("\u2502 " if c else "  " for c in cont)
    if cont:
        prefix += "\u2514\u2500" if last else "\u251c\u2500"
    text = f"{prefix}{addr:#x}{marks}"
    if n_kids and not is_expanded:
        text += f" \u25b8+{n_kids}"
    return text[:width]


# --------------------------------------------------------------------------
# Live snapshot shared between the explore worker and the UI thread.
# --------------------------------------------------------------------------

MAX_TRACKED = 200_000


@dataclass
class Snapshot:
    lock: threading.Lock = field(default_factory=threading.Lock)
    steps: int = 0
    active: Set[int] = field(default_factory=set)
    visited: Set[int] = field(default_factory=set)
    found: int = 0
    deadended: int = 0
    done: bool = False
    stop: bool = False


def make_observer(snap: Snapshot) -> Callable[[int, Any], Optional[bool]]:
    def _observe(step: int, simgr: Any) -> Optional[bool]:
        if snap.stop:
            return True  # stop exploration
        try:
            addrs = [s.addr for s in simgr.active[:64]]
            with snap.lock:
                snap.steps = step
                snap.active = set(addrs)
                snap.visited.update(addrs)
                if len(snap.visited) > MAX_TRACKED:
                    snap.visited = set(list(snap.visited)[-MAX_TRACKED:])
                snap.found = len(simgr.stashes.get("found", []))
                snap.deadended = len(simgr.deadended)
        except Exception:
            pass
        return None

    return _observe


# --------------------------------------------------------------------------
# angr CFG glue.
# --------------------------------------------------------------------------

def build_graph(proj: Any) -> tuple:
    """Return (entry_addr, {addr: [successor addrs]})."""
    logger.info("[+] Building CFG (one-time cost)...")
    cfg = proj.analyses.CFGFast(normalize=True, show_progressbar=False)
    adj: Dict[int, List[int]] = {}
    for src, dst in cfg.graph.edges():
        adj.setdefault(src.addr, set()).add(dst.addr)
    main = None
    try:
        sym = proj.loader.find_symbol("main")
        main = sym.rebased_addr if sym is not None else None
    except Exception:
        main = None
    entry = main if main is not None else proj.entry
    return entry, {a: sorted(s) for a, s in adj.items()}


# --------------------------------------------------------------------------
# Curses UI.
# --------------------------------------------------------------------------

def _marks(addr: int, snap_data: dict, finds: Set[int], avoids: Set[int]) -> str:
    marks = ""
    if addr in finds:
        marks += "F"
    if addr in avoids:
        marks += "A"
    if addr in snap_data["active"]:
        marks += "\u25cf"
    elif addr in snap_data["visited"]:
        marks += "\u00b7"
    return marks


def _run_curses_ui(
    proj: Any,
    finds: Set[int],
    avoids: Set[int],
    snap: Snapshot,
    timeout: Optional[float],
    started: float,
) -> None:
    import curses

    ANSI = {"C_ACT": 1, "C_FIND": 2, "C_AVOID": 3, "C_DIM": 4}

    def draw(stdscr: Any) -> None:
        curses.curs_set(0)
        stdscr.timeout(200)
        if curses.has_colors():
            try:
                curses.start_color()
                curses.use_default_colors()
                curses.init_pair(ANSI["C_ACT"], curses.COLOR_GREEN, -1)
                curses.init_pair(ANSI["C_FIND"], curses.COLOR_YELLOW, -1)
                curses.init_pair(ANSI["C_AVOID"], curses.COLOR_RED, -1)
                curses.init_pair(ANSI["C_DIM"], curses.COLOR_CYAN, -1)
                use_color = True
            except Exception:
                use_color = False
        else:
            use_color = False

        entry, adj = build_graph(proj)
        levels: List[List[int]] = [[entry]]
        acc = Accordion()
        cursor = 0
        status_msg = ""
        status_at = 0.0

        def rebuild() -> None:
            del levels[1:]
            lv = 0
            while lv in acc.expanded:
                idx = acc.expanded[lv]
                if idx >= len(levels[lv]):
                    acc.collapse(lv)
                    break
                levels.append(adj.get(levels[lv][idx], []))
                lv += 1

        def reload_graph() -> None:
            nonlocal entry, adj
            entry, adj = build_graph(proj)
            while levels and levels[0] != [entry]:
                levels[0] = [entry]
            rebuild()

        def status(text: str) -> None:
            nonlocal status_msg, status_at
            status_msg, status_at = text, time.time()

        def line_attr(addr: int, snap_data: dict, selected: bool) -> int:
            if addr in snap_data["active"]:
                attr = curses.color_pair(ANSI["C_ACT"]) | curses.A_BOLD if use_color else curses.A_BOLD
            elif addr in finds:
                attr = curses.color_pair(ANSI["C_FIND"]) if use_color else curses.A_BOLD
            elif addr in avoids:
                attr = curses.color_pair(ANSI["C_AVOID"]) if use_color else curses.A_NORMAL
            elif addr in snap_data["visited"]:
                attr = curses.color_pair(ANSI["C_DIM"]) if use_color else curses.A_DIM
            else:
                attr = curses.A_NORMAL
            return attr | curses.A_REVERSE if selected else attr

        rebuild()
        status("Enter expands \u2500 r rebuilds \u2500 q quits")
        while True:
            with snap.lock:
                snap_data = {
                    "steps": snap.steps,
                    "active": set(snap.active),
                    "visited": set(snap.visited),
                    "found": snap.found,
                    "deadended": snap.deadended,
                    "done": snap.done,
                }
            rows, cols = stdscr.getmaxyx()
            width = max(cols - 1, 10)
            lines = render_lines(entry, adj, acc.expanded)
            cursor = min(max(cursor, 0), max(len(lines) - 1, 0))
            stdscr.erase()
            elapsed = time.time() - started
            head = (
                f"steps {snap_data['steps']} | active {len(snap_data['active'])} "
                f"| found {snap_data['found']} | dead {snap_data['deadended']} "
                f"| blocks {len(adj)} | {elapsed:.0f}s"
            )
            if timeout:
                head += f"/{timeout:.0f}s"
            if snap_data["done"]:
                head += "  DONE \u2014 q to exit"
            stdscr.addstr(0, 0, head[:width])
            keys = "\u2191/\u2193 move  \u2190/\u2192 siblings  Enter expand  Bksp collapse  r reload  q"
            stdscr.addstr(1, 0, keys[:width])
            # Scroll so the cursor line is visible.
            first = max(0, min(cursor, len(lines) - (rows - 3)))
            first = min(first, cursor)
            for vi, li in enumerate(range(first, len(lines))):
                y = vi + 2
                if y >= rows:
                    break
                level, sib_idx, addr, last, cont = lines[li]
                kids = adj.get(addr, [])
                is_exp = acc.expanded.get(level) == sib_idx and bool(kids)
                text = format_line(
                    addr, _marks(addr, snap_data, finds, avoids),
                    len(kids), is_exp, last, cont, width,
                )
                try:
                    stdscr.addstr(
                        y, 0, text, line_attr(addr, snap_data, li + first == cursor)
                    )
                except Exception:
                    pass
            if status_msg and time.time() - status_at < 4 and rows > 1:
                try:
                    stdscr.addstr(rows - 1, 0, status_msg[:width])
                except Exception:
                    pass
            stdscr.refresh()
            if snap_data["done"]:
                stdscr.timeout(-1)
            key = stdscr.getch()
            if key == ord("q"):
                with snap.lock:
                    snap.stop = True
                return
            if snap_data["done"]:
                return
            if key == ord("r"):
                status("rebuilding CFG\u2026")
                stdscr.refresh()
                reload_graph()
                status(f"graph reloaded: {len(adj)} blocks")
                continue
            level, sib_idx, addr, last, cont = lines[cursor]
            n_sibs = len(levels[level]) if level < len(levels) else 1
            if key in (curses.KEY_UP, ord("k")):
                cursor = max(0, cursor - 1)
            elif key in (curses.KEY_DOWN, ord("j")):
                cursor = min(len(lines) - 1, cursor + 1)
            elif key in (curses.KEY_LEFT, ord("h")):
                if sib_idx > 0:
                    # relocate cursor to the sibling line
                    for li2, ln in enumerate(lines):
                        if ln[0] == level and ln[1] == sib_idx - 1:
                            cursor = li2
                            break
            elif key in (curses.KEY_RIGHT, ord("l")):
                if sib_idx + 1 < n_sibs:
                    for li2, ln in enumerate(lines):
                        if ln[0] == level and ln[1] == sib_idx + 1:
                            cursor = li2
                            break
            elif key in (curses.KEY_ENTER, 10, 13, ord(" ")):
                # Accordion: a same-level expand replaces the previous one.
                kids = adj.get(addr, [])
                if not kids:
                    status(f"{addr:#x}: no successors")
                    continue
                acc.expand(level, sib_idx)
                rebuild()
                lines = render_lines(entry, adj, acc.expanded)
                for li2, ln in enumerate(lines):
                    if ln[0] == level + 1 and ln[1] == 0:
                        cursor = li2
                        break
            elif key in (curses.KEY_BACKSPACE, 127, 8, ord("u")):
                if level > 0:
                    acc.collapse(level - 1)
                    rebuild()
                    lines = render_lines(entry, adj, acc.expanded)
                    parent_sib = acc.expanded.get(level - 1, 0)
                    for li2, ln in enumerate(lines):
                        if ln[0] == level - 1 and ln[1] == parent_sib:
                            cursor = li2
                            break

    import curses as _curses

    _curses.wrapper(draw)


def run_with_cfg_view(proj: Any, input_setup: Any, cfg: Any) -> Any:
    """Explore with the interactive accordion CFG viewer.  Returns Solution."""
    from angrsolve.explorer import explore

    if not sys.stdin.isatty() or not sys.stdout.isatty():
        raise ValueError("--cfg-view needs an interactive terminal")
    try:
        import curses  # noqa: F401
    except ImportError:
        raise ValueError("--cfg-view needs the 'curses' module (Unix terminal)")

    print("[+] Building CFG...", file=sys.stderr)
    finds = set(cfg.find_addresses)
    avoids = set(cfg.avoid_addresses)

    snap = Snapshot()
    cfg.observer = make_observer(snap)
    box: Dict[str, Any] = {}
    started = time.time()

    def _worker() -> None:
        box["sol"] = explore(proj, input_setup, cfg)
        with snap.lock:
            snap.done = True

    # Mute logging while curses owns the screen; restored in finally.
    logging.disable(logging.CRITICAL)
    t = threading.Thread(target=_worker, daemon=True)
    try:
        t.start()
        _run_curses_ui(proj, finds, avoids, snap, cfg.timeout, started)
        with snap.lock:
            snap.stop = True
        t.join()
    finally:
        logging.disable(logging.NOTSET)
    return box.get("sol")
