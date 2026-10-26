"""EXPERIMENTAL interactive accordion CFG viewer.

Shows the binary's control-flow graph level by level (one terminal row per
depth).  Each row lists that depth's basic blocks; at most one node per
level is expanded — expanding a sibling collapses the previously expanded
one and resets deeper levels.  Blocks are badged live from exploration:

    ``●`` active state here   ``·`` visited   ``F`` find target
    ``A`` avoid target        ``★`` solution found here

Keys: ←/→ or h/l move, Enter/Space expand, Backspace/u collapse one level,
q abandon the run.  Exploration runs in a worker thread; the UI polls a
lock-protected snapshot so rendering never touches live angr state.
"""

from __future__ import annotations

import logging
import shutil
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
        self.cursor: Dict[int, int] = {}

    def expand(self, level: int, idx: int) -> None:
        self.expanded[level] = idx
        for lv in [lv for lv in self.expanded if lv > level]:
            del self.expanded[lv]

    def collapse(self, level: int) -> None:
        for lv in [lv for lv in self.expanded if lv >= level]:
            del self.expanded[lv]

    def move(self, level: int, idx: int) -> None:
        self.cursor[level] = idx


def fit_cells(
    cells: List[str], selected: int, width: int
) -> tuple:
    """Truncate a row to terminal width, always keeping `selected` visible.

    Returns (shown_cells, hidden_head_count) so the caller can map
    highlighted positions back to the full row."""
    if not cells:
        return [], 0
    widths = [len(c) + 1 for c in cells]
    if sum(widths) <= width:
        return cells, 0
    # Grow a window around the selection until the width budget is spent.
    lo = hi = selected
    used = widths[selected]
    while True:
        grown = False
        if lo > 0 and used + widths[lo - 1] + 4 <= width:
            lo -= 1
            used += widths[lo]
            grown = True
        if hi + 1 < len(cells) and used + widths[hi + 1] + 4 <= width:
            hi += 1
            used += widths[hi]
            grown = True
        if not grown:
            break
    out = list(cells[lo : hi + 1])
    if lo > 0:
        out[0] = f"\u2026+{lo} " + out[0]
    if hi + 1 < len(cells):
        out[-1] = out[-1] + f" \u2026+{len(cells) - hi - 1}"
    return out, lo


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

def _cell_text(addr: int, snap_data: dict, finds: Set[int], avoids: Set[int]) -> str:
    marks = ""
    if addr in finds:
        marks += "F"
    if addr in avoids:
        marks += "A"
    if addr in snap_data["active"]:
        marks += "●"
    elif addr in snap_data["visited"]:
        marks += "·"
    return f"{addr:#x}{marks}"


def _run_curses_ui(
    entry: int,
    adj: Dict[int, List[int]],
    finds: Set[int],
    avoids: Set[int],
    snap: Snapshot,
    timeout: Optional[float],
    started: float,
) -> None:
    import curses

    def draw(stdscr: Any) -> None:
        import curses

        curses.curs_set(0)
        stdscr.timeout(200)
        active_lv = 0
        levels: List[List[int]] = [[entry]]
        acc = Accordion()

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

        rebuild()
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
            stdscr.erase()
            elapsed = time.time() - started
            head = (
                f"steps {snap_data['steps']} | active {len(snap_data['active'])} "
                f"| found {snap_data['found']} | dead {snap_data['deadended']} "
                f"| {elapsed:.0f}s"
            )
            if timeout:
                head += f"/{timeout:.0f}s"
            if snap_data["done"]:
                head += "  DONE — q to exit"
            stdscr.addstr(0, 0, head[:width])
            stdscr.addstr(
                1, 0, "↑/↓ level  ←/→ move  Enter expand  Bksp collapse  q"[:width]
            )
            # Scroll so the active level is visible.
            first = max(0, active_lv - (rows - 4))
            for li, lv in enumerate(range(first, len(levels))):
                y = li + 2
                if y >= rows:
                    break
                row = levels[lv]
                cursor = min(acc.cursor.get(lv, 0), max(len(row) - 1, 0))
                cells = [_cell_text(a, snap_data, finds, avoids) for a in row]
                shown, offset = fit_cells(cells, cursor, width)
                if lv == active_lv:
                    try:
                        stdscr.addstr(y, 0, ">"[:width])
                    except Exception:
                        pass
                x = 2
                for i, cell in enumerate(shown):
                    if x + len(cell) > width:
                        break
                    attr = curses.A_NORMAL
                    if lv == active_lv and offset + i == cursor:
                        attr = curses.A_REVERSE
                    try:
                        stdscr.addstr(y, x, cell, attr)
                    except Exception:
                        pass
                    x += len(cell) + 1
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
            active_lv = min(active_lv, len(levels) - 1)
            row = levels[active_lv]
            if not row:
                continue
            cursor = min(acc.cursor.get(active_lv, 0), len(row) - 1)
            if key in (curses.KEY_UP, ord("k")):
                active_lv = max(0, active_lv - 1)
            elif key in (curses.KEY_DOWN, ord("j")):
                active_lv = min(len(levels) - 1, active_lv + 1)
            elif key in (curses.KEY_LEFT, ord("h")):
                acc.move(active_lv, max(0, cursor - 1))
            elif key in (curses.KEY_RIGHT, ord("l")):
                acc.move(active_lv, min(len(row) - 1, cursor + 1))
            elif key in (curses.KEY_ENTER, 10, 13, ord(" ")):
                # Accordion: a same-level expand replaces the previous one.
                acc.expand(active_lv, cursor)
                rebuild()
                if len(levels) > active_lv + 1 and levels[active_lv + 1]:
                    active_lv += 1
                    acc.move(active_lv, 0)
            elif key in (curses.KEY_BACKSPACE, 127, 8, ord("u")):
                if active_lv > 0:
                    acc.collapse(active_lv - 1)
                    rebuild()
                    active_lv -= 1

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
    entry, adj = build_graph(proj)
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
        _run_curses_ui(entry, adj, finds, avoids, snap, cfg.timeout, started)
        with snap.lock:
            snap.stop = True
        t.join()
    finally:
        logging.disable(logging.NOTSET)
    return box.get("sol")
