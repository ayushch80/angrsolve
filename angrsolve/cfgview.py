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
    """Set of expanded nodes per depth level.

    Expanding never collapses anything: ``expand(level, idx)`` only adds.
    ``collapse(level)`` drops that level and everything below;
    ``collapse_node(level, idx)`` drops a single node.
    """

    def __init__(self) -> None:
        self.expanded: Dict[int, Set[int]] = {}

    def expand(self, level: int, idx: int) -> None:
        self.expanded.setdefault(level, set()).add(idx)

    def collapse(self, level: int) -> None:
        for lv in [lv for lv in self.expanded if lv >= level]:
            del self.expanded[lv]

    def collapse_node(self, level: int, idx: int) -> None:
        if level in self.expanded:
            self.expanded[level].discard(idx)
            if not self.expanded[level]:
                del self.expanded[level]


def render_lines(
    entry: int, adj: Dict[int, List[int]], expanded: Dict[int, Set[int]]
) -> List[tuple]:
    """Flatten the accordion-unfolded tree into visible lines.

    Each line is (level, sib_idx, addr, last, cont, parent, branch) where
    `last` marks the final sibling, `cont` flags per ancestor level whether
    it has a following sibling (drives the vertical lines), `parent` is the
    parent block address (None at the root), and `branch` is the level-1
    ancestor index so whole downstream paths share one color.
    """
    lines: List[tuple] = []

    def rec(
        addr: int,
        level: int,
        sib_idx: int,
        last: bool,
        cont: tuple,
        parent: Optional[int],
        branch: int,
    ) -> None:
        lines.append((level, sib_idx, addr, last, cont, parent, branch))
        kids = adj.get(addr, [])
        kid_cont_base = cont + (not last,)
        if sib_idx in expanded.get(level, ()):
            for i, k in enumerate(kids):
                # A child's continuation segments describe its ancestors:
                # the parent contributes only if it has a following sibling.
                rec(
                    k, level + 1, i, i == len(kids) - 1, kid_cont_base,
                    addr, branch if level > 0 else i,
                )
        else:
            for i, k in enumerate(kids):
                lines.append(
                    (level + 1, i, k, i == len(kids) - 1,
                     kid_cont_base, addr, branch if level > 0 else i)
                )

    rec(entry, 0, 0, True, (), None, 0)
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
    text = f"{prefix}{marks}{addr:#x}"
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
    # Witness-input lookup: UI sets input_request to a block address; the
    # worker resolves input_result = {addr, stdin, argv, status}.
    input_request: Optional[int] = None
    input_result: Optional[dict] = None
    # Most recently resolved concrete input (shown in the header).
    current_input: Optional[dict] = None


def make_observer(
    snap: Snapshot, input_setup: Any = None
) -> Callable[[int, Any], Optional[bool]]:
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
                req = snap.input_request
            if req is not None and input_setup is not None:
                _resolve_witness(snap, simgr, input_setup, req)
        except Exception:
            pass
        return None

    return _observe


def _resolve_witness(snap: Snapshot, simgr: Any, input_setup: Any, addr: int) -> None:
    """Find a live state that passed through `addr` and concretize its input.

    Runs in the worker thread (safe: the UI never touches simgr).  Only one
    in flight at a time; the result lands in ``snap.input_result``.
    """
    from angrsolve.explorer import _extract_argv_from_mem, _extract_stdin

    result: dict = {"addr": addr, "stdin": None, "argv": None, "status": "unknown"}
    try:
        states = list(simgr.active) + list(simgr.deadended)[:200]
        witness = None
        for s in states:
            try:
                if addr in list(s.history.bbl_addrs):
                    witness = s
                    break
            except Exception:
                continue
        if witness is None:
            result["status"] = "pruned (no live state passed through it)"
        else:
            if input_setup.stdin_size > 0:
                result["stdin"] = _extract_stdin(witness, input_setup.stdin_size)
            if input_setup.argv_size > 0 and input_setup.argv_addr is not None:
                result["argv"] = _extract_argv_from_mem(
                    witness, input_setup.argv_addr, input_setup.argv_size
                )
            result["status"] = "witness (example input that reached it)"
    except Exception:
        result["status"] = "lookup failed"
    with snap.lock:
        # Only publish if the UI is still waiting for this address.
        if snap.input_request == addr:
            snap.input_result = result
            snap.input_request = None
            snap.current_input = result


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

    BRANCH_COLORS = (
        "COLOR_GREEN", "COLOR_YELLOW", "COLOR_CYAN",
        "COLOR_MAGENTA", "COLOR_BLUE", "COLOR_WHITE",
    )

    def draw(stdscr: Any) -> None:
        curses.curs_set(0)
        stdscr.timeout(200)
        if curses.has_colors():
            try:
                curses.start_color()
                curses.use_default_colors()
                for i, name in enumerate(BRANCH_COLORS):
                    curses.init_pair(10 + i, getattr(curses, name), -1)
                use_color = True
            except Exception:
                use_color = False
        else:
            use_color = False

        entry, adj = build_graph(proj)
        acc = Accordion()
        cursor = 0
        xoff = 0
        status_msg = ""
        status_at = 0.0
        popup = None  # (title, [body lines]) or None

        def status(text: str) -> None:
            nonlocal status_msg, status_at
            status_msg, status_at = text, time.time()

        def branch_attr(branch: int, addr: int, selected: bool) -> int:
            if use_color:
                attr = curses.color_pair(10 + branch % len(BRANCH_COLORS))
            else:
                attr = curses.A_NORMAL
            if addr in snap_data["active"]:
                attr |= curses.A_BOLD
            return attr | curses.A_REVERSE if selected else attr

        def show_popup(title: str, body: List[str]) -> None:
            nonlocal popup
            popup = (title, body)

        def fmt_blob(data: Any) -> List[str]:
            if not data:
                return ["<empty>"]
            if isinstance(data, bytes):
                hexs = data.hex()
                lines = [hexs[i : i + 64] for i in range(0, len(hexs), 64)]
                printable = "".join(chr(b) if 32 <= b < 127 else "." for b in data)
                return lines[:8] + [f"ascii: {printable[:64]}"]
            return [str(data)[:128]]

        status("Enter expands \u2014 i shows input \u2014 r rebuilds \u2014 q quits")
        while True:
            with snap.lock:
                snap_data = {
                    "steps": snap.steps,
                    "active": set(snap.active),
                    "visited": set(snap.visited),
                    "found": snap.found,
                    "deadended": snap.deadended,
                    "done": snap.done,
                    "current_input": snap.current_input,
                    "input_result": snap.input_result,
                }
                if snap.input_result is not None:
                    res = snap.input_result
                    snap.input_result = None
                    show_popup(
                        f"input reaching {res['addr']:#x} ({res['status']})",
                        ["stdin:"] + fmt_blob(res["stdin"]) + ["argv:"] + fmt_blob(res["argv"]),
                    )
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
            cur_in = snap_data["current_input"]
            if cur_in and cur_in.get("stdin"):
                raw = cur_in["stdin"]
                preview = "".join(chr(b) if 32 <= b < 127 else "." for b in raw[:24])
                head += f" | in: {preview}"
            if snap_data["done"]:
                head += "  DONE \u2014 q to exit"
            stdscr.addstr(0, 0, head[:width])
            keys = ("\u2191/\u2193 move  \u2190/\u2192 siblings  Enter expand  "
                    "Bksp fold  i input  [/] scroll  r reload  q")
            stdscr.addstr(1, 0, keys[:width])
            # Scroll so the cursor line is visible.
            first = max(0, min(cursor, len(lines) - (rows - 3)))
            first = min(first, cursor)
            for vi, li in enumerate(range(first, len(lines))):
                y = vi + 2
                if y >= rows - 1:
                    break
                level, sib_idx, addr, last, cont, parent, branch = lines[li]
                kids = adj.get(addr, [])
                is_exp = bool(kids) and sib_idx in acc.expanded.get(level, ())
                text = format_line(
                    addr, _marks(addr, snap_data, finds, avoids),
                    len(kids), is_exp, last, cont, 10**9,
                )
                text = text[xoff : xoff + width]
                try:
                    stdscr.addstr(
                        y, 0, text, branch_attr(branch, addr, li == cursor)
                    )
                except Exception:
                    pass
            if status_msg and time.time() - status_at < 4:
                try:
                    stdscr.addstr(rows - 1, 0, status_msg[:width])
                except Exception:
                    pass
            if popup is not None:
                title, body = popup
                ph, pw = min(len(body) + 4, rows - 2), min(max([len(title)] + [len(b) for b in body]) + 4, width)
                py, px = max(0, (rows - ph) // 2), max(0, (width - pw) // 2)
                try:
                    win = curses.newwin(ph, pw, py, px)
                    win.box()
                    win.addstr(0, 2, title[: pw - 4], curses.A_BOLD)
                    for bi, bl in enumerate(body[: ph - 2]):
                        win.addstr(bi + 1, 1, bl[: pw - 2])
                    win.addstr(ph - 1, 2, "any key to close"[: pw - 4])
                    win.refresh()
                except Exception:
                    pass
                stdscr.refresh()
                stdscr.timeout(-1)
                stdscr.getch()
                stdscr.timeout(200 if not snap_data["done"] else -1)
                popup = None
                continue
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
                entry, adj = build_graph(proj)
                status(f"graph reloaded: {len(adj)} blocks")
                continue
            if key in (ord("["), ord("{")):
                xoff = max(0, xoff - 8)
                continue
            if key in (ord("]"), ord("}")):
                xoff += 8
                continue
            if key == ord("i"):
                level, sib_idx, addr, last, cont, parent, branch = lines[cursor]
                with snap.lock:
                    snap.input_request = addr
                    snap.input_result = None
                status(f"resolving input for {addr:#x}\u2026")
                continue
            level, sib_idx, addr, last, cont, parent, branch = lines[cursor]
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
                n_sibs = len(adj.get(parent, [addr])) if parent is not None else 1
                if sib_idx + 1 < n_sibs:
                    for li2, ln in enumerate(lines):
                        if ln[0] == level and ln[1] == sib_idx + 1:
                            cursor = li2
                            break
            elif key in (curses.KEY_ENTER, 10, 13, ord(" ")):
                kids = adj.get(addr, [])
                if not kids:
                    status(f"{addr:#x}: no successors")
                    continue
                acc.expand(level, sib_idx)
                lines = render_lines(entry, adj, acc.expanded)
                for li2, ln in enumerate(lines):
                    if ln[0] == level + 1 and ln[1] == 0:
                        # land on this node's first child
                        if ln[5] == addr:
                            cursor = li2
                            break
            elif key in (curses.KEY_BACKSPACE, 127, 8, ord("u"), ord("x")):
                if level > 0:
                    if key == ord("x"):
                        # fold just this node, keep its siblings open
                        acc.collapse_node(level, sib_idx)
                    else:
                        acc.collapse(level - 1)
                    lines = render_lines(entry, adj, acc.expanded)
                    # land on the folded node's parent
                    for li2, ln in enumerate(lines):
                        if ln[2] == parent:
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
    cfg.observer = make_observer(snap, input_setup)
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
