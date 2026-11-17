"""EXPERIMENTAL interactive CFG river viewer.

Shows the binary's control-flow graph as an expanding tree: each split
branches downstream with connector lines, and every level-1 branch keeps
its own color so forks stay traceable.  Multiple branches stay open at
once; expanding never collapses siblings.  Blocks are badged live from
exploration:

    ``●`` active state here   ``·`` visited   ``F`` find target
    ``A`` avoid target        dimmed = subtree fully exhausted (dead)
    ``L`` = on a loop path (red when the terminal supports colors)
    ``⟲→ADDR`` = repeating state (a loop back-edge to ancestor ADDR;
    the latch and its straight-line parents render in the loop color)
    Collapsed nodes show only their own line: ``▸+N`` counts children
    that stay hidden until you explicitly expand the node.

Keys: ↑/↓ or k/j move, ←/→ or h/l siblings, Enter/Space expand the
selected block, Backspace folds it (or jumps to its parent when already
folded), x folds one node, i shows a witness input reaching the block,
[/] scroll horizontally, r rebuilds the graph, q abandons the run.
Exploration runs in a worker thread; the UI polls a lock-protected
snapshot so rendering never touches live angr state.
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
    """Set of expanded block addresses.

    Keyed by address (not position): sibling indices repeat under every
    parent, so position keys leak expansion state across subtrees.
    Expanding never collapses anything.  Folding a node drops it plus
    the part of its downstream reachable only through it — blocks that
    stay visible via another expanded path (shared joins, cycle
    re-entries) keep their flags.
    """

    def __init__(self) -> None:
        self.expanded: Set[int] = set()

    def expand(self, addr: int) -> None:
        self.expanded.add(addr)

    def collapse_node(
        self, entry: int, addr: int, adj: Dict[int, List[int]]
    ) -> None:
        # Drop the folded node itself, then keep exactly the expanded
        # flags still on screen: nodes reachable from the root without
        # passing through the folded node.  A shared join stays (it is
        # reachable via its other parent) while exclusively-downstream
        # blocks go; a cycle head stays (it is above the fold, not
        # below it).  Roots the walk at `entry` so ancestors are never
        # mistaken for descendants on cyclic graphs.
        allowed = self.expanded - {addr}
        if entry not in allowed:
            self.expanded = set()
            return
        seen = {entry}
        stack = [entry]
        while stack:
            a = stack.pop()
            for k in adj.get(a, []):
                if k in allowed and k not in seen:
                    seen.add(k)
                    stack.append(k)
        self.expanded = seen


_MAX_LINES = 20000


def render_lines(
    entry: int,
    adj: Dict[int, List[int]],
    expanded: Set[int],
    limit: int = _MAX_LINES,
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
        path: frozenset = frozenset(),
    ) -> None:
        if len(lines) >= limit:
            return  # render budget: huge trees stay interactive
        lines.append((level, sib_idx, addr, last, cont, parent, branch))
        kids = adj.get(addr, [])
        kid_cont_base = cont + (not last,)
        # Never descend into an address already on the current path:
        # CFGs contain cycles, and expanding along one must terminate.
        # A collapsed node shows only its own line (``▸+N`` counts the
        # hidden children) — nothing unfolds without explicit expansion,
        # so the path-blocked repeat simply isn't rendered; the latch
        # that closes the loop carries the loop marker instead.
        if addr in expanded and addr not in path:
            path = path | {addr}
            for i, k in enumerate(kids):
                # A child's continuation segments describe its ancestors:
                # the parent contributes only if it has a following sibling.
                rec(
                    k, level + 1, i, i == len(kids) - 1, kid_cont_base,
                    addr, branch if level > 0 else i, path,
                )
        # else: collapsed — own line only, children stay hidden.

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


def _parent_indices(lines: List[tuple]) -> List[Optional[int]]:
    """Map each line to its parent line (preorder: nearest level-1)."""
    parent_idx: List[Optional[int]] = []
    stack: List[int] = []
    for i, ln in enumerate(lines):
        while stack and lines[stack[-1]][0] >= ln[0]:
            stack.pop()
        parent_idx.append(stack[-1] if stack else None)
        stack.append(i)
    return parent_idx


def detect_loops(
    lines: List[tuple], adj: Dict[int, List[int]]
) -> tuple:
    """Find repeating blocks (loop latches) in the rendered tree.

    A block repeats when one of its CFG successors is its own ancestor.
    Keyed by line index: the same address can appear under several
    parents (joins, shared stubs), and each occurrence has its own
    ancestor chain.  Returns (loops, colored) where loops maps line idx
    -> target addr and colored holds the latch lines plus every ancestor
    line up the chain as long as each has exactly one successor (the
    straight-line loop body).  Coloring stops at forks.
    """
    parent_idx = _parent_indices(lines)
    loops: Dict[int, int] = {}
    for i, ln in enumerate(lines):
        seen: Set[int] = set()
        j = parent_idx[i]
        while j is not None:
            seen.add(lines[j][2])
            j = parent_idx[j]
        for s in adj.get(ln[2], []):
            if s in seen:
                loops[i] = s
                break
    addrs = [ln[2] for ln in lines]
    # Each set holds line indices (not addresses): the same block can
    # appear under several parents with different loop membership.
    # Seed with single-successor latches only: a fork that happens to
    # sit on a cycle still gets the arrow suffix, but not the color.
    colored: Set[int] = {i for i in loops if len(adj.get(addrs[i], [])) == 1}
    for i, tgt in loops.items():
        j = parent_idx[i]
        while j is not None:
            # The loop closes at its target: color it only when it is
            # itself straight-line; above it is outside the loop.
            # A fork on the path is skipped but the walk continues up
            # to the target.
            if addrs[j] == tgt:
                if len(adj.get(addrs[j], [])) == 1:
                    colored.add(j)
                break
            if len(adj.get(addrs[j], [])) == 1:
                colored.add(j)
            j = parent_idx[j]
    return loops, colored


def sibling_line(lines: List[tuple], cursor: int, direction: int) -> Optional[int]:
    """Line index of the sibling next to the cursor line, if displayed.

    Matches on (level, sibling index) *and* the same parent address:
    sibling indices repeat under every parent, so without the parent
    check a jump from the second subtree lands in the first.
    """
    level, sib_idx, parent = lines[cursor][0], lines[cursor][1], lines[cursor][5]
    want = sib_idx + direction
    if want < 0:
        return None
    for li2, ln in enumerate(lines):
        if ln[0] == level and ln[1] == want and ln[5] == parent:
            return li2
    return None


def parent_line(lines: List[tuple], cursor: int) -> Optional[int]:
    """Line index of the cursor line's true parent via the render order."""
    return _parent_indices(lines)[cursor]


def expand_with_ancestors(acc: Accordion, lines: List[tuple], li: int) -> None:
    """Expand the line at index `li` and every folded ancestor to root.

    render_lines descends top-down, so expanding a node whose parent is
    folded would show nothing.  Walk the parent line links upward.
    """
    parent_idx = _parent_indices(lines)
    i: Optional[int] = li
    while i is not None:
        acc.expand(lines[i][2])
        i = parent_idx[i]


def compute_dead(
    adj: Dict[int, List[int]], visited: Set[int], active: Set[int]
) -> Set[int]:
    """Visited blocks whose subtree holds no live state.

    A node is dead when it was visited, is not itself active, and no
    active address is reachable below it — exploration under it is fully
    exhausted.  Computed as visited minus (active plus all ancestors
    of active), so one reverse walk covers the whole graph.
    """
    parents: Dict[int, Set[int]] = {}
    for p, kids in adj.items():
        for k in kids:
            parents.setdefault(k, set()).add(p)
    live = set(active)
    stack = list(active)
    while stack:
        a = stack.pop()
        for p in parents.get(a, ()):
            if p not in live:
                live.add(p)
                stack.append(p)
    return set(visited) - live


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

    loops_cache_key: Any = None
    loops_cache_val: tuple = ({}, set())

    def draw(stdscr: Any) -> None:
        nonlocal loops_cache_key, loops_cache_val
        curses.curs_set(0)
        stdscr.timeout(200)
        if curses.has_colors():
            try:
                curses.start_color()
                curses.use_default_colors()
                for i, name in enumerate(BRANCH_COLORS):
                    curses.init_pair(10 + i, getattr(curses, name), -1)
                curses.init_pair(17, curses.COLOR_RED, -1)  # loop latch
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

        def branch_attr(
            branch: int, addr: int, selected: bool,
            dead: bool = False, loop: bool = False,
        ) -> int:
            if use_color:
                if loop:
                    attr = curses.color_pair(17)
                else:
                    attr = curses.color_pair(10 + branch % len(BRANCH_COLORS))
            else:
                attr = curses.A_NORMAL
            if addr in snap_data["active"]:
                attr |= curses.A_BOLD
            if dead:
                attr |= curses.A_DIM
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
            try:
                lines = render_lines(entry, adj, acc.expanded, limit=_MAX_LINES)
            except RecursionError:
                # Degenerate deep chain: keep last good frame, say why.
                status("tree too deep to render \u2014 fold branches")
            dead = compute_dead(adj, snap_data["visited"], snap_data["active"])
            loops_key = (id(adj), frozenset(acc.expanded))
            if loops_key != loops_cache_key:
                loops_cache_key = loops_key
                loops_cache_val = detect_loops(lines, adj)
            loops, loop_lines = loops_cache_val
            if len(lines) >= _MAX_LINES:
                status(f"tree too large \u2014 showing first {_MAX_LINES} rows")
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
                head += "  DONE \u2014 any key to exit"
            try:
                stdscr.addstr(0, 0, head[:width])
            except Exception:
                pass
            keys = ("\u2191/\u2193 move  \u2190/\u2192 siblings  Enter expand  "
                    "Bksp fold  i input  [/] scroll  r reload  q")
            try:
                stdscr.addstr(1, 0, keys[:width])
            except Exception:
                pass
            # Scroll so the cursor line is visible.
            first = max(0, min(cursor, len(lines) - (rows - 3)))
            for vi, li in enumerate(range(first, len(lines))):
                y = vi + 2
                if y >= rows - 1:
                    break
                level, sib_idx, addr, last, cont, parent, branch = lines[li]
                kids = adj.get(addr, [])
                is_exp = bool(kids) and addr in acc.expanded
                marks = _marks(addr, snap_data, finds, avoids)
                if li in loop_lines:
                    marks += "L"  # on a loop path (mono cue; red when colored)
                text = format_line(
                    addr, marks,
                    len(kids), is_exp, last, cont, 10**9,
                )
                if li in loops:
                    text += f" \u27f2\u2192{loops[li]:#x}"  # repeating state
                text = text[xoff : xoff + width]
                try:
                    stdscr.addstr(
                        y, 0, text, branch_attr(
                            branch, addr, li == cursor, addr in dead,
                            li in loop_lines,
                        ),
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
                try:
                    status("rebuilding CFG\u2026")
                    stdscr.refresh()
                    entry, adj = build_graph(proj)
                    known = set(adj)
                    for kids in adj.values():
                        known.update(kids)
                    acc.expanded.intersection_update(known)
                    status(f"graph reloaded: {len(adj)} blocks")
                except Exception as exc:
                    status(f"reload failed: {exc}")
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
                dest = sibling_line(lines, cursor, -1)
                if dest is not None:
                    cursor = dest
            elif key in (curses.KEY_RIGHT, ord("l")):
                dest = sibling_line(lines, cursor, +1)
                if dest is not None:
                    cursor = dest
            elif key in (curses.KEY_ENTER, 10, 13, ord(" ")):
                kids = adj.get(addr, [])
                if not kids:
                    status(f"{addr:#x}: no successors")
                    continue
                # Expand the node plus any folded ancestors, otherwise
                # the flag lands in a folded subtree and nothing shows.
                expand_with_ancestors(acc, lines, cursor)
                lines = render_lines(entry, adj, acc.expanded)
                for li2, ln in enumerate(lines):
                    if ln[0] == level + 1 and ln[1] == 0:
                        # land on this node's first child
                        if ln[5] == addr:
                            cursor = li2
                            break
            elif key in (curses.KEY_BACKSPACE, 127, 8, ord("u"), ord("x")):
                if key == ord("x") or addr in acc.expanded:
                    # fold this node itself (plus descendants), keep its
                    # siblings open
                    acc.collapse_node(entry, addr, adj)
                    lines = render_lines(entry, adj, acc.expanded)
                    for li2, ln in enumerate(lines):
                        if ln[2] == addr:
                            cursor = li2
                            break
                elif level > 0:
                    # already folded: move up to the true parent line
                    # (address scan would land on a duplicate repeat).
                    dest = parent_line(lines, cursor)
                    if dest is not None:
                        cursor = dest

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
