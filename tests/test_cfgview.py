"""Tests for the experimental river-tree CFG viewer (no angr needed)."""

from __future__ import annotations

from angrsolve.cfgview import (
    Accordion,
    Snapshot,
    compute_dead,
    detect_loops,
    expand_with_ancestors,
    format_line,
    make_observer,
    render_lines,
)


def _graph() -> tuple:
    # entry -> A, B ; A -> A1 ; B -> B1 (same sibling idx as A1 by design)
    entry, a, b, a1, b1 = 0x1000, 0x1100, 0x1200, 0x1110, 0x1210
    adj = {entry: [a, b], a: [a1], b: [b1], a1: [], b1: []}
    return entry, adj


def test_accordion_expand_never_collapses() -> None:
    acc = Accordion()
    acc.expand(0x1100)
    acc.expand(0x1200)  # sibling stays open too
    assert acc.expanded == {0x1100, 0x1200}


def test_accordion_collapse_drops_descendants() -> None:
    adj = {0x1000: [0x1100], 0x1100: [0x1110]}
    acc = Accordion()
    acc.expand(0x1000)
    acc.expand(0x1100)
    acc.collapse_node(0x1000, adj)
    assert acc.expanded == set()


def test_accordion_collapse_keeps_siblings() -> None:
    entry, adj = _graph()
    acc = Accordion()
    acc.expand(entry)
    acc.expand(0x1100)
    acc.expand(0x1200)
    acc.collapse_node(0x1100, adj)
    assert acc.expanded == {entry, 0x1200}


def test_render_no_cross_subtree_leak() -> None:
    # The bug: position-keyed flags let A1's expansion leak onto B1
    # (same level + same sibling index, different parent).
    entry, adj = _graph()
    acc = Accordion()
    acc.expand(entry)
    acc.expand(0x1100)
    acc.expand(0x1110)  # A1
    lines = render_lines(entry, adj, acc.expanded)
    by_addr = {ln[2]: ln for ln in lines}
    assert 0x1210 in by_addr  # B1 visible (B expanded? no — B collapsed)
    # B is folded, so B1 must appear as a collapsed child line even
    # though it shares A1's (level, idx).
    assert by_addr[0x1210][1] == 0
    # Now expand B: B1 must NOT spring open from A1's flag... it will
    # only open if B1 itself was expanded.
    acc.expand(0x1200)
    lines = render_lines(entry, adj, acc.expanded)
    rows = [ln for ln in lines if ln[0] == 3]
    assert rows == []  # no grandchildren visible under B1


def test_render_river_splits_and_continuation() -> None:
    entry, adj = _graph()
    acc = Accordion()
    for a in (entry, 0x1100, 0x1200):
        acc.expand(a)
    lines = render_lines(entry, adj, acc.expanded)
    by_addr = {ln[2]: ln for ln in lines}
    # A is not last, B is last
    assert by_addr[0x1100][3] is False
    assert by_addr[0x1200][3] is True
    # A1 descends from A (not last) -> continuation segment True;
    # B1 descends from B (last) -> segment False
    assert by_addr[0x1110][4] == (False, True)
    assert by_addr[0x1210][4] == (False, False)


def test_render_collapsed_children_hidden() -> None:
    entry, adj = _graph()
    lines = render_lines(entry, adj, set())
    addrs = [ln[2] for ln in lines]
    assert addrs == [entry, 0x1100, 0x1200]


def test_render_branch_ids_share_downstream_color() -> None:
    entry, adj = _graph()
    acc = Accordion()
    for a in (entry, 0x1100, 0x1200):
        acc.expand(a)
    lines = render_lines(entry, adj, acc.expanded)
    by_addr = {ln[2]: ln for ln in lines}
    assert by_addr[0x1100][6] == 0  # branch of A
    assert by_addr[0x1110][6] == 0  # A1 inherits A's branch
    assert by_addr[0x1200][6] == 1  # B is its own branch


def test_render_parent_links() -> None:
    entry, adj = _graph()
    acc = Accordion()
    for a in (entry, 0x1100, 0x1200):
        acc.expand(a)
    lines = render_lines(entry, adj, acc.expanded)
    by_addr = {ln[2]: ln for ln in lines}
    assert by_addr[entry][5] is None
    assert by_addr[0x1100][5] == entry
    assert by_addr[0x1110][5] == 0x1100


def test_expand_with_ancestors_opens_chain() -> None:
    entry, adj = _graph()
    acc = Accordion()
    lines = render_lines(entry, adj, acc.expanded)
    # A is the 2nd line (index 1); expanding it must open the root too.
    expand_with_ancestors(acc, lines, 1)
    assert acc.expanded == {0x1100, entry}
    lines = render_lines(entry, adj, acc.expanded)
    assert 0x1110 in [ln[2] for ln in lines]
    # A1 is now visible (index 2: entry, A, A1, B).
    expand_with_ancestors(acc, lines, 2)
    assert acc.expanded == {0x1110, 0x1100, entry}


def test_compute_dead_marks_exhausted_subtrees() -> None:
    entry, adj = _graph()
    # A1 visited and idle, B never visited, entry has live state below.
    dead = compute_dead(adj, {entry, 0x1100, 0x1110}, {entry})
    assert dead == {0x1100, 0x1110}


def test_compute_dead_ignores_live_subtrees() -> None:
    entry, adj = _graph()
    dead = compute_dead(adj, {entry, 0x1100, 0x1110}, {0x1110})
    assert dead == set()


def test_compute_dead_unvisited_not_dead() -> None:
    entry, adj = _graph()
    assert compute_dead(adj, set(), set()) == set()


def test_detect_loops_finds_latch_and_target() -> None:
    # head -> body -> latch, latch jumps back to head.
    head, body, latch = 0x1000, 0x1100, 0x1200
    adj = {head: [body], body: [latch], latch: [head]}
    acc = Accordion()
    for a in (head, body, latch):
        acc.expand(a)
    lines = render_lines(head, adj, acc.expanded)
    loops, colored = detect_loops(lines, adj)
    # Every expanded occurrence on the cycle is a latch: the latch
    # itself, the repeated head, and the repeated body under it.
    assert loops == {2: head, 3: body, 4: latch}
    # straight-line chain: latch + body + head all loop-colored.
    assert colored == {latch, body, head}


def test_detect_loops_stops_coloring_at_fork() -> None:
    # head -> mid -> body -> latch -> head, but mid also -> side.
    # mid is a fork on the loop path, so it stays uncolored.
    head, mid, body, latch, side = 0x1000, 0x1050, 0x1100, 0x1200, 0x1300
    adj = {
        head: [mid], mid: [body, side], body: [latch],
        latch: [head], side: [],
    }
    acc = Accordion()
    for a in (head, mid, body, latch, side):
        acc.expand(a)
    lines = render_lines(head, adj, acc.expanded)
    loops, colored = detect_loops(lines, adj)
    # latch line index: head, mid, body, latch.
    assert loops[3] == head
    assert mid not in colored
    assert colored == {latch, body, head}


def test_detect_loops_no_false_positive_on_join() -> None:
    # Classic diamond: joins are descendants, not ancestors.
    head, left, right, join = 0x1000, 0x1100, 0x1200, 0x1300
    adj = {head: [left, right], left: [join], right: [join], join: []}
    acc = Accordion()
    for a in (head, left, right, join):
        acc.expand(a)
    lines = render_lines(head, adj, acc.expanded)
    loops, colored = detect_loops(lines, adj)
    assert loops == {} and colored == set()


def test_render_terminates_on_cycle() -> None:
    head, body = 0x1000, 0x1100
    adj = {head: [body], body: [head]}
    acc = Accordion()
    acc.expand(head)
    acc.expand(body)
    lines = render_lines(head, adj, acc.expanded)
    # body rendered once; the repeated head is a collapsed leaf,
    # and so is head's child listed under it.
    assert [ln[2] for ln in lines] == [head, body, head, body]


def test_format_line_branch_split() -> None:
    text = format_line(0x1100, "", 1, True, False, (False,), 200)
    assert text == "  ├─0x1100"


def test_format_line_root() -> None:
    assert format_line(0x1000, "", 2, True, True, (), 200) == "0x1000"


def test_format_line_last_child() -> None:
    assert format_line(0x1200, "", 0, True, True, (False,), 200) == "  └─0x1200"


def test_format_line_collapsed_count_and_find() -> None:
    text = format_line(0x1100, "F", 3, False, True, (), 200)
    assert text == "F0x1100 ▸+3"


def test_observer_updates_snapshot() -> None:
    snap = Snapshot()

    class _S:
        def __init__(self, addr: int) -> None:
            self.addr = addr

    class _Simgr:
        active = [_S(1), _S(2)]
        deadended: list = []
        stashes = {"found": [_S(9)]}

    obs = make_observer(snap)
    assert obs(10, _Simgr()) is None
    assert snap.steps == 10
    assert snap.active == {1, 2}
    assert snap.visited == {1, 2}
    assert snap.found == 1


def test_observer_stop_flag() -> None:
    snap = Snapshot()
    snap.stop = True
    assert make_observer(snap)(1, object()) is True
