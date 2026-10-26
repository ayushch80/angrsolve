"""Tests for the experimental river-tree CFG viewer (no angr needed)."""

from __future__ import annotations

from angrsolve.cfgview import Accordion, Snapshot, format_line, make_observer, render_lines


def _graph() -> tuple:
    # entry -> A, B ; A -> A1 ; B -> (leaf)
    entry, a, b, a1 = 0x1000, 0x1100, 0x1200, 0x1110
    adj = {entry: [a, b], a: [a1], b: [], a1: []}
    return entry, adj


def test_accordion_expand_never_collapses() -> None:
    acc = Accordion()
    acc.expand(1, 0)
    acc.expand(1, 1)  # sibling stays open too
    assert acc.expanded[1] == {0, 1}
    acc.expand(2, 0)
    assert acc.expanded[1] == {0, 1}


def test_accordion_collapse_node_keeps_sibling() -> None:
    acc = Accordion()
    acc.expand(1, 0)
    acc.expand(1, 1)
    acc.collapse_node(1, 0)
    assert acc.expanded[1] == {1}


def test_accordion_collapse_level_and_below() -> None:
    acc = Accordion()
    acc.expand(1, 0)
    acc.expand(2, 0)
    acc.collapse(1)
    assert acc.expanded == {}


def test_render_river_splits_and_continuation() -> None:
    entry, adj = _graph()
    lines = render_lines(entry, adj, {0: {0}, 1: {0, 1}})
    by_addr = {ln[2]: ln for ln in lines}
    # A is not last, B is last
    assert by_addr[0x1100][3] is False
    assert by_addr[0x1200][3] is True
    # A1 descends from A (not last) -> continuation segment True;
    # B descends from entry which is the last of its level -> False
    assert by_addr[0x1110][4] == (False, True)
    assert by_addr[0x1200][4] == (False,)


def test_render_collapsed_children_hidden() -> None:
    entry, adj = _graph()
    lines = render_lines(entry, adj, {})
    addrs = [ln[2] for ln in lines]
    assert addrs == [entry, 0x1100, 0x1200]


def test_render_branch_ids_share_downstream_color() -> None:
    entry, adj = _graph()
    lines = render_lines(entry, adj, {0: {0}, 1: {0, 1}})
    by_addr = {ln[2]: ln for ln in lines}
    assert by_addr[0x1100][6] == 0  # branch of A
    assert by_addr[0x1110][6] == 0  # A1 inherits A's branch
    assert by_addr[0x1200][6] == 1  # B is its own branch


def test_render_parent_links() -> None:
    entry, adj = _graph()
    lines = render_lines(entry, adj, {0: {0}, 1: {0, 1}})
    by_addr = {ln[2]: ln for ln in lines}
    assert by_addr[entry][5] is None
    assert by_addr[0x1100][5] == entry
    assert by_addr[0x1110][5] == 0x1100


def test_render_ignores_stale_indices() -> None:
    entry, adj = _graph()
    lines = render_lines(entry, adj, {0: {0}, 1: {0, 5}})  # 5 is out of range
    assert 0x1110 in [ln[2] for ln in lines]


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
