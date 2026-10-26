from __future__ import annotations

from types import SimpleNamespace

from angrsolve.cfgview import Accordion, Snapshot, format_line, make_observer, render_lines


class TestAccordion:
    def test_expand_replaces_same_level(self) -> None:
        acc = Accordion()
        acc.expand(0, 0)
        acc.expand(1, 2)
        acc.expand(1, 0)  # sibling: replaces, deeper intact (none here)
        assert acc.expanded == {0: 0, 1: 0}

    def test_expand_drops_deeper(self) -> None:
        acc = Accordion()
        acc.expand(0, 0)
        acc.expand(1, 1)
        acc.expand(0, 2)  # re-expand level 0: level 1 goes off
        assert acc.expanded == {0: 2}

    def test_collapse_drops_level_and_below(self) -> None:
        acc = Accordion()
        acc.expand(0, 0)
        acc.expand(1, 1)
        acc.collapse(1)
        assert acc.expanded == {0: 0}


class TestRenderLines:
    ADJ = {0x100: [0x110, 0x120], 0x110: [0x111, 0x112], 0x120: []}

    def test_collapsed_hides_children(self) -> None:
        lines = render_lines(0x100, self.ADJ, {})
        assert [(a) for _, _, a, _, _ in lines] == [0x100]

    def test_expand_unfolds_one_path(self) -> None:
        lines = render_lines(0x100, self.ADJ, {0: 0, 1: 0})
        addrs = [a for _, _, a, _, _ in lines]
        assert addrs == [0x100, 0x110, 0x111, 0x112, 0x120]

    def test_sibling_switch(self) -> None:
        lines = render_lines(0x100, self.ADJ, {0: 0, 1: 1})
        addrs = [a for _, _, a, _, _ in lines]
        assert addrs == [0x100, 0x110, 0x120]

    def test_continuation_flags(self) -> None:
        lines = render_lines(0x100, self.ADJ, {0: 0, 1: 0})
        by_addr = {a: (last, cont) for _, _, a, last, cont in lines}
        assert by_addr[0x110] == (False, (False,))
        assert by_addr[0x111] == (False, (False, True))
        assert by_addr[0x120] == (True, (False,))


class TestFormatLine:
    def test_truncates_to_width(self) -> None:
        text = format_line(0x1234, "F●", 3, False, False, (True,), 10)
        assert len(text) == 10

    def test_collapsed_shows_kid_count(self) -> None:
        text = format_line(0x120, "", 3, False, True, (False,), 60)
        assert text.endswith("▸+3")

    def test_expanded_hides_kid_count(self) -> None:
        text = format_line(0x110, "", 2, True, False, (False,), 60)
        assert "▸" not in text


class TestObserver:
    def test_records_snapshot(self) -> None:
        snap = Snapshot()
        obs = make_observer(snap)
        simgr = SimpleNamespace(
            active=[SimpleNamespace(addr=0x10), SimpleNamespace(addr=0x20)],
            deadended=[],
            stashes={"found": [1], "avoided": []},
        )
        assert obs(7, simgr) is None
        assert snap.steps == 7
        assert snap.active == {0x10, 0x20}
        assert snap.visited == {0x10, 0x20}
        assert snap.found == 1

    def test_stop_requests_halt(self) -> None:
        snap = Snapshot()
        snap.stop = True
        obs = make_observer(snap)
        assert obs(1, SimpleNamespace()) is True
