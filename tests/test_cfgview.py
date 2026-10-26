from __future__ import annotations

from types import SimpleNamespace

from angrsolve.cfgview import Accordion, Snapshot, fit_cells, make_observer


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

    def test_move_remembers_cursor(self) -> None:
        acc = Accordion()
        acc.move(2, 5)
        assert acc.cursor[2] == 5


class TestFitCells:
    def test_fits_unchanged(self) -> None:
        cells = ["0x1", "0x2"]
        assert fit_cells(cells, 0, 80) == (cells, 0)

    def test_truncates_keeps_selection(self) -> None:
        cells = [f"0x{i:04x}" for i in range(20)]
        shown, offset = fit_cells(cells, 19, 30)
        assert "0x0013" in shown[-1]
        assert offset > 0

    def test_empty(self) -> None:
        assert fit_cells([], 0, 80) == ([], 0)


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
