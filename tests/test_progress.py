from __future__ import annotations

from types import SimpleNamespace

from angrsolve.cli import build_explore_config, build_parser
from angrsolve.progress import ProgressDisplay, ProgressTracker, write_html_report


def _fake_simgr(n_active: int = 3) -> SimpleNamespace:
    return SimpleNamespace(
        active=[SimpleNamespace(addr=0x400100 + i) for i in range(n_active)],
        deadended=[],
        stashes={"found": [], "avoided": []},
    )


class TestProgressTracker:
    def test_samples_accumulate(self) -> None:
        t = ProgressTracker(min_interval=0)
        simgr = _fake_simgr()
        assert t.sample(1, simgr, 0.0)
        assert t.sample(2, simgr, 0.0)
        assert len(t.samples) == 2
        assert t.samples[0]["step"] == 1
        assert t.samples[0]["active"] == 3
        assert t.samples[0]["deepest"] == "0x400102"

    def test_throttles_by_interval(self) -> None:
        t = ProgressTracker(min_interval=3600)
        simgr = _fake_simgr()
        assert t.sample(1, simgr, 0.0)
        assert not t.sample(2, simgr, 0.0)
        assert len(t.samples) == 1


class TestProgressDisplay:
    def test_disabled_is_noop(self, capsys) -> None:
        d = ProgressDisplay(enabled=False)
        d.update(10, _fake_simgr())
        d.finish(10, found=True)
        assert capsys.readouterr().err == ""


class TestHtmlReport:
    def test_writes_standalone_page(self, tmp_path) -> None:
        out = tmp_path / "rep.html"
        write_html_report(
            str(out),
            [{"t": 0.0, "step": 1, "active": 2, "deadended": 0, "found": 0,
              "avoided": 0, "deepest": None}],
            {"steps": 1, "found": 0},
        )
        text = out.read_text()
        assert "<canvas" in text
        assert "steps" in text


class TestProgressFlags:
    def test_defaults_off(self) -> None:
        args = build_parser().parse_args(["/bin/ls"])
        ec = build_explore_config(args)
        assert ec.progress is False
        assert ec.progress_report is None

    def test_flags_wired(self, tmp_path) -> None:
        rep = str(tmp_path / "r.html")
        args = build_parser().parse_args(
            ["/bin/ls", "--progress", "--progress-report", rep]
        )
        ec = build_explore_config(args)
        assert ec.progress is True
        assert ec.progress_report == rep
