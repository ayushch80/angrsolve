"""EXPERIMENTAL progress visualization for exploration.

Telemetry is collected by sampling the simulation manager from the existing
``step_func`` hook in ``explorer.py``.  The live panel writes ANSI status
lines to stderr (so piped stdout / ``--json`` output stays clean) and renders
only on a TTY unless ``--quiet`` is given.  The HTML report is a standalone
file with an embedded timeline chart, generated from the same samples.
"""

from __future__ import annotations

import html
import json
import sys
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class ProgressTracker:
    """Time-throttled sampler for exploration stats."""

    min_interval: float = 0.25
    samples: List[Dict[str, Any]] = field(default_factory=list)
    _last: float = 0.0

    def sample(self, step: int, simgr: Any, started: float) -> bool:
        now = time.time()
        if self.samples and (now - self._last) < self.min_interval:
            return False
        self._last = now
        self.samples.append(
            {
                "t": round(now - started, 2),
                "step": step,
                "active": len(simgr.active),
                "deadended": len(simgr.deadended),
                "found": len(simgr.stashes.get("found", [])),
                "avoided": len(simgr.stashes.get("avoided", [])),
                "deepest": _deepest_addr(simgr),
            }
        )
        return True


def _deepest_addr(simgr: Any) -> Optional[str]:
    try:
        addrs = [s.addr for s in simgr.active]
        return hex(max(addrs)) if addrs else None
    except Exception:
        return None


class ProgressDisplay:
    """Single-line ANSI status panel on stderr.  No-op when disabled."""

    def __init__(self, enabled: bool, timeout: Optional[float] = None) -> None:
        # Gate on TTY so CI logs and piped output stay clean.
        self.enabled = enabled and sys.stderr.isatty()
        self.timeout = timeout
        self._started = time.time()

    def update(self, step: int, simgr: Any) -> None:
        if not self.enabled:
            return
        elapsed = time.time() - self._started
        try:
            active = len(simgr.active)
            found = len(simgr.stashes.get("found", []))
            dead = len(simgr.deadended)
        except Exception:
            return
        line = (
            f"\r[+] step {step} | active {active} | found {found} "
            f"| dead {dead} | {elapsed:.0f}s"
        )
        if self.timeout:
            line += f"/{self.timeout:.0f}s"
        sys.stderr.write(line)
        sys.stderr.flush()

    def finish(self, steps: int, found: bool) -> None:
        if not self.enabled:
            return
        elapsed = time.time() - self._started
        sys.stderr.write(
            f"\n[+] exploration done: {steps} steps, "
            f"{'solution found' if found else 'no solution'} in {elapsed:.1f}s\n"
        )
        sys.stderr.flush()


def write_html_report(
    path: str,
    samples: List[Dict[str, Any]],
    summary: Dict[str, Any],
) -> None:
    """Write a standalone HTML page with a timeline chart + summary table."""
    data = json.dumps(samples)
    rows = "\n".join(
        f"<tr><td>{html.escape(str(k))}</td><td>{html.escape(str(v))}</td></tr>"
        for k, v in summary.items()
    )
    page = f"""<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>angrsolve progress report</title>
<style>body{{font-family:monospace;max-width:900px;margin:2em auto}}
table{{border-collapse:collapse}}td,th{{border:1px solid #999;padding:4px 10px}}
canvas{{width:100%;height:220px;border:1px solid #999}}</style></head>
<body><h1>angrsolve progress report</h1>
<h2>Summary</h2><table>{rows}</table>
<h2>States over time</h2><canvas id="c" width="880" height="220"></canvas>
<script>
const S = {data};
const c = document.getElementById('c'), x = c.getContext('2d');
const maxT = Math.max(...S.map(p => p.t), 1);
const maxN = Math.max(...S.map(p => Math.max(p.active, p.deadended)), 1);
function line(key, color) {{
  x.strokeStyle = color; x.beginPath();
  S.forEach((p, i) => {{
    const px = (p.t / maxT) * 880, py = 220 - (p[key] / maxN) * 210;
    i ? x.lineTo(px, py) : x.moveTo(px, py);
  }});
  x.stroke();
}}
line('active', '#06c'); line('deadended', '#c60'); line('found', '#0a0');
x.fillStyle = '#000';
x.fillText('active', 8, 12); x.fillStyle = '#06c'; x.fillRect(50, 4, 12, 8);
x.fillStyle = '#000'; x.fillText('deadended', 70, 12);
x.fillStyle = '#c60'; x.fillRect(140, 4, 12, 8);
x.fillStyle = '#000'; x.fillText('found', 160, 12);
x.fillStyle = '#0a0'; x.fillRect(195, 4, 12, 8);
</script></body></html>
"""
    with open(path, "w") as f:
        f.write(page)
