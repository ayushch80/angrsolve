from __future__ import annotations

from typing import List

from angrsolve.strategies.base import SolveStrategy
from angrsolve.strategies.feedback_loop import FeedbackLoopStrategy

# Strategies are tried in list order (first match wins).
_BUILTIN_STRATEGIES: List[type[SolveStrategy]] = [
    FeedbackLoopStrategy,
]


def get_strategies() -> List[SolveStrategy]:
    return [cls() for cls in _BUILTIN_STRATEGIES]
