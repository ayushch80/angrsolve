from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, Optional

import angr

from angrsolve.inputs import InputSetup
from angrsolve.output import Solution

if TYPE_CHECKING:
    from angrsolve.explorer import ExploreConfig


class SolveStrategy(ABC):
    """Base class for solution strategies.

    Subclasses implement ``detect()`` and ``solve()``.  ``detect()`` is
    called first; if it returns ``True``, ``solve()`` is tried before
    falling through to symbolic exploration.
    """

    name: str = ""

    @abstractmethod
    def detect(self, proj: angr.Project) -> bool:
        """Return ``True`` if this strategy applies to *proj*."""
        ...

    @abstractmethod
    def solve(
        self,
        proj: angr.Project,
        input_setup: InputSetup,
        cfg: ExploreConfig,
    ) -> Optional[Solution]:
        """Attempt to solve the binary.

        Return a *Solution* or ``None`` if the strategy cannot produce one.
        """
        ...
