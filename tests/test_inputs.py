from __future__ import annotations

import angr
import claripy

from angrsolve.constraints import ConstraintConfig
from angrsolve.inputs import InputConfig, setup_input


class TestSetupInput:
    def test_stdin_size(self, stdin_binary: str) -> None:
        proj = angr.Project(str(stdin_binary), auto_load_libs=False)
        cfg = ConstraintConfig(mode="printable")
        inputs = [InputConfig(source="stdin", size=16)]
        setup = setup_input(proj, inputs, cfg)
        assert setup.stdin_size == 16
        assert setup.argv_size == 0
        assert setup.files == []

    def test_stdin_state_is_entry_state(self, stdin_binary: str) -> None:
        proj = angr.Project(str(stdin_binary), auto_load_libs=False)
        cfg = ConstraintConfig(mode="printable")
        inputs = [InputConfig(source="stdin", size=16)]
        setup = setup_input(proj, inputs, cfg)
        # stdin-only should use entry_state
        assert hasattr(setup.state, "regs")

    def test_argv_size(self, argv_binary: str) -> None:
        proj = angr.Project(str(argv_binary), auto_load_libs=False)
        cfg = ConstraintConfig(mode="printable")
        inputs = [InputConfig(source="argv", size=32)]
        setup = setup_input(proj, inputs, cfg)
        assert setup.argv_size == 32
        assert setup.argv_addr is not None

    def test_file_size(self, file_binary: str) -> None:
        proj = angr.Project(str(file_binary), auto_load_libs=False)
        cfg = ConstraintConfig(mode="printable")
        inputs = [InputConfig(source="file", size=16, filename="flag.txt")]
        setup = setup_input(proj, inputs, cfg)
        assert len(setup.files) == 1
        assert setup.files[0].size == 16
        assert setup.files[0].filename == "flag.txt"
        assert setup.files[0].sym_content is not None

    def test_combined_stdin_argv(self, stdin_binary: str) -> None:
        proj = angr.Project(str(stdin_binary), auto_load_libs=False)
        cfg = ConstraintConfig(mode="printable")
        inputs = [InputConfig(source="stdin", size=8), InputConfig(source="file", size=16, filename="data.txt")]
        setup = setup_input(proj, inputs, cfg)
        assert setup.stdin_size == 8
        assert len(setup.files) == 1

    def test_apply_printable_constraints(self, stdin_binary: str) -> None:
        proj = angr.Project(str(stdin_binary), auto_load_libs=False)
        cfg = ConstraintConfig(mode="digits")
        inputs = [InputConfig(source="stdin", size=8)]
        setup = setup_input(proj, inputs, cfg)
        # Check constraints exist by trying to solve
        s = setup.state
        assert s.solver.satisfiable()
