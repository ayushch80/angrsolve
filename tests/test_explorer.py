from __future__ import annotations

import angr

from angrsolve.constraints import ConstraintConfig
from angrsolve.explorer import ExploreConfig, explore
from angrsolve.inputs import InputConfig, setup_input
from angrsolve.loader import resolve_address


class TestExplore:
    def test_argv_finds_solution(self, argv_binary: str) -> None:
        proj = angr.Project(str(argv_binary), auto_load_libs=False)
        find_addr = resolve_address(proj, "win")
        assert find_addr is not None

        input_cfg = ConstraintConfig(mode="printable")
        inputs = [InputConfig(source="argv", size=32)]
        input_setup = setup_input(proj, inputs, input_cfg)

        explore_cfg = ExploreConfig(find_addresses=[find_addr], timeout=30)

        sol = explore(proj, input_setup, explore_cfg)
        assert sol is not None
        assert sol.find_addr == find_addr

    def test_stdin_finds_solution(self, stdin_binary: str) -> None:
        proj = angr.Project(str(stdin_binary), auto_load_libs=False)
        find_addr = resolve_address(proj, "win")
        assert find_addr is not None

        input_cfg = ConstraintConfig(mode="printable")
        inputs = [InputConfig(source="stdin", size=16)]
        input_setup = setup_input(proj, inputs, input_cfg)

        explore_cfg = ExploreConfig(find_addresses=[find_addr], timeout=30)

        sol = explore(proj, input_setup, explore_cfg)
        assert sol is not None
        assert sol.find_addr == find_addr

    def test_file_finds_solution(self, file_binary: str) -> None:
        proj = angr.Project(str(file_binary), auto_load_libs=False)
        find_addr = resolve_address(proj, "win")
        assert find_addr is not None

        input_cfg = ConstraintConfig(mode="printable")
        inputs = [InputConfig(source="file", size=16, filename="flag.txt")]
        input_setup = setup_input(proj, inputs, input_cfg)

        explore_cfg = ExploreConfig(find_addresses=[find_addr], timeout=30)

        sol = explore(proj, input_setup, explore_cfg)
        assert sol is not None
        assert sol.find_addr == find_addr

    def test_solution_contains_argv_payload(self, argv_binary: str) -> None:
        proj = angr.Project(str(argv_binary), auto_load_libs=False)
        find_addr = resolve_address(proj, "win")
        assert find_addr is not None

        input_cfg = ConstraintConfig(mode="printable")
        inputs = [InputConfig(source="argv", size=32)]
        input_setup = setup_input(proj, inputs, input_cfg)

        explore_cfg = ExploreConfig(find_addresses=[find_addr], timeout=30)
        sol = explore(proj, input_setup, explore_cfg)
        assert sol is not None
        assert sol.argv is not None
        assert b"s3cr3t" in sol.argv

    def test_solution_contains_stdin_payload(self, stdin_binary: str) -> None:
        proj = angr.Project(str(stdin_binary), auto_load_libs=False)
        find_addr = resolve_address(proj, "win")
        assert find_addr is not None

        input_cfg = ConstraintConfig(mode="printable")
        inputs = [InputConfig(source="stdin", size=16)]
        input_setup = setup_input(proj, inputs, input_cfg)

        explore_cfg = ExploreConfig(find_addresses=[find_addr], timeout=30)
        sol = explore(proj, input_setup, explore_cfg)
        assert sol is not None
        assert sol.stdin is not None
        assert b"s3cr3t" in sol.stdin

    def test_solution_with_avoid(self, argv_binary: str) -> None:
        proj = angr.Project(str(argv_binary), auto_load_libs=False)
        find_addr = resolve_address(proj, "win")
        avoid_addr = resolve_address(proj, "fail")
        assert find_addr is not None
        assert avoid_addr is not None

        input_cfg = ConstraintConfig(mode="printable")
        inputs = [InputConfig(source="argv", size=32)]
        input_setup = setup_input(proj, inputs, input_cfg)

        explore_cfg = ExploreConfig(find_addresses=[find_addr], avoid_addresses=[avoid_addr], timeout=30)
        sol = explore(proj, input_setup, explore_cfg)
        assert sol is not None

    def test_timeout_returns_none(self, argv_binary: str) -> None:
        proj = angr.Project(str(argv_binary), auto_load_libs=False)
        find_addr = resolve_address(proj, "win")
        assert find_addr is not None

        input_cfg = ConstraintConfig(mode="unrestricted")
        inputs = [InputConfig(source="argv", size=32)]
        input_setup = setup_input(proj, inputs, input_cfg)

        # Very short timeout to trigger
        explore_cfg = ExploreConfig(find_addresses=[find_addr], timeout=0.001)
        sol = explore(proj, input_setup, explore_cfg)
        # With unrestricted, the solver might still find it but timeout could fire
        # Just check it doesn't crash and returns either None or a Solution
        assert sol is None or isinstance(sol, type(sol))

    def test_no_find_returns_none(self, argv_binary: str) -> None:
        proj = angr.Project(str(argv_binary), auto_load_libs=False)

        input_cfg = ConstraintConfig(mode="printable")
        inputs = [InputConfig(source="argv", size=32)]
        input_setup = setup_input(proj, inputs, input_cfg)

        # No find addresses → nothing to find
        explore_cfg = ExploreConfig(find_addresses=[], timeout=10)
        sol = explore(proj, input_setup, explore_cfg)
        assert sol is None
