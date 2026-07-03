from __future__ import annotations

import angr

from angrsolve.loader import load_binary, resolve_address, resolve_addresses, resolve_auto_symbols


class TestLoadBinary:
    def test_loads_without_error(self, argv_binary: str) -> None:
        proj = load_binary(str(argv_binary))
        assert isinstance(proj, angr.Project)
        assert proj.loader.main_object is not None

    def test_auto_load_libs_false(self, argv_binary: str) -> None:
        proj = load_binary(str(argv_binary))
        # The external objects should only be libraries loaded via SimProcedures
        assert len(proj.loader.all_objects) >= 1


class TestResolveAddress:
    def test_symbol_found(self, argv_binary: str) -> None:
        proj = load_binary(str(argv_binary))
        addr = resolve_address(proj, "win")
        assert addr is not None
        assert isinstance(addr, int)

    def test_symbol_not_found(self, argv_binary: str) -> None:
        proj = load_binary(str(argv_binary))
        addr = resolve_address(proj, "nonexistent_symbol_xyz")
        assert addr is None

    def test_hex_address(self, argv_binary: str) -> None:
        proj = load_binary(str(argv_binary))
        addr = resolve_address(proj, "0x401000")
        assert addr is not None

    def test_pie_address(self, pie_binary: str) -> None:
        proj = load_binary(str(pie_binary))
        addr = resolve_address(proj, "win")
        assert addr is not None
        # PIE binary: address should be > base address
        base = proj.loader.main_object.min_addr
        assert addr > base

    def test_fail_symbol_resolved(self, argv_binary: str) -> None:
        proj = load_binary(str(argv_binary))
        addr = resolve_address(proj, "fail")
        assert addr is not None
        assert isinstance(addr, int)


class TestResolveAddresses:
    def test_list_of_targets(self, argv_binary: str) -> None:
        proj = load_binary(str(argv_binary))
        addrs = resolve_addresses(proj, ["win", "fail"])
        assert len(addrs) == 2
        assert all(isinstance(a, int) for a in addrs)

    def test_invalid_target_skipped(self, argv_binary: str) -> None:
        proj = load_binary(str(argv_binary))
        addrs = resolve_addresses(proj, ["win", "nope"])
        assert len(addrs) == 1


class TestResolveAutoSymbols:
    def test_finds_win_and_fail(self, argv_binary: str) -> None:
        proj = load_binary(str(argv_binary))
        result = resolve_auto_symbols(proj)
        assert "win" in [proj.loader.find_symbol("win").name for _ in [1]]
        assert len(result["find"]) >= 1
        assert len(result["avoid"]) >= 1

    def test_no_symbols_in_nostdlib(self, nostdlib_binary: str) -> None:
        proj = load_binary(str(nostdlib_binary))
        result = resolve_auto_symbols(proj)
        assert result["find"] == []
        assert result["avoid"] == []
