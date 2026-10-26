from __future__ import annotations

import argparse

import pytest

from angrsolve.cli import (
    _parse_custom_bytes,
    build_constraint_config,
    build_explore_config,
    build_input_configs,
    build_parser,
    parse_args,
)


class TestParser:
    def test_binary_required(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["/bin/ls"])
        assert args.binary == "/bin/ls"

    def test_default_stdin(self) -> None:
        args = parse_args(["/bin/ls"])
        # No --stdin/--argv/--file specified → auto-default stdin=128
        assert args.stdin == 128
        assert args.argv is None
        assert args.files == []

    def test_stdin_explicit(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["/bin/ls", "--stdin", "64"])
        assert args.stdin == 64

    def test_argv(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["/bin/ls", "--argv", "32"])
        assert args.argv == 32

    def test_file(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["/bin/ls", "--file", "flag.txt", "128"])
        assert args.files == [["flag.txt", "128"]]

    def test_find_symbol(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["/bin/ls", "--find", "win"])
        assert args.find_targets == ["win"]

    def test_find_address(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["/bin/ls", "--find", "0x401234"])
        assert args.find_targets == ["0x401234"]

    def test_avoid(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["/bin/ls", "--avoid", "fail", "--avoid", "exit"])
        assert args.avoid_targets == ["fail", "exit"]

    def test_mode_printable_default(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["/bin/ls"])
        assert args.mode == "printable"

    def test_mode_alphanumeric(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["/bin/ls", "--mode", "alphanumeric"])
        assert args.mode == "alphanumeric"

    def test_auto_avoid_default_on(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["/bin/ls"])
        assert args.auto_avoid is True

    def test_no_auto_avoid(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["/bin/ls", "--no-auto-avoid"])
        assert args.auto_avoid is False

    def test_verbose_count(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["/bin/ls", "-v"])
        assert args.verbose == 1
        args = parser.parse_args(["/bin/ls", "-vv"])
        assert args.verbose == 2
        args = parser.parse_args(["/bin/ls", "-vvv"])
        assert args.verbose == 3

    def test_quiet(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["/bin/ls", "-q"])
        assert args.quiet is True

    def test_json(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["/bin/ls", "--json"])
        assert args.json is True

    def test_no_color(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["/bin/ls", "--no-color"])
        assert args.no_color is True

    def test_timeout(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["/bin/ls", "--timeout", "5.5"])
        assert args.timeout == 5.5

    def test_max_depth(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["/bin/ls", "--max-depth", "100"])
        assert args.max_depth == 100

    def test_max_active(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["/bin/ls", "--max-active", "10"])
        assert args.max_active == 10

    def test_max_steps(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["/bin/ls", "--max-steps", "500"])
        assert args.max_steps == 500

    def test_unicorn(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["/bin/ls", "--unicorn"])
        assert args.unicorn is True

    def test_veritesting(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["/bin/ls", "--veritesting"])
        assert args.veritesting is True

    def test_save(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["/bin/ls", "--save", "/tmp/out.bin"])
        assert args.save == "/tmp/out.bin"


class TestBuildInputConfigs:
    def test_stdin(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["/bin/ls", "--stdin", "64"])
        configs = build_input_configs(args)
        assert len(configs) == 1
        assert configs[0].source == "stdin"
        assert configs[0].size == 64

    def test_argv(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["/bin/ls", "--argv", "32"])
        configs = build_input_configs(args)
        assert len(configs) == 1
        assert configs[0].source == "argv"
        assert configs[0].size == 32

    def test_file(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["/bin/ls", "--file", "data.txt", "256"])
        configs = build_input_configs(args)
        assert len(configs) == 1
        assert configs[0].source == "file"
        assert configs[0].size == 256
        assert configs[0].filename == "data.txt"

    def test_combined(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["/bin/ls", "--stdin", "16", "--argv", "32"])
        configs = build_input_configs(args)
        assert len(configs) == 2
        sources = {c.source for c in configs}
        assert sources == {"stdin", "argv"}

    def test_stdin_size_zero_rejected(self) -> None:
        args = argparse.Namespace(stdin=0, argv=None, files=[])
        with pytest.raises(ValueError):
            build_input_configs(args)

    def test_argv_size_negative_rejected(self) -> None:
        args = argparse.Namespace(stdin=None, argv=-5, files=[])
        with pytest.raises(ValueError):
            build_input_configs(args)

    def test_file_size_invalid_rejected(self) -> None:
        args = argparse.Namespace(stdin=None, argv=None, files=[("f", "zz")])
        with pytest.raises(ValueError):
            build_input_configs(args)

    def test_file_size_zero_rejected(self) -> None:
        args = argparse.Namespace(stdin=None, argv=None, files=[("f", "0")])
        with pytest.raises(ValueError):
            build_input_configs(args)


class TestBuildConstraintConfig:
    def test_mode(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["/bin/ls", "--mode", "letters"])
        cc = build_constraint_config(args)
        assert cc.mode == "letters"

    def test_default_mode(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["/bin/ls"])
        cc = build_constraint_config(args)
        assert cc.mode == "printable"

    def test_custom_bytes(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["/bin/ls", "--custom-bytes", "0x41,0x42"])
        cc = build_constraint_config(args)
        assert cc.custom_bytes == [0x41, 0x42]

    def test_custom_bytes_invalid(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["/bin/ls", "--custom-bytes", "zz"])
        with pytest.raises(ValueError):
            build_constraint_config(args)

    def test_max_depth_zero_rejected(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["/bin/ls", "--max-depth", "0"])
        with pytest.raises(ValueError):
            build_explore_config(args)

    def test_timeout_negative_rejected(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["/bin/ls", "--timeout", "-1"])
        with pytest.raises(ValueError):
            build_explore_config(args)


class TestParseCustomBytes:
    def test_single_values(self) -> None:
        assert _parse_custom_bytes("66,0x42") == [66, 0x42]

    def test_range(self) -> None:
        assert _parse_custom_bytes("0x30-0x33") == [0x30, 0x31, 0x32, 0x33]

    def test_bad_token_raises(self) -> None:
        with pytest.raises(ValueError):
            _parse_custom_bytes("zz")

    def test_reversed_range_raises(self) -> None:
        with pytest.raises(ValueError):
            _parse_custom_bytes("0x40-0x30")

    def test_out_of_range_raises(self) -> None:
        with pytest.raises(ValueError):
            _parse_custom_bytes("256")

    def test_empty_spec_raises(self) -> None:
        with pytest.raises(ValueError):
            _parse_custom_bytes(" , ")


class TestBuildExploreConfig:
    def test_all_fields(self) -> None:
        parser = build_parser()
        args = parser.parse_args(
            [
                "/bin/ls",
                "--timeout", "10",
                "--max-depth", "50",
                "--max-active", "5",
                "--max-steps", "200",
                "--veritesting",
                "--unicorn",
            ]
        )
        ec = build_explore_config(args)
        assert ec.timeout == 10
        assert ec.max_depth == 50
        assert ec.max_active == 5
        assert ec.max_steps == 200
        assert ec.veritesting is True
        assert ec.use_unicorn is True

    def test_defaults(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["/bin/ls"])
        ec = build_explore_config(args)
        assert ec.timeout is None
        assert ec.max_depth is None
        assert ec.max_active is None
        assert ec.max_steps is None
        assert ec.veritesting is False
        assert ec.use_unicorn is False
