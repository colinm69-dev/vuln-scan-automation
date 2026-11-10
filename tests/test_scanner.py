import pytest

from vulnscan.scanner import ScanError, ScanOptions, build_command


def test_command_is_a_list_with_targets_after_separator():
    cmd = build_command(["192.0.2.0/24"], ScanOptions())
    assert cmd[0] == "nmap"
    assert cmd[-2:] == ["--", "192.0.2.0/24"]
    assert "-oX" in cmd


def test_vulners_is_opt_in():
    assert "vulners" not in build_command(["192.0.2.1"], ScanOptions())
    assert "vulners" in build_command(["192.0.2.1"], ScanOptions(vulners=True))


def test_invalid_profile_and_timing_rejected():
    with pytest.raises(ScanError):
        build_command(["192.0.2.1"], ScanOptions(profile="nope"))
    with pytest.raises(ScanError):
        build_command(["192.0.2.1"], ScanOptions(timing=9))
