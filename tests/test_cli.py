import json
from pathlib import Path

from vulnscan.cli import main

FIXTURE = str(Path(__file__).parent / "fixtures" / "sample_scan.xml")


def test_from_xml_writes_reports(tmp_path):
    rc = main(["--from-xml", FIXTURE, "--output-dir", str(tmp_path), "--name", "demo"])
    assert rc == 0
    assert (tmp_path / "demo.md").read_text().startswith("# Vulnerability scan report")
    assert json.loads((tmp_path / "demo.json").read_text())["summary"]


def test_fail_on_sets_exit_code(tmp_path):
    assert main(["--from-xml", FIXTURE, "--output-dir", str(tmp_path), "--fail-on", "critical"]) == 2


def test_scan_requires_authorised_flag(tmp_path, capsys):
    rc = main(["192.0.2.0/24", "--output-dir", str(tmp_path)])
    assert rc == 1
    assert "--authorised" in capsys.readouterr().err


def test_public_target_refused(tmp_path, capsys):
    rc = main(["100.64.0.8", "--authorised", "--output-dir", str(tmp_path)])
    assert rc == 1
    assert "non-private" in capsys.readouterr().err


def test_redact_skips_raw_xml(tmp_path):
    rc = main(
        ["--from-xml", FIXTURE, "--output-dir", str(tmp_path), "--name", "r", "--redact", "--format", "md"]
    )
    assert rc == 0
    assert "192.0.2." not in (tmp_path / "r.md").read_text()
