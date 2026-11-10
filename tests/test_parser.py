import pytest

from vulnscan.parser import parse_xml


def test_parses_meta_and_up_hosts(scan):
    meta, hosts = scan
    assert meta.nmap_version == "7.94"
    assert (meta.hosts_up, meta.hosts_down) == (5, 251)
    assert len(hosts) == 5  # the host marked down is skipped
    assert all(h.address.startswith("192.0.2.") for h in hosts)


def test_parses_ports_and_scripts(scan):
    _, hosts = scan
    app = next(h for h in hosts if h.address == "192.0.2.30")
    http = next(p for p in app.ports if p.number == 80)
    assert http.product == "Apache httpd" and http.version == "2.4.49"
    assert http.scripts and "CVE-2021-42013" in http.scripts[0].output


def test_rejects_non_nmap_xml():
    with pytest.raises(ValueError):
        parse_xml("<html></html>")


def test_blocks_entity_expansion():
    bomb = '<?xml version="1.0"?><!DOCTYPE x [<!ENTITY a "aaaa">]><nmaprun>&a;</nmaprun>'
    with pytest.raises(Exception):  # noqa: B017 - defusedxml raises its own error types
        parse_xml(bomb)
