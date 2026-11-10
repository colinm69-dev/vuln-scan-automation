"""Parse Nmap XML into plain objects. Uses defusedxml so untrusted files cannot abuse the parser."""

from __future__ import annotations

from pathlib import Path

from defusedxml import ElementTree as ET

from vulnscan.models import Host, Port, ScanMeta, Script


def _attr(el, name: str, default: str = "") -> str:
    return el.get(name, default) if el is not None else default


def parse_xml(xml_text: str) -> tuple[ScanMeta, list[Host]]:
    root = ET.fromstring(xml_text)
    if root.tag != "nmaprun":
        raise ValueError("Not an Nmap XML file (root element is not <nmaprun>)")

    meta = ScanMeta(
        nmap_version=_attr(root, "version"),
        args=_attr(root, "args"),
        start=_attr(root, "startstr"),
    )
    finished = root.find("runstats/finished")
    meta.elapsed = _attr(finished, "elapsed")
    hosts_el = root.find("runstats/hosts")
    meta.hosts_up = int(_attr(hosts_el, "up", "0") or 0)
    meta.hosts_down = int(_attr(hosts_el, "down", "0") or 0)

    hosts: list[Host] = []
    for h in root.findall("host"):
        status = h.find("status")
        if _attr(status, "state", "up") != "up":
            continue
        address = ""
        for a in h.findall("address"):
            if a.get("addrtype") in ("ipv4", "ipv6"):
                address = a.get("addr", "")
                break
        if not address:
            continue
        host = Host(
            address=address,
            hostnames=[n.get("name", "") for n in h.findall("hostnames/hostname") if n.get("name")],
        )
        match = h.find("os/osmatch")
        if match is not None:
            host.os_guess = match.get("name", "")
        for p in h.findall("ports/port"):
            state = _attr(p.find("state"), "state")
            if state != "open":
                continue
            svc = p.find("service")
            port = Port(
                number=int(p.get("portid", "0")),
                protocol=p.get("protocol", "tcp"),
                state=state,
                service=_attr(svc, "name"),
                product=_attr(svc, "product"),
                version=_attr(svc, "version"),
                extrainfo=_attr(svc, "extrainfo"),
                tunnel=_attr(svc, "tunnel"),
            )
            for s in p.findall("script"):
                port.scripts.append(Script(id=s.get("id", ""), output=s.get("output", "")))
            host.ports.append(port)
        hosts.append(host)
    return meta, hosts


def parse_file(path: str | Path) -> tuple[ScanMeta, list[Host]]:
    return parse_xml(Path(path).read_text(encoding="utf-8"))
