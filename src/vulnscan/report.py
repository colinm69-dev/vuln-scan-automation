"""Write Markdown and JSON reports, with optional redaction of addresses and hostnames."""

from __future__ import annotations

import copy
import json
from collections import Counter
from dataclasses import asdict
from datetime import UTC, datetime

from vulnscan.models import Finding, HostResult, ScanMeta
from vulnscan.scoring import BANDS, all_findings


def redact(meta: ScanMeta, results: list[HostResult]) -> tuple[ScanMeta, list[HostResult]]:
    """Replace addresses and hostnames with stable labels so a report can be shared safely.

    Service banners are cut back to product and version, because the extra info field can carry
    domain names, workgroups or timestamps.
    """
    meta = copy.deepcopy(meta)
    results = copy.deepcopy(results)
    for i, r in enumerate(results, start=1):
        label = f"host-{i:02d}"
        for port in r.host.ports:
            port.extrainfo = ""
        banners = {(p.number, p.protocol): p.banner for p in r.host.ports}
        r.host.address = label
        r.host.hostnames = []
        r.host.os_guess = ""
        for f in r.findings:
            f.host = label
            f.banner = banners.get((f.port, f.protocol), "")
    meta.args = "(redacted)"
    return meta, results


def _cell(text: str) -> str:
    return str(text).replace("|", "\\|").replace("\n", " ")


def _counts(findings: list[Finding]) -> Counter:
    return Counter(f.band for f in findings)


def to_markdown(meta: ScanMeta, results: list[HostResult], top: int = 15) -> str:
    findings = all_findings(results)
    counts = _counts(findings)
    host_counts = Counter(r.band for r in results)
    now = datetime.now(UTC).strftime("%Y-%m-%d %H:%M UTC")

    out: list[str] = ["# Vulnerability scan report", ""]
    out += [f"Generated: {now}", ""]
    out += ["## Scan details", "", "| Item | Value |", "|------|-------|"]
    out += [
        f"| Nmap version | {_cell(meta.nmap_version or 'n/a')} |",
        f"| Command | `{_cell(meta.args or 'n/a')}` |",
        f"| Started | {_cell(meta.start or 'n/a')} |",
        f"| Duration (s) | {_cell(meta.elapsed or 'n/a')} |",
        f"| Hosts up / down | {meta.hosts_up} / {meta.hosts_down} |",
        "",
    ]

    out += ["## Summary", "", "| Priority | Hosts | Findings |", "|----------|------:|---------:|"]
    for band in BANDS:
        out.append(f"| {band} | {host_counts.get(band, 0)} | {counts.get(band, 0)} |")
    out.append("")

    out += [f"## Top priorities (up to {top})", ""]
    actionable = [f for f in findings if f.band != "Info"][:top]
    if actionable:
        out += [
            "| # | Host | Port | Service | Score | Priority | Why |",
            "|--:|------|------|---------|------:|----------|-----|",
        ]
        for i, f in enumerate(actionable, start=1):
            why = f.reasons[0].split(":")[0]
            out.append(
                f"| {i} | {_cell(f.host)} | {f.port}/{f.protocol} | {_cell(f.service)} | "
                f"{f.score} | {f.band} | {_cell(why)} |"
            )
    else:
        out.append("No findings above informational level.")
    out.append("")

    out += ["## Hosts", ""]
    for r in results:
        names = f" ({', '.join(r.host.hostnames)})" if r.host.hostnames else ""
        out += [f"### {r.host.address}{names}: {r.band} ({r.score})", ""]
        if r.host.os_guess:
            out += [f"OS guess: {_cell(r.host.os_guess)}", ""]
        if not r.findings:
            out += ["No open ports found.", ""]
            continue
        out += [
            "| Port | Service | Version | Score | Priority |",
            "|------|---------|---------|------:|----------|",
        ]
        for f in r.findings:
            out.append(
                f"| {f.port}/{f.protocol} | {_cell(f.service)} | {_cell(f.banner or '-')} | "
                f"{f.score} | {f.band} |"
            )
        out.append("")
        fixes: list[str] = []
        for f in r.findings:
            if f.band == "Info":
                continue
            for fix in f.remediation:
                line = f"- **{f.port}/{f.protocol}**: {fix}"
                if line not in fixes:
                    fixes.append(line)
        if fixes:
            out += ["Recommended actions:", "", *fixes, ""]

    out += [
        "## Method and limits",
        "",
        "- Each open port is scored 0-10 from an editable rule set (`rules.toml`) and, when the "
        "vulners script was used, the highest CVSS score it reported.",
        "- A host score is its highest finding plus a small bonus (up to 1.0) when several "
        "findings are Medium or above.",
        "- Bands: Critical 9+, High 7+, Medium 4+, Low 2+, Info below 2.",
        "- Scores express exposure risk. They are not proof that a vulnerability exists, and "
        "this scan does not test authentication or exploitability.",
        "",
    ]
    return "\n".join(out)


def to_json(meta: ScanMeta, results: list[HostResult]) -> str:
    findings = all_findings(results)
    payload = {
        "meta": asdict(meta),
        "summary": {band: _counts(findings).get(band, 0) for band in BANDS},
        "hosts": [
            {
                "address": r.host.address,
                "hostnames": r.host.hostnames,
                "os_guess": r.host.os_guess,
                "score": r.score,
                "band": r.band,
                "findings": [asdict(f) for f in r.findings],
            }
            for r in results
        ],
    }
    return json.dumps(payload, indent=2)
