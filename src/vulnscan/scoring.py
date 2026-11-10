"""Turn parsed hosts into prioritised findings using editable rules plus optional CVE data."""

from __future__ import annotations

import re
import tomllib
from importlib import resources
from pathlib import Path
from typing import Any

from vulnscan.models import Finding, Host, HostResult, Port

BANDS = ["Critical", "High", "Medium", "Low", "Info"]
CVE_LINE = re.compile(r"(CVE-\d{4}-\d{4,7})\s+(\d{1,2}(?:\.\d)?)")
INFO_SCORE = 1.0
BREADTH_BONUS_MAX = 1.0


def band_for(score: float) -> str:
    if score >= 9.0:
        return "Critical"
    if score >= 7.0:
        return "High"
    if score >= 4.0:
        return "Medium"
    if score >= 2.0:
        return "Low"
    return "Info"


def load_rules(path: str | Path | None = None) -> dict[str, Any]:
    if path is None:
        data = resources.files("vulnscan").joinpath("rules.toml").read_bytes()
    else:
        data = Path(path).read_bytes()
    return tomllib.loads(data.decode("utf-8"))


def _rule_matches(rule: dict[str, Any], port: Port) -> bool:
    protocols = rule.get("protocols", ["tcp"])
    if port.protocol not in protocols:
        return False
    if rule.get("cleartext") and port.tunnel == "ssl":
        return False  # the service is wrapped in TLS, so the clear-text concern does not apply
    return port.number in rule.get("ports", []) or port.service in rule.get("services", [])


def _cves_from_scripts(port: Port) -> list[tuple[str, float]]:
    found: dict[str, float] = {}
    for script in port.scripts:
        for cve, cvss in CVE_LINE.findall(script.output):
            value = float(cvss)
            if 0.0 <= value <= 10.0:
                found[cve] = max(found.get(cve, 0.0), value)
    return sorted(found.items(), key=lambda kv: kv[1], reverse=True)


def assess_port(host: Host, port: Port, rules: dict[str, Any]) -> Finding:
    score = INFO_SCORE
    scored_reasons: list[tuple[float, str]] = []
    remediation: list[str] = []

    def add(s: float, why: str, fixes: list[str]) -> None:
        nonlocal score
        score = max(score, s)
        scored_reasons.append((s, why))
        for fix in fixes:
            if fix not in remediation:
                remediation.append(fix)

    for rule in rules.get("rule", []):
        if _rule_matches(rule, port):
            add(float(rule["score"]), f"{rule['title']}: {rule['rationale']}", rule.get("remediation", []))

    for eol in rules.get("eol", []):
        if port.product == eol["product"] and any(
            port.version.startswith(p) for p in eol["version_prefixes"]
        ):
            add(float(eol["score"]), f"{eol['rationale']} (found {port.banner})", eol.get("remediation", []))

    cves = _cves_from_scripts(port)
    if cves:
        top = cves[0][1]
        add(
            top,
            f"{len(cves)} CVE(s) reported by the vulners script, highest CVSS {top}.",
            ["Apply vendor patches for the listed CVEs, or upgrade the affected software."],
        )

    # Highest-scoring reason first, so reports lead with what actually drives the priority.
    scored_reasons.sort(key=lambda sr: -sr[0])
    reasons = [why for _, why in scored_reasons]
    if not reasons:
        reasons.append("Open service with no specific risk rule. Confirm it is expected.")

    return Finding(
        host=host.address,
        port=port.number,
        protocol=port.protocol,
        service=port.service or "unknown",
        banner=port.banner,
        score=round(score, 1),
        band=band_for(score),
        reasons=reasons,
        remediation=remediation,
        cves=[c for c, _ in cves],
    )


def assess(hosts: list[Host], rules: dict[str, Any]) -> list[HostResult]:
    results: list[HostResult] = []
    for host in hosts:
        findings = [assess_port(host, p, rules) for p in host.ports]
        findings.sort(key=lambda f: (-f.score, f.port))
        if findings:
            top = findings[0].score
            serious = sum(1 for f in findings if f.score >= 4.0)
            score = min(10.0, top + min(BREADTH_BONUS_MAX, 0.1 * max(0, serious - 1)))
        else:
            score = 0.0
        results.append(HostResult(host=host, score=round(score, 1), band=band_for(score), findings=findings))
    results.sort(key=lambda r: (-r.score, r.host.address))
    return results


def all_findings(results: list[HostResult]) -> list[Finding]:
    findings = [f for r in results for f in r.findings]
    findings.sort(key=lambda f: (-f.score, f.host, f.port))
    return findings


def exceeds(results: list[HostResult], threshold_band: str) -> bool:
    """True if any finding is at or above the given band (used for CI exit codes)."""
    limit = BANDS.index(threshold_band)
    return any(BANDS.index(f.band) <= limit for r in results for f in r.findings)
