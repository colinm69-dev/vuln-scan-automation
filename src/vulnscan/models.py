"""Plain data containers shared by the parser, scorer and report writers."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class Script:
    id: str
    output: str


@dataclass
class Port:
    number: int
    protocol: str
    state: str
    service: str = ""
    product: str = ""
    version: str = ""
    extrainfo: str = ""
    tunnel: str = ""
    scripts: list[Script] = field(default_factory=list)

    @property
    def banner(self) -> str:
        parts = [self.product, self.version, f"({self.extrainfo})" if self.extrainfo else ""]
        return " ".join(p for p in parts if p).strip()


@dataclass
class Host:
    address: str
    hostnames: list[str] = field(default_factory=list)
    state: str = "up"
    os_guess: str = ""
    ports: list[Port] = field(default_factory=list)


@dataclass
class ScanMeta:
    nmap_version: str = ""
    args: str = ""
    start: str = ""
    elapsed: str = ""
    hosts_up: int = 0
    hosts_down: int = 0


@dataclass
class Finding:
    host: str
    port: int
    protocol: str
    service: str
    banner: str
    score: float
    band: str
    reasons: list[str] = field(default_factory=list)
    remediation: list[str] = field(default_factory=list)
    cves: list[str] = field(default_factory=list)


@dataclass
class HostResult:
    host: Host
    score: float
    band: str
    findings: list[Finding]
