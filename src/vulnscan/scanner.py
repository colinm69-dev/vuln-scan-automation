"""Run Nmap safely: argument list only, no shell, XML on stdout, bounded runtime."""

from __future__ import annotations

import shutil
import subprocess  # noqa: S404 - needed to call nmap, arguments are validated
from dataclasses import dataclass

PROFILES: dict[str, list[str]] = {
    # Fast check of the most common ports.
    "quick": ["-F", "-sV", "--version-light"],
    # Service detection on the top 1000 ports.
    "standard": ["-sV", "--top-ports", "1000"],
    # Every TCP port. Much slower.
    "thorough": ["-sV", "-p-"],
}


class ScanError(RuntimeError):
    pass


@dataclass
class ScanOptions:
    profile: str = "standard"
    timing: int = 3
    host_timeout: str = "5m"
    vulners: bool = False
    timeout_seconds: int = 3600


def build_command(targets: list[str], opts: ScanOptions) -> list[str]:
    if opts.profile not in PROFILES:
        raise ScanError(f"Unknown profile {opts.profile!r}; choose from {', '.join(PROFILES)}")
    if not 0 <= opts.timing <= 5:
        raise ScanError("Timing template must be between 0 and 5")
    cmd = ["nmap", *PROFILES[opts.profile], f"-T{opts.timing}", "--open"]
    cmd += ["--host-timeout", opts.host_timeout]
    if opts.vulners:
        # Needs the vulners NSE script and outbound internet access to its API.
        cmd += ["--script", "vulners"]
    cmd += ["-oX", "-", "--", *targets]
    return cmd


def run_nmap(targets: list[str], opts: ScanOptions) -> str:
    """Run Nmap and return its XML output."""
    if shutil.which("nmap") is None:
        raise ScanError("nmap was not found on PATH. Install it, or use --from-xml with a saved scan.")
    cmd = build_command(targets, opts)
    try:
        proc = subprocess.run(  # noqa: S603 - fixed argv list, validated targets, no shell
            cmd,
            capture_output=True,
            text=True,
            timeout=opts.timeout_seconds,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise ScanError(f"Scan exceeded {opts.timeout_seconds} seconds and was stopped") from exc
    if proc.returncode != 0:
        raise ScanError(f"nmap exited with status {proc.returncode}: {proc.stderr.strip()[:500]}")
    return proc.stdout
