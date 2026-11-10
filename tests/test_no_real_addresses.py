"""Guard against committing real network details: every IPv4 literal in the repo must be a
non-global address (documentation, private, loopback, shared or reserved)."""

import ipaddress
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
IPV4 = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")
SKIP_DIRS = {".git", ".venv", "__pycache__", ".pytest_cache", ".ruff_cache", "reports", "build"}
TEXT_SUFFIXES = {".py", ".md", ".toml", ".xml", ".yml", ".yaml", ".json", ".txt", ""}


def iter_files():
    for path in ROOT.rglob("*"):
        if path.is_file() and not (set(path.parts) & SKIP_DIRS) and path.suffix in TEXT_SUFFIXES:
            yield path


def allowed(addr: ipaddress.IPv4Address) -> bool:
    return not addr.is_global  # private, loopback, documentation, shared and reserved ranges


def test_only_safe_addresses_in_repo():
    offenders = []
    for path in iter_files():
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        for match in IPV4.findall(text):
            try:
                addr = ipaddress.IPv4Address(match)
            except ValueError:
                continue  # not an address, for example a four-part version string
            if not allowed(addr):
                offenders.append(f"{path.relative_to(ROOT)}: {match}")
    assert not offenders, "Non-private addresses found:\n" + "\n".join(offenders)
