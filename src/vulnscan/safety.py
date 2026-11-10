"""Guard rails: only scan address ranges you are allowed to, and never pass odd input to Nmap."""

from __future__ import annotations

import ipaddress

DEFAULT_MAX_HOSTS = 1024

Network = ipaddress.IPv4Network | ipaddress.IPv6Network


class TargetError(ValueError):
    """Raised when a scan target is rejected."""


def parse_targets(raw: list[str]) -> list[Network]:
    """Accept only literal IPs or CIDR ranges. Hostnames and Nmap options are rejected."""
    networks: list[Network] = []
    for item in raw:
        text = item.strip()
        if not text or text.startswith("-"):
            raise TargetError(f"Invalid target: {item!r}")
        try:
            networks.append(ipaddress.ip_network(text, strict=False))
        except ValueError as exc:
            raise TargetError(
                f"Target {item!r} is not an IP address or CIDR range (hostnames are not accepted)"
            ) from exc
    if not networks:
        raise TargetError("No targets given")
    return networks


def is_lab_range(net: Network) -> bool:
    """Private, loopback, link-local and documentation ranges count as lab space."""
    return bool(net.is_private or net.is_loopback or net.is_link_local)


def validate(
    networks: list[Network],
    *,
    allow_public: bool = False,
    max_hosts: int = DEFAULT_MAX_HOSTS,
) -> None:
    total = sum(n.num_addresses for n in networks)
    if total > max_hosts:
        raise TargetError(
            f"Targets cover {total} addresses, above the limit of {max_hosts}. "
            "Raise --max-hosts if this is intentional."
        )
    if not allow_public:
        public = [str(n) for n in networks if not is_lab_range(n)]
        if public:
            raise TargetError(
                "Refusing to scan non-private ranges: "
                + ", ".join(public)
                + ". Use --allow-public only for networks you own or have written permission to test."
            )
