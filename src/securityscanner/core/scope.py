"""Deny-by-default scope, exact hosts only, DNS pinning and revalidation."""

import ipaddress
import re
import subprocess
import sys
from collections.abc import Callable

MAX_TARGETS = 16
MAX_ADDRESSES = 16
Resolver = Callable[[str], set[str]]


class ScopeError(ValueError):
    """A destination is invalid or outside the approved scope."""


def canonical(value: str) -> str:
    if not value or value != value.strip() or len(value) > 253:
        raise ScopeError("Use an exact IP or ASCII hostname, without spaces or URLs.")
    try:
        addr = ipaddress.ip_address(value)
    except ValueError:
        host = value.lower().removesuffix(".")
        if not re.fullmatch(r"[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?", host):
            raise ScopeError(
                "Ranges, CIDRs, URLs, wildcards and command options are prohibited."
            ) from None
        if all(c in "0123456789.-" for c in host):
            raise ScopeError("Ambiguous numeric host: use a canonical IP address.") from None
        if any(
            not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", x) for x in host.split(".")
        ):
            raise ScopeError("Invalid hostname label.") from None
        return host
    if "%" in value or addr.is_multicast or addr.is_unspecified or addr.is_link_local:
        raise ScopeError(
            "Unspecified, multicast, link-local and zone-qualified IPs are prohibited."
        )
    if addr == ipaddress.ip_address("255.255.255.255"):
        raise ScopeError("Broadcast destinations are prohibited.")
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped:
        raise ScopeError("Use the IPv4 address directly, not an IPv4-mapped IPv6 address.")
    return str(addr)


def resolve(host: str) -> set[str]:
    """Bound OS DNS resolution using a killable subprocess, never a lingering thread."""
    try:
        return {str(ipaddress.ip_address(host))}
    except ValueError:
        pass
    code = (
        "import socket,sys; "
        "print('\\n'.join(sorted({x[4][0] for x in "
        "socket.getaddrinfo(sys.argv[1],None,type=socket.SOCK_STREAM)})))"
    )
    try:
        result = subprocess.run(
            [sys.executable, "-I", "-c", code, host],
            capture_output=True,
            text=True,
            timeout=5,
            check=True,
        )
    except (subprocess.SubprocessError, OSError) as exc:
        raise ScopeError(f"DNS resolution failed for {host}; check DNS and retry.") from exc
    return set(result.stdout.splitlines())


class Scope:
    def __init__(self, allowed: list[str], authorized: bool, resolver: Resolver = resolve):
        if not authorized:
            raise ScopeError("Active scans require --authorized and an explicit --allow list.")
        if not allowed or len(allowed) > MAX_TARGETS:
            raise ScopeError(f"Provide between 1 and {MAX_TARGETS} explicit allowed hosts.")
        self.allowed = {canonical(x) for x in allowed}
        self.resolver = resolver
        self.pinned: dict[str, set[str]] = {}

    def addresses(self, host: str) -> set[str]:
        result = self.resolver(host)
        if not result or len(result) > MAX_ADDRESSES:
            raise ScopeError("DNS returned no addresses or too many addresses.")
        addresses = {canonical(x) for x in result}
        for address in addresses:
            try:
                ipaddress.ip_address(address)
            except ValueError as exc:
                raise ScopeError("Resolver returned a non-IP destination.") from exc
        return addresses

    def approve(self, targets: list[str]) -> dict[str, list[str]]:
        if not targets or len(targets) > MAX_TARGETS:
            raise ScopeError(f"Provide between 1 and {MAX_TARGETS} individual targets.")
        names = {canonical(x) for x in targets}
        if not names <= self.allowed:
            raise ScopeError("Target is outside the exact allow list; no scan was started.")
        # All syntax/scope checks precede DNS. All DNS checks precede target connections.
        pins = {name: self.addresses(name) for name in sorted(names)}
        if len(set().union(*pins.values())) > MAX_ADDRESSES:
            raise ScopeError(f"At most {MAX_ADDRESSES} resolved IPs are permitted per scan.")
        self.pinned = pins
        return {name: sorted(addresses) for name, addresses in pins.items()}

    def revalidate(self, host: str) -> None:
        if host not in self.pinned or self.addresses(host) != self.pinned[host]:
            raise ScopeError("DNS changed after approval; scan stopped. Review scope and retry.")
