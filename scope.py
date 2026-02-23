"""
scope.py — Scope enforcement for every tool call.

All tool handlers must call ScopeEnforcer.validate() before executing
any network action. A ScopeViolation is returned as an error JSON by
the dispatcher — it never crashes the agent loop.
"""
from __future__ import annotations

import ipaddress
import re
from typing import List, Union
from urllib.parse import urlparse


class ScopeViolation(Exception):
    """Raised when a target is outside the declared scope."""


class ScopeEnforcer:
    """
    Parses ``allowed_scope`` (a list of strings) into:
      - ``ipaddress.IPv4Network`` / ``ipaddress.IPv6Network`` objects
      - plain domain strings (matched by equality or suffix)

    ``validate(target)`` accepts:
      - bare IP addresses  (e.g. "192.168.1.5")
      - CIDR-less IP strings
      - URLs             (e.g. "http://example.com/path")
      - hostnames / domain names
    """

    def __init__(self, allowed_scope: List[str]) -> None:
        self._networks: List[Union[ipaddress.IPv4Network, ipaddress.IPv6Network]] = []
        self._domains: List[str] = []

        for entry in allowed_scope:
            entry = entry.strip()
            if not entry:
                continue
            try:
                self._networks.append(ipaddress.ip_network(entry, strict=False))
            except ValueError:
                # Treat as a domain / hostname string
                self._domains.append(entry.lower().lstrip("*."))

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def validate(self, target: str) -> None:
        """
        Check *target* against the configured scope.

        Raises ``ScopeViolation`` if the host is not within scope.
        If ``allowed_scope`` is empty the enforcer allows everything
        (the operator must set scope before the agent runs — main.py
        ensures at least the primary target is always added).
        """
        if not self._networks and not self._domains:
            # No scope configured — allow all (main.py should prevent this)
            return

        host = self._extract_host(target)
        if not host:
            raise ScopeViolation(f"Could not parse a host from target: {target!r}")

        # Try as IP first
        try:
            addr = ipaddress.ip_address(host)
            for net in self._networks:
                if addr in net:
                    return
            raise ScopeViolation(
                f"IP {host} is not within any allowed network: "
                f"{[str(n) for n in self._networks]}"
            )
        except ValueError:
            pass  # Not a bare IP — treat as domain

        # Domain matching: exact match or subdomain suffix
        host_lower = host.lower()
        for domain in self._domains:
            if host_lower == domain or host_lower.endswith("." + domain):
                return

        raise ScopeViolation(
            f"Host {host!r} is not in allowed domains: {self._domains}"
        )

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _extract_host(target: str) -> str:
        """
        Return the bare hostname / IP from a target string.
        Handles: raw IPs, hostnames, and URLs (http://…, https://…).
        """
        target = target.strip()
        if re.match(r"^https?://", target, re.IGNORECASE):
            parsed = urlparse(target)
            host = parsed.hostname or ""
            return host
        # Could be "host:port" — strip the port
        if ":" in target and not target.startswith("["):
            # Not an IPv6 address; strip port
            parts = target.rsplit(":", 1)
            try:
                int(parts[-1])
                return parts[0]
            except ValueError:
                pass
        return target
