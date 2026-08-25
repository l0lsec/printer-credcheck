#!/usr/bin/env python3
"""
Target expansion and HTTP service discovery.

Turns whatever the user typed - a CIDR, an address range, a bare host, a
host:port, a URL, or a file containing any mix of those - into a concrete list
of HTTP endpoints worth fingerprinting.

Ports are probed with a plain TCP connect followed by a TLS handshake attempt,
which is both far cheaper than an HTTP request and tells us whether to speak
http or https to the port. Anything that does not answer is dropped before the
vendor modules ever see it.
"""
import ipaddress
import os
import re
import socket
import ssl
from typing import List, Optional, Sequence, Set, Tuple

from vendors.base import Target

DEFAULT_PORTS = "80,443,8080,8443"

# Ports we assume are TLS / cleartext when the handshake probe is skipped.
ASSUME_HTTPS = {443, 4443, 8443, 9443, 10443}
ASSUME_HTTP = {80, 280, 631, 8000, 8008, 8080, 8081, 8888}


def scheme_for_port(port: int, default_scheme: str) -> str:
    """Best guess at how to speak to a port before the TLS probe runs."""
    if port in ASSUME_HTTPS:
        return "https"
    if port in ASSUME_HTTP:
        return "http"
    return default_scheme

_RANGE_RE = re.compile(r"^([0-9.]+)\s*-\s*([0-9.]+)$")
_HOSTPORT_RE = re.compile(r"^(?P<host>\[[0-9a-fA-F:]+\]|[^:/\s]+):(?P<port>\d{1,5})$")

# A /16 sweep across four ports is 260k endpoints - almost always a typo.
MAX_EXPANSION = 65536


class TargetSpecError(ValueError):
    pass


def parse_ports(spec: str) -> List[int]:
    """'80,443,8000-8010' -> [80, 443, 8000, ..., 8010]"""
    ports: List[int] = []
    seen: Set[int] = set()
    for chunk in str(spec).split(","):
        chunk = chunk.strip()
        if not chunk:
            continue
        if "-" in chunk:
            low, _, high = chunk.partition("-")
            try:
                start, end = int(low), int(high)
            except ValueError:
                raise TargetSpecError(f"bad port range '{chunk}'")
            if start > end:
                start, end = end, start
            candidates = range(start, end + 1)
        else:
            try:
                candidates = [int(chunk)]
            except ValueError:
                raise TargetSpecError(f"bad port '{chunk}'")
        for port in candidates:
            if not 1 <= port <= 65535:
                raise TargetSpecError(f"port out of range: {port}")
            if port not in seen:
                seen.add(port)
                ports.append(port)
    if not ports:
        raise TargetSpecError("no ports given")
    return ports


def _hosts_from_range(spec: str) -> Optional[List[str]]:
    """'10.0.0.1-10.0.0.50' or '10.0.0.1-50' -> list of addresses."""
    m = _RANGE_RE.match(spec)
    if not m:
        return None
    start_raw, end_raw = m.group(1), m.group(2)
    try:
        start = ipaddress.ip_address(start_raw)
    except ValueError:
        return None
    if "." not in end_raw:
        # shorthand final octet: 10.0.0.1-50
        prefix = start_raw.rsplit(".", 1)[0]
        end_raw = f"{prefix}.{end_raw}"
    try:
        end = ipaddress.ip_address(end_raw)
    except ValueError:
        return None
    if int(end) < int(start):
        start, end = end, start
    return [str(ipaddress.ip_address(i)) for i in range(int(start), int(end) + 1)]


def read_spec_file(path: str) -> List[str]:
    specs: List[str] = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            specs.append(stripped)
    return specs


def expand(specs: Sequence[str], ports: Sequence[int], default_scheme: str) -> List[Target]:
    """
    Expand target specs into concrete Targets.

    A spec that pins a scheme or port (a URL, or host:port) is taken literally
    and is NOT multiplied across the port list. Everything else - bare hosts,
    CIDRs, ranges - is expanded across every port.
    """
    targets: List[Target] = []
    seen: Set[str] = set()

    def add(base: str) -> None:
        target = Target.parse(base, default_scheme)
        if target.base_url not in seen:
            seen.add(target.base_url)
            targets.append(target)

    for spec in specs:
        spec = spec.strip()
        if not spec:
            continue

        # A file of targets (possibly containing more files).
        if os.path.isfile(spec):
            for nested in expand(read_spec_file(spec), ports, default_scheme):
                if nested.base_url not in seen:
                    seen.add(nested.base_url)
                    targets.append(nested)
            continue

        # Explicit URL - honour it exactly as written.
        if "://" in spec:
            add(spec)
            continue

        # Explicit host:port - honour the port, infer the scheme.
        hostport = _HOSTPORT_RE.match(spec)
        if hostport:
            port = int(hostport.group("port"))
            add(f"{scheme_for_port(port, default_scheme)}://{spec}")
            continue

        # CIDR block.
        hosts: List[str]
        if "/" in spec:
            try:
                network = ipaddress.ip_network(spec, strict=False)
            except ValueError:
                raise TargetSpecError(f"not a valid CIDR block: '{spec}'")
            hosts = [str(h) for h in network.hosts()] or [str(network.network_address)]
        else:
            ranged = _hosts_from_range(spec)
            hosts = ranged if ranged is not None else [spec]

        if len(hosts) * len(ports) > MAX_EXPANSION:
            raise TargetSpecError(
                f"'{spec}' expands to {len(hosts) * len(ports)} endpoints "
                f"(limit {MAX_EXPANSION}); narrow the range or the --ports list"
            )

        for host in hosts:
            for port in ports:
                add(f"{scheme_for_port(port, default_scheme)}://{host}:{port}")

    return targets


def probe(target: Target, timeout: float) -> Tuple[bool, Optional[str]]:
    """
    TCP connect, then try a TLS handshake to work out how to talk to the port.

    Returns (is_open, scheme) where scheme is 'https' or 'http'. A port that is
    open but not TLS comes back as 'http'; a closed or filtered port comes back
    as (False, None).
    """
    parsed_host = target.hostport.rsplit(":", 1)[0] if ":" in target.hostport else target.hostport
    parsed_host = parsed_host.strip("[]")
    try:
        port = int(target.port)
    except (TypeError, ValueError):
        return False, None

    try:
        sock = socket.create_connection((parsed_host, port), timeout=timeout)
    except (OSError, ValueError):
        return False, None

    try:
        sock.settimeout(timeout)
        tls_context = ssl.create_default_context()
        tls_context.check_hostname = False
        tls_context.verify_mode = ssl.CERT_NONE
        try:
            wrapped = tls_context.wrap_socket(sock, server_hostname=parsed_host)
        except Exception:
            # Open, but it did not complete a TLS handshake - treat it as cleartext.
            return True, "http"
        try:
            wrapped.close()
        except Exception:
            pass
        return True, "https"
    finally:
        try:
            sock.close()
        except Exception:
            pass


def with_scheme(target: Target, scheme: str) -> Target:
    """Return the same endpoint re-pointed at the scheme the probe discovered."""
    if scheme == target.scheme:
        return target
    return Target.parse(f"{scheme}://{target.hostport}", scheme)
