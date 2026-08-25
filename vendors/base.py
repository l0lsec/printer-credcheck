#!/usr/bin/env python3
"""
Shared plumbing for printer vendor modules.

Every vendor module subclasses PrinterModule and implements, at minimum,
fingerprint() and attempt_login(). Address book export is optional and is
advertised through the supports_export flag.
"""
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse

import re

import requests


@dataclass
class Target:
    """A single scan target parsed from the hosts file."""

    raw: str
    scheme: str
    hostport: str
    base_url: str

    @classmethod
    def parse(cls, base: str, default_scheme: str) -> "Target":
        """base can be a hostname, ip, host:port, or a full URL."""
        parsed = urlparse(base if "://" in base else f"{default_scheme}://{base}")
        scheme = parsed.scheme or default_scheme
        hostport = parsed.netloc or parsed.path
        return cls(raw=base, scheme=scheme, hostport=hostport, base_url=f"{scheme}://{hostport}")

    @property
    def port(self) -> str:
        parsed = urlparse(self.base_url)
        if parsed.port:
            return str(parsed.port)
        return "443" if parsed.scheme == "https" else "80"


@dataclass
class Account:
    """A default account to test on a device."""

    label: str          # what gets reported, e.g. "admin" or "Administrator"
    username: str       # value sent as the login name / role selection
    password: str = ""  # blank for Ricoh defaults, "admin" for Sharp defaults
    can_export: bool = True
    note: str = ""

    def describe(self) -> str:
        return f"{self.label}:{self.password}" if self.password else f"{self.label}:<blank>"


@dataclass
class ScanContext:
    """Per-run settings handed to every vendor module."""

    timeout: int = 10
    export_timeout: int = 30
    verify_tls: bool = False
    verbose: bool = False
    output_dir: str = "."


@dataclass
class LoginResult:
    target: Target
    vendor: str
    account: Account
    outcome: str            # SUCCESS | FAIL | ERROR: <msg>
    status_code: int = 0
    detail: str = ""
    session: Dict = field(default_factory=dict)   # vendor-defined session material

    @property
    def ok(self) -> bool:
        return self.outcome == "SUCCESS"


class PrinterModule:
    """Base class for a vendor implementation."""

    name = "generic"                 # --vendor value
    display_name = "Generic printer"
    default_accounts: List[Account] = []
    supports_export = False
    export_note = ""

    # ---- required ------------------------------------------------------
    def fingerprint(self, target: Target, ctx: ScanContext) -> Tuple[bool, str]:
        """Return (is_this_vendor, human readable reason)."""
        raise NotImplementedError

    def attempt_login(self, target: Target, account: Account, ctx: ScanContext) -> LoginResult:
        raise NotImplementedError

    # ---- optional ------------------------------------------------------
    def export_address_book(self, result: LoginResult,
                            ctx: ScanContext) -> Tuple[str, str, Optional[str]]:
        """
        Return (hostport, result_message, saved_path). saved_path is None when
        nothing was written, so callers never have to parse the message.
        """
        return result.target.hostport, "ERROR: export not supported for this vendor", None

    def extract_contacts(self, text: str) -> Tuple[List[str], List[str]]:
        """Return (emails, names) parsed out of an exported address book."""
        return [], []

    def accounts(self, override: Optional[List[Account]] = None) -> List[Account]:
        return override if override else list(self.default_accounts)


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

BROWSER_UA = (
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36"
)

RULE = "=" * 80

# Nothing a printer web UI serves is anywhere near this large. The cap exists so
# that pointing the scanner at an arbitrary HTTP service - a file server, a video
# stream, a log tail - cannot exhaust memory or stall a worker indefinitely.
MAX_BODY_BYTES = 512 * 1024


def http_request(method: str, url: str, ctx: "ScanContext", *,
                 timeout: Optional[float] = None,
                 max_bytes: int = MAX_BODY_BYTES, **kwargs):
    """
    requests.request() with this run's timeout/TLS settings and a hard ceiling
    on how much of the response body we are willing to read.
    """
    kwargs.setdefault("verify", ctx.verify_tls)
    resp = requests.request(method, url, timeout=timeout or ctx.timeout, stream=True, **kwargs)
    try:
        body = bytearray()
        for chunk in resp.iter_content(8192):
            body.extend(chunk)
            if len(body) >= max_bytes:
                break
        resp._content = bytes(body[:max_bytes])
        resp._content_consumed = True
    finally:
        resp.close()
    return resp


def http_get(url: str, ctx: "ScanContext", **kwargs):
    return http_request("GET", url, ctx, **kwargs)


def http_post(url: str, ctx: "ScanContext", **kwargs):
    return http_request("POST", url, ctx, **kwargs)


def log_request(ctx: ScanContext, tag: str, hostport: str, method: str, url: str,
                headers: Optional[Dict] = None, cookies: Optional[Dict] = None,
                data: Optional[Dict] = None) -> None:
    if not ctx.verbose:
        return
    print(f"\n{RULE}\n[{tag}] {hostport}\n{RULE}")
    print(f"{method} {url}")
    for label, blob in (("Headers", headers), ("Cookies", cookies), ("Form Data", data)):
        if blob:
            print(f"\n{label}:")
            for k, v in blob.items():
                print(f"  {k}: {v}")
    print(RULE)


def log_response(ctx: ScanContext, tag: str, hostport: str, resp, body_limit: int = 800) -> None:
    if not ctx.verbose:
        return
    text = resp.text or ""
    print(f"\n{RULE}\n[{tag}] {hostport}\n{RULE}")
    print(f"Status: {resp.status_code}")
    print("\nResponse Headers:")
    for k, v in resp.headers.items():
        print(f"  {k}: {v}")
    print(f"\nResponse Body ({len(text)} bytes):")
    print(text[:body_limit])
    if len(text) > body_limit:
        print("... (truncated)")
    print(f"{RULE}\n")


_TITLE_RE = re.compile(r"<title>(.*?)</title>", re.S | re.I)


def page_title(text: str) -> str:
    m = _TITLE_RE.search(text or "")
    return m.group(1).strip() if m else ""


def parse_set_cookies(resp) -> Dict[str, str]:
    """
    Collect cookies from a response, preferring raw Set-Cookie headers so that
    duplicate names and reset values ("--") are handled the way the devices
    actually send them.
    """
    jar: Dict[str, str] = {}
    raw = resp.headers.get("Set-Cookie", "")
    if raw:
        for part in raw.split(", "):
            cookie_def = part.strip().split(";")[0].strip()
            if "=" not in cookie_def:
                continue
            name, value = (piece.strip() for piece in cookie_def.split("=", 1))
            if name not in jar or value != "--":
                jar[name] = value
    for name, value in resp.cookies.items():
        jar.setdefault(name, value)
    return jar
