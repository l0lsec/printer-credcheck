#!/usr/bin/env python3
import argparse
import concurrent.futures
import sys
from typing import List, Tuple
from urllib.parse import urlparse

import requests
from requests.exceptions import RequestException


def parse_hosts_file(path: str) -> List[str]:
    hosts: List[str] = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            hosts.append(stripped)
    return hosts


def build_target(base: str, default_scheme: str) -> Tuple[str, str, str]:
    """
    Returns (scheme, hostport, base_url) for the given base entry.
    base can be a hostname, ip, host:port, or full URL.
    """
    parsed = urlparse(base if "://" in base else f"{default_scheme}://{base}")
    scheme = parsed.scheme or default_scheme
    hostport = parsed.netloc or parsed.path
    base_url = f"{scheme}://{hostport}"
    return scheme, hostport, base_url


def attempt_login(
    base: str,
    default_scheme: str,
    timeout_seconds: int,
    verify_tls: bool,
) -> Tuple[str, str, int]:
    """
    Returns tuple: (host_display, result, status_code)
    result is one of: SUCCESS, FAIL, ERROR:<msg>
    """
    scheme, hostport, base_url = build_target(base, default_scheme)

    url = f"{base_url}/web/guest/en/websys/webArch/login.cgi"
    referer = f"{base_url}/web/guest/en/websys/webArch/authForm.cgi"

    headers = {
        "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:140.0) Gecko/20100101 Firefox/140.0",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
        "Accept-Encoding": "gzip, deflate, br",
        "Content-Type": "application/x-www-form-urlencoded",
        "Origin": base_url,
        "Referer": referer,
        "Upgrade-Insecure-Requests": "1",
    }

    # Default cookies from the provided request
    cookies = {
        "risessionid": "012450409054315",
        "cookieOnOffChecker": "on",
        "wimsesid": "--",
    }

    # Form body from the provided request
    data = {
        "wimToken": "1615404968",
        "userid_work": "",
        # YWRtaW4= is base64("admin")
        "userid": "YWRtaW4=",
        "password_work": "",
        "password": "",
        "open": "",
    }

    try:
        resp = requests.post(
            url,
            headers=headers,
            cookies=cookies,
            data=data,
            timeout=timeout_seconds,
            verify=verify_tls,
        )
        status = resp.status_code
        text = resp.text or ""
        if "Authentication has failed" in text:
            return hostport, "FAIL", status
        # Consider non-200 as an error, but still report content check result first
        if status != 200:
            return hostport, f"ERROR: HTTP {status}", status
        return hostport, "SUCCESS", status
    except RequestException as exc:
        return hostport, f"ERROR: {exc.__class__.__name__}: {exc}", 0


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Send default login POST requests to a list of hosts and report results."
        )
    )
    parser.add_argument(
        "hosts_file",
        help="Path to file containing hosts or URLs (one per line)",
    )
    parser.add_argument(
        "--scheme",
        default="https",
        choices=["http", "https"],
        help="Default URL scheme if hosts file lines omit a scheme (default: https)",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=10,
        help="Request timeout in seconds (default: 10)",
    )
    parser.add_argument(
        "--workers",
        type=int,
        default=10,
        help="Number of concurrent workers (default: 10)",
    )
    parser.add_argument(
        "--verify",
        action="store_true",
        help="Verify TLS certificates (default: disabled)",
    )

    args = parser.parse_args()

    if not args.verify:
        # Suppress only the specific InsecureRequestWarning when verify=False
        try:
            from urllib3.exceptions import InsecureRequestWarning
            import urllib3

            urllib3.disable_warnings(InsecureRequestWarning)
        except Exception:
            pass

    hosts = parse_hosts_file(args.hosts_file)
    if not hosts:
        print("No hosts found in file.")
        return 1

    results: List[Tuple[str, str, int]] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as executor:
        futures = [
            executor.submit(
                attempt_login, host, args.scheme, args.timeout, args.verify
            )
            for host in hosts
        ]
        for fut in concurrent.futures.as_completed(futures):
            results.append(fut.result())

    successes = 0
    failures = 0
    errors = 0

    for host, outcome, status_code in sorted(results, key=lambda r: r[0]):
        print(f"{host}\t{outcome}\tstatus={status_code}")
        if outcome == "SUCCESS":
            successes += 1
        elif outcome == "FAIL":
            failures += 1
        else:
            errors += 1

    print(
        f"\nTotal: {len(results)}\tSUCCESS: {successes}\tFAIL: {failures}\tERROR: {errors}"
    )
    return 0 if successes or failures else 1


if __name__ == "__main__":
    sys.exit(main())


