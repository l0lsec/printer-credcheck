#!/usr/bin/env python3
"""
Printer default credential checker.

Vendor-agnostic front end: each supported printer family lives in vendors/ and
implements fingerprinting, a default credential test, and - where the request
flow has been captured - address book export.

Point it at a host, a file of hosts, or a whole subnet. Every endpoint is port
probed and fingerprinted before a single credential is sent, so non-printer HTTP
services are identified and skipped rather than logged into.

Supported today: Ricoh (Web Image Monitor), Sharp (MX/BP series MFPs).
"""
import argparse
import concurrent.futures
import os
import sys
from typing import Dict, List, Optional, Tuple

import discovery
import vendors
from vendors.base import Account, LoginResult, PrinterModule, ScanContext, Target, VulnFinding


def parse_accounts(spec: str) -> List[Account]:
    """--accounts admin:,supervisor: or --accounts Administrator:admin"""
    accounts: List[Account] = []
    for chunk in spec.split(","):
        chunk = chunk.strip()
        if not chunk:
            continue
        username, _, password = chunk.partition(":")
        accounts.append(Account(label=username, username=username, password=password))
    return accounts


def probe_endpoint(target: Target, timeout: float) -> Tuple[Target, bool, Optional[str]]:
    try:
        is_open, scheme = discovery.probe(target, timeout)
    except Exception:
        return target, False, None
    return target, is_open, scheme


def identify(target: Target, modules: List[PrinterModule],
             ctx: ScanContext) -> Tuple[Target, Optional[PrinterModule], str]:
    """
    Run each enabled module's fingerprint until one claims the host.

    A module that raises on a weird endpoint must not take the scan down with
    it, so every fingerprint call is contained.
    """
    reasons: List[str] = []
    for module in modules:
        try:
            matched, reason = module.fingerprint(target, ctx)
        except Exception as exc:
            reasons.append(f"{module.name}: {exc.__class__.__name__}")
            continue
        if matched:
            return target, module, reason
        reasons.append(f"{module.name}: {reason}")
    return target, None, "; ".join(reasons)


def usernames_from_emails(emails) -> List[str]:
    """
    Derive login names from harvested addresses: the local part of each mailbox,
    lowercased and de-duplicated. jane.doe@corp.example -> jane.doe
    """
    usernames = set()
    for email in emails:
        if "@" not in email:
            continue
        local = email.split("@", 1)[0].strip().lower()
        if local:
            usernames.add(local)
    return sorted(usernames)


def read_export(path: str) -> str:
    try:
        with open(path, "r", encoding="utf-8") as f:
            return f.read()
    except OSError as exc:
        print(f"Warning: Failed to read {path}: {exc}")
        return ""


def write_lines(path: str, values: List[str], label: str) -> None:
    if not values:
        return
    with open(path, "w", encoding="utf-8") as f:
        for value in values:
            f.write(f"{value}\n")
    print(f"Extracted {len(values)} unique {label}(s) to {path}")


# The reporting import format shared by both findings files:
#   AssetName  URI  Protocol  Port  Output
# AssetName must line up with an existing EngagementAsset; we use the same
# host:port the successful-logins file uses so the two line up.
FINDINGS_COLUMNS = ("AssetName", "URI", "Protocol", "Port", "Output")


def _one_line(value: str, delimiter: str) -> str:
    """Keep a field on one line and clear of the column delimiter."""
    return " ".join(str(value).replace(delimiter, " ").split())


def write_findings(path: str, rows: List[Tuple[str, str, str, str, str]],
                   delimiter: str, label: str) -> None:
    """Write findings rows in the TAB/backtick delimited EngagementAsset format."""
    if not rows:
        return
    with open(path, "w", encoding="utf-8") as f:
        f.write("# Format: " + delimiter.join(FINDINGS_COLUMNS) + "\n")
        for asset, uri, protocol, port, output in rows:
            cols = [_one_line(c, delimiter) for c in (asset, uri, protocol, port, output)]
            f.write(delimiter.join(cols) + "\n")
    print(f"{label}: {len(rows)} finding(s) written to {path}")


def summarize_folders(target: Target,
                      folders: List[Dict[str, str]]) -> Tuple[List[str], Tuple[str, str, str, str, str]]:
    """
    Turn a device's scan-to-folder destinations into console detail lines and a
    single findings row summarising them. Passwords are reported as stored or
    not; their values live only in the exported CSV on disk.
    """
    detail_lines: List[str] = []
    parts: List[str] = []
    for folder in folders:
        host = folder.get("host") or ""
        path = folder.get("path") or ""
        if host and path:
            location = f"{host.rstrip('/')}/{path.lstrip('/')}"
        else:
            location = host or path or "(destination set)"
        user = folder.get("username") or "n/a"
        stored = ", password stored" if folder.get("has_password") == "yes" else ""
        name = folder.get("name") or "(unnamed)"
        protocol = folder.get("protocol") or "folder"
        detail_lines.append(f"[{protocol}] {name}: {location} (user: {user}{stored})")
        parts.append(f"[{protocol}] {location} (user: {user}{stored})")

    shown = "; ".join(parts[:6])
    if len(parts) > 6:
        shown += f"; +{len(parts) - 6} more"
    output = (
        f"Address book contains {len(folders)} scan-to-folder destination(s) storing "
        f"reusable credentials for internal shares: {shown}. Review whether each is "
        f"required and rotate the service accounts."
    )
    row = (target.hostport, target.hostport, "tcp", target.port, output)
    return detail_lines, row


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Test printers for default credentials and export address books.",
        epilog="Targets may be hosts, host:port, URLs, CIDR blocks (10.0.0.0/24), "
               "ranges (10.0.0.1-50), or files containing any mix of those.",
    )
    parser.add_argument("targets", nargs="*",
                        help="Hosts, CIDR blocks, ranges, URLs, or files of targets")
    parser.add_argument("--vendor", default="auto",
                        help="Comma separated vendors to test, or 'auto' to fingerprint "
                             f"each host (known: {', '.join(vendors.names())})")
    parser.add_argument("--list-vendors", action="store_true",
                        help="List supported printer vendors and their default accounts, then exit")
    parser.add_argument("--accounts",
                        help="Override the accounts tested, as user:pass pairs "
                             "(e.g. 'admin:,supervisor:' or 'Administrator:admin')")
    parser.add_argument("--ports", default=discovery.DEFAULT_PORTS,
                        help=f"Ports to sweep on bare hosts and subnets, comma separated, "
                             f"ranges allowed (default: {discovery.DEFAULT_PORTS})")
    parser.add_argument("--connect-timeout", type=float, default=2.0,
                        help="TCP connect timeout in seconds during the port sweep (default: 2.0)")
    parser.add_argument("--no-port-scan", action="store_true",
                        help="Skip the TCP port sweep and fingerprint every expanded endpoint")
    parser.add_argument("--scan-workers", type=int, default=100,
                        help="Concurrent workers for the port sweep (default: 100)")
    parser.add_argument("--show-skipped", action="store_true",
                        help="Print a line for every endpoint that is not a supported printer")
    parser.add_argument("--scheme", default="https", choices=["http", "https"],
                        help="Scheme for ports with no well-known default (default: https)")
    parser.add_argument("--timeout", type=int, default=10,
                        help="HTTP request timeout in seconds (default: 10)")
    parser.add_argument("--workers", type=int, default=10,
                        help="Number of concurrent workers for HTTP stages (default: 10)")
    parser.add_argument("--verify", action="store_true",
                        help="Verify TLS certificates (default: disabled)")
    parser.add_argument("--no-export", action="store_true",
                        help="Skip the address book harvest stage. By default the tool exports "
                             "address books from every device whose default credentials worked "
                             "and falls back to reading whatever the device exposes without a "
                             "login (Sharp only), then writes emails, names, and usernames.")
    parser.add_argument("--output-dir", default=".",
                        help="Output directory for exported address books (default: current directory)")
    parser.add_argument("--export-timeout", type=int, default=30,
                        help="Timeout in seconds for address book export requests (default: 30)")
    parser.add_argument("--verbose", action="store_true",
                        help="Enable verbose output for debugging")
    parser.add_argument("--success-file", default="successful_logins.txt",
                        help="Output file for successful logins, backtick delimited "
                             "(default: successful_logins.txt)")
    parser.add_argument("--findings-file", default="default_credentials.txt",
                        help="Output file for default-credential findings, in the "
                             "AssetName/URI/Protocol/Port/Output report format "
                             "(default: default_credentials.txt)")
    parser.add_argument("--folder-findings-file", default="scan_to_folder.txt",
                        help="Output file for scan-to-folder address book findings, same "
                             "report format (default: scan_to_folder.txt)")
    parser.add_argument("--priority-file", default="priority_followup.txt",
                        help="Output file for priority findings: devices with both a service "
                             "account default and scan-to-folder entries (default: priority_followup.txt)")
    parser.add_argument("--vulns-file", default="vulnerabilities.txt",
                        help="Output file for vendor-published vulnerability findings, same "
                             "report format (default: vulnerabilities.txt)")
    parser.add_argument("--no-vuln-checks", action="store_true",
                        help="Skip the published-vulnerability stage (Sharp: pre-auth LFI "
                             "probe against /installed_emanual_down.html plus advisory-only "
                             "findings for CVE-2024-28038, CVE-2024-34162, CVE-2024-36248, "
                             "hardcoded AWS keys, and CVE-2022-45796)")
    parser.add_argument("--findings-delimiter", choices=["backtick", "tab"], default="backtick",
                        help="Field delimiter for the findings files (default: backtick)")

    args = parser.parse_args()

    if args.list_vendors:
        for module in vendors.MODULES:
            export = "yes" if module.supports_export else "no"
            print(f"{module.name:<8} {module.display_name}  (address book export: {export})")
            for account in module.default_accounts:
                print(f"           - {account.describe():<24} {account.note}")
            if module.export_note:
                print(f"           note: {module.export_note}")
        return 0

    if not args.targets:
        parser.error("at least one target is required (or use --list-vendors)")

    try:
        if args.vendor.lower() == "auto":
            modules = list(vendors.MODULES)
        else:
            modules = [vendors.get(name.strip()) for name in args.vendor.split(",") if name.strip()]
    except KeyError as exc:
        parser.error(str(exc))

    account_override = parse_accounts(args.accounts) if args.accounts else None

    if not args.verify:
        try:
            import urllib3
            from urllib3.exceptions import InsecureRequestWarning

            urllib3.disable_warnings(InsecureRequestWarning)
        except Exception:
            pass

    try:
        ports = discovery.parse_ports(args.ports)
        endpoints = discovery.expand(args.targets, ports, args.scheme)
    except discovery.TargetSpecError as exc:
        parser.error(str(exc))
    except OSError as exc:
        parser.error(f"could not read target file: {exc}")

    if not endpoints:
        print("No targets found.")
        return 1

    if not args.no_export:
        os.makedirs(args.output_dir, exist_ok=True)

    ctx = ScanContext(
        timeout=args.timeout,
        export_timeout=args.export_timeout,
        verify_tls=args.verify,
        verbose=args.verbose,
        output_dir=args.output_dir,
    )

    # ---- Stage 1: find HTTP services -----------------------------------
    print(f"Step 1: {len(endpoints)} endpoint(s) from {len(args.targets)} target spec(s) "
          f"across port(s) {','.join(str(p) for p in ports)}")

    if args.no_port_scan:
        live = endpoints
        print("Port sweep skipped (--no-port-scan)")
    else:
        print(f"Port sweep: {args.scan_workers} workers, {args.connect_timeout}s connect timeout")
        live = []
        completed = 0
        step = max(1, len(endpoints) // 10)
        with concurrent.futures.ThreadPoolExecutor(max_workers=args.scan_workers) as executor:
            futures = [executor.submit(probe_endpoint, t, args.connect_timeout) for t in endpoints]
            for future in concurrent.futures.as_completed(futures):
                target, is_open, scheme = future.result()
                completed += 1
                if is_open and scheme:
                    live.append(discovery.with_scheme(target, scheme))
                if len(endpoints) > 50 and completed % step == 0:
                    print(f"  ... probed {completed}/{len(endpoints)}, {len(live)} open")
        print(f"Found {len(live)} listening HTTP service(s) out of {len(endpoints)} endpoint(s)")

    if not live:
        print("\nNo listening HTTP services found. Exiting.")
        return 1

    # ---- Stage 2: work out which of them are printers ------------------
    print(f"\n{'-' * 80}")
    print(f"Step 2: Fingerprinting {len(live)} service(s) against: "
          f"{', '.join(m.name for m in modules)}")
    print(f"Workers: {args.workers}")
    print("-" * 80)

    identified: List[Tuple[Target, PrinterModule]] = []
    skipped = 0
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as executor:
        futures = [executor.submit(identify, target, modules, ctx) for target in live]
        for future in concurrent.futures.as_completed(futures):
            try:
                target, module, reason = future.result()
            except Exception as exc:
                skipped += 1
                if args.show_skipped or args.verbose:
                    print(f"✗ <unknown>\tSKIPPED: {exc.__class__.__name__}: {exc}")
                continue
            if module:
                identified.append((target, module))
                print(f"✓ {target.base_url}\t{reason}")
            else:
                skipped += 1
                if args.show_skipped or args.verbose:
                    print(f"✗ {target.base_url}\tSKIPPED: {reason}")

    if skipped and not (args.show_skipped or args.verbose):
        print(f"({skipped} service(s) skipped as not a supported printer - "
              f"use --show-skipped to list them)")

    if not identified:
        print("\nNo supported printers found. Exiting.")
        return 1

    by_vendor: Dict[str, int] = {}
    for _target, module in identified:
        by_vendor[module.name] = by_vendor.get(module.name, 0) + 1

    # ---- Stage 3: test default credentials -----------------------------
    jobs: List[Tuple[Target, PrinterModule, Account]] = []
    for target, module in identified:
        for account in module.accounts(account_override):
            jobs.append((target, module, account))

    print(f"\n{'-' * 80}")
    print(f"Step 3: Testing credentials on {len(identified)} confirmed printer(s) "
          f"({', '.join(f'{k}={v}' for k, v in sorted(by_vendor.items()))})")
    print(f"Total credential tests: {len(jobs)}")
    print("-" * 80)

    successes = failures = errors = exported = harvested = 0
    completed = 0
    successful_logins: List[Tuple[str, str, str, str, str]] = []
    # Default-credential findings: successes against the built-in default
    # accounts (i.e. not a user-supplied --accounts list), reported so the
    # client can be told exactly which devices still ship factory logins.
    default_findings: List[Tuple[str, str, str, str, str]] = []
    folder_findings: List[Tuple[str, str, str, str, str]] = []
    service_default_hosts: Dict[str, List[str]] = {}
    success_by_host: Dict[str, LoginResult] = {}

    with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as executor:
        futures = {
            executor.submit(module.attempt_login, target, account, ctx): (target, module, account)
            for target, module, account in jobs
        }
        for future in concurrent.futures.as_completed(futures):
            target, module, account = futures[future]
            try:
                result: LoginResult = future.result()
            except Exception as exc:  # a module blowing up must not kill the scan
                errors += 1
                completed += 1
                print(f"[{completed}/{len(jobs)}] {target.hostport}\t{module.name}\t"
                      f"{account.label}\tERROR: {exc.__class__.__name__}: {exc}")
                continue

            completed += 1
            detail = f"\t{result.detail}" if result.detail else ""
            print(f"[{completed}/{len(jobs)}] {target.hostport}\t{module.name}\t"
                  f"{account.label}\t{result.outcome}\tstatus={result.status_code}{detail}")

            if not result.ok:
                if result.outcome == "FAIL":
                    failures += 1
                else:
                    errors += 1
                continue

            successes += 1
            credential = account.password if account.password else "blank password"
            output_msg = (
                f"Successful {module.display_name} login with account '{account.label}' "
                f"and {'password ' + credential if account.password else credential} "
                f"(HTTP {result.status_code})"
            )
            successful_logins.append(
                (target.hostport, target.hostport, "tcp", target.port, output_msg)
            )

            # A success against the built-in defaults is a reportable finding:
            # the device still carries a vendor factory login. Overridden
            # account lists (--accounts) are a custom password test, not a
            # default-credential finding, so they are logged but not flagged.
            if account_override is None:
                cred_desc = (f"default password '{account.password}'"
                             if account.password else "a blank password")
                risk = f" {account.risk_note}." if account.risk_note else ""
                finding = (
                    f"Default credentials in use - {module.display_name} accepts account "
                    f"'{account.label}' with {cred_desc}. Change the vendor default to a "
                    f"strong, unique password.{risk}"
                )
                default_findings.append(
                    (target.hostport, target.hostport, "tcp", target.port, finding)
                )
                if account.risk_note:
                    service_default_hosts.setdefault(target.hostport, []).append(account.label)
                    print(f"    ⚠⚠ SERVICE ACCOUNT DEFAULT: {target.hostport}  "
                          f"{module.display_name}  '{account.label}' / "
                          f"{account.password or '<blank>'}  -- {account.risk_note}")
                else:
                    print(f"    ⚠ DEFAULT CREDENTIALS: {target.hostport}  {module.display_name}  "
                          f"'{account.label}' / {account.password or '<blank>'}")

            # Keep the most capable session per host for the harvest stage.
            existing = success_by_host.get(target.hostport)
            if existing is None or (account.can_export and not existing.account.can_export):
                success_by_host[target.hostport] = result

    # ---- Stage 3.5: published-vulnerability checks ---------------------
    # Non-destructive checks tied to each vendor's advisories. Where a safe
    # probe exists (e.g. Sharp's pre-auth LFI, which is a plain read of
    # /etc/passwd), we run it and mark the finding verified. For CVEs whose
    # only reliable proof would crash the device, rewrite its configuration,
    # or exfiltrate real user credentials, the module returns advisory-only
    # findings instead. Every finding here is a per-device report row.
    vuln_findings_rows: List[Tuple[str, str, str, str, str]] = []
    verified_vulns = 0
    if not args.no_vuln_checks:
        vuln_targets = [(t, m) for t, m in identified if m.supports_vuln_checks]
        if vuln_targets:
            print(f"\n{'-' * 80}")
            print(f"Step 3.5: Checking published vulnerabilities on {len(vuln_targets)} printer(s)")
            print("-" * 80)
            with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as executor:
                futures = {
                    executor.submit(module.check_vulnerabilities, target, ctx,
                                    success_by_host.get(target.hostport)): (target, module)
                    for target, module in vuln_targets
                }
                for future in concurrent.futures.as_completed(futures):
                    target, module = futures[future]
                    try:
                        findings: List[VulnFinding] = future.result()
                    except Exception as exc:
                        print(f"{target.hostport}\tVULN CHECK ERROR: "
                              f"{exc.__class__.__name__}: {exc}")
                        continue
                    for finding in findings:
                        mark = "verified" if finding.verified else "advisory"
                        if finding.verified and finding.severity == "critical":
                            symbol = "⚠⚠⚠"
                        elif finding.severity in ("critical", "high"):
                            symbol = "⚠⚠"
                        else:
                            symbol = "⚠"
                        print(f"{symbol} VULN [{finding.cve}] [{finding.severity}] "
                              f"[{mark}] {target.hostport}\t{finding.title}")
                        if finding.verified:
                            verified_vulns += 1
                        output_field = (
                            f"{finding.cve} [{finding.severity}] [{mark}] - "
                            f"{finding.title}. {finding.output}"
                        )
                        vuln_findings_rows.append(
                            (target.hostport, target.hostport, "tcp",
                             target.port, output_field)
                        )

    # ---- Stage 4: harvest address books --------------------------------
    all_emails: List[str] = []
    all_names: List[str] = []

    if not args.no_export:
        print(f"\n{'-' * 80}")
        print(f"Step 4: Harvesting address books from {len(identified)} printer(s)")
        print("-" * 80)

        for target, module in identified:
            login = success_by_host.get(target.hostport)
            path = None

            # Preferred route: a real export, if we got in and the account allows it.
            if login and module.supports_export and login.account.can_export:
                _host, message, path = module.export_address_book(login, ctx)
                print(f"{target.hostport}\tEXPORT: {message}")
                if path:
                    exported += 1
                    export_text = read_export(path)
                    emails, names = module.extract_contacts(export_text)
                    all_emails.extend(emails)
                    all_names.extend(names)

                    # Scan-to-folder destinations carry stored FTP/SMB service
                    # credentials for internal shares - a finding in their own
                    # right, so surface them loudly and record a report row.
                    folders = module.extract_scan_to_folder(export_text)
                    if folders:
                        detail_lines, row = summarize_folders(target, folders)
                        folder_findings.append(row)
                        with_pw = sum(1 for f in folders if f.get("has_password") == "yes")
                        print(f"{target.hostport}\t⚠ SCAN-TO-FOLDER: {len(folders)} "
                              f"destination(s) in the address book, {with_pw} with a stored password")
                        for line in detail_lines:
                            print(f"    - {line}")
                        if target.hostport in service_default_hosts:
                            accts = ", ".join(sorted(set(service_default_hosts[target.hostport])))
                            print(f"{target.hostport}\t⚠⚠⚠ PRIORITY: service account "
                                  f"defaults ({accts}) + scan-to-folder on same device")

            # Fallback: read whatever the device shows without an export. Many
            # Sharp MFPs render their whole address book to anonymous visitors,
            # so this still produces contacts on devices whose default
            # credentials have been changed.
            if not path:
                if not module.supports_scrape:
                    if not login:
                        print(f"{target.hostport}\tHARVEST: SKIPPED - no default credentials "
                              f"and no unauthenticated harvest for {module.name}")
                    continue
                session = login.session if login else None
                emails, names, message = module.scrape_contacts(target, ctx, session)
                print(f"{target.hostport}\tHARVEST: {message}")
                all_emails.extend(emails)
                all_names.extend(names)
                if emails or names:
                    harvested += 1

    # Priority follow-up: devices that have BOTH a service account default
    # AND scan-to-folder destinations — the combination means a technician
    # login can reach stored credentials for internal shares.
    priority_findings: List[Tuple[str, str, str, str, str]] = []
    folder_hosts = {row[0] for row in folder_findings}
    for hostport in sorted(folder_hosts & service_default_hosts.keys()):
        accts = ", ".join(sorted(set(service_default_hosts[hostport])))
        folder_row = next(r for r in folder_findings if r[0] == hostport)
        port = folder_row[3]
        output = (
            f"PRIORITY - Device has default service account credentials ({accts}) "
            f"and scan-to-folder destinations storing reusable credentials for "
            f"internal shares. A technician-level login combined with stored "
            f"network credentials increases the risk of lateral movement. "
            f"Change the service account defaults and review the scan-to-folder "
            f"destinations immediately."
        )
        priority_findings.append((hostport, hostport, "tcp", port, output))

    summary = (f"\nEndpoints: {len(endpoints)}\tListening: {len(live)}\t"
               f"Printers: {len(identified)}\tSkipped: {skipped}"
               f"\nCredential Tests: {len(jobs)}\tSUCCESS: {successes}\tFAIL: {failures}\tERROR: {errors}")
    if not args.no_export:
        summary += f"\tEXPORTED: {exported}\tHARVESTED: {harvested}"
    summary += (f"\nFindings\tDefault credentials: {len(default_findings)}"
                f"\tScan-to-folder: {len(folder_findings)}"
                f"\tPriority follow-up: {len(priority_findings)}")
    if not args.no_vuln_checks:
        summary += (f"\tVulnerabilities: {len(vuln_findings_rows)} "
                    f"({verified_vulns} verified)")
    print(summary)

    if successful_logins:
        with open(args.success_file, "w", encoding="utf-8") as f:
            f.write("# Format: AssetName`URI`Protocol`Port`Output\n")
            for asset_name, uri, protocol, port, output_msg in successful_logins:
                f.write(f"{asset_name}`{uri}`{protocol}`{port}`{output_msg}\n")
        print(f"\nSuccessful logins saved to: {args.success_file} "
              f"({len(successful_logins)} entry/entries)")

    # Report-ready findings files. Both use the AssetName/URI/Protocol/Port/Output
    # format the client's tooling imports; backtick by default, --findings-delimiter
    # tab to switch. Paths are honoured as given so they can point anywhere.
    delimiter = "\t" if args.findings_delimiter == "tab" else "`"
    if default_findings:
        print()
        write_findings(args.findings_file, default_findings, delimiter,
                       "⚠ Default-credential findings")
    if folder_findings:
        write_findings(args.folder_findings_file, folder_findings, delimiter,
                       "⚠ Scan-to-folder findings")
    if priority_findings:
        write_findings(args.priority_file, priority_findings, delimiter,
                       "⚠⚠⚠ Priority follow-up findings")
    if vuln_findings_rows:
        label = (f"⚠ Vulnerability findings ({verified_vulns} verified, "
                 f"{len(vuln_findings_rows) - verified_vulns} advisory)")
        write_findings(args.vulns_file, vuln_findings_rows, delimiter, label)

    if (not args.no_export) and (all_emails or all_names):
        emails = sorted(set(all_emails))
        names = sorted(set(all_names))
        usernames = usernames_from_emails(emails)
        print()
        write_lines(os.path.join(args.output_dir, "extracted_emails.txt"), emails, "email")
        write_lines(os.path.join(args.output_dir, "extracted_names.txt"), names, "name")
        write_lines(os.path.join(args.output_dir, "extracted_usernames.txt"), usernames, "username")

    return 0 if successes or failures else 1


if __name__ == "__main__":
    sys.exit(main())
