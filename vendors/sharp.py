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

ROLE_SELECT_FIELD = "ggt_select(10009)"     # "Login Name" dropdown
LOGIN_NAME_FIELD = "ggt_textbox(10002)"     # free-text login name (user-auth mode)
PASSWORD_FIELD = "ggt_textbox(10003)"       # "Password"

_FORM_RE = re.compile(r"<form[^>]*name=\"login\"[^>]*>(.*?)</form>", re.S | re.I)
_INPUT_RE = re.compile(r"<input\b([^>]*)>", re.S | re.I)
_SELECT_RE = re.compile(r"<select[^>]*name=\"([^\"]+)\"[^>]*>(.*?)(?:</select>)", re.S | re.I)
_OPTION_RE = re.compile(r"<option[^>]*value=\"([^\"]*)\"([^>]*)>\s*([^<]*)", re.S | re.I)
_ATTR_RE = re.compile(r"(\w[\w-]*)\s*=\s*\"([^\"]*)\"", re.S)
_MODEL_RE = re.compile(r"[-–]\s*([A-Z]{2}[A-Z0-9][A-Z0-9\-]*)\s*$")


def _attrs(blob: str) -> Dict[str, str]:
    return {k.lower(): v for k, v in _ATTR_RE.findall(blob)}


class LoginForm:
    """The parsed contents of a Sharp login form."""

    def __init__(self, html: str):
        body = _FORM_RE.search(html)
        self.raw = body.group(1) if body else (html or "")
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
    supports_export = False
    export_note = (
        "Address book export is not implemented for Sharp yet - it needs a captured "
        "authenticated export request from a Sharp device to implement faithfully."
    )
    default_accounts = [
        Account(
            label="Administrator",
            username="Administrator",
            password="admin",
            can_export=False,
            note="Sharp factory default administrator password",
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
        login_url = f"{target.base_url}{LOGIN_PATH}?{POST_LOGIN_TARGET}"
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
