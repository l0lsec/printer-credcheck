## printer-credcheck

### Overview
Tests network printers and MFPs for vendor default credentials, and exports address books
from devices that still have them. Point it at a host, a file of hosts, or a whole subnet.

The tool is vendor-agnostic: each printer family lives in its own module under `vendors/`.
Every endpoint is port probed and fingerprinted before a single credential is sent, so
unrelated HTTP services on the range are identified and skipped rather than logged into.

Supported today:

| Vendor | Module | Default accounts tested | Address book export | Unauthenticated harvest | Published-CVE checks | Credential recovery |
|---|---|---|---|---|---|---|
| Ricoh (Web Image Monitor) | `vendors/ricoh.py` | `admin` / blank, `supervisor` / blank | Yes | No | No | No |
| Sharp (MX / BP series MFP) | `vendors/sharp.py` | `Administrator` / `admin`, `Service` / `service`, `FSS` / `servicefss` | Yes (CSV) | Yes | Yes (3 verified, zero-FP by default) | Yes (scan-to-folder, LDAP, device accounts) |

### Features
- **Subnet scanning**: takes CIDR blocks, address ranges, hosts, `host:port`, URLs, or files
  containing any mix of those
- **HTTP service discovery**: sweeps a port list with a TCP connect plus a TLS handshake, so
  it finds printer web UIs on non-standard ports and knows whether to speak http or https
- **Safe on mixed ranges**: anything that is not a supported printer is skipped without ever
  receiving a credential, and a service that hangs, floods, or errors cannot break the scan
- **Vendor fingerprinting**: every host is identified before any credential is sent, which
  keeps devices that accept any username/password out of the results
- **Auto-detection**: `--vendor auto` (the default) tries each module until one claims the host
- **Credential testing**: checks whether devices still carry their factory default logins
- **Default-credential findings**: flags every default login on the console as it is found and
  writes a report-ready findings file (`default_credentials.txt`) for the client
- **Scan-to-folder alerting**: warns when an exported address book holds scan-to-folder
  (FTP/SMB/Desktop) destinations, which store reusable service-account credentials for internal
  shares, and writes them to their own findings file (`scan_to_folder.txt`)
- **Credential recovery**: recovers the stored secrets in cleartext rather than just reporting
  that the device holds them - scan-to-folder FTP/SMB/Desktop passwords out of the exported CSV
  and LDAP bind credentials off the settings pages. Written to `recovered_credentials.txt`;
  disable with `--no-recover-secrets`
- **Device memory recovery** (opt-in, `--dump-coredumps`): reads account passwords out of the
  printer's world-readable coredumps through the pre-auth LFI, which is what recovers credentials
  from devices whose defaults have already been changed
- **Priority follow-up**: devices that have both a technician-level service account default *and*
  scan-to-folder destinations are flagged separately in `priority_followup.txt` — these combine
  default credentials with stored network credentials and should be remediated first
- **Successful login export**: writes all successful logins to a backtick-delimited file
- **Address book export**: pulls address books from vulnerable devices (supported vendors)
- **Unauthenticated harvest**: when default credentials fail, still reads whatever contacts the
  device exposes without a login
- **Email, name & username extraction**: parses everything harvested into email, name, and
  username lists
- **Published-CVE checks (Sharp)**: zero-false-positive by default. Actively
  probes the pre-authenticated arbitrary file read (`/installed_emanual_down.html?path=..`),
  and when it hits, chains the same LFI to fetch `/tmp/main/main` and byte-match
  the exact hardcoded Google OAuth client IDs (CVE-2024-36248) and AWS analytics
  key from Pierre Kim's June 2024 advisory. Every emitted row is proof of an
  on-device condition, never fingerprint-derived. Pass `--include-advisories`
  to also emit rows for CVE-2024-28038, CVE-2022-45796, and CVE-2024-34162,
  which this tool cannot safely test
- **Real-time progress**: prints each result as it completes
- **Concurrent scanning**: multi-threaded across hosts
- **Verbose mode**: full HTTP request/response tracing for debugging

### How scanning works

1. **Expand** — target specs become concrete `scheme://host:port` endpoints. A URL or an
   explicit `host:port` is taken literally; bare hosts, CIDRs, and ranges are multiplied
   across `--ports`.
2. **Probe** — each endpoint gets a TCP connect followed by a TLS handshake attempt. That is
   far cheaper than an HTTP request and it decides http vs https per port, so a printer UI on
   an odd port is still spoken to correctly. Closed ports never reach stage 3.
3. **Fingerprint** — every listening service is matched against the enabled vendor modules.
   Only a positive match moves on.
4. **Test credentials** — the matched vendor's default accounts, and nothing else.
5. **Recover stored credentials** — pull the device's stored secrets back out in cleartext
   (skip with `--no-recover-secrets`; add `--dump-coredumps` for the memory source).
6. **Check published CVEs** — for vendor modules that ship one (Sharp today), run
   active on-device probes and emit only rows that were actually confirmed. Pass
   `--include-advisories` to also emit the fingerprint-based advisory rows for
   CVEs that cannot be safely verified without an exploit. Disable with
   `--no-vuln-checks`.

Response bodies are read through a 512 KB ceiling, so pointing the scanner at a file server
or a streaming endpoint cannot exhaust memory or stall a worker. A module that raises on a
strange endpoint is contained and the scan continues.

### How detection works

**Ricoh** — `GET /web/guest/en/websys/webArch/mainFrame.cgi` and look for `RICOH`,
`Web Image Monitor`, `rimNote`, `rimLocal`, or a redirect to `authForm.cgi`. The path-shaped
markers (`websys/webArch`, `/web/guest/`) only count after any echo of the request URL has
been stripped from the response — otherwise any server that quotes your request back at you,
such as a proxy error page or a 404 handler, fingerprints as a Ricoh. For the same reason a
bare `HTTP 200` on the login POST is not treated as a successful login unless the response
actually looks like Web Image Monitor or the device issued a session cookie.

**Sharp** — `GET /login.html` and look for the proprietary `Extend-sharp-*` response header
or an `MFPSESSIONID` cookie (either is conclusive on its own), backed up by
`Server: Rapid Logic`, the `ggt_textbox(...)` / `ggt_select(...)` form fields, and a
`Login - <MODEL>` page title. `Rapid Logic` never counts on its own — it is a generic
embedded web server shipped in plenty of non-Sharp gear.

### How the Sharp login works
Sharp's web login differs from Ricoh's in two ways that the module handles:

1. **The login name is a dropdown, not a text box.** On a device in administrator-authority
   mode the `ggt_select(10009)` select holds a single option, `Administrator` (value `3`).
   Devices running user authentication instead expose a free-text `ggt_textbox(10002)` field,
   which the module fills in when it is present.
2. **Every login form carries a one-shot CSRF token.** `token2` has to be scraped from the
   form and posted back on the same `MFPSESSIONID` session; a replayed token is rejected.

The resulting exchange:

```text
GET  /login.html?/addressbook.html      -> 200, login form + token2 + MFPSESSIONID
POST /login.html?/addressbook.html
     ggt_select(10009)=3&ggt_textbox(10003)=<password>&action=loginbtn
     &token2=<per-session>&ordinate=0&ggt_hidden(10008)=5
<-   302, Location: /addressbook.html, fresh MFPSESSIONID   (success)
<-   200, login form re-rendered                            (failure)
```

A `302` alone is not treated as proof. The module follows the redirect once with the new
session cookie and confirms the page that comes back is not the login form again, so a device
that redirects on failure cannot produce a false positive.

**More than one privileged login.** The administrator account is not the only factory login. The
device also ships `/service_login.html` and `/fss_default.html`, which are thin shims that
redirect to the same `/login.html` form with a different post-login target:

| Shim | Login form requested | Role in `ggt_select(10009)` | Default password |
|---|---|---|---|
| `/login.html` | `/login.html?/addressbook.html` | `3` Administrator | `admin` |
| `/service_login.html` | `/login.html?/service_testpage.html` | `4` Service | `service` |
| `/fss_default.html` | `/login.html?/fss_default.html` | `7` FSS | `servicefss` |

The exchange is otherwise identical, so the module maps each account's role name to its target
page (`ROLE_TARGETS`) and reuses the same login flow. The role *value* is read from the form
rather than hard-coded, since each target page offers only its own role. The Service and FSS
accounts are technician logins that do not reach System Settings, so they confirm the default
credential but the address book is still harvested by the unauthenticated scrape.

### How the Sharp export works
Sharp does not expose the address book as a data feed behind the list page. It ships a real
export under **System Settings > Data Import/Export (CSV Format)**, which the module drives in
three steps:

```text
GET  /sysmgt_storagebackup_csv.html        -> export form + token1/token2
POST /sysmgt_storagebackup_csv.html
     action=export_btn&ggt_radio(50)=33    (33 = Address Book, 23 = User Register Information)
<-   302, Location: /storage_backup_csv.html?type=33
GET  /storage_backup_csv.html?type=33      -> text/csv attachment
```

The CSV's first row names its columns, and the parser looks columns up by name rather than
position because the set varies with firmware and with which destination types the device
supports:

```text
"address","search-id","name","search-string","category-id","frequently-used","mail-address",
"fax-number","ifax-address","ftp-host","ftp-directory","ftp-username","ftp-password",
"smb-directory","smb-username",...
```

> **Handle the export carefully.** It is not just contacts. Scan-to-folder destinations bring
> `ftp-host` / `ftp-username` / `ftp-password` and the SMB equivalents with them, so an
> exported CSV can contain live service account credentials for internal file shares.

### Harvesting without a login
Changing the administrator password does not necessarily protect the address book. On the
Sharp MFPs tested, `/addressbook.html` renders the full contact table - names and e-mail
addresses - to anonymous visitors, with only the *Login* button hinting that no session
exists. The harvest stage therefore falls back to reading that page whenever a device's default
credentials have been changed:

```text
default credentials work  -> CSV export via System Settings (complete, includes FTP/SMB creds)
default credentials fail  -> scrape /addressbook.html    (names + e-mail addresses only)
```

#### Pagination
The list page shows 10-50 entries at a time, so anything larger has to be paged. Every control
on that page submits the same form and the device decides what to do from the `action` field,
which the page's own `validate()` sets to *the name of whichever control fired*. That is the
whole trick:

| Intent | Field to send |
|---|---|
| Change page size | `action=ggt_select(9)` with `ggt_select(9)=<option value>` |
| Next page | `action=nextbtn` |
| Previous page | `action=prevbtn` |

Sending `action=updatebtn` — the obvious guess — is silently ignored.

The harvester widens the page to the largest offered size first, since one request for 100
rows beats ten requests for 10, then walks any remainder with `nextbtn`. The CSRF token is
single use, so it is re-read from each page before submitting the next, and the device's
session cookie is carried throughout because paging state lives server side. None of this
needs a login.

Rows are de-duplicated on the device's own member id rather than on name and address: two
distinct contacts can legitimately share both. The module reads the device's `Total Address`
count and reports `PARTIAL: Harvested 50 of 137 (stopped on page 2 of 4)` if it ever falls
short, so a truncated read is never silent.

> **Lockout note:** Sharp MFPs can be configured to lock an account after consecutive failed
> logins ("A Warning when Login Fails", typically 3 attempts / 5 minutes). The counter is
> per-account, and each account tested costs one attempt per host. The three built-in defaults
> (`Administrator`, `Service`, `FSS`) are distinct accounts, so a normal run spends one attempt
> on each - well clear of the threshold. The risk is a long `--accounts` list aimed at the *same*
> account, so keep those short on production fleets.

### Sharp published-CVE checks
Alongside credential testing, the Sharp module runs a per-device pass through Pierre Kim's
June 2024 advisory bundle ([JVN VU#93051062](https://jvn.jp/en/vu/JVNVU93051062/index.html))
and writes the findings to `vulnerabilities.txt` in the standard AssetName/URI/Protocol/Port/Output
format. Pass `--no-vuln-checks` to skip the stage.

Every finding is one of two kinds and the tag is written into the report row so the
client's tooling can filter on it:

- **`[verified]`** — the module actively confirmed the condition on this specific
  device with a safe read. This is the default output.
- **`[advisory]`** — the vendor advisory names the product/firmware family, but this
  tool cannot actively test the condition without an exploit that would crash the
  printer, rewrite its configuration, or exfiltrate real user credentials. Suppressed
  by default; opt in with `--include-advisories`.

| # | Finding | Kind | How the module tests (or doesn't) |
|---|---|---|---|
| 1 | Pre-auth LFI (no-CVE, *Local File Inclusion allowing to read any file*) | **Verified** | `GET /installed_emanual_down.html?path=/manual/../../../etc/passwd` — a plain read of a small, harmless file. A `root:...:0:0:` line in the response is unmistakable. Chains to the coredump / uaccnt credential dumps. |
| 2 | CVE-2024-36248 — hardcoded Google OAuth client IDs | **Verified** *(chained via #1)* | When the LFI probe hits, the same primitive fetches `/tmp/main/main` and byte-matches the four advisory-verbatim client IDs. Only emits when at least one ID is found in **this device's** binary. |
| 3 | Hardcoded AWS analytics key (no-CVE) | **Verified** *(chained via #1)* | Same binary read, byte-matched against `PBYXSIK6av8fBt8Qe1EQUaF9ZaKvTDutaXS9YwWA`, the Postman token, and the analytics endpoint host. |
| 4 | CVE-2024-28038 — pre-auth memory corruption RCE | Advisory | The published PoC (~643-byte `MFPSESSIONID`) crashes the main binary — which serves HTTP, FTP, LPD, IPP, SNMP, and the touchscreen UI — and reboots the printer. |
| 5 | CVE-2022-45796 — authenticated IPv6 command injection | Advisory | The payload writes into `/nw_interface.html` (`ggt_textbox(16)`), which the device passes to `ping6`; a successful exploit persists a shell payload into the printer's live IPv6 network configuration. |
| 6 | CVE-2024-34162 — LDAP credential exfiltration via SIMPLE downgrade | Advisory | Requires standing up a rogue slapd and overwriting the device's LDAP settings before the Connect Test transmits the stored bind credential. |

Under `--include-advisories`, the two authenticated-only advisory findings (CVE-2022-45796
and CVE-2024-34162) escalate to `severity=critical` when this scan also confirmed the
Administrator account is still on the vendor default password, since an attacker then
already has the prerequisite session. Absent that, they stay at `severity=high`.

The binary chain fetches up to 128 MB of `/tmp/main/main` per device, because on the
production MX-M6071 firmware the hardcoded strings live at offsets ~43 MB and ~81 MB and
a smaller cap misses them (verified false-negative during development).

#### Proof-of-concept artifacts
Every verified row writes a per-device evidence file into `--output-dir` so the
client can re-open the actual proof without re-running the tool:

| Finding | File | Contents |
|---|---|---|
| Pre-auth LFI | `evidence_lfi_<host>_<port>.txt` | Verbatim `/etc/passwd` bytes returned by the device, prefixed with the exact request line and HTTP status |
| CVE-2024-36248 Google keys | `evidence_google_keys_<host>_<port>.txt` | For each of the four blog-verbatim client IDs found in `/tmp/main/main`, the byte offset plus a 96-byte hex + printable-ASCII window around the match (the surrounding firmware strings are visible, so the match is not confusable with a coincidence) |
| Hardcoded AWS keys | `evidence_aws_keys_<host>_<port>.txt` | Same shape for the AWS API key, Postman token, and analytics endpoint host |

The finding's Output column names the exact file: `Proof-of-concept saved to
evidence_google_keys_192.0.2.66_443.txt (offsets + hex + ASCII context around
each match).` Evidence files are `.gitignore`d so real device data never leaks
into git.

The FSS User backdoor documented alongside these vulnerabilities is not a separate row in
`vulnerabilities.txt` - it is the `FSS` / `servicefss` entry in the default-account list, and
the tool already reports it (with a `SERVICE ACCOUNT DEFAULT` console callout and a row in
`default_credentials.txt`) whenever the hidden account still accepts its factory password.

### Recovering stored credentials

Knowing that a printer *holds* a scan-to-folder or LDAP bind password is only half a finding.
The credential is a real account on the client's network - a scan-to-folder destination exists
so the MFP can write into a share unattended, which means the account is real, it is usually a
service account, and it usually has write access. This stage recovers the value.

Three independent sources run per device, cheapest first. A device that blocks one still gives
up the others:

| # | Source | Needs | Recovers |
|---|---|---|---|
| 1 | The address book CSV already pulled in the harvest stage | Administrator default still works | FTP / SMB / Desktop scan-to-folder passwords |
| 2 | The LDAP settings pages, `/nw_ldap_entry.html?ldapid=N` | Administrator default still works | Directory server, bind DN, and the bind password on firmware that renders it back into the form |
| 3 | The printer's coredumps, through the pre-auth LFI | Nothing - no login at all. **Opt-in: `--dump-coredumps`** | Account passwords, LDAP binds, and folder credentials in cleartext |

Sources 1 and 2 run by default because they re-read configuration the scan has already
downloaded, and they return only the credentials the device was deliberately configured to
store. Source 3 is gated behind `--dump-coredumps` because it does something different in kind:
it returns whatever passwords are resident in the printer's memory, including those of users who
merely logged in. A routine subnet sweep should not produce a file full of a client's account
passwords unless someone decided to go after them.

Source 3 is the one that matters when the defaults have already been changed. Per the advisory,
`/mnt/log` holds gzipped, world-readable (`-rw-r--r--`) coredumps of the main binary, and that
binary keeps credentials in the clear - the reporter recovered an administrator password *"even
when the admin user has not been logged-in the printer since the printer booted"*. The main
binary is also the web server, so the form POST bodies it processed are resident in the same
dump, which is what makes the strongest hits here structured rather than guessed:

```text
GET /installed_emanual_down.html?path=/manual/../../../mnt/log/core-main.log.gz.001
-> ggt_select(10009)=3&ggt_textbox(10003)=ExampleP%40ss2&action=loginbtn
                       ^^^^^^^^^^^^^^^^^ the device's own password field, so this is a
                                         submitted password, not a pattern that resembles one
```

The stage only runs after the `/etc/passwd` probe confirms traversal works, so a patched device
costs one small request rather than a multi-megabyte download. Coredumps are gzip and are split
into numbered parts (`core-main.log.gz.001` was 17,316,455 bytes on the reporter's MX-M6071);
the download is capped by `--recovery-max-bytes` and a truncated stream is inflated as far as it
goes rather than discarded.

#### Confidence

Every recovered credential is labelled, and the label is written into the report row:

- **`[verified]`** — the value came out of a field whose meaning is unambiguous: a CSV password
  column, a settings form field, or a form POST body recovered verbatim from memory with the
  device's own field name attached. It is a credential.
- **`[candidate]`** — the value came from a `<something>password=<value>` match over
  unstructured memory. Very likely a credential, not proven to be one. The account and host
  attached to it are the nearest ones in the dump, which is an association by proximity - check
  the byte offset in the evidence file before quoting it in a report.
- **`[config-only]`** — the account and where it points were recovered, the password was not.
  Typical of an LDAP settings page that masks the stored bind password. When another source
  later produces that same account's password, the two rows are merged into one.

#### Encoding

Sharp's CSV export declares an encoding per credential field in a companion column
(`ftp-password` is described by `ftp-password/@encodingMethod`), because the same file has to
round-trip values that are not valid CSV text. Base64 and hex are decoded; an encoding the tool
does not know is reported verbatim with a note saying so, since a password you have to decode by
hand still beats being told nothing was found.

#### Output

Recovered credentials go to `--creds-file` (default `recovered_credentials.txt`) in the same
`AssetName`/`URI`/`Protocol`/`Port`/`Output` format as the other findings files, one row per
credential, plus a per-device evidence file:

| File | Contents |
|---|---|
| `recovered_credentials.txt` | One report row per credential: kind, confidence, username, password, where it is valid, how it was recovered |
| `evidence_recovered_credentials_<host>_<port>.txt` | The memory-recovered credentials with the byte offset each was found at and the request that produced the dump |

> **These files hold live credentials for someone else's network.** Both are `.gitignore`d.
> Keep them with the engagement evidence and destroy them at close. `scan_to_folder.txt`
> deliberately stays a summary - it names each destination and whether its password came back,
> and leaves the secret itself to the credential file - so it can go into the report body
> without carrying live secrets through it.

### Target formats
Targets can be given on the command line, in a file, or both:

| Form | Example | Behaviour |
|---|---|---|
| CIDR block | `10.10.62.0/24` | every host, swept across `--ports` |
| Address range | `10.10.62.1-50` or `10.10.62.1-10.10.62.50` | every host, swept across `--ports` |
| Bare host | `10.10.62.20` | swept across `--ports` |
| Host with port | `10.10.62.22:8443` | taken literally, port not multiplied |
| Full URL | `https://10.10.62.21` | taken literally, scheme honoured |
| File | `./hosts.txt` | one spec per line, any of the above |

A file uses one spec per line; blank lines and lines beginning with `#` are ignored.

```text
# Staging devices
10.10.62.20
https://10.10.62.21
10.10.62.22:8443
```

### Usage
```bash
python3 printer_credcheck.py <target> [<target> ...] [OPTIONS]
```

#### Arguments
- `targets`: one or more hosts, CIDR blocks, ranges, URLs, or files of targets
- `--vendor <list>`: comma-separated vendors to test, or `auto` to fingerprint each host (default: `auto`)
- `--list-vendors`: list supported vendors and their default accounts, then exit
- `--accounts <pairs>`: override the accounts tested, as `user:pass` pairs (e.g. `admin:,supervisor:`)
- `--ports <list>`: ports to sweep on bare hosts and subnets, ranges allowed (default: `80,443,8080,8443`)
- `--connect-timeout <float>`: TCP connect timeout during the port sweep (default: `2.0`)
- `--no-port-scan`: skip the port sweep and fingerprint every expanded endpoint
- `--scan-workers <int>`: concurrent workers for the port sweep (default: `100`)
- `--show-skipped`: print a line for every endpoint that is not a supported printer
- `--scheme {http,https}`: scheme for ports with no well-known default (default: `https`)
- `--timeout <int>`: HTTP request timeout in seconds (default: `10`)
- `--workers <int>`: number of concurrent workers for HTTP stages (default: `10`)
- `--verify`: enable TLS certificate verification (disabled by default)
- `--no-export`: skip the address book harvest stage (by default the tool exports on success
  and falls back to the unauthenticated read on failure)
- `--output-dir <path>`: output directory for exported address books (default: current directory)
- `--export-timeout <int>`: timeout in seconds for export requests (default: `30`)
- `--success-file <path>`: output file for successful logins (default: `successful_logins.txt`)
- `--findings-file <path>`: output file for default-credential findings (default: `default_credentials.txt`)
- `--folder-findings-file <path>`: output file for scan-to-folder findings (default: `scan_to_folder.txt`)
- `--priority-file <path>`: output file for priority follow-up findings — devices with both a service account default and scan-to-folder entries (default: `priority_followup.txt`)
- `--vulns-file <path>`: output file for published-CVE findings (default: `vulnerabilities.txt`)
- `--no-vuln-checks`: skip the published-CVE stage
- `--include-advisories`: also emit advisory-only rows for CVEs this tool cannot safely
  actively test (CVE-2024-28038, CVE-2022-45796, CVE-2024-34162). Off by default so
  `vulnerabilities.txt` is zero-false-positive
- `--no-recover-secrets`: skip the credential recovery stage (scan-to-folder passwords from the
  export, LDAP bind credentials, and coredump recovery)
- `--dump-coredumps`: also recover credentials from the device's raw memory — downloads the
  printer's world-readable coredumps through the pre-auth LFI and reads cleartext passwords out
  of them. Off by default; needed to recover credentials from devices whose defaults were changed
- `--creds-file <path>`: output file for recovered credentials — contains live cleartext secrets
  (default: `recovered_credentials.txt`)
- `--recovery-max-bytes <int>`: ceiling on a single credential-recovery download, e.g. a printer
  coredump (default: `67108864`)
- `--findings-delimiter {backtick,tab}`: field delimiter for the findings files (default: `backtick`)
- `--verbose`: show all HTTP requests and responses

### Examples

#### Sweep a subnet
```bash
python3 printer_credcheck.py 10.10.62.0/24
```

#### Sweep several ranges at once, including extra ports
```bash
python3 printer_credcheck.py 10.10.62.0/24 10.10.70.1-50 --ports 80,443,8080,8443,631
```

#### Fingerprint and test everything in a file
```bash
python3 printer_credcheck.py ./hosts.txt
```

#### See why things on the range were skipped
```bash
python3 printer_credcheck.py 10.10.62.0/24 --show-skipped
```

#### Only test Sharp devices
```bash
python3 printer_credcheck.py ./hosts.txt --vendor sharp
```

#### Change the output directory for the address book export
```bash
python3 printer_credcheck.py 10.10.62.0/24 --output-dir ./exports
```

#### Test credentials only (skip both address book harvest and CVE checks)
```bash
python3 printer_credcheck.py 10.10.62.0/24 --no-export --no-vuln-checks
```

#### Try a non-default password list on Sharp devices
```bash
python3 printer_credcheck.py ./hosts.txt --vendor sharp --accounts 'Administrator:admin,Administrator:sharp'
```

#### Recover the credentials a fleet has stored
```bash
python3 printer_credcheck.py 10.10.62.0/24 --output-dir ./engagement
```
Runs by default: scan-to-folder and LDAP credentials come back from devices whose defaults still
work.

#### Also recover credentials from device memory
```bash
python3 printer_credcheck.py 10.10.62.0/24 --dump-coredumps --output-dir ./engagement
```
Adds the coredump source, which recovers account passwords from any device with the pre-auth
LFI — including devices whose defaults were changed, where nothing else works. This downloads
the printer's memory and reads every password in it, so use it when the engagement calls for it
rather than as a default.

#### Skip credential recovery (findings only, no secrets on disk)
```bash
python3 printer_credcheck.py 10.10.62.0/24 --no-recover-secrets
```

#### Cap the coredump download on a large fleet
```bash
python3 printer_credcheck.py 10.10.62.0/24 --recovery-max-bytes 16777216
```

#### See what each vendor module will send
```bash
python3 printer_credcheck.py --list-vendors
```

#### Verbose debugging over HTTP
```bash
python3 printer_credcheck.py ./hosts.txt --scheme http --verbose
```

#### Skip the published-CVE stage (credentials only)
```bash
python3 printer_credcheck.py 10.10.62.0/24 --no-vuln-checks
```

### Output

The scan runs in six stages:
1. **Step 1** — expand the targets and port sweep them for listening HTTP services
2. **Step 2** — fingerprint every live service and assign it to a vendor module (or skip it)
3. **Step 3** — test that vendor's default accounts
4. **Step 3.5** — run vendor-published-CVE checks against the fingerprinted devices
   (Sharp: safe pre-auth LFI probe, chained to a binary read of `/tmp/main/main`
   for byte-matched Google/AWS key verification; add `--include-advisories` for
   fingerprint-based advisory rows; skip the whole stage with `--no-vuln-checks`)
5. **Step 4** — harvest address books, by export where the credentials worked and by
   unauthenticated read where they did not (skipped with `--no-export`)
6. **Step 4.5** — recover stored credentials in cleartext: scan-to-folder passwords out of the
   exported CSV and LDAP bind credentials off the settings pages, plus — with `--dump-coredumps`
   — account passwords out of the device's coredumps through the pre-auth LFI (skip the whole
   stage with `--no-recover-secrets`)

Skipped endpoints are counted rather than listed; pass `--show-skipped` to see each one and
the reason every module rejected it.

Successful logins are written to `--success-file` in backtick-delimited format:

```text
# Format: AssetName`URI`Protocol`Port`Output
192.0.2.113`192.0.2.113`tcp`443`Successful Sharp MFP login with account 'Administrator' and password admin (HTTP 302)
```

#### Findings files

Up to five findings files are written in the same reporting format - `AssetName`, `URI`,
`Protocol`, `Port`, `Output` - so they drop straight into the client report. The `AssetName`
is the same `host:port` the successful-logins file uses, which needs to match an existing
EngagementAsset. Fields are backtick-delimited by default; pass `--findings-delimiter tab`
for tab-delimited. Each file is written only when it has at least one finding.

`--findings-file` (default `default_credentials.txt`) — one row per device/account still on a
vendor default. Technician-level accounts (Service, FSS) are called out with a risk note in the
Output column and a distinct `⚠⚠ SERVICE ACCOUNT DEFAULT` console alert so they stand out from
regular administrator defaults:

```text
# Format: AssetName`URI`Protocol`Port`Output
192.0.2.113`192.0.2.113`tcp`443`Default credentials in use - Sharp MFP accepts account 'Administrator' with default password 'admin'. Change the vendor default to a strong, unique password.
192.0.2.113`192.0.2.113`tcp`443`Default credentials in use - Sharp MFP accepts account 'Service' with default password 'service'. Change the vendor default to a strong, unique password. Technician-level service account - grants access to diagnostic functions; prioritise remediation.
```

`--folder-findings-file` (default `scan_to_folder.txt`, skipped under `--no-export`) — one row per device
whose exported address book holds scan-to-folder (FTP/SMB/Desktop) destinations. These store reusable
credentials so the MFP can drop scans onto an internal share unattended, so each is worth
reporting on its own. This row stays a summary: it names the destinations and says whether each
password came back, and leaves the values to `recovered_credentials.txt`, so it can go into the
report body without carrying live credentials through it:

```text
# Format: AssetName`URI`Protocol`Port`Output
192.0.2.113`192.0.2.113`tcp`443`Address book contains 2 scan-to-folder destination(s) storing reusable credentials for internal shares: [FTP] ftp.corp.example/scans (user: svc-scanner, password recovered); [SMB] \\SHARESRV\share$ (user: EXAMPLE\svc-printer, password recovered). Review whether each is required and rotate the service accounts.
```

`--creds-file` (default `recovered_credentials.txt`, skipped under `--no-recover-secrets`) — one
row per credential recovered in cleartext, from any of the three sources described under
[Recovering stored credentials](#recovering-stored-credentials). The confidence label is written
into the Output column so the client's tooling can filter on it, and the row names the evidence
file the value came from:

```text
# Format: AssetName`URI`Protocol`Port`Output
192.0.2.113`192.0.2.113`tcp`443`Recovered scan-to-folder credential [verified]: username 'EXAMPLE\svc-scanner'. password 'ExampleP@ss1'. valid for \\SHARESRV\share$. Source: SMB destination in the address book CSV exported through System Settings > Data Import/Export on 192.0.2.113:443. address book entry 'Scan to Finance'; stored with encodingMethod=base64. Rotate this account and remove the stored credential from the device.
192.0.2.113`192.0.2.113`tcp`443`Recovered device account credential [verified]: username 'Administrator'. password 'ExampleP@ss2'. valid for 192.0.2.113:443. Source: login form POST body recovered cleartext in core-main.log.gz.001 read through the pre-auth LFI on 192.0.2.113:443. matched ggt_textbox(10003)= at offset 0x79ea; role selection Administrator. Evidence: evidence_recovered_credentials_192.0.2.113_443.txt. Rotate this account and remove the stored credential from the device.
```

**This file holds live credentials.** It is `.gitignore`d; keep it with the engagement evidence
and destroy it at close.

`--priority-file` (default `priority_followup.txt`, skipped under `--no-export`) — one row per device
that has **both** a technician-level service account default (Service/FSS) **and** scan-to-folder
destinations in its address book. This combination is the highest priority because a default
technician login paired with stored network credentials for internal shares creates a lateral
movement risk. These devices are also flagged on the console with a `⚠⚠⚠ PRIORITY` alert:

```text
# Format: AssetName`URI`Protocol`Port`Output
192.0.2.113`192.0.2.113`tcp`443`PRIORITY - Device has default service account credentials (FSS, Service) and scan-to-folder destinations storing reusable credentials for internal shares. A technician-level login combined with stored network credentials increases the risk of lateral movement. Change the service account defaults and review the scan-to-folder destinations immediately.
```

`--vulns-file` (default `vulnerabilities.txt`) — one row per (device, published CVE),
tagged `[verified]` when the module actively confirmed the condition on this device or
`[advisory]` when the row comes from a fingerprint-based advisory (only emitted under
`--include-advisories`). Default output is zero-false-positive — every row is proof.
See the *Sharp published-CVE checks* section above for how each finding is tested:

```text
# Format: AssetName`URI`Protocol`Port`Output
192.0.2.59`192.0.2.59`tcp`443`no-CVE (pre-auth LFI) [critical] [verified] - Unauthenticated arbitrary file read via /installed_emanual_down.html path traversal. Unauthenticated Local File Inclusion confirmed on this device: GET /installed_emanual_down.html?path=/manual/../../../etc/passwd returned the printer's /etc/passwd ...
192.0.2.59`192.0.2.59`tcp`443`CVE-2024-36248 [medium] [verified] - Hardcoded Google OAuth client IDs in the main firmware binary. Verified on this device: fetched /tmp/main/main through the pre-auth LFI and matched the following Google OAuth client ID(s) verbatim in the binary: 265490466885-m5cjvglv9q8aak493cgepe7juvafgh8c.apps.googleusercontent.com; ...
```

Exported address books are saved per vendor - `addressbook_ricoh_<host>.txt` for Ricoh's
array payload, `addressbook_sharp_<host>.csv` for Sharp's CSV. Everything harvested across the
whole run, exports and unauthenticated reads alike, is pooled into three de-duplicated files
in the output directory:

| File | Contents |
|---|---|
| `extracted_emails.txt` | every e-mail address found |
| `extracted_names.txt` | every address book display name |
| `extracted_usernames.txt` | the local part of each address, lowercased - `j.doe@corp.example` becomes `j.doe` |

### Adding a vendor
1. Create `vendors/<vendor>.py` with a class that subclasses `PrinterModule` from `vendors/base.py`.
2. Implement `fingerprint()` and `attempt_login()`. Implement `export_address_book()` and
   `extract_contacts()` too if you have a captured export request, and set
   `supports_export = True`. If the device leaks contacts without a session, implement
   `scrape_contacts()` and set `supports_scrape = True`.
3. Register the class in `MODULES` in `vendors/__init__.py`.

`vendors/base.py` supplies the shared `Target` / `Account` / `ScanContext` / `LoginResult`
types plus the verbose logging and `Set-Cookie` parsing helpers, so a module only has to
describe the vendor's own request flow.

### Known gaps
- **Sharp export is verified end to end, but only against an empty address book.** The device
  it was built against reported `0 / 0` entries, so the request chain, the CSV headers, and
  the file handling are confirmed against real firmware while row parsing is exercised only
  by synthetic rows built on the device's own header. Worth a second look the first time it
  runs against a populated device.
