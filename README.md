## printer-credcheck

### Overview
Tests network printers and MFPs for vendor default credentials, and exports address books
from devices that still have them. Point it at a host, a file of hosts, or a whole subnet.

The tool is vendor-agnostic: each printer family lives in its own module under `vendors/`.
Every endpoint is port probed and fingerprinted before a single credential is sent, so
unrelated HTTP services on the range are identified and skipped rather than logged into.

Supported today:

| Vendor | Module | Default accounts tested | Address book export | Unauthenticated harvest |
|---|---|---|---|---|
| Ricoh (Web Image Monitor) | `vendors/ricoh.py` | `admin` / blank, `supervisor` / blank | Yes | No |
| Sharp (MX / BP series MFP) | `vendors/sharp.py` | `Administrator` / `admin`, `Service` / `service`, `FSS` / `servicefss` | Yes (CSV) | Yes |

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
- **Scan-to-folder alerting**: warns when an exported address book holds scan-to-folder (FTP/SMB)
  destinations, which store reusable service-account credentials for internal shares, and writes
  them to their own findings file (`scan_to_folder.txt`)
- **Successful login export**: writes all successful logins to a backtick-delimited file
- **Address book export**: pulls address books from vulnerable devices (supported vendors)
- **Unauthenticated harvest**: when default credentials fail, still reads whatever contacts the
  device exposes without a login
- **Email, name & username extraction**: parses everything harvested into email, name, and
  username lists
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
exists. `--export` therefore falls back to reading that page whenever a device's default
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
- `--export`: export address books from devices with successful default credentials
- `--output-dir <path>`: output directory for exported address books (default: current directory)
- `--export-timeout <int>`: timeout in seconds for export requests (default: `30`)
- `--success-file <path>`: output file for successful logins (default: `successful_logins.txt`)
- `--findings-file <path>`: output file for default-credential findings (default: `default_credentials.txt`)
- `--folder-findings-file <path>`: output file for scan-to-folder findings (default: `scan_to_folder.txt`)
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

#### Check credentials and harvest address books, usernames included
```bash
python3 printer_credcheck.py 10.10.62.0/24 --export --output-dir ./exports
```

#### Try a non-default password list on Sharp devices
```bash
python3 printer_credcheck.py ./hosts.txt --vendor sharp --accounts 'Administrator:admin,Administrator:sharp'
```

#### See what each vendor module will send
```bash
python3 printer_credcheck.py --list-vendors
```

#### Verbose debugging over HTTP
```bash
python3 printer_credcheck.py ./hosts.txt --scheme http --verbose
```

### Output

The scan runs in four stages:
1. **Step 1** — expand the targets and port sweep them for listening HTTP services
2. **Step 2** — fingerprint every live service and assign it to a vendor module (or skip it)
3. **Step 3** — test that vendor's default accounts
4. **Step 4** — harvest address books, by export where the credentials worked and by
   unauthenticated read where they did not

Skipped endpoints are counted rather than listed; pass `--show-skipped` to see each one and
the reason every module rejected it.

Successful logins are written to `--success-file` in backtick-delimited format:

```text
# Format: AssetName`URI`Protocol`Port`Output
192.0.2.113`192.0.2.113`tcp`443`Successful Sharp MFP login with account 'Administrator' and password admin (HTTP 302)
```

#### Findings files

Two findings files are written in the same reporting format - `AssetName`, `URI`, `Protocol`,
`Port`, `Output` - so they drop straight into the client report. The `AssetName` is the same
`host:port` the successful-logins file uses, which needs to match an existing EngagementAsset.
Fields are backtick-delimited by default; pass `--findings-delimiter tab` for tab-delimited.
Each file is written only when it has at least one finding.

`--findings-file` (default `default_credentials.txt`) — one row per device/account still on a
vendor default. Each one is also printed on the console the moment it is found:

```text
# Format: AssetName`URI`Protocol`Port`Output
192.0.2.113`192.0.2.113`tcp`443`Default credentials in use - Sharp MFP accepts account 'Administrator' with default password 'admin'. Change the vendor default to a strong, unique password.
```

`--folder-findings-file` (default `scan_to_folder.txt`, requires `--export`) — one row per device
whose exported address book holds scan-to-folder (FTP/SMB) destinations. These store reusable
credentials so the MFP can drop scans onto an internal share unattended, so each is worth
reporting on its own. The finding names the destinations and whether a password is stored; the
password *values* stay in the exported CSV on disk and are never written into the finding:

```text
# Format: AssetName`URI`Protocol`Port`Output
192.0.2.113`192.0.2.113`tcp`443`Address book contains 2 scan-to-folder destination(s) storing reusable credentials for internal shares: [FTP] ftp.corp.example/scans (user: svc-scanner, password stored); [SMB] \\SHARESRV\share$ (user: EXAMPLE\svc-printer, password stored). Review whether each is required and rotate the service accounts.
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
