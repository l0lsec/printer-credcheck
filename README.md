## printer-credcheck

### Overview
Tests network printers and MFPs for vendor default credentials, and exports address books
from devices that still have them. Point it at a host, a file of hosts, or a whole subnet.

The tool is vendor-agnostic: each printer family lives in its own module under `vendors/`.
Every endpoint is port probed and fingerprinted before a single credential is sent, so
unrelated HTTP services on the range are identified and skipped rather than logged into.

Supported today:

| Vendor | Module | Default accounts tested | Address book export |
|---|---|---|---|
| Ricoh (Web Image Monitor) | `vendors/ricoh.py` | `admin` / blank, `supervisor` / blank | Yes |
| Sharp (MX / BP series MFP) | `vendors/sharp.py` | `Administrator` / `admin` | Yes (CSV) |

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
- **Successful login export**: writes all successful logins to a backtick-delimited file
- **Address book export**: pulls address books from vulnerable devices (supported vendors)
- **Email & name extraction**: parses exported address books into email and name lists
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

> **Lockout note:** Sharp MFPs can be configured to lock an account after consecutive failed
> logins ("A Warning when Login Fails", typically 3 attempts / 5 minutes). Each account in
> `--accounts` costs one attempt per host, so keep the list short on production fleets.

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

#### Check credentials and export address books
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

The scan runs in three stages:
1. **Step 1** — expand the targets and port sweep them for listening HTTP services
2. **Step 2** — fingerprint every live service and assign it to a vendor module (or skip it)
3. **Step 3** — test that vendor's default accounts, then export where supported

Skipped endpoints are counted rather than listed; pass `--show-skipped` to see each one and
the reason every module rejected it.

Successful logins are written to `--success-file` in backtick-delimited format:

```text
# Format: AssetName`URI`Protocol`Port`Output
192.0.2.113`192.0.2.113`tcp`443`Successful Sharp MFP login with account 'Administrator' and password admin (HTTP 302)
```

Exported address books are saved per vendor - `addressbook_ricoh_<host>.txt` for Ricoh's
array payload, `addressbook_sharp_<host>.csv` for Sharp's CSV - and the parsed contacts land
in `extracted_emails.txt` and `extracted_names.txt` in the output directory.

### Adding a vendor
1. Create `vendors/<vendor>.py` with a class that subclasses `PrinterModule` from `vendors/base.py`.
2. Implement `fingerprint()` and `attempt_login()`. Implement `export_address_book()` and
   `extract_contacts()` too if you have a captured export request, and set `supports_export = True`.
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
