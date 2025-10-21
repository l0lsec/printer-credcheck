## ricohprint_defaultcredchecker.py

### Overview
This script tests Ricoh printers for default credentials (admin and supervisor with empty passwords) by sending authenticated web login requests. It can also export address books from printers with successful default admin credentials.

### Features
- **Ricoh Printer Detection**: Pre-checks each host to verify it's a Ricoh printer before testing credentials (reduces false positives)
- **Credential Testing**: Checks if printers still use default admin and supervisor credentials
- **Successful Login Export**: Automatically saves all successful logins to a tab-delimited file
- **Address Book Export**: Automatically exports address books from vulnerable printers (admin account only)
- **Email & Name Extraction**: Automatically parses exported address books and extracts all emails and names
- **Real-Time Progress**: Shows progress counter as tests complete
- **Concurrent Scanning**: Multi-threaded for fast scanning of multiple devices
- **Verbose Mode**: Detailed debugging output showing all HTTP requests/responses

### Default Accounts Tested
- **admin** (with blank password) - Can export address books if successful
- **supervisor** (with blank password) - Cannot export address books (limited privileges)

### How Ricoh Detection Works
To minimize false positives, the script first verifies each host is a Ricoh printer by:
1. Sending a GET request to `/web/guest/en/websys/webArch/mainFrame.cgi`
2. Checking for Ricoh-specific indicators in the response:
   - "RICOH" in the page content
   - "Web Image Monitor" (Ricoh's web interface name)
   - Ricoh-specific paths like `websys/webArch`, `/web/guest/`
   - Redirects to authentication pages like `authForm.cgi`
3. Only testing credentials on devices that pass this verification

This prevents testing credentials on non-Ricoh devices that might accept any username/password (causing false positives).

### Hosts file format
Provide one host or URL per line. Lines beginning with `#` and blank lines are ignored.
- Can be an IP/hostname (e.g., `10.10.62.20`)
- Can include a port (e.g., `10.10.62.22:8443`)
- Can be a full URL (e.g., `https://10.10.62.21`)

Example file:
```text
# Staging devices
10.10.62.20
https://10.10.62.21
10.10.62.22:8443
```

### Usage
```bash
python3 ricohprint_defaultcredchecker.py /path/to/hosts.txt [OPTIONS]
```

#### Arguments
- `hosts_file`: Path to the file with hosts/URLs (one per line)
- `--scheme {http,https}`: Default scheme if a line omits it (default: `https`)
- `--timeout <int>`: Request timeout in seconds for login requests (default: `10`)
- `--workers <int>`: Number of concurrent workers (default: `10`)
- `--verify`: Enable TLS certificate verification (disabled by default)
- `--export`: Export address books from printers with successful default credentials
- `--output-dir <path>`: Output directory for exported address books (default: current directory)
- `--export-timeout <int>`: Timeout in seconds for address book export requests (default: `30`)
- `--success-file <path>`: Output file for successful logins in tab-delimited format (default: `successful_logins.txt`)
- `--verbose`: Enable verbose output showing all HTTP requests and responses

### Examples

#### Basic credential check (no export)
```bash
python3 ricohprint_defaultcredchecker.py ./hosts.txt
```

#### Check credentials AND export address books
```bash
python3 ricohprint_defaultcredchecker.py ./hosts.txt --export
```

#### Export with custom timeout and output directory
```bash
python3 ricohprint_defaultcredchecker.py ./hosts.txt --export --export-timeout 60 --output-dir ./exports
```

#### Use HTTP and enable verbose debugging
```bash
python3 ricohprint_defaultcredchecker.py ./hosts.txt --scheme http --export --verbose
```

#### Scan with more workers and enable TLS verification
```bash
python3 ricohprint_defaultcredchecker.py ./hosts.txt --workers 20 --verify --export
```

#### Specify custom output file for successful logins
```bash
python3 ricohprint_defaultcredchecker.py ./hosts.txt --success-file ./results/logins.txt
```

### Output

The script runs in two stages:
1. **Stage 1**: Checks each host to verify it's a Ricoh printer
2. **Stage 2**: Tests credentials only on confirmed Ricoh printers

#### Basic credential check output
```text
Step 1: Checking if 5 host(s) are Ricoh printers...
Workers: 10
--------------------------------------------------------------------------------
✓ 10.10.62.20	Ricoh printer detected (found: RICOH, Web Image Monitor, /web/guest/)
✗ 10.1.96.25	SKIPPED: Not a Ricoh printer (no Ricoh indicators found in response)
✓ 10.10.62.21	Ricoh printer detected (redirect to auth page)
✗ 10.1.96.44	SKIPPED: Not a Ricoh printer (HTTP 404 - page not found)
✓ 10.10.62.22	Ricoh printer detected (found: RICOH, websys/webArch, /web/guest/)

--------------------------------------------------------------------------------
Step 2: Testing credentials on 3 confirmed Ricoh printer(s)...
Testing usernames: admin, supervisor
Total credential tests: 6
--------------------------------------------------------------------------------
[1/6] 10.10.62.20     admin           FAIL    status=302
[2/6] 10.10.62.20     supervisor      FAIL    status=302
[3/6] 10.10.62.21     admin           SUCCESS status=302
[4/6] 10.10.62.21     supervisor      SUCCESS status=302
[5/6] 10.10.62.22     admin           SUCCESS status=302
[6/6] 10.10.62.22     supervisor      FAIL    status=302
```

#### With address book export enabled
```text
Step 1: Checking if 3 host(s) are Ricoh printers...
Workers: 10
--------------------------------------------------------------------------------
✓ 10.10.62.20	Ricoh printer detected (found: RICOH, Web Image Monitor)
✓ 10.10.62.21	Ricoh printer detected (found: RICOH, /web/guest/)
✓ 10.10.62.22	Ricoh printer detected (redirect to auth page)

--------------------------------------------------------------------------------
Step 2: Testing credentials on 3 confirmed Ricoh printer(s)...
Testing usernames: admin, supervisor
Total credential tests: 6
--------------------------------------------------------------------------------
[1/6] 10.10.62.20     admin           FAIL    status=302
[2/6] 10.10.62.20     supervisor      FAIL    status=302
[3/6] 10.10.62.21     admin           SUCCESS status=302
[3/6] 10.10.62.21     EXPORT: SUCCESS: Exported to ./addressbook_10.10.62.21.txt
[4/6] 10.10.62.21     supervisor      SUCCESS status=302
[5/6] 10.10.62.22     admin           SUCCESS status=302
[5/6] 10.10.62.22     EXPORT: SUCCESS: Exported to ./addressbook_10.10.62.22.txt
[6/6] 10.10.62.22     supervisor      FAIL    status=302
```

**Note**: 
- **Stage 1** filters out non-Ricoh devices to prevent false positives
- **Stage 2** progress counter `[X/Y]` shows current progress in real-time as tests complete
- Results appear immediately as workers finish (not sorted by host during execution)
- Address books are only exported for successful admin logins
- The supervisor account has limited privileges and cannot export address books

#### Final summary
```text
Total Hosts: 5	Ricoh Printers: 3	Skipped: 2
Credential Tests: 6	SUCCESS: 4	FAIL: 2	ERROR: 0	EXPORTED: 2

Successful logins saved to: successful_logins.txt (4 entry/entries)

Extracting emails from address books...
Extracted 15 unique email(s) to ./extracted_emails.txt

Extracting names from address books...
Extracted 18 unique name(s) to ./extracted_names.txt
```

#### Successful Logins File Format
The `successful_logins.txt` file contains tab-delimited entries for all successful default credential logins:
```text
# Format: AssetName	URI	Protocol	Port	Output
10.10.62.21	10.10.62.21	tcp	443	Successful login with username 'admin' and blank password (HTTP 302)
10.10.62.21	10.10.62.21	tcp	443	Successful login with username 'supervisor' and blank password (HTTP 302)
10.10.62.22:8080	10.10.62.22:8080	tcp	8080	Successful login with username 'admin' and blank password (HTTP 302)
192.168.1.50	192.168.1.50	tcp	80	Successful login with username 'admin' and blank password (HTTP 302)
```

**Format Details:**
- **AssetName**: The host/IP (matches EngagementAsset)
- **URI**: The host/IP with optional port
- **Protocol**: `tcp` (web services use TCP)
- **Port**: `443` for HTTPS, `80` for HTTP, or custom port if specified
- **Output**: Description of the successful login including username and HTTP status

### Result interpretation
- **SUCCESS**: Login succeeded with default credentials (HTTP 302 redirect to mainFrame.cgi)
- **FAIL**: Authentication failed (redirect to authForm.cgi or "Authentication has failed" in response)
- **ERROR: HTTP <code>**: Unexpected HTTP status code returned
- **ERROR: <exception>**: Network or TLS error occurred while making the request
- **EXPORT: SUCCESS**: Address book successfully exported to file
- **EXPORT: ERROR**: Address book export failed (details included in message)

### Address Book Export

When `--export` is enabled, the script performs a three-step process for each printer with successful default credentials:

1. **Login**: Authenticate with default credentials (admin/empty password)
   - Captures `wimsesid` and `risessionid` cookies from 302 response

2. **Navigate to Address List**: Access the address book section
   - Gets a fresh `risessionid` specific to the address book module

3. **Export Data**: Download the address book entries
   - Saves data to `addressbook_<hostname>.txt` in JSON-like array format

#### Exported Data Format
Address books are saved as plain text files containing arrays of contact entries:
```
[[28,1,'00001','Accounting Scans','','1665508224#Oct 11,2022 12:10 PM','','\\\\DC-12DC\\VC_Data\\Scans'],
 [29,2,'00002','Corp Acctng','','0000000000#--- --,---- --:-- --','',''],
 [30,1,'00003','John Doe','','1653592843#May 26,2022 02:20 PM','john.doe@example.com','']]
```

Each entry contains: ID, type, number, name, description, timestamp, email, and network path.

#### Automatic Email & Name Extraction

After all address books are exported, the script automatically parses them and extracts:

1. **Emails**: Extracts all email addresses (index 6 in each entry)
   - Basic validation: must contain `@` and `.`
   - Duplicates are automatically removed
   - Saved to `extracted_emails.txt` (one email per line, sorted alphabetically)

2. **Names**: Extracts all contact names (index 3 in each entry)
   - Filters out empty values
   - Duplicates are automatically removed  
   - Saved to `extracted_names.txt` (one name per line, sorted alphabetically)

**Example extracted_emails.txt:**
```
accounting@example.com
hr@example.com
john.doe@example.com
sales@example.com
```

**Example extracted_names.txt:**
```
Accounting Scans
Corp Acctng
HR Department
John Doe
Sales Team
```

This automated extraction happens only when `--export` is used and at least one address book is successfully exported.

### Verbose Mode

With `--verbose`, the script displays detailed information about each HTTP transaction:

```text
================================================================================
[LOGIN REQUEST] 10.9.65.127
================================================================================
POST http://10.9.65.127/web/guest/en/websys/webArch/login.cgi

Headers:
  User-Agent: Mozilla/5.0...
  Content-Type: application/x-www-form-urlencoded
  ...

Cookies:
  risessionid: 012450409054315
  cookieOnOffChecker: on
  wimsesid: --

Form Data:
  userid: YWRtaW4=
  password: 
  ...
================================================================================

================================================================================
[LOGIN RESPONSE] 10.9.65.127
================================================================================
Status: 302

Response Headers:
  Set-Cookie: risessionid=066124883298009;HttpOnly
  Set-Cookie: wimsesid=178962527;path=/;HttpOnly
  Location: /web/entry/en/websys/webArch/mainFrame.cgi
  ...

Response Body (105 bytes):
<html><head><title>302 Moved Temporarily</title></head>...
================================================================================

[DEBUG] 10.9.65.127: Manually parsed Set-Cookie: {'risessionid': '066124883298009', 'wimsesid': '178962527'}
[DEBUG] 10.9.65.127: Final captured cookies for session: {...}
```

This is useful for:
- Troubleshooting authentication issues
- Verifying cookie capture
- Understanding the authentication flow
- Debugging network problems

### Exit codes
- `0`: At least one host produced a `SUCCESS` or `FAIL` result (requests completed successfully)
- `1`: No hosts were found in the file, or all attempts resulted in errors

### Security Notes and Best Practices

⚠️ **Important Security Considerations:**

1. **Legal Authorization**: Only scan devices you own or have explicit permission to test
2. **Network Impact**: Be mindful of the load on production systems
3. **Credential Testing**: This script tests for default credentials which is a security assessment activity
4. **Data Handling**: Exported address books may contain sensitive contact information (emails, names, network paths)
5. **TLS Verification**: Disabled by default to handle self-signed certificates - use `--verify` in trusted environments

**Recommendations:**
- Store exported address books and extracted files securely
- Notify device administrators of findings
- Delete exported data (`addressbook_*.txt`, `extracted_emails.txt`, `extracted_names.txt`) after analysis
- Use this tool as part of a broader security assessment
- Respect rate limits and timeout settings on production networks

### Technical Notes

#### Authentication Flow
The script implements the Ricoh printer web interface authentication:
1. Default credentials: Username `admin` (base64 encoded as `YWRtaW4=`), empty password
2. Successful login returns HTTP 302 redirect with session cookies
3. The script properly handles duplicate cookie values in Set-Cookie headers
4. Address book access requires session-specific `risessionid` cookie

#### Cookie Handling
The script includes special logic to handle Ricoh's cookie implementation:
- Parses Set-Cookie headers manually to capture the correct session IDs
- Filters out reset values (`wimsesid=--`)
- Maintains separate cookies for different application sections

#### Multi-threading
- Uses `ThreadPoolExecutor` for concurrent requests
- Default: 10 workers (adjustable with `--workers`)
- Each host is processed independently

### Troubleshooting

**Issue**: Login shows SUCCESS but export fails
- Try increasing `--export-timeout` (some printers are slow)
- Use `--verbose` to see detailed request/response data
- Verify the printer has an address book configured

**Issue**: All requests timeout
- Increase `--timeout` value
- Check network connectivity to printers
- Verify the scheme (http vs https) is correct

**Issue**: TLS/SSL errors
- Use `--scheme http` if printers don't support HTTPS
- Use `--verify` flag only if you trust the certificates
- Check if printers are on correct ports

**Issue**: Exported files are empty or contain error messages
- Printer may have logged out the session (rare race condition)
- Use `--verbose` to see what data was received
- Verify printer firmware version is compatible

**Issue**: Email/name extraction shows 0 results despite successful exports
- Verify the `addressbook_*.txt` files contain data in the expected format
- The extraction expects array format: `[[id, type, number, name, ..., email, ...], ...]`
- Use `--verbose` to see the raw export data
- Some printers may use a different address book format (not yet supported)

### Requirements
- Python 3.6+
- `requests` library (`pip install requests`)

### License
Use responsibly and only on systems you own or have permission to test.
