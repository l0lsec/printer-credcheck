## ricohprint_defaultadmincheck.py

### Overview
This script sends a default Ricoh printer web login POST to each host from a provided file and reports whether authentication succeeded, failed, or encountered an error.

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
python3 ricohprint_defaultadmincheck.py /path/to/hosts.txt [--scheme https] [--timeout 10] [--workers 10] [--verify]
```

#### Arguments
- `hosts_file`: Path to the file with hosts/URLs (one per line)
- `--scheme {http,https}`: Default scheme if a line omits it (default: `https`)
- `--timeout <int>`: Request timeout in seconds (default: `10`)
- `--workers <int>`: Number of concurrent workers (default: `10`)
- `--verify`: Enable TLS certificate verification (disabled by default). When omitted, TLS verification is off and the script suppresses the related warning.

### Examples
- Minimal run (default https, 10 workers, 10s timeout, TLS verification off):
```bash
python3 ricohprint_defaultadmincheck.py ./hosts.txt
```

- Specify concurrency and enable TLS verification:
```bash
python3 ricohprint_defaultadmincheck.py ./hosts.txt --workers 20 --verify
```

- Use HTTP for hosts without a scheme:
```bash
python3 ricohprint_defaultadmincheck.py ./hosts.txt --scheme http
```

### Output
Per-host line with outcome and HTTP status:
```text
10.10.62.20	FAIL	status=200
10.10.62.21	SUCCESS	status=200
10.10.62.22	ERROR: HTTP 404	status=404
```

A final tally is printed:
```text
Total: 3	SUCCESS: 1	FAIL: 1	ERROR: 1
```

### Result interpretation
- **SUCCESS**: HTTP 200 and the response does not contain the string `Authentication has failed`.
- **FAIL**: Response body contains `Authentication has failed`.
- **ERROR: HTTP <code>**: Non-200 HTTP status code returned.
- **ERROR: <exception>**: Network or TLS error occurred while making the request.

### Exit codes
- `0`: At least one host produced a `SUCCESS` or `FAIL` result (i.e., requests completed and were interpretable).
- `1`: No hosts were found in the file, or all attempts resulted in errors (no `SUCCESS`/`FAIL`).

### Notes and caveats
- TLS verification is disabled by default to facilitate scanning devices with self-signed certificates. Use `--verify` in trusted networks when you need certificate validation.
- The script uses the request metadata and default credentials provided. If those change, update the script accordingly.
- Be mindful of legal and policy constraints when testing authentication against devices you do not own or administer.


