# MiniRecon v3.0 Security Platform

MiniRecon is an educational Python framework for authorized web reconnaissance, directory discovery, parameter-aware fuzzing, HTTP intelligence, risk scoring, AI-assisted analysis, and visualization.

MiniRecon is for use only on systems you own or have explicit written permission to test. Unauthorized use is illegal.

## Install

```powershell
git clone https://github.com/<your-username>/Mini_recon.git
cd Mini_recon
pip install -r requirements.txt
python main.py --check-setup
```

Optional AI analysis uses NVIDIA NIM through an OpenAI-compatible API. Create a local `.env` file:

```text
NVIDIA_API_KEY=paste_your_key_here
```

Never hardcode API keys. `.env` is ignored by git. `.env.example` is only a template.

## Quick Start

Run a full authorized scan:

```powershell
python main.py --target example.com --mode all --ports 80,443 --output reports\example.json
```

Run recon only:

```powershell
python main.py --target example.com --mode recon --ports 80,443
```

Fuzz a specific endpoint:

```powershell
python main.py --target example.com --mode fuzz --fuzz-url "https://example.com/search?q=test&id=1"
```

Generate an HTML report:

```powershell
python main.py --target example.com --mode all --ports 80,443 --output reports\example.html
```

Launch the desktop GUI:

```powershell
python main.py --gui
```

## Modes

- `recon`: IP resolution, ports, subdomains, HTTP intelligence, TLS, DNS/email, CVE lookup
- `discover`: directory and file discovery
- `fuzz`: parameter-aware payload testing
- `all`: runs recon, discovery, and fuzzing

## Key Flags

- `--check-setup`: verify Python version, required packages, and wordlist files
- `--version`: print the MiniRecon version
- `--target`: target domain, host, URL, or fuzz URL
- `--targets-file`: scan multiple targets from a text file, one per line
- `--mode`: `recon`, `discover`, `fuzz`, or `all`
- `--gui`: launch the desktop GUI
- `--output`: save `.json`, `.txt`, or `.html` report
- `--save-report`: preserve the latest auto report as important
- `--ai`: enable NVIDIA NIM AI analyst manually
- `--visualize`: generate `output/scan_graph.png`
- `--stealth`: enable request pacing and browser User-Agent rotation
- `--passive`: passive recon only, avoiding direct target server contact
- `--active`: active recon only, using direct scanning and probing
- `--recon-mode`: `all`, `active`, or `passive`
- `--bypass-waf`: enable authorized WAF behavior-testing payload variants
- `--wayback`: collect historical URLs and parameters from the Wayback CDX API
- `--js-analysis`: analyze linked JavaScript for endpoints, routes, and secret-like values
- `--find-origin`: collect origin IP candidates and compare HTTP fingerprints
- `--verify`: verify supported fuzzing findings and CORS behavior after fuzzing
- `--auth-test`: detect login forms, JWT issues, session cookie flags, and basic rate limiting
- `--fingerprint`: detect web technologies and map product/version hints to CVEs
- `--bounty-report`: generate a HackerOne-style Markdown bounty report skeleton
- `--learn`: add professional text-only learning notes and progress tracking to reports
- `--proxy`: route HTTP requests through a proxy, for example `http://127.0.0.1:8080`
- `--ca-cert`: use a custom CA certificate for HTTPS requests
- `--scope`: comma-separated allowed domains; out-of-scope requests are blocked
- `--resume`: continue from `output/scan_state.json`
- `--recursive`: recursively scan discovered directories
- `--recursive-depth`: recursive directory depth from 1 to 4
- `--ports`: comma-separated ports or `all`
- `--range`: port range, for example `1-1000`
- `--dir-threads`, `--fuzz-threads`, `--subdomain-threads`, `--port-threads`: tune worker counts
- `--http-timeout`, `--dns-timeout`, `--port-timeout`, `--retries`: tune network timeouts and retries

## Examples

Passive recon only:

```powershell
python main.py --target example.com --mode recon --passive
```

Active recon only:

```powershell
python main.py --target example.com --mode recon --active --ports 80,443
```

Use a strict scope:

```powershell
python main.py --target example.com --mode all --scope example.com,api.example.com
```

Proxy traffic through a local testing proxy:

```powershell
python main.py --target example.com --mode all --proxy http://127.0.0.1:8080 --ca-cert certs\proxy-ca.pem
```

Use WAF behavior testing in the fuzzer:

```powershell
python main.py --target example.com --mode fuzz --fuzz-url "https://example.com/search?q=test" --bypass-waf
```

Scan multiple authorized targets:

```powershell
python main.py --targets-file targets.txt --mode recon --resume
```

Run with AI analysis:

```powershell
python main.py --target example.com --mode all --ports 80,443 --ai
```

Run modern intelligence, verification, bounty, and learn-mode reporting together:

```powershell
python main.py --target example.com --mode all --wayback --js-analysis --fingerprint --verify --bounty-report --learn --output reports\example.html
```

## What MiniRecon Does

- Resolves target IPs and scans selected TCP ports.
- Brute-forces subdomains from `wordlists/subdomains.txt`.
- Labels findings as `[ACTIVE]` or `[PASSIVE]` where applicable.
- Checks HTTP headers, cookies, redirect behavior, framework hints, and `robots.txt`.
- Checks TLS certificate issuer, expiry, and Subject Alternative Names.
- Collects DNS/email intelligence including SPF, DMARC, and MX records.
- Looks up known CVEs from detected HTTP server technology.
- Collects historical URLs, parameters, and old endpoints from Wayback data.
- Analyzes linked JavaScript for endpoints, routes, and secret-like values.
- Finds origin IP candidates and compares HTTP fingerprints.
- Discovers directories and sensitive files from `wordlists/dirs.txt`.
- Supports recursive directory discovery.
- Fuzzes each URL parameter individually using `wordlists/payloads.txt`.
- Classifies payloads into SQLi, XSS, LFI, SSTI, and generic categories.
- Detects anomalous fuzzing responses using status, length, and body similarity.
- Verifies supported SQLi, XSS, and CORS signals.
- Checks authentication surfaces including login forms, JWT-like tokens, cookies, and basic rate limiting.
- Builds bug bounty context, remediation notes, and optional Markdown skeletons.
- Adds optional text-only Learn Mode notes and progress tracking.
- Calculates LOW, MEDIUM, HIGH, or CRITICAL risk scores.
- Saves scan state after each module for resume support.
- Auto-saves reports and can preserve important reports.
- Saves reports as JSON, TXT, or dark-themed HTML.
- Optionally creates a NetworkX/Matplotlib graph visualization.

## Infrastructure Features

### Scope Enforcement

Use `--scope` to hard-block requests outside approved domains:

```powershell
python main.py --target example.com --mode all --scope example.com
```

Blocked attempts are recorded in scan data under `scope_blocks`.

### Proxy and Custom CA

HTTP-based modules accept proxy and certificate settings:

```powershell
python main.py --target example.com --mode all --proxy http://127.0.0.1:8080 --ca-cert certs\ca.pem
```

### Resume Support

MiniRecon writes progress to:

```text
output/scan_state.json
```

Use `--resume` to continue a matching target and mode from the last completed module.

### WAF Detection and Payload Variants

The fuzzer can detect common WAF signals such as Cloudflare, Akamai, AWS WAF, Imperva, Sucuri, and ModSecurity. With `--bypass-waf`, it adds conservative authorized comparison variants such as double URL encoding, case switching, whitespace mutation, duplicate parameters, GET/POST comparison, and encoding rotation.

## Project Structure

```text
project/
|-- main.py
|-- bypass/
|   |-- __init__.py
|   |-- origin_discovery.py
|   `-- waf_bypass.py
|-- core/
|   |-- __init__.py
|   |-- ai_module.py
|   |-- analyzer.py
|   |-- bounty.py
|   |-- cve_lookup.py
|   |-- dns_intel.py
|   |-- http_intel.py
|   |-- learn.py
|   |-- stealth.py
|   |-- suggestions.py
|   |-- tls_intel.py
|   `-- visualize.py
|-- discovery/
|   |-- __init__.py
|   `-- dir_enum.py
|-- fuzzing/
|   |-- __init__.py
|   `-- fuzzer.py
|-- gui/
|   |-- __init__.py
|   |-- app.py
|   |-- config.py
|   |-- theme.py
|   |-- frames/
|   |   |-- dashboard_frame.py
|   |   |-- export_frame.py
|   |   |-- reports_frame.py
|   |   |-- scan_frame.py
|   |   |-- settings_frame.py
|   |   `-- wordlist_frame.py
|   `-- widgets/
|       |-- finding_card.py
|       |-- log_panel.py
|       |-- nav_sidebar.py
|       `-- stat_card.py
|-- intelligence/
|   |-- __init__.py
|   |-- auth_tester.py
|   |-- fingerprint.py
|   |-- js_analyzer.py
|   `-- wayback.py
|-- output/
|   |-- __init__.py
|   `-- report.py
|-- recon/
|   |-- __init__.py
|   |-- portscan.py
|   `-- subdomain.py
|-- utils/
|   |-- __init__.py
|   |-- report_manager.py
|   |-- scope_checker.py
|   `-- state_manager.py
|-- verification/
|   |-- __init__.py
|   |-- cors_tester.py
|   |-- sqli_verifier.py
|   |-- verifier.py
|   `-- xss_verifier.py
|-- wordlists/
|   |-- dirs.txt
|   |-- payloads.txt
|   `-- subdomains.txt
|-- .env.example
|-- .gitignore
|-- README.md
`-- requirements.txt
```

## Direct Module Commands

Directory discovery:

```powershell
python discovery\dir_enum.py https://example.com --threads 20
```

Parameter-aware fuzzing:

```powershell
python fuzzing\fuzzer.py "https://example.com/search?q=test&id=1" --threads 10
```

Subdomain intelligence:

```powershell
python recon\subdomain.py example.com --threads 20
```

Port scan:

```powershell
python recon\portscan.py example.com --ports 80,443
```

## Example Output Shape

```text
[Recon]
- IP: 93.184.216.34
- Open Ports: [ACTIVE] 80 (HTTP), [ACTIVE] 443 (HTTPS)
- Subdomains: [PASSIVE] www.example.com, [ACTIVE] api.example.com

[Directory Discovery]
- /admin -> redirects to /login [ADMIN PANEL LIKELY]
- /backup.zip -> 200 OK [SENSITIVE FILE LIKELY]

[Fuzzing]
PARAM: q | PAYLOAD: ' OR 1=1-- | STATUS: 403 | LENGTH: 5474
Parameter 'q' -> 3 vulnerabilities found

[Risk Score]
Score: 12
Level: CRITICAL
```

## Notes

Fuzzing findings are signals, not proof. Confirm manually, stay in scope, and keep request rates appropriate for the system you are authorized to test.
