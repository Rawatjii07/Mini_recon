# MiniRecon v3.0 College Project Report Notes

MiniRecon is for use only on systems you own or have explicit written permission to test. Unauthorized use is illegal.

## Section 1: Project Introduction

### 1a. What The Project Does

[MiniRecon v3.0]
What: MiniRecon is a Python security assessment platform that performs authorized reconnaissance, directory discovery, parameter fuzzing, HTTP/TLS/DNS intelligence, Wayback and JavaScript analysis, origin discovery, verification, reporting, AI-assisted summaries, GUI operation, and learn-mode explanations.
Why: It was built to combine many common web security testing steps into one coordinated workflow instead of requiring a student or tester to run many disconnected tools manually.
Where: The main orchestration is in `main.py`, with scanning modules under `recon/`, `discovery/`, `fuzzing/`, `core/`, `intelligence/`, `bypass/`, and `verification/`.
When: A user runs it during an authorized security assessment, bug bounty triage, student project demo, or defensive review.
How: `main.py` reads CLI flags, calls selected modules in order, stores results in `scan_data`, builds risk/suggestions/bounty/learn context, then prints and saves reports.
(found in: `main.py`)

### 1b. Problem Solved

[Manual Security Workflow Automation]
What: The project automates repeated manual tasks such as port scanning, subdomain checks, HTTP header review, hidden path discovery, payload testing, verification, and report generation.
Why: These tasks are worth automating because they are repetitive, error-prone, and easier to compare when results follow one common structure.
Where: Automation is spread across `run_recon`, `run_discovery`, `run_fuzzing`, `run_verification`, and report functions in `main.py`.
When: It is useful at the beginning and middle of a web assessment, when the tester needs quick coverage and organized findings.
How: Each module returns dictionaries or dataclasses that are converted into a shared report structure.
(found in: `main.py`, `core/analyzer.py`, `output/report.py`)

### 1c. Target User

[Students]
What: Students can use the tool to understand how recon, discovery, fuzzing, verification, and reporting connect in one project.
Why: Learn Mode explains findings using analogies, next steps, thought experiments, and report-quality checks.
Where: Learn Mode is implemented in `core/learn.py` and activated by `--learn`.
When: A student would use it while learning web security concepts or preparing a college project report.
How: It reads bounty findings, creates educational text blocks, and saves progress to `output/learn_progress.json`.
(found in: `core/learn.py`, `main.py`)

[Bug Bounty Hunters]
What: Bug bounty users benefit from `--bounty-report`, verification, fingerprinting, Wayback URL discovery, JS endpoint extraction, and report skeletons.
Why: These features reduce the time between finding a signal and preparing a structured report.
Where: Bounty logic is in `core/bounty.py`; verification is in `verification/`; intelligence is in `intelligence/`.
When: A hunter would use it after choosing an in-scope target and before manually validating final impact.
How: The tool converts scan results into severity, typical bounty context, remediation, and HackerOne-style skeletons.
(found in: `core/bounty.py`, `verification/verifier.py`, `main.py`)

[Security Professionals]
What: Professionals can use the platform for authorized scanning, proxy routing, scope enforcement, report management, and HTML exports.
Why: Scope control, custom CA support, passive/active modes, and saved reports make the workflow safer and more organized.
Where: Scope logic is in `utils/scope_checker.py`, reports are handled by `utils/report_manager.py`, and proxy/CA settings are passed from `main.py`.
When: A professional would use it during controlled internal assessment or defensive review.
How: CLI flags configure scope, proxy, CA certificate, active/passive behavior, and output formats.
(found in: `main.py`, `utils/scope_checker.py`, `utils/report_manager.py`)

### 1d. Differences From Basic Tools

[Integrated GUI]
What: The project includes a Tkinter desktop GUI with scan controls, tabs, dashboard, reports, export, settings, and wordlist editing.
Why: Basic command-line tools may be harder for non-technical users to operate or present in a college demo.
Where: GUI files are under `gui/`.
When: It runs when the user starts `python main.py --gui`.
How: The GUI launches the CLI as a subprocess, streams output through a queue, and loads the generated JSON report.
(found in: `gui/app.py`, `gui/frames/scan_frame.py`)

[AI Analysis]
What: AI analysis can summarize ports, directories, fuzzing, headers, and the final scan.
Why: It helps convert raw technical output into readable security interpretation.
Where: Implemented in `core/ai_module.py`.
When: It runs only when `--ai` is used and `NVIDIA_API_KEY` exists in `.env`.
How: It uses the OpenAI-compatible NVIDIA NIM endpoint at `https://integrate.api.nvidia.com/v1`.
(found in: `core/ai_module.py`, `main.py`)

[WAF Testing And Payload Mutation]
What: The fuzzer can detect WAF-like responses and generate conservative payload variants.
Why: Basic fuzzers may stop at blocked requests without comparing encoded or mutated variants.
Where: Implemented in `bypass/waf_bypass.py` and used by `fuzzing/fuzzer.py`.
When: Detection happens during fuzzing; extra variants activate with `--bypass-waf`.
How: It checks headers/status/body markers and generates encoded, case-switched, whitespace, and duplicate-parameter variants.
(found in: `bypass/waf_bypass.py`, `fuzzing/fuzzer.py`)

[FIFO Report Management]
What: Auto reports and saved reports are stored separately with FIFO cleanup.
Why: It prevents unlimited report growth while protecting important reports from normal auto-report rotation.
Where: Implemented in `utils/report_manager.py`.
When: Auto-save happens after every scan; saved reports are created with `--save-report` or from the GUI reports page.
How: HTML reports are sorted by creation time, and the oldest report is deleted when the limit is exceeded.
(found in: `utils/report_manager.py`, `main.py`, `gui/frames/reports_frame.py`)

## Section 2: Project Overview

### 2a. Modules And Folders

[main.py]
What: CLI entry point and orchestrator for all scan phases.
Why: It centralizes flag parsing, scan order, state saving, reporting, and mode decisions.
Where: It calls modules from every scanner folder and sends final results to `output/report.py` and `utils/report_manager.py`.
When: It runs for every CLI scan and also launches the GUI when `--gui` is used.
How: It uses `argparse`, builds `scan_data`, calls `run_*` functions, and saves reports.
(found in: `main.py`)

[recon/]
What: Contains TCP port scanning and subdomain brute-forcing.
Why: Recon is separated because it discovers the target surface before deeper checks.
Where: Output goes into `scan_data["ports"]` and `scan_data["subdomains"]`.
When: It runs in `recon` or `all` mode.
How: `main.py` calls `scan_ports` and `brute_force_subdomains`.
(found in: `recon/portscan.py`, `recon/subdomain.py`, `main.py`)

[core/]
What: Contains shared intelligence, AI, analysis, bounty, learn, suggestions, TLS, DNS, CVE lookup, and visualization logic.
Why: These features support multiple scan modes and reporting.
Where: Outputs include `http_intel`, `tls_certificate`, `dns_intel`, `known_cves`, risk, suggestions, bounty context, learn mode, and graph images.
When: Core functions run during recon, reporting, AI, bounty, learn, or visualization stages.
How: `main.py` imports and calls the required core functions based on flags and modes.
(found in: `core/`)

[discovery/]
What: Performs directory and file discovery from `wordlists/dirs.txt`.
Why: Hidden paths can expose admin panels, backups, configs, logs, or API documentation.
Where: Results go to `scan_data["directories"]` and report section `directory_discovery`.
When: It runs in `discover` or `all` mode when active scanning is enabled.
How: It builds URLs, sends threaded GET requests, classifies risky paths, and optionally recurses into found directories.
(found in: `discovery/dir_enum.py`, `main.py`)

[fuzzing/]
What: Sends payloads to URL parameters and compares responses.
Why: It tests whether parameters react suspiciously to SQLi, XSS, LFI, SSTI, SSRF, XXE, and redirect-style payloads.
Where: Results go to `scan_data["fuzzing"]` and report section `fuzzing`.
When: It runs in `fuzz` or `all` mode when active scanning is enabled.
How: It extracts parameters, gets baselines, sends payloads with threads, compares status/length/body similarity, and classifies risk.
(found in: `fuzzing/fuzzer.py`, `main.py`)

[intelligence/]
What: Contains Wayback, JavaScript analysis, fingerprinting, and authentication testing.
Why: These modules gather context that basic port/path scans miss.
Where: Outputs go to `wayback`, `js_analysis`, `fingerprint`, and `auth_test` report sections.
When: They run only when their flags are enabled.
How: `main.py` calls each module through `run_wayback`, `run_js_analysis`, `run_fingerprint`, and `run_auth_test`.
(found in: `intelligence/`, `main.py`)

[bypass/]
What: Contains WAF behavior helpers and origin IP discovery.
Why: It supports testing blocked responses and identifying possible origin servers behind protective layers.
Where: WAF helpers affect fuzzing; origin results go to `scan_data["origin_discovery"]`.
When: WAF payload expansion runs during fuzzing with `--bypass-waf`; origin discovery runs with `--find-origin`.
How: It uses header/body WAF markers, payload transformations, DNS/crt.sh/DNSDumpster candidates, and fingerprint comparison.
(found in: `bypass/waf_bypass.py`, `bypass/origin_discovery.py`)

[verification/]
What: Verifies SQLi, XSS, and CORS signals.
Why: Verification reduces false positives from raw fuzzing anomalies.
Where: Results go to `scan_data["verification"]`.
When: It runs after fuzzing when `--verify` is enabled in `fuzz` or `all` mode.
How: It sends controlled confirmation requests and records confidence/evidence.
(found in: `verification/`, `main.py`)

[utils/]
What: Contains scope enforcement, resume state, and report management helpers.
Why: These utilities keep safety, persistence, and file management separate from scanners.
Where: Scope blocks go into `scan_data["scope_blocks"]`; state goes to `output/scan_state.json`; reports go to `output/reports/`.
When: Scope is used during HTTP/DNS-related actions, state saves after modules, and report management runs after scans.
How: `main.py` creates `ScopeChecker`, calls `save_state`, and calls report manager functions.
(found in: `utils/`)

[gui/]
What: Tkinter desktop interface with pages, widgets, theme, and local settings.
Why: It gives users a visual way to run and inspect scans.
Where: It reads/writes GUI settings in `output/gui_settings.json` and reads scan output from `output/gui_latest.json`.
When: It starts with `python main.py --gui`.
How: It starts `main.py` as a subprocess and streams logs into a GUI queue.
(found in: `gui/`)

[wordlists/]
What: Contains subdomain names, directory paths, and fuzz payloads.
Why: The scanner needs known candidate names and payloads instead of random guessing.
Where: Loaded by `recon/subdomain.py`, `discovery/dir_enum.py`, and `fuzzing/fuzzer.py`.
When: Used during subdomain, discovery, and fuzzing stages.
How: Each file is read line-by-line, ignoring blank lines and comments.
(found in: `wordlists/`)

### 2b. Overall Data Flow

[CLI Data Flow]
What: Input flags become module decisions, module outputs become `scan_data`, and `scan_data` becomes reports.
Why: A shared dictionary makes it possible for later modules and report builders to reuse earlier findings.
Where: The data flow is implemented in `run_target`.
When: The handoff happens after each selected module and again before final reporting.
How: `run_target` calls modules in this order: recon/HTTP/TLS/DNS, Wayback, JS, origin, discovery, fuzzing, verification, auth, fingerprint, risk, suggestions, bounty, learn, AI, visualization, report saving.
(found in: `main.py`)

### 2c. Two Ways To Run

[CLI]
What: Run scans with commands such as `python main.py --target example.com --mode all`.
Why: CLI is best for repeatable scans, scripts, and exact flag control.
Where: CLI parser is in `main.py`.
When: Use it for professional or automated workflows.
How: `argparse` reads flags and directly calls scan functions.
(found in: `main.py`)

[GUI]
What: Run `python main.py --gui` to open the Tkinter interface.
Why: GUI is best for demonstrations, visual review, and easier report browsing.
Where: GUI launcher is in `gui/app.py`.
When: Use it when the user wants buttons, tabs, logs, and report views.
How: GUI starts a subprocess command and loads JSON output after the scan.
(found in: `main.py`, `gui/app.py`, `gui/frames/scan_frame.py`)

### 2d. External APIs And Services

[NVIDIA NIM OpenAI-Compatible API]
What: Provides AI analysis for scan data.
Why: It turns raw scan results into professional explanations.
Where: Called in `core/ai_module.py`.
When: Only when `--ai` is enabled and `NVIDIA_API_KEY` is set.
How: `OpenAI(base_url="https://integrate.api.nvidia.com/v1")` sends chat prompts.
(found in: `core/ai_module.py`)

[Wayback CDX API]
What: Provides archived URLs and historical endpoint data.
Why: Old URLs can reveal forgotten endpoints and parameters.
Where: Called in `intelligence/wayback.py`.
When: It runs when `--wayback` is enabled.
How: Requests are sent to the CDX API and parsed into URLs, params, old endpoints, and fuzzer targets.
(found in: `intelligence/wayback.py`)

[NVD CVE API]
What: Provides known CVE hints for detected technologies.
Why: Version or server hints can map to known public vulnerabilities.
Where: Called in `core/cve_lookup.py`.
When: During HTTP intelligence and fingerprinting.
How: It queries NVD, extracts severity/description, and stores CVE hints in `known_cves`.
(found in: `core/cve_lookup.py`, `intelligence/fingerprint.py`)

[crt.sh And DNSDumpster]
What: Provide candidate origin IP or certificate-related information.
Why: They can reveal public IP candidates related to a protected domain.
Where: Called in `bypass/origin_discovery.py`.
When: It runs with `--find-origin`.
How: It collects candidate IPs and compares fingerprints against the target host.
(found in: `bypass/origin_discovery.py`)

## Section 3: Features List

### Reconnaissance Features

[TCP Port Scanner]
What: Scans selected TCP ports and guesses service names.
Why: Open ports reveal exposed services and attack surface.
Where: Applies to the target host and stores results in `ports`.
When: Runs in `recon` or `all` mode when active scanning is enabled.
How: Uses sockets, queues, worker threads, and optional banner grabbing.
CLI flag: `--ports`, `--range`, `--port-threads`, `--port-timeout`.
(found in: `recon/portscan.py`, `main.py`)

[Subdomain Enumeration]
What: Brute-forces subdomains from `wordlists/subdomains.txt` and can check web presence.
Why: Hidden subdomains often expose development, admin, or internal systems.
Where: Applies to the base domain and stores results in `subdomains`.
When: Runs in `recon` or `all` mode.
How: Uses dnspython DNS resolution and optional HTTP/HTTPS checks.
CLI flag: `--subdomain-wordlist`, `--subdomain-threads`, `--dns-timeout`.
(found in: `recon/subdomain.py`, `main.py`)

[HTTP Intelligence]
What: Checks headers, cookies, redirects, server hints, frameworks, and robots paths.
Why: Missing security headers and cookie flags are common web weaknesses.
Where: Applies to the target web URL and stores `http_intel` and `robots_paths`.
When: Runs during active recon.
How: Sends HTTP requests with optional proxy/CA/scope settings.
CLI flag: automatic in `recon` or `all` active mode.
(found in: `core/http_intel.py`, `main.py`)

[TLS Certificate Intelligence]
What: Reads issuer, expiry, days until expiry, and Subject Alternative Names.
Why: Certificates reveal hostnames and expiry risk.
Where: Applies to HTTPS target host and stores `tls_certificate`.
When: Runs during active recon.
How: Uses Python `ssl` and socket certificate retrieval.
CLI flag: automatic in `recon` or `all` active mode.
(found in: `core/tls_intel.py`, `main.py`)

[DNS And Email Intelligence]
What: Collects SPF, DMARC, MX records, and mail-provider hints.
Why: Email DNS records affect spoofing resistance and mail routing security.
Where: Applies to the target domain and stores `dns_intel`.
When: Runs during passive recon.
How: Uses dnspython TXT and MX queries.
CLI flag: automatic in `recon` or `all` passive mode.
(found in: `core/dns_intel.py`, `main.py`)

### Discovery Features

[Directory Discovery]
What: Finds hidden files and paths from `wordlists/dirs.txt`.
Why: Exposed backups, configs, logs, and admin paths can be high risk.
Where: Applies to the target web root and stores `directories`.
When: Runs in `discover` or `all` active mode.
How: Sends threaded GET requests, checks status codes, follows redirects, and classifies risky paths.
CLI flag: `--mode discover`, `--dir-wordlist`, `--dir-threads`.
(found in: `discovery/dir_enum.py`, `main.py`)

[Recursive Directory Discovery]
What: Reuses the directory wordlist under discovered directory paths.
Why: Important files may be nested under valid folders.
Where: Applies after a directory is discovered.
When: Runs when `--recursive` is enabled.
How: Uses discovered paths as seeds up to `--recursive-depth` 1-4.
CLI flag: `--recursive`, `--recursive-depth`.
(found in: `discovery/dir_enum.py`, `main.py`)

### Fuzzing Features

[Parameter Fuzzer]
What: Tests URL parameters using payloads and compares baseline responses.
Why: Parameters are common places for injection and input-handling bugs.
Where: Applies to `--fuzz-url`, Wayback fuzzer targets, or derived target URL.
When: Runs in `fuzz` or `all` active mode.
How: Extracts parameters, builds per-parameter URLs, sends payloads, compares status/length/body similarity, and assigns risk.
CLI flag: `--mode fuzz`, `--fuzz-url`, `--payload-wordlist`, `--fuzz-threads`.
(found in: `fuzzing/fuzzer.py`, `main.py`)

[Payload Classification]
What: Classifies payloads as SQLi, XSS, LFI, SSTI, SSRF, XXE, or related types.
Why: Classification makes results easier to understand and report.
Where: Used in fuzzer results and analyzer output.
When: Runs during fuzzing and smart analysis.
How: Matches payload text against known patterns.
CLI flag: automatic during fuzzing.
(found in: `fuzzing/fuzzer.py`, `core/analyzer.py`)

### Intelligence Features

[Wayback Historical URL Collection]
What: Collects archived URLs, parameters, old endpoints, and fuzzer targets.
Why: Historical URLs can reveal endpoints no longer linked in the current site.
Where: Stores `wayback`, `wayback_urls`, `wayback_params`, `old_endpoints`, and `fuzzer_targets`.
When: Runs with `--wayback`.
How: Calls the Wayback CDX API and writes `output/wayback_urls.txt`.
CLI flag: `--wayback`.
(found in: `intelligence/wayback.py`, `main.py`)

[JavaScript Analyzer]
What: Finds linked JS files, endpoints, route-like strings, secrets, and comments.
Why: Frontend code often exposes API routes and sensitive-looking values.
Where: Stores `js_analysis` and feeds `js_discovery_paths` into directory discovery.
When: Runs with `--js-analysis`.
How: Fetches page HTML and scripts, parses URLs, regex patterns, and secret-like values.
CLI flag: `--js-analysis`.
(found in: `intelligence/js_analyzer.py`, `main.py`)

[Technology Fingerprinting]
What: Detects technologies and version hints, then maps hints to CVEs.
Why: Technology identification helps prioritize known-risk components.
Where: Stores `fingerprint` and appends CVEs to `known_cves`.
When: Runs with `--fingerprint`.
How: Reads headers, cookies, and HTML body evidence.
CLI flag: `--fingerprint`.
(found in: `intelligence/fingerprint.py`, `core/cve_lookup.py`, `main.py`)

[Authentication Testing]
What: Detects login forms, checks session cookie flags, decodes JWT-like tokens, and tests basic rate-limit behavior.
Why: Auth areas are high-value security surfaces.
Where: Stores `auth_test`.
When: Runs with `--auth-test`.
How: Parses HTML forms, inspects cookies, decodes JWT header/payload, and sends repeated login attempts.
CLI flag: `--auth-test`.
(found in: `intelligence/auth_tester.py`, `main.py`)

### Bypass Features

[WAF Detection And Bypass Variants]
What: Detects common WAF markers and generates authorized payload variants.
Why: WAF behavior can hide signal or require controlled comparison variants.
Where: Used inside fuzzing.
When: Extra variants run with `--bypass-waf`.
How: Uses status/header/body markers and payload transformations.
CLI flag: `--bypass-waf`.
(found in: `bypass/waf_bypass.py`, `fuzzing/fuzzer.py`)

[Origin Discovery]
What: Collects public origin IP candidates and compares fingerprints.
Why: It can identify servers that resemble the protected target origin.
Where: Stores `origin_discovery`.
When: Runs with `--find-origin`.
How: Resolves current DNS, queries crt.sh/DNSDumpster, fingerprints candidates, and compares title/server/body hash/status.
CLI flag: `--find-origin`.
(found in: `bypass/origin_discovery.py`, `main.py`)

### Verification Features

[SQLi Verification]
What: Compares true/false and timing-style SQLi checks.
Why: Raw SQLi-like fuzz responses can be false positives.
Where: Results are placed under `verification["sqli"]`.
When: Runs with `--verify` after fuzzing.
How: Sends controlled confirmation requests to the same parameter.
CLI flag: `--verify`.
(found in: `verification/sqli_verifier.py`, `verification/verifier.py`)

[XSS Verification]
What: Checks whether payload markers reflect in the response.
Why: Reflection is a stronger signal than a status or length anomaly alone.
Where: Results are placed under `verification["xss"]`.
When: Runs with `--verify` after fuzzing.
How: Sends marker payloads and searches returned text.
CLI flag: `--verify`.
(found in: `verification/xss_verifier.py`, `verification/verifier.py`)

[CORS Verification]
What: Tests allowed origins and credential behavior.
Why: Dangerous CORS behavior can expose browser-accessible data.
Where: Results are placed under `verification["cors"]`.
When: Runs with `--verify`.
How: Sends requests with test Origin headers and checks CORS response headers.
CLI flag: `--verify`.
(found in: `verification/cors_tester.py`, `verification/verifier.py`)

### AI Features

[AI Analyst]
What: Generates analysis for ports, directories, fuzzing, headers, and final summary.
Why: It helps explain raw data in professional report language.
Where: Output goes to `scan_data["ai_analyses"]` and report AI sections.
When: Runs with `--ai` and a configured `.env` key.
How: Sends structured JSON data to NVIDIA NIM through the OpenAI client.
CLI flag: `--ai`.
(found in: `core/ai_module.py`, `main.py`)

### Reporting Features

[Terminal, JSON, TXT, HTML Reports]
What: Prints a terminal summary and saves JSON/TXT/HTML when requested.
Why: Different users need machine-readable, plain-text, or presentation-friendly output.
Where: Implemented in `output/report.py`.
When: Runs after scan modules complete.
How: Uses Rich for terminal display, JSON serialization, plain text rendering, and Jinja2 HTML templates.
CLI flag: `--output`.
(found in: `output/report.py`, `main.py`)

[Auto And Saved Reports]
What: Automatically saves HTML reports and can preserve important reports.
Why: It keeps a history without letting reports grow endlessly.
Where: `output/reports/auto` and `output/reports/saved`.
When: Auto-save runs every scan; saved copy runs with `--save-report`.
How: Uses FIFO cleanup with a limit of 100 per location.
CLI flag: `--save-report`.
(found in: `utils/report_manager.py`, `main.py`)

[Visualization]
What: Builds a scan graph image.
Why: Graphs help show relationships between target, subdomains, ports, paths, and fuzz findings.
Where: Saves to `output/scan_graph.png`.
When: Runs with `--visualize`.
How: Uses NetworkX and Matplotlib.
CLI flag: `--visualize`.
(found in: `core/visualize.py`, `main.py`)

### GUI Features

[Desktop GUI]
What: Provides scan, dashboard, reports, export, wordlist, and settings pages.
Why: It gives a visual workflow for running and reviewing scans.
Where: Implemented in `gui/`.
When: Runs with `--gui`.
How: Uses Tkinter frames, reusable widgets, a log queue, and a background subprocess.
CLI flag: `--gui`.
(found in: `gui/app.py`, `gui/frames/scan_frame.py`)

### Learning Features

[Learn Mode]
What: Adds educational explanations, next steps, thought experiments, progress, and report quality checks.
Why: It helps students understand what a finding means instead of only seeing raw output.
Where: Stores `learn_mode` and `output/learn_progress.json`.
When: Runs with `--learn`.
How: Builds learning blocks from bounty context findings.
CLI flag: `--learn`.
(found in: `core/learn.py`, `main.py`)

## Section 4: Requirements

### 4a. Python Libraries

[requests]
What: Sends HTTP requests for web intel, discovery, fuzzing, Wayback, CVE lookup, JS analysis, auth tests, verification, WAF checks, and origin discovery.
Why: It is the common HTTP client used across the project.
Where: Imported in many scanner modules including `core/http_intel.py`, `fuzzing/fuzzer.py`, and `verification/`.
When: Needed whenever an HTTP-based module runs.
How: Sends GET/POST requests with timeout, proxy, and certificate options.
(found in: `requirements.txt`, multiple Python files)

[dnspython]
What: Resolves DNS records for subdomain, SPF, DMARC, and MX checks.
Why: Built-in DNS support is limited for record-specific queries.
Where: Used in `recon/subdomain.py` and `core/dns_intel.py`.
When: Needed during passive recon.
How: Uses `dns.resolver.Resolver()`.
(found in: `requirements.txt`, `recon/subdomain.py`, `core/dns_intel.py`)

[openai]
What: Provides the OpenAI-compatible client for NVIDIA NIM.
Why: The AI endpoint uses an OpenAI-style API.
Where: Used in `core/ai_module.py`.
When: Needed only if `--ai` is enabled.
How: Creates `OpenAI(base_url=BASE_URL, api_key=api_key)`.
(found in: `requirements.txt`, `core/ai_module.py`)

[python-dotenv]
What: Loads `.env` values.
Why: API keys should not be hardcoded.
Where: Used in `core/ai_module.py`.
When: Needed before AI configuration is checked.
How: Calls `load_dotenv()`.
(found in: `requirements.txt`, `core/ai_module.py`)

[rich]
What: Renders terminal tables, panels, and console messages.
Why: It improves readability of CLI output.
Where: Used in `main.py`, `output/report.py`, `fuzzing/fuzzer.py`, `recon/portscan.py`, and others.
When: Needed for CLI display.
How: Uses `Console`, `Table`, and `Panel`.
(found in: `requirements.txt`)

[networkx]
What: Builds the scan graph data structure.
Why: It models relationships between target assets and findings.
Where: Used in `core/visualize.py`.
When: Needed with `--visualize`.
How: Creates graph nodes and edges.
(found in: `requirements.txt`, `core/visualize.py`)

[matplotlib]
What: Renders the graph image.
Why: The graph needs image output.
Where: Used in `core/visualize.py`.
When: Needed with `--visualize`.
How: Draws and saves `output/scan_graph.png`.
(found in: `requirements.txt`, `core/visualize.py`)

[tqdm]
What: Shows progress bars.
Why: Threaded scans can take time and need progress feedback.
Where: Used in `recon/portscan.py` and `fuzzing/fuzzer.py`.
When: Needed during port scanning and fuzzing.
How: Wraps progress totals and updates as futures/workers complete.
(found in: `requirements.txt`)

[jinja2]
What: Renders HTML reports.
Why: HTML output needs a template renderer.
Where: Used in `output/report.py`.
When: Needed when saving HTML reports and auto reports.
How: Uses a Jinja2 template string and `template.render(report=report)`.
(found in: `requirements.txt`, `output/report.py`)

### 4b. Other Requirements

[Python 3.10+]
What: The setup check requires Python 3.10 or newer.
Why: The code uses modern type hint syntax such as `str | Path`.
Where: Checked in `check_setup`.
When: Needed before running the project.
How: Compares `sys.version_info >= (3, 10)`.
(found in: `main.py`)

[NVIDIA_API_KEY]
What: Optional API key stored in `.env` as `NVIDIA_API_KEY=...`.
Why: Required for AI analysis.
Where: Read by `core/ai_module.py`; saved by GUI settings if entered.
When: Needed only when `--ai` is used.
How: Loaded by `python-dotenv` and passed to the OpenAI-compatible client.
(found in: `.env.example`, `core/ai_module.py`, `gui/frames/settings_frame.py`)

[Network Access]
What: The tool needs network access to authorized targets and optional public APIs.
Why: Scanning, DNS, HTTP, Wayback, CVE lookup, and origin discovery all require network communication.
Where: Used across recon, discovery, fuzzing, intelligence, bypass, and verification modules.
When: Needed during active scans and passive API lookups.
How: Uses sockets, dnspython, and HTTP requests.
(found in: `recon/`, `core/`, `intelligence/`, `bypass/`, `verification/`)

[OS Compatibility]
What: The project is Python-based and should run anywhere Python/Tkinter and dependencies are available; examples use Windows PowerShell paths.
Why: Tkinter GUI and socket/HTTP modules are cross-platform, but command examples are Windows-oriented.
Where: Paths in README and GUI use `Path`.
When: Needed during install and running.
How: Python abstracts most path handling through `pathlib`.
(found in: `README.md`, `gui/`, `main.py`)

### 4c. CLI Flags

`--target`: Optional by parser, required unless `--targets-file`, `--gui`, or `--check-setup` is used. It sets the target host, domain, URL, or FUZZ URL. Use it for a single scan target. It feeds every selected module through `args.target`. (found in: `main.py`)

`--targets-file`: Optional. It scans multiple targets from one text file. Use it when testing several authorized targets. It is loaded by `load_targets` and each target is passed to `run_target`. (found in: `main.py`, `utils/state_manager.py`)

`--mode`: Required unless GUI/check setup is used. It chooses `recon`, `discover`, `fuzz`, or `all`. Use it to control which major scan groups run. It gates module calls in `run_target`. (found in: `main.py`)

`--gui`: Optional. It launches the Tkinter desktop app. Use it when a visual interface is preferred. It imports and calls `gui.app.launch`. (found in: `main.py`)

`--output`: Optional. It saves the final report as `.json`, `.txt`, or `.html`. Use it when you need a report file. It calls `save_report`. (found in: `main.py`, `output/report.py`)

`--save-report`: Optional. It copies the auto report into the saved/important folder. Use it to protect an important scan report. It calls `save_important_report`. (found in: `main.py`, `utils/report_manager.py`)

`--ai`: Optional. It enables AI analysis. Use it when `.env` has `NVIDIA_API_KEY`. It calls AI functions in `core/ai_module.py`. (found in: `main.py`)

`--visualize`: Optional. It saves a graph image. Use it when a visual relationship diagram is needed. It calls `build_graph`. (found in: `main.py`, `core/visualize.py`)

`--stealth`: Optional. It rotates browser User-Agent values and applies delays. Use it to slow request behavior. It affects HTTP-based modules through hooks. (found in: `main.py`, `core/stealth.py`)

`--passive`: Optional. It avoids direct target server contact where supported. Use it for lower-impact recon. It changes `recon_profile`. (found in: `main.py`)

`--active`: Optional. It runs direct scanning/probing only. Use it when direct testing is authorized. It changes `recon_profile`. (found in: `main.py`)

`--recon-mode`: Optional alias with choices `all`, `active`, `passive`. It maps to active/passive booleans. Use it for clearer recon profile selection. (found in: `main.py`)

`--bypass-waf`: Optional. It enables WAF behavior testing payload variants. Use it during authorized fuzzing when blocked responses appear. It is passed into `fuzz_url`. (found in: `main.py`, `fuzzing/fuzzer.py`)

`--wayback`: Optional. It enables historical URL collection. Use it before fuzzing/discovery to find old endpoints. It calls `collect_wayback_intel`. (found in: `main.py`, `intelligence/wayback.py`)

`--js-analysis`: Optional. It enables JavaScript endpoint and secret-like value analysis. Use it when the target has frontend scripts. It calls `analyze_javascript`. (found in: `main.py`, `intelligence/js_analyzer.py`)

`--find-origin`: Optional. It enables origin IP candidate discovery. Use it when testing CDN/WAF-protected targets with permission. It calls `discover_origin`. (found in: `main.py`, `bypass/origin_discovery.py`)

`--verify`: Optional. It verifies supported fuzzing findings and CORS behavior. Use it after fuzzing to reduce false positives. It calls `verify_findings`. (found in: `main.py`, `verification/verifier.py`)

`--auth-test`: Optional. It runs authentication surface checks. Use it when the target has login/session behavior. It calls `run_auth_tests`. (found in: `main.py`, `intelligence/auth_tester.py`)

`--fingerprint`: Optional. It detects technologies and CVE hints. Use it to identify framework/product risk. It calls `fingerprint_target`. (found in: `main.py`, `intelligence/fingerprint.py`)

`--bounty-report`: Optional. It exports a Markdown bounty report skeleton. Use it when preparing a bug bounty style report. It calls `export_bounty_markdown`. (found in: `main.py`, `core/bounty.py`)

`--learn`: Optional. It adds learn-mode content. Use it for educational project explanation. It calls `build_learn_mode`. (found in: `main.py`, `core/learn.py`)

`--proxy`: Optional. It routes HTTP requests through a proxy. Use it with tools like an intercepting proxy. It creates a `requests` proxy mapping. (found in: `main.py`)

`--ca-cert`: Optional. It sets a custom certificate authority file. Use it when proxying HTTPS through a trusted local CA. It becomes the `verify` option for requests. (found in: `main.py`)

`--scope`: Optional. It defines allowed domains. Use it to prevent out-of-scope requests. It creates `ScopeChecker` instances in modules. (found in: `main.py`, `utils/scope_checker.py`)

`--resume`: Optional. It resumes from `output/scan_state.json`. Use it after interrupted scans. It loads completed modules and skips them. (found in: `main.py`, `utils/state_manager.py`)

`--dir-wordlist`, `--payload-wordlist`, `--subdomain-wordlist`: Optional. They replace default wordlist paths. Use them for custom testing lists. They are passed into discovery, fuzzing, and subdomain modules. (found in: `main.py`)

`--fuzz-url`: Optional. It overrides target for fuzzing with a specific URL. Use it for a known parameterized endpoint. It controls target URLs in `run_fuzzing`. (found in: `main.py`)

`--baseline`: Optional. It sets baseline value for FUZZ placeholders. Use it when comparing payload responses against a known safe value. It is passed to `fuzz_url`. (found in: `main.py`, `fuzzing/fuzzer.py`)

`--no-urlencode`: Optional. It sends payloads without URL encoding. Use it only when raw payload behavior is needed. It flips `url_encode` in fuzzing. (found in: `main.py`)

`--no-mutation`: Optional. It disables mutation retries. Use it when exact payload-only testing is desired. It flips `enable_mutation`. (found in: `main.py`, `fuzzing/fuzzer.py`)

`--ports`, `--range`: Optional. They control port selection. Use them to narrow or expand port scanning. They feed `parse_ports`. (found in: `main.py`, `recon/portscan.py`)

`--dir-threads`, `--fuzz-threads`, `--subdomain-threads`, `--port-threads`: Optional. They tune worker counts. Use them to balance speed and load. They are passed to the relevant threaded modules. (found in: `main.py`)

`--recursive`, `--recursive-depth`: Optional. They enable and limit recursive directory discovery. Use them when valid folders may contain nested targets. They are passed to `fetch_robots_paths` and `enumerate_directories`. (found in: `main.py`, `discovery/dir_enum.py`)

`--http-timeout`, `--dns-timeout`, `--port-timeout`, `--retries`: Optional. They tune network waits and retries. Use them for slow or unstable targets. They are passed to HTTP, DNS, port, discovery, and fuzzing functions. (found in: `main.py`)

`--check-setup`: Optional. It checks Python version, packages, and wordlists. Use it after installation. It runs without a target. (found in: `main.py`)

`--version`: Optional. It prints `MiniRecon v3.0`. Use it to confirm version. (found in: `main.py`)

## Section 5: Architecture Summary

### 5a. Folder Tree

```text
project/
|-- main.py
|-- bypass/
|   |-- origin_discovery.py
|   |-- waf_bypass.py
|   `-- __init__.py
|-- core/
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
|   |-- visualize.py
|   `-- __init__.py
|-- discovery/
|   |-- dir_enum.py
|   `-- __init__.py
|-- fuzzing/
|   |-- fuzzer.py
|   `-- __init__.py
|-- gui/
|   |-- app.py
|   |-- config.py
|   |-- theme.py
|   |-- frames/
|   |   |-- dashboard_frame.py
|   |   |-- export_frame.py
|   |   |-- reports_frame.py
|   |   |-- scan_frame.py
|   |   |-- settings_frame.py
|   |   |-- wordlist_frame.py
|   |   `-- __init__.py
|   |-- widgets/
|   |   |-- finding_card.py
|   |   |-- log_panel.py
|   |   |-- nav_sidebar.py
|   |   |-- stat_card.py
|   |   `-- __init__.py
|   `-- __init__.py
|-- intelligence/
|   |-- auth_tester.py
|   |-- fingerprint.py
|   |-- js_analyzer.py
|   |-- wayback.py
|   `-- __init__.py
|-- output/
|   |-- report.py
|   `-- __init__.py
|-- recon/
|   |-- portscan.py
|   |-- subdomain.py
|   `-- __init__.py
|-- utils/
|   |-- report_manager.py
|   |-- scope_checker.py
|   |-- state_manager.py
|   `-- __init__.py
|-- verification/
|   |-- cors_tester.py
|   |-- sqli_verifier.py
|   |-- verifier.py
|   |-- xss_verifier.py
|   `-- __init__.py
|-- wordlists/
|   |-- dirs.txt
|   |-- payloads.txt
|   `-- subdomains.txt
|-- .env.example
|-- README.md
|-- requirements.txt
`-- summary.txt
```

### 5b. File Categories

[Core scanning modules]
What: `recon/`, `discovery/`, `fuzzing/`, `intelligence/`, `bypass/`, and `verification/` perform the scan work.
Why: They are grouped by security task so each module has a clear job.
Where: Their outputs go into `scan_data`.
When: They run when selected by mode and flags.
How: `main.py` imports their functions and calls them in scan order.
(found in: project tree and `main.py`)

[Utility/helper modules]
What: `utils/` and shared `core/` files handle scope, state, reports, risk, AI, bounty, learn mode, and visualization.
Why: Shared helpers prevent repeated logic inside scanner modules.
Where: They are used by `main.py` and scanner modules.
When: They run during setup, module execution, and reporting.
How: They receive scan data or configuration and return normalized results.
(found in: `utils/`, `core/`)

[GUI modules]
What: `gui/` contains the desktop app, frames, widgets, config, and theme.
Why: GUI code is separated from CLI scanning.
Where: GUI stores settings in `output/gui_settings.json` and reads `output/gui_latest.json`.
When: It runs with `--gui`.
How: It builds Tkinter frames and launches the CLI subprocess.
(found in: `gui/`)

[Configuration and data files]
What: `.env.example`, `requirements.txt`, and `wordlists/` configure dependencies, API key structure, and scan inputs.
Why: They keep install and scan data outside code.
Where: The code reads these files during setup, AI startup, and scans.
When: Requirements are needed at install; wordlists are needed during scans; `.env` is needed for AI.
How: Files are loaded with `Path.read_text`, dotenv, or pip.
(found in: `.env.example`, `requirements.txt`, `wordlists/`)

### 5c. How main.py Connects Everything

[main.py Orchestration]
What: `main.py` calls `run_recon`, `run_http_intel`, `run_tls_intel`, `run_dns_intel`, `run_wayback`, `run_js_analysis`, `run_origin_discovery`, `run_discovery`, `run_fuzzing`, `run_verification`, `run_auth_test`, and `run_fingerprint`.
Why: One orchestrator keeps mode/flag decisions consistent.
Where: All calls happen inside `run_target`.
When: Decisions are made after CLI parsing and before each module stage.
How: It checks `args.mode`, active/passive profile, and feature flags, then updates `report` and `scan_data`.
(found in: `main.py`)

### 5d. GUI To CLI Core Connection

[GUI subprocess and queue]
What: The GUI does not call scanner functions directly; it builds a CLI command and runs `main.py` in a background subprocess.
Why: This keeps GUI responsive and reuses the CLI behavior.
Where: Implemented in `gui/frames/scan_frame.py`.
When: It starts when the user presses Start Scan.
How: A worker thread reads subprocess output, pushes log messages into a queue, and the main Tk loop polls that queue every 100 ms.
(found in: `gui/app.py`, `gui/frames/scan_frame.py`, `gui/widgets/log_panel.py`)

## Section 6: GUI Description

### 6a. GUI Pages

[ScanFrame]
What: Main scan page with target, mode, option checkboxes, progress, result cards, trees, and tabs.
Why: It is the primary place to start and inspect a scan.
When: User opens the Scan page or starts a scan.
How: Populated from `output/gui_latest.json` after the subprocess finishes.
(found in: `gui/frames/scan_frame.py`)

[DashboardFrame]
What: Dashboard with statistic cards and recent report table.
Why: It summarizes stored reports.
When: User opens Dashboard.
How: Reads report counts and auto report list through `utils.report_manager`.
(found in: `gui/frames/dashboard_frame.py`)

[ReportsFrame]
What: Lists auto and saved reports and supports open, save important, and delete actions.
Why: It lets users manage report history visually.
When: User opens Reports.
How: Uses `list_auto_reports`, `list_saved_reports`, `save_important_report`, and `delete_report`.
(found in: `gui/frames/reports_frame.py`)

[ExportFrame]
What: Lets users choose report formats and copy a selected report to a destination.
Why: It supports report sharing.
When: User opens Export.
How: Uses file dialogs and `shutil.copy2`.
(found in: `gui/frames/export_frame.py`)

[WordlistFrame]
What: Shows and edits wordlist files.
Why: Users may need custom subdomain, directory, or payload lists.
When: User opens Wordlists.
How: Reads and writes files under `wordlists/`.
(found in: `gui/frames/wordlist_frame.py`)

[SettingsFrame]
What: Saves scan defaults, API key, report limits, and learn-mode preference.
Why: Repeated scans need persistent defaults.
When: User opens Settings and clicks save.
How: Writes `.env` for API key and `output/gui_settings.json` for GUI defaults.
(found in: `gui/frames/settings_frame.py`, `gui/config.py`)

### 6b. Reusable Widgets

[StatCard]
What: Displays a small metric title and value.
Why: Scan and dashboard pages both need compact metrics.
Where: Used in scan overview and dashboard.
How: Receives values through `set_value`.
(found in: `gui/widgets/stat_card.py`)

[FindingCard]
What: Displays one finding with title, severity, summary, and details.
Why: Findings need a repeated visual pattern.
Where: Used in scan overview.
How: It receives values during report population.
(found in: `gui/widgets/finding_card.py`)

[LogPanel]
What: Displays live log text and supports clearing/saving logs.
Why: Long scans need visible progress without freezing the GUI.
Where: Used on the right side of the main app.
How: `poll_logs` sends queue messages into its `log` method.
(found in: `gui/widgets/log_panel.py`, `gui/app.py`)

[NavSidebar]
What: Shows navigation buttons for GUI pages.
Why: It gives consistent page switching.
Where: Used in `MiniReconApp`.
How: Buttons call the app's `show_frame` callback.
(found in: `gui/widgets/nav_sidebar.py`, `gui/app.py`)

### 6c. Theme

[Dark Theme]
What: Main colors are `#1a1a2e`, `#16213e`, `#0f3460`, `#12172b`, accent `#378ADD`, text `#e0e0e0`, muted `#8892a4`, success `#2ecc71`, warning `#f1c40f`, danger `#ff5c7a`, info `#66d9ef`, low `#8be28b`, border `#2a3b5f`.
Why: A dark theme reduces glare and gives a security-dashboard style.
Where: All GUI frames and widgets use ttk styles from `theme.py`.
When: Applied when `MiniReconApp` starts.
How: `apply_theme` configures ttk styles for frames, labels, buttons, tabs, entries, treeviews, and progress bars.
(found in: `gui/theme.py`, `gui/app.py`)

### 6d. Main Scan Tabs

[Overview]
What: Shows stat cards and finding cards.
Why: Users need quick scan status first.
When: Populated after report load.
How: Reads ports, directories, fuzz findings, subdomains, and risk.
(found in: `gui/frames/scan_frame.py`)

[Ports]
What: Shows open port rows.
Why: Ports are core recon output.
When: Populated after recon results are loaded.
How: Reads `report["recon"]["open_ports"]`.
(found in: `gui/frames/scan_frame.py`)

[Directories]
What: Shows discovered paths.
Why: Hidden files and folders need separate review.
When: Populated after discovery results load.
How: Reads `directory_discovery`.
(found in: `gui/frames/scan_frame.py`)

[Fuzz Results]
What: Shows parameter payload results.
Why: Fuzz output can contain many rows and needs a table.
When: Populated after fuzzing results load.
How: Reads `fuzzing["results"]`.
(found in: `gui/frames/scan_frame.py`)

[TLS/DNS]
What: Shows certificate and DNS fields.
Why: Infrastructure metadata is separate from paths and payloads.
When: Populated after recon results load.
How: Reads `tls_certificate` and `dns_intel`.
(found in: `gui/frames/scan_frame.py`)

[JS Analysis]
What: Shows JavaScript endpoints.
Why: JS-discovered routes need direct review.
When: Populated after JS analysis results load.
How: Reads `js_analysis["endpoints"]`.
(found in: `gui/frames/scan_frame.py`)

[Wayback]
What: Shows historical URL records.
Why: Old endpoints can be numerous and separate from live discovery.
When: Populated after Wayback results load.
How: Reads `wayback["records"]`.
(found in: `gui/frames/scan_frame.py`)

[AI Analysis]
What: Shows AI analysis JSON/text.
Why: AI output is a separate explanatory layer.
When: Populated after scan output loads.
How: Reads `ai_analyses`.
(found in: `gui/frames/scan_frame.py`)

### 6e. Live Log Streaming

[Queue-based logging]
What: The GUI uses a `queue.Queue` for log messages from the scan worker thread.
Why: Tkinter must update UI from the main thread, not directly from background work.
Where: Queue is created in `gui/app.py` and used by `ScanFrame` and `LogPanel`.
When: It updates while the subprocess is running and every 100 ms in `poll_logs`.
How: The worker reads stdout lines, puts `(level, message)` tuples into the queue, and `poll_logs` writes them to the log panel.
(found in: `gui/app.py`, `gui/frames/scan_frame.py`, `gui/widgets/log_panel.py`)

## Section 7: Wordlists, Payloads & Directories

### 7A. Subdomains Wordlist

Count: 211 entries.

[Development and test environments]
Entries: dev, test, stage, staging, beta, demo, uat, sit, qa, qas, develop, development, preprod, pre-prod, sandbox, testing, alpha, preview, canary, green, blue.

[API and backend]
Entries: api, api-v1, api-v2, api-v3, api2, rest, graphql, gateway, proxy, backend, mobileapi, webhook, hooks, callback, notify, notification.

[Admin and management]
Entries: admin, administrator, panel, manager, management, control, console, cpanel, plesk, whm, webmin, phpmyadmin, adminer, sqladmin, dashboard, portal.

[Mail and communication]
Entries: mail, webmail, smtp, pop, imap, mx, pop3, exchange, owa, autodiscover, autoconfig, roundcube, chat, slack, teams, meet, conference, zoom.

[Infrastructure and DevOps]
Entries: ns1, ns2, vpn, cdn, static, assets, img, images, ftp, sftp, ssh, rdp, vnc, bastion, jump, relay, waf, firewall, ids, ips, siem, jenkins, gitlab, github, bitbucket, jira, confluence, sonar, nexus, artifactory, registry, docker, k8s, kubernetes, rancher, portainer.

[Monitoring and logging]
Entries: grafana, kibana, prometheus, datadog, splunk, elastic, logstash, sentry, bugsnag, rollbar, newrelic, dynatrace, health, monitor, uptime, ping, alive.

[Business applications]
Entries: payment, billing, invoice, checkout, cart, ecommerce, marketplace, pos, finance, payroll, hr, crm, erp, sap, salesforce, hubspot, marketo.

[Content and storage]
Entries: www, app, apps, auth, login, blog, docs, support, help, status, shop, store, media, video, stream, upload, download, files, storage, s3, blob, bucket.

[Legacy and data]
Entries: old, backup, db, database, internal, intranet, corp, remote, citrix, pulse, anyconnect, webvpn, legacy, v1, v2, v3, archive, vault, secret, oauth, sso, identity, ldap, ad.

[Search, cache, and databases]
Entries: search, solr, sphinx, algolia, meilisearch, cache, redis, memcache, varnish, haproxy, nginx, mysql, postgres, mongo, oracle, mssql.

What: A subdomain is a named child of a domain, such as `api.example.com`.
Why: Hidden subdomains may reveal admin panels, development systems, storage, APIs, or internal services.
Where: Loaded by `recon/subdomain.py` through `DEFAULT_WORDLIST`.
When: Used during recon mode or all mode.
How: The tool combines each word with the base domain, resolves it with DNS, optionally probes HTTP/HTTPS, and stores live or resolved findings in `subdomains`.
(found in: `wordlists/subdomains.txt`, `recon/subdomain.py`, `main.py`)

### 7B. Directory Wordlist

Count: 196 entries.

[Admin panels]
Entries: admin, administrator, dashboard, login, logout, panel, phpmyadmin, wp-admin, console, phpmyadmin/, pma/, adminer/, dbadmin/, sqladmin/, cpanel/, whm/, administrator/.

[Configuration and secrets]
Entries: config, .env, .env.local, .env.production, .env.backup, wp-config.php, wp-config.php.bak, wp-config.bak, config.php, config.php.bak, configuration.php, database.yml, database.yml.bak, settings.py, local_settings.py, secrets.yml, credentials.yml, web.config, web.config.bak, applicationHost.config, .htaccess, .htpasswd, server.key, server.crt.

[Version control]
Entries: .git, .git/config, .git/HEAD, .git/index, .svn, .svn/entries, .hg, .bzr.

[Backups and archives]
Entries: backup, backup.zip, old, backup.tar.gz, backup.sql, dump.sql, db.sql, database.sql, data.sql, users.sql, site.zip, www.zip, html.zip, public.zip, admin.zip, backup/, backups/, bak/, old/, archive/.

[API and documentation]
Entries: api/, api/v1/, api/v2/, api/v3/, api/swagger, api/swagger.json, api/swagger.yaml, swagger-ui.html, openapi.json, openapi.yaml, graphql, graphiql.

[Debug/status]
Entries: debug, server-status, actuator, actuator/health, actuator/env, actuator/mappings, actuator/beans, actuator/info, server-info, nginx_status, phpinfo.php, info.php, test.php, debug.php, trace, elmah.axd, trace.axd, ScriptResource.axd.

[Development/build files]
Entries: docker-compose.yml, docker-compose.yaml, Dockerfile, .dockerignore, kubernetes.yml, package.json, package-lock.json, yarn.lock, composer.json, composer.lock, Gemfile, Gemfile.lock, requirements.txt, Pipfile, setup.py, pyproject.toml, Makefile, Gruntfile.js, Gulpfile.js, webpack.config.js.

[System/user files]
Entries: .DS_Store, Thumbs.db, desktop.ini, .bash_history, .bash_profile, .bashrc, .profile, .ssh/id_rsa, .ssh/authorized_keys, id_rsa, id_rsa.pub.

[Logs]
Entries: logs/, log/, error.log, access.log, debug.log, app.log.

[Site metadata]
Entries: robots.txt, sitemap.xml, sitemap_index.xml, crossdomain.xml, clientaccesspolicy.xml, security.txt, .well-known/security.txt, humans.txt, readme.txt, README.md, CHANGELOG.md, LICENSE, TODO, INSTALL, CONTRIBUTING.md.

[CMS and applications]
Entries: jenkins/, gitlab/, bitbucket/, sonar/, nexus/, grafana/, kibana/, portainer/, rancher/, wp-admin/, wp-includes/, wp-content/, wp-content/uploads/, wp-content/plugins/, joomla/, drupal/, typo3/, webmail/, roundcube/, horde/.

[Uploads and runtime folders]
Entries: private, static, images, js, uploads, wp-content, dev, test, db, backup/, uploads/, upload/, files/, file/, media/, images/, tmp/, temp/, cache/, sessions/, sess_, cgi-bin/, scripts/, bin/, exe/, run/.

What: Directory brute-forcing means requesting many likely paths and checking which ones exist.
Why: Hidden paths can expose backups, logs, admin tools, source metadata, or credentials; random guessing would miss common names and waste requests.
Where: Loaded by `discovery/dir_enum.py` and used by `run_discovery`.
When: Runs in `discover` or `all` mode, and can receive extra paths from robots, Wayback, and JS analysis.
How: The tool sends GET requests, treats useful status codes as findings, classifies risky paths by extension/name, and recursively scans discovered directories when enabled.
(found in: `wordlists/dirs.txt`, `discovery/dir_enum.py`, `main.py`)

### 7C. Payload Wordlist

Count: 77 payload entries.

[SQLi payloads]
Entries: `'`, `"`, `' OR '1'='1`, `" OR "1"="1`, `' OR 1=1--`, `" OR 1=1--`, `admin'--`, `' UNION SELECT NULL--`, `' OR SLEEP(5)--`, `'; WAITFOR DELAY '0:0:5'--`, `' OR 1=1 LIMIT 1--`, `' UNION SELECT NULL,NULL,NULL--`, `' UNION SELECT table_name,NULL FROM information_schema.tables--`, `'; SELECT * FROM users--`, `' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--`, `1' AND 1=1--`, `1' AND 1=2--`, `' OR 'x'='x`, `' OR 1=1#`, `") OR ("1"="1`, `')) OR (('1'='1`.
Explanation: SQLi payloads test whether user input changes database query behavior.

[XSS payloads]
Entries: `<script>alert(1)</script>`, `"><script>alert(1)</script>`, `'><img src=x onerror=alert(1)>`, `<svg onload=alert(1)>`, `<img src=x onerror=alert(1)>`, `<svg/onload=alert(1)>`, `javascript:alert(1)`, `<iframe src="javascript:alert(1)">`, `'><script>alert(1)</script>`, `<body onload=alert(1)>`, `<input onfocus=alert(1) autofocus>`, `<select onchange=alert(1)><option>1</option></select>`, `<details open ontoggle=alert(1)>`, `<video src=1 onerror=alert(1)>`, `<audio src=1 onerror=alert(1)>`.
Explanation: XSS payloads test whether input is reflected or rendered as browser-executable content.

[LFI / Path Traversal payloads]
Entries: `../../../../etc/passwd`, `..%2f..%2f..%2fetc%2fpasswd`, `../../../etc/passwd`, `....//....//....//etc/passwd`, `/etc/passwd%00`, `/etc/shadow`, `/proc/self/environ`, `/var/log/apache2/access.log`, `/var/log/nginx/access.log`, `C:\Windows\System32\drivers\etc\hosts`, `C:\Windows\win.ini`, `%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd`.
Explanation: LFI/path traversal payloads test whether file path input can read unintended system files.

[SSTI payloads]
Entries: `{{7*7}}`, `${7*7}`, `<%= 7*7 %>`, `{{config}}`, `*{7*7}`, `@{7*7}`.
Explanation: SSTI payloads test whether template engines execute user-controlled template syntax.

[SSRF payloads]
Entries: `http://localhost/`, `http://127.0.0.1/`, `http://169.254.169.254/latest/meta-data/`, `http://[::1]/`, `http://0.0.0.0/`, `http://metadata.google.internal/`, `dict://localhost:6379/info`, `file:///etc/passwd`.
Explanation: SSRF payloads test whether the server can be made to request internal or metadata resources.

[XXE payloads]
Entries: `<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM 'file:///etc/passwd'>]><root>&test;</root>`.
Explanation: XXE payloads test whether XML parsers resolve external entities.

[Open Redirect payloads]
Entries: `//evil.com`, `/\evil.com`, `/%09/evil.com`, `https://evil.com`, `https://target.com.evil.com`.
Explanation: Open redirect payloads test whether redirect parameters can send users to attacker-controlled destinations.

[Generic and edge-case payloads]
Entries: `%00`, `null`, `undefined`, `true`, `false`, `0`, `-1`, `9999999999`, `aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa`.
Explanation: Generic payloads test null bytes, boolean handling, numeric edge cases, and length-based anomalies.

What: A payload is test input designed to reveal unsafe application behavior.
Why: Random text is less useful because each payload family tests a specific weakness pattern.
Where: Loaded by `fuzzing/fuzzer.py`.
When: Sent during `fuzz` or `all` mode; WAF bypass changes sending behavior when `--bypass-waf` is enabled.
How: The fuzzer chooses parameters from URLs, sends baseline and payload requests, compares status/length/body similarity, classifies risk, and verification can confirm some findings.
(found in: `wordlists/payloads.txt`, `fuzzing/fuzzer.py`, `verification/`)

### 7D. Report Management System

[Report limits and locations]
What: Auto reports and saved reports both use a FIFO limit of 100 HTML files.
Why: Unlimited reports could fill storage; separate saved reports protect important outputs from normal auto-report rotation.
Where: Auto reports save to `output/reports/auto`; saved reports save to `output/reports/saved`.
When: Auto reports save after every scan; saved reports are copied when `--save-report` is used or from the GUI reports page.
How: `enforce_fifo_limit` sorts reports oldest-first by creation time and deletes oldest files until the count is within the limit.
(found in: `utils/report_manager.py`, `main.py`)

[Functions]
What: Functions are `_ensure_dirs`, `_safe_name`, `_location_path`, `enforce_fifo_limit`, `save_auto_report`, `save_important_report`, `list_auto_reports`, `list_saved_reports`, `delete_report`, and `get_report_count`.
Why: They separate report storage operations from scan logic.
Where: Used by `main.py`, dashboard, reports page, and export page.
When: They run during report save, listing, deletion, and GUI refresh.
How: They create folders, sanitize filenames, render HTML, copy files, list files, and delete selected reports.
(found in: `utils/report_manager.py`, `gui/frames/reports_frame.py`, `gui/frames/dashboard_frame.py`)
