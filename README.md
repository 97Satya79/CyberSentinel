# 🛡️ CyberSentinel: Automated DevSecOps DAST & Vulnerability Orchestration Platform

[![Python](https://img.shields.io/badge/Python-3.10%2B-blue?logo=python&logoColor=white)](https://www.python.org/)
[![Docker](https://img.shields.io/badge/Docker-Compose-2496ED?logo=docker&logoColor=white)](https://www.docker.com/)
[![OWASP ZAP](https://img.shields.io/badge/Security-OWASP%20ZAP%20Automation-005B94?logo=owasp&logoColor=white)](https://www.zaproxy.org/)
[![Status](https://img.shields.io/badge/Prototype-Phase%201-orange)](#)

---

## 📌 Executive Summary

Modern web applications face sophisticated cyber threats ranging from Injection attacks to Broken Access Control. Traditional penetration testing is manual, slow, and expensive—often conducted right before production release. 

**CyberSentinel** is an automated **Dynamic Application Security Testing (DAST) and Security Orchestration platform** built to bring automated vulnerability assessment into the modern DevSecOps lifecycle. 

It programmatically provisions isolated vulnerable target environments, generates declarative **Scan-as-Code** plans, instructs an industrial-grade scanning engine ([OWASP ZAP](https://www.zaproxy.org/)), monitors real-time telemetry, and triages discovered vulnerabilities into a **live findings dashboard** that tells an engineer what is broken, where, and how to fix it.

---

## 🎯 The Core Problem & Value Proposition

| Traditional Security Testing | The CyberSentinel Approach (Shift-Left DevSecOps) |
|---|---|
| **Manual & Periodic**: Conducted once a quarter or annually. | **Automated & Continuous**: Executed programmatically per build or on-demand. |
| **Expensive & Late**: Vulnerabilities discovered right before release or in production. | **Cost-Effective & Early**: Discovered early in development when remediation is 10x cheaper. |
| **Siloed Reports**: Static 100-page PDF documents developers ignore. | **Actionable Telemetry**: Structured JSON alert streams mapped directly to vulnerable URLs. |

---

## 🏗️ Architecture & How It Works

```mermaid
flowchart TD
    subgraph Host["💻 Host Machine (CyberSentinel Orchestrator)"]
        CLI["CLI / User Input\n(Target URL)"] --> PY["orchestrator.py\n(Python Engine)"]
        UI["🖥 Findings Dashboard\nFastAPI + SSE (:5000)"] -->|URL + session cookie| PY
        PY -->|Stage events, telemetry & findings| UI
        PY -->|Step 1: Write Scan-as-Code| YAML["scan_plan.yaml\n(ZAP Automation Plan)"]
        PY -->|Step 2: Trigger Plan via REST API| ZAP["OWASP ZAP Daemon\n(:8080)"]
        PY <-->|Step 3: Real-Time Telemetry Polling| ZAP
        PY -->|Step 4: Harvest & Triage Alerts| ALERTS["Vulnerability Report\n(High / Med / Low / Info)"]
    end

    subgraph Docker["🐳 Docker Sandbox (Target Environments)"]
        ZAP -->|Crawling & Spidering| TARGET["Target Application"]
        ZAP -->|Active Attack Payloads| TARGET
        TARGET --- M["Mutillidae II Stack\n(PHP, MySQL, LDAP)\n:8081, :8082, :8083"]
        TARGET --- D["DVWA Stack\n:9090"]
    end
```

### The 4-Stage Execution Pipeline

1. **Scan-as-Code Generation (`generate_yaml_plan`)**:
   Generates a declarative YAML configuration specifying target scope, inclusion regex rules, spidering duration, passive inspection, and active attack parameters.
2. **API Handshake & Execution (`trigger_zap_scan`)**:
   Dispatches the YAML plan to OWASP ZAP's Automation Framework API (`/JSON/automation/action/runPlan/`), receiving an execution `planId`.
3. **Telemetry & Asynchronous Polling (`poll_plan_progress`)**:
   Continuously monitors engine state (`/JSON/automation/view/planProgress/`, `/JSON/spider/view/scans/`, `/JSON/ascan/view/scans/`), providing terminal output of Spider %, Active Scan %, current phase, and timeout failsafes.
4. **Vulnerability Harvesting (`harvest_alerts`)**:
   Queries `/JSON/core/view/alerts/` to extract risk ratings (Critical, High, Medium, Low, Informational), CWE IDs, affected endpoints, and parameter attack vectors.

---

## 🛠️ Technology Stack & Selection Rationale

Why were these specific technologies chosen over industry alternatives?

### 1. Orchestration Language: Python
* **Selected**: `Python 3.10+` (`requests`, `sys`, `time`, `os`)
* **Why**: Python is the lingua franca of cybersecurity and DevSecOps tooling. It offers robust HTTP handling, easy JSON parsing, cross-platform compatibility, and clean code that is easy to present and extend.
* **Alternatives Evaluated**:
  * *Bash / Shell Scripting*: Brittle, lacks structured exception handling, difficult to parse nested JSON responses and poll async tasks cleanly.
  * *Go / Rust*: Excellent performance, but introduces unnecessary compilation overhead and slower prototyping speed for a prototype orchestrator.

### 2. DAST Security Engine: OWASP ZAP (ZAP Automation Framework)
* **Selected**: `OWASP Zed Attack Proxy (ZAP)` via Automation Framework & REST API.
* **Why**: ZAP is open-source, maintained by OWASP, free of enterprise licensing restrictions, and features an **Automation Framework (AF)** that decouples scan logic into declarative YAML files.
* **Alternatives Evaluated**:
  * *Burp Suite Professional / Enterprise*: Industry-leading scanner, but proprietary, closed-source, expensive, and its REST API is restricted to high-cost enterprise tiers.
  * *Nuclei*: Superb for fast, template-driven known CVE scanning, but lacks stateful crawling, dynamic form submission, and deep active attack generation required for bespoke web apps.
  * *Nikto*: Obsolete, noisy, produces excessive false positives, and lacks modern REST APIs and active application analysis.

### 3. Declarative Configuration: YAML (Scan-as-Code)
* **Selected**: `scan_plan.yaml`
* **Why**: Follows the modern GitOps and DevSecOps paradigm. Security scans are treated like code—version-controlled, auditable, and easily editable without modifying the Python orchestrator script.

### 4. Sandboxed Target Environments: Docker & Docker Compose
* **Selected**: Multi-container Docker stacks for **OWASP Mutillidae II** and **DVWA**.
* **Why**:
  * Provides isolated, repeatable, and safe testing ground for high-risk exploits (SQL Injection, LDAP Injection, XSS) without legal or ethical risks.
  * Zero pollution of host system (no native Apache/PHP/MySQL dependencies).
  * Fast spin-up and teardown in seconds.

### 5. Dashboard Delivery: FastAPI + Server-Sent Events

* **Selected**: `FastAPI` + `Uvicorn` serving one HTML page and vanilla JS, with progress pushed over **Server-Sent Events**.
* **Why**: The scan pipeline is a long-running, one-directional telemetry source — exactly what SSE models without extra machinery. A browser reconnects and replays missed events for free, and the backend stays in the same Python runtime as the orchestrator, so no scan logic is duplicated for the UI.
* **Alternatives evaluated**:
  * *WebSockets*: Bidirectional, but the dashboard only sends one command (start/stop) and receives a stream; SSE adds reconnect semantics without a protocol upgrade or connection-state code.
  * *Client polling*: Simplest to implement, but re-polling every second multiplies request load and makes progress visibly jerky.
  * *React / Next.js SPA*: Better for a large product surface, but introduces a Node build pipeline for a single operator screen.
  * *Off-the-shelf (DefectDojo / Security Hub)*: Mature finding management, yet it hides the orchestration story this project exists to demonstrate; PostgreSQL persistence for the DefectDojo-style schema remains available through `storage.py`.

---

## 📂 Repository Structure

```text
CyberSentinel/
├── orchestrator.py         # Main pipeline: discovery -> ZAP -> SSLyze -> harvest (CLI entry point)
├── web_dashboard.py        # FastAPI app: scan queue, SSE progress stream, findings API
├── events.py               # In-memory scan jobs; thread-safe event fan-out to dashboard clients
├── zap_client.py           # OWASP ZAP Automation Framework adapter + scan policy presets
├── discovery.py            # Nmap service discovery and scanner routing
├── targeting.py            # URL parsing, ZAP scope regex, authorization guardrails
├── normalizer.py           # ZAP/SSLyze output -> common RawFinding contract (+ deduplication)
├── models.py               # Typed dataclasses shared across the pipeline
├── tls_audit.py            # SSLyze TLS audit
├── storage.py / schema.sql # PostgreSQL product -> engagement -> test -> finding hierarchy
├── exceptions.py           # Domain error hierarchy
├── scan_plan.yaml          # Declarative YAML scan configuration (auto-generated & customizable)
├── templates/dashboard.html # Server-rendered dashboard page
├── static/dashboard.js     # Live progress + findings UI (no build step)
├── static/dashboard.css    # Dashboard styling
├── tests/                  # Unit tests for discovery, targeting, normalizer, orchestrator, dashboard
├── requirements.txt
├── DASHBOARD.md            # Module 2 deep-dive: request lifecycle, SSE protocol, viva question bank
├── README.md               # Complete platform documentation and architecture guide
└── mutillidae/             # Dockerized Multi-Container Vulnerability Target Stack
    ├── docker-compose.yml  # Compose definition (Web, MySQL, OpenLDAP, phpMyAdmin, phpLDAPadmin)
    └── README.md           # Mutillidae-specific operations and port documentation
```

Scan evidence is written per run to `scan_results/<scan_id>/` (`findings.json`,
`scan_plan.yaml`); that directory is generated and git-ignored.

## Module 1 Implementation

The current implementation is an authorized, multi-stage pipeline:

1. **Target validation**: HTTP(S) targets are normalized into a strict ZAP scope. Loopback targets are accepted for local development; a remote target requires the operator to provide `--authorized` as an explicit permission attestation.
2. **Nmap discovery**: `python-nmap` runs a narrow service-version scan. An explicit port scans only that port; an origin URL without a port checks the supported web-service port set.
3. **Service router**: only discovered web services enter ZAP. HTTPS/TLS services also enter SSLyze.
4. **ZAP active scan**: the Automation Framework plan is generated with an absolute path, polled using plan/spider/active telemetry, and stopped if it exceeds its timeout.
5. **SSLyze TLS audit**: SSLyze writes JSON output which is retained with the scan record. Deprecated SSL/TLS versions, weak ciphers, and expired certificates are normalized when present.
6. **PostgreSQL persistence**: every Nmap, ZAP, and SSLyze execution creates a `test` row within the required `product -> engagement -> test -> finding <-> endpoint_status -> endpoint` hierarchy. Repeated findings retain history and are marked with the required SHA-256 deduplication hash.

The public Python entry point is `run_scan(target_url, ...)` in `orchestrator.py`. The CLI is intentionally thin so CI/CD integrations can call the same pipeline directly.

---

## 🖥️ Module 2 Implementation: Findings Dashboard

Module 1 answered *"can we drive a DAST engine programmatically?"*. Module 2 answers the question a developer actually asks: *"what is broken, where, and how do I fix it?"*

The dashboard is a FastAPI service that exposes the **exact same pipeline** as the CLI — no duplicated scan logic — and streams its telemetry to a browser while it runs.

> 📘 **Full technical write-up:** [`DASHBOARD.md`](DASHBOARD.md) documents this module end to end — the request lifecycle, the thread→asyncio event bridge, the SSE frame protocol with wire captures, the findings data contract, session/cookie injection into ZAP, security guardrails, measured verification evidence, limitations, troubleshooting, and a viva question bank.

### Operator flow

1. Paste a target URL, for example `http://127.0.0.1:4280/vulnerabilities/csrf/?password_new=ss&password_conf=ss&Change=Change`.
2. Paste the session cookie. Both `security=low; PHPSESSID=abc…` and a copied `Cookie: security=low; …` header are accepted — the prefix and any newlines are stripped before the value reaches the ZAP plan.
3. Choose the vulnerability scope (`all`, `sqli`, `xss`, `csrf`). These map 1:1 to the `SCAN_POLICIES` presets in `zap_client.py`; `all` leaves ZAP's default policy in place.
4. Press **Enter** (or click *Start scan*). Progress renders live; findings appear as the engine harvests them.

### Live progress panel

| Element | Source |
|---|---|
| Stage stepper (discovery → ZAP → TLS → harvest) | `stage` events emitted by `run_scan` |
| Spider / active-scan percentage bars, elapsed clock | `progress` events from `ZAPClient.poll_plan` |
| Discovered services | Nmap result of the discovery stage |
| Crawled URLs | ZAP spider results, reported before fuzzing starts |
| Engine log | The same lines the CLI prints on stdout |
| Stop | Sets a cancellation flag that `poll_plan` checks each poll, then calls ZAP's `stopPlan` |

### Findings dashboard

Every finding is rendered with the fields a developer needs to act, produced by `finding_to_dict()` in `orchestrator.py`:

**name · severity · affected URL · vulnerable parameter · evidence · confidence · recommended fix**, plus CWE, attack payload, scanner source, and reference links.

Findings are filterable by severity chip, tabbed by **active exploit** vs **passive warning**, and searchable by name, URL, or parameter. Active findings (real exploitation) are deliberately separated from passive hygiene warnings so the exploitable issues are never buried under header findings.

### HTTP API

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/` | Dashboard UI |
| `GET` | `/api/health?zap_url=…` | Preflight: ZAP reachability + version, Nmap availability, active scan id |
| `POST` | `/api/scans` | Queue a scan (`target_url`, `cookie`, `policy`, `zap_url`, `zap_timeout`, `authorized`) |
| `GET` | `/api/scans/{id}/events` | Server-Sent Event stream for one scan |
| `GET` | `/api/scans/{id}` | Snapshot: status, findings, and full event history |
| `GET` | `/api/scans` | Recent scan summaries |
| `POST` | `/api/scans/{id}/stop` | Request cancellation |

Event types on the stream: `scan.queued`, `scan.started`, `stage`, `services`, `plan`, `progress`, `urls`, `finding`, `log`, `error`, `summary`, `scan.cancelling`, `scan.finished`.

### Design decisions

* **Threads publish, the event loop delivers.** The pipeline is synchronous and blocking, so each scan runs in a worker thread while SSE responses live on asyncio's loop. `events.py` crosses that boundary with `loop.call_soon_threadsafe`, which keeps the scan code free of any async concerns.
* **Refresh-safe.** Every event is appended to the job's history, so reloading the page re-attaches to the in-flight scan and rebuilds the panel from the replay instead of losing it.
* **Preflight beats a hang.** A missing ZAP daemon is reported by `/api/health` before a scan is queued; the ZAP base URL is editable in the UI (and via `CYBERSENTINEL_ZAP_URL`) because a desktop ZAP install rarely listens on `8080` by default.
* **One scan at a time.** A single ZAP daemon is a shared, stateful resource, so a second `POST /api/scans` returns `409` rather than interleaving two plans.
* **The session cookie is write-only.** It reaches the ZAP plan but is never echoed back — API responses expose only `cookie_provided: true`.
* **Duplicates collapse once, in the normalizer.** ZAP re-reports byte-identical alerts when the spider revisits a URL with reordered parameters, so `normalize_zap_alerts()` deduplicates them. The terminal summary, `findings.json`, and the dashboard counts therefore always agree.
* **Bind to loopback.** The dashboard has no authentication and can launch scans; run it on `127.0.0.1` against systems you are authorised to test.

### Artifacts

Each scan writes to its own directory so evidence is never overwritten:

```text
scan_results/<scan_id>/
├── findings.json    # normalized active + passive findings
└── scan_plan.yaml   # the exact ZAP Automation Framework plan that ran
```

---

## 🚀 Quick Start (Run with Docker Compose)

The fastest and most reliable way to run CyberSentinel and the OWASP ZAP engine together:

```bash
# 1. Clone the repository
git clone https://github.com/97Satya79/CyberSentinel.git
cd CyberSentinel

# 2. Start the entire platform (ZAP Engine + Findings Dashboard)
docker compose up
```

Once started, open your browser at **[http://localhost:5000](http://localhost:5000)**.

---

## 🛠️ Manual / Local Development Setup

### Prerequisites
- **macOS / Linux / Windows (WSL2)**
- **Docker & Docker Compose** installed and running
- **Python 3.10+** with the project dependencies installed
- **Nmap** installed and available on `PATH`
- **OWASP ZAP** installed (Desktop GUI or Headless Docker Daemon)
- **PostgreSQL 14+** for persistent engagements, tests, findings, and endpoints

Install Python dependencies from the repository root:

```bash
python3 -m pip install -r requirements.txt
```

`requirements.txt` also installs `fastapi` and `uvicorn` for the Module 2 dashboard. The UI itself is plain HTML/CSS/JS with no Node build step.

For PostgreSQL persistence, supply a normal PostgreSQL DSN through `--db-dsn` or the `CYBERSENTINEL_DATABASE_URL` environment variable. Initialize the six-table schema once with:

```bash
python3 orchestrator.py --init-db --db-dsn "postgresql://USER:PASSWORD@127.0.0.1:5432/cybersentinel"
```

---

### Step 1: Start the Target Environment (Mutillidae II)

Spin up the containerized target stack:

```bash
cd mutillidae
docker compose up -d
```

Verify containers are running:
```bash
docker ps
```

| Service | Local URL | Description |
|---|---|---|
| **Mutillidae II Web App** | [http://127.0.0.1:8081](http://127.0.0.1:8081) | Primary target application |
| **Database Setup** | [http://127.0.0.1:8081/set-up-database.php](http://127.0.0.1:8081/set-up-database.php) | One-click database table initializer |
| **phpMyAdmin** | [http://127.0.0.1:8082](http://127.0.0.1:8082) | MySQL Database Web GUI |
| **phpLDAPadmin** | [http://127.0.0.1:8083](http://127.0.0.1:8083) | LDAP Directory Web GUI |

*(Note: On first start, visit `http://127.0.0.1:8081/set-up-database.php` to initialize the database tables).*

---

### Step 2: Start OWASP ZAP API Daemon

Start ZAP with API access enabled on port `8080`:

* **Via ZAP Desktop App**:
  1. Open OWASP ZAP.
  2. Tools → Options → API → Ensure API is enabled on port `8080`.
  3. (Recommended for local dev) Disable API key or configure `zap_base_url`.

* **Or via ZAP Docker Headless Container**:
  ```bash
  docker run -u zap -p 8080:8080 -d ghcr.io/zaproxy/zaproxy:stable zap.sh -daemon -host 0.0.0.0 -port 8080 -config api.disablekey=true
  ```

---

### Step 3: Run CyberSentinel Orchestrator

Execute the scanner against your desired target (e.g., local Mutillidae, DVWA, or an authorized testbed):

```bash
# Scan the local SentinelVault endpoint and persist every scanner output.
python3 orchestrator.py "http://127.0.0.1:5050/vulnerabilities/sqli/" \
  --db-dsn "postgresql://USER:PASSWORD@127.0.0.1:5432/cybersentinel"

# Scan local Mutillidae over HTTP.
python3 orchestrator.py "http://127.0.0.1:8081/" \
  --db-dsn "postgresql://USER:PASSWORD@127.0.0.1:5432/cybersentinel"
```

For a non-local system, explicit authorization is required in addition to the URL:

```bash
python3 orchestrator.py "https://authorized.example/" --authorized --db-dsn "$CYBERSENTINEL_DATABASE_URL"
```

Use `python3 orchestrator.py --help` for timeout, output directory, product name, and ZAP daemon options.

#### Sample Terminal Output:
```text
Scan plan successfully generated and saved to: .../scan_plan.yaml
ZAP API Response: {'planId': 0}

[+] Monitoring Plan ID: 0 (polling every 5s, timeout 360s)...
[Progress] Plan ID: 0 | Elapsed: 5s  | Job: spider     | Spider: 25% | ActiveScan: 0%
[Progress] Plan ID: 0 | Elapsed: 15s | Job: spider     | Spider: 100%| ActiveScan: 0%
[Progress] Plan ID: 0 | Elapsed: 30s | Job: activeScan | Spider: 100%| ActiveScan: 45%
[Progress] Plan ID: 0 | Elapsed: 60s | Job: activeScan | Spider: 100%| ActiveScan: 100%

[✓] Automation Plan 0 completed successfully!

[+] Harvesting alerts for http://127.0.0.1:8081/ (14 found)...
[High] SQL Injection - http://127.0.0.1:8081/index.php?page=user-info.php
[High] Cross Site Scripting (Reflected) - http://127.0.0.1:8081/index.php?page=dns-lookup.php
[Medium] Content Security Policy (CSP) Header Not Set - http://127.0.0.1:8081/
[Low] X-Content-Type-Options Header Missing - http://127.0.0.1:8081/
```

---

### Step 4: Launch the Findings Dashboard

The dashboard reuses the Module 1 pipeline, so the ZAP daemon and Nmap from the
prerequisites must already be available.

```bash
# From the repository root
python -m uvicorn web_dashboard:app --host 127.0.0.1 --port 5000
```

Open <http://127.0.0.1:5000>, paste the target URL and session cookie, pick a
vulnerability scope, and press **Enter**.

If ZAP's API is not on `http://127.0.0.1:8080`, set it once for the process or
per scan from the UI:

```bash
CYBERSENTINEL_ZAP_URL="http://127.0.0.1:8090" python -m uvicorn web_dashboard:app --host 127.0.0.1 --port 5000
```

The **ZAP daemon** chip in the header reflects `/api/health`, so an unreachable
engine is visible before a scan is queued rather than failing mid-run.

---

## 🎤 Panel Pitch & Presentation Guide

When showcasing CyberSentinel to evaluation committees, professors, or industry panels, use this structured pitch script:

### 1. The Hook (30 Seconds)
> *"Every software company wants to ship features fast, but security is often treated as an afterthought or bottleneck. Today, over 80% of data breaches exploit web application vulnerabilities like SQL injection and broken authentication. **CyberSentinel** solves this by automating Dynamic Application Security Testing, enabling development teams to find and fix critical flaws continuously before malicious hackers can exploit them."*

### 2. The Prototype Demo (90 Seconds)
> *"What we have built today is a working prototype demonstrating automated security orchestration:*
> 1. *We use Docker to instantly spin up isolated multi-tier vulnerable enterprise environments (OWASP Mutillidae II).*
> 2. *Our Python orchestrator generates a declarative Scan-as-Code specification on the fly.*
> 3. *It interfaces with OWASP ZAP's Automation Framework daemon through asynchronous REST APIs.*
> 4. *It streams real-time telemetry (spider crawling and active attack completion).*
> 5. *Finally, it harvests, deduplicates, and triages security alerts categorized by risk severity."*

### 3. The Future Vision & Enterprise Roadmap (60 Seconds)
> *"This prototype is our foundational engine. In the next phase, we are evolving CyberSentinel from a scanning tool into an end-to-end **Autonomous AI Security Engineer**."* (Present the roadmap below).

---

## 🔮 Roadmap: Scaling from Prototype to Real-World Product

To transition CyberSentinel into an enterprise-ready security product, the following high-impact features are planned:

```mermaid
graph LR
    P[Current Prototype\n• Python Orchestrator\n• ZAP REST API\n• Docker Testbeds\n• Live SSE Findings Dashboard\n• Risk Triage] --> F1[1. AI Remediation Engine\n• LLM Context Analysis\n• Auto PR Code Patches\n• False Positive Filter]
    P --> F2[2. CI/CD DevSecOps Gate\n• GitHub Actions / GitLab CI\n• Quality Gates\n• Block Insecure Builds]
    P --> F3[3. Enterprise Integrations\n• Auto Jira / Slack Tickets\n• CVSS 3.1 Scoring\n• Audit Compliance Reports]
```

### 1. 🤖 AI-Powered Remediation & False Positive Reduction
* **The Problem**: DAST scanners produce raw alerts and occasional false positives. Developers waste hours reading abstract vulnerability descriptions without knowing how to fix the code.
* **The Solution**: Pipe harvested vulnerability alerts and payloads into an LLM (such as Gemini 1.5 Pro / Claude 3.5 Sonnet) along with the application's source code. 
* **Outcome**: The platform will generate **automated Git Pull Requests with the exact code patches** (e.g., converting a raw SQL string to parameterized prepared statements).

### 2. 🚦 CI/CD Security Quality Gates (Shift-Left)
* **The Problem**: Security teams cannot manually review every pull request in fast-moving engineering teams.
* **The Solution**: Package CyberSentinel as a native GitHub Action and GitLab CI runner.
* **Outcome**: Automatically spin up preview deployments, execute a 3-minute targeted DAST scan, and **automatically fail the build** if any `High` or `Critical` severity vulnerabilities are detected.

### 3. 🎫 Automated Issue Tracking & Ticketing
* **Integration**: Native connectors for **Jira**, **GitHub Issues**, and **Slack/Teams Webhooks**.
* **Outcome**: Critical alerts automatically create assigned Jira tickets containing reproduction cURL commands, attack payloads, evidence screenshots, and remediation guidance.

### 4. 📊 Executive & Regulatory Compliance Dashboards
* **Mapping**: Auto-correlate scan findings against global compliance standards:
  * **OWASP Top 10 (2021)**
  * **CWE Top 25**
  * **PCI-DSS 4.0** (Requirement 6.5)
  * **HIPAA / ISO 27001**
* **Reporting**: 1-click generation of audit-ready executive PDF and developer-friendly Markdown/SARIF reports.

### 5. 🔐 Authenticated Crawling & API-First Scanning
* **In place**: pre-authenticated **session cookie** handling — the dashboard injects the operator's cookie into every spider and active-scan request and excludes logout paths from the crawl so the session survives the scan.
* **Next**: OAuth2 / JWT flows and Selenium-driven browser replay to reach portals behind multi-factor login.
* **Next**: Support scanning OpenAPI / Swagger JSON specs directly to audit backend microservices and headless APIs.

---

## 🔒 Ethical & Legal Disclaimer

> **IMPORTANT**: CyberSentinel is designed strictly for authorized penetration testing, security research, and continuous integration testing on systems you own or have explicit, documented permission to test. Unauthorized port scanning or vulnerability exploitation against third-party systems is illegal and violates global cybersecurity legislation (including the Computer Fraud and Abuse Act - CFAA). Always test responsibly within sandboxed environments like the included Docker testbeds.

---

## 👥 Contributors & Acknowledgements

* **Author**: Adithya Pawar
* **Frameworks & References**:
  * [OWASP ZAP Project](https://www.zaproxy.org/)
  * [OWASP Mutillidae II Project](https://github.com/webpwnized/mutillidae)
  * [Damn Vulnerable Web Application (DVWA)](https://github.com/digininja/DVWA)
