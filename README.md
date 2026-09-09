# ⚡ RECKON — Ultimate Reconnaissance & Threat Intelligence Framework

<p align="center">
  <img src="https://img.shields.io/badge/version-3.0-blue.svg?style=for-the-badge&logo=shield" alt="Version 3.0" />
  <img src="https://img.shields.io/badge/license-MIT-green.svg?style=for-the-badge" alt="License MIT" />
  <img src="https://img.shields.io/badge/platform-Linux%20%7C%20Kali%20%7C%20Parrot%20%7C%20macOS%20%7C%20WSL-orange.svg?style=for-the-badge&logo=linux" alt="Platform Support" />
  <img src="https://img.shields.io/badge/bash-4.0%2B-lightgrey.svg?style=for-the-badge&logo=gnu-bash" alt="Bash 4+" />
  <img src="https://img.shields.io/badge/security-Audited-red.svg?style=for-the-badge&logo=target" alt="Security Audited" />
</p>

```
██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗    ██╗   ██╗██╗  ████████╗
██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║    ██║   ██║██║  ╚══██╔══╝
██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║    ██║   ██║██║     ██║   
██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║    ██║   ██║██║     ██║   
██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║    ╚██████╔╝███████╗██║   
╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝     ╚═════╝ ╚══════╝╚═╝   

        ┌─────────────────────────────────────────────────────┐
        │   Ultimate Reconnaissance Tool  v1.0                │
        │   Multi-Tool • Correlated Insights • Full Reports   │
        └─────────────────────────────────────────────────────┘
```

**Reckon** is an enterprise-grade, fully automated reconnaissance framework designed for security researchers, penetration testers, red teams, and bug hunters. It orchestrates dozens of industry-standard security tools into a streamlined, correlated multi-phase pipeline—transforming raw target domain or IP inputs into prioritized attack surface insights, exploit intelligence, and publication-ready HTML & JSON dashboards.

---

## 📑 Table of Contents

- [Key Capabilities](#-key-capabilities)
- [Architecture & Recon Pipeline](#-architecture--recon-pipeline)
  - [Pipeline Workflow Diagram](#pipeline-workflow-diagram)
  - [Phase Breakdown](#phase-breakdown)
- [Installation & Setup](#-installation--setup)
  - [Quick Remote One-Liner](#1-quick-remote-one-liner)
  - [Full Toolsuite Installation](#2-install-with-all-extended-recon-tools)
  - [Local Clone Installation](#3-local-repository-installation)
  - [Manual Package Manager Installation](#4-manual-package-manager-installation)
  - [Uninstalling Reckon](#5-uninstalling-reckon)
- [Command-Line Reference](#-command-line-reference)
  - [Options & Flags](#options--flags)
  - [Practical Usage Scenarios](#practical-usage-scenarios)
- [CVE & Exploit Intelligence Engine](#-cve--exploit-intelligence-engine)
- [Artifacts & Directory Structure](#-artifacts--directory-structure)
- [Reporting](#-reporting)
  - [Interactive Dark-Mode HTML Report](#interactive-dark-mode-html-report)
  - [Structured JSON Report Schema](#structured-json-report-schema)
- [Supported Tools Matrix](#-supported-tools-matrix)
- [Best Practices & Pro Tips](#-best-practices--pro-tips)
- [Legal & Ethical Disclaimer](#-legal--ethical-disclaimer)
- [License](#-license)

---

## 🚀 Key Capabilities

- **Zero-Friction Execution**: Run a single command against any target (`reckon -t example.com`) and let Reckon automate passive gathering, active enumeration, service fingerprinting, vulnerability scanning, exploit correlation, and report synthesis.
- **Graceful Tool Degradation & Smart Fallbacks**: Reckon automatically detects available tools on your system. If specialized Go tools (`subfinder`, `httpx`, `ffuf`) are absent, Reckon gracefully falls back to native tools (`dig`, `host`, `curl`, `gobuster`, pure Bash loops) without failing.
- **Deep Exploit & CVE Correlation**:
  - Live queries against the **NIST National Vulnerability Database (NVD) REST API v2** for detected services.
  - Automated local cross-referencing against **Exploit-DB (`searchsploit`)** with automated categorization into:
    - 🔴 **Remote Code Execution (RCE)**
    - 🟠 **Web Application Exploits**
    - 🟡 **Local Privilege Escalation (LPE)**
    - 🔵 **Denial of Service (DoS)**
    - ⚪ **Shellcode & Papers**
- **Intelligent Risk Heuristics**:
  - Email spoofing analysis (missing SPF & DMARC records).
  - DNS security validation (DNSSEC verification and active DNS Zone Transfer AXFR tests).
  - SSL/TLS certificate health (validity countdown, expiration warnings, deprecated TLSv1/SSLv3 protocols).
  - HTTP security header auditing (HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy).
  - Dangerous cookie configurations (missing `HttpOnly`, `Secure`).
  - Sensitive files fuzzing (`.git`, `.env`, database dumps, Docker configs, backups).
  - Web Application Firewall (WAF) detection and tech stack fingerprinting.
  - CORS origin reflection and Clickjacking vulnerability tests.
- **Modern Reporting Engine**:
  - **Standalone Interactive HTML Dashboard**: Dark-mode, glassmorphism UI with real-time severity metrics (Critical, High, Medium, Low, Info), responsive design, and timestamped finding records.
  - **Machine-Readable JSON**: Complete structured output for DevSecOps, CI/CD pipelines, DefectDojo, Splunk, or Elastic SIEM integration.

---

## 🏛 Architecture & Recon Pipeline

Reckon executes reconnaissance in structured, sequential phases. Active and brute-force phases can be toggled or tuned based on your rules of engagement.

### Pipeline Workflow Diagram

```
                              ┌───────────────────────────┐
                              │     TARGET DOMAIN / IP    │
                              └─────────────┬─────────────┘
                                            │
                                            ▼
       ┌────────────────────────────────────────────────────────────────────────┐
       │ PHASE 1: PASSIVE RECONNAISSANCE                                        │
       │  • WHOIS Analysis           • DNS Records (A, AAAA, MX, NS, TXT, CAA)  │
       │  • SPF / DMARC Email Spoof  • DNSSEC & Zone Transfer (AXFR) Checks     │
       │  • ASN & IP Geolocation     • crt.sh Certificate Transparency Logs    │
       │  • SSL/TLS Expiry & Ciphers • Google Dork Query Synthesis              │
       └────────────────────────────────────┬───────────────────────────────────┘
                                            │
                                            ▼
       ┌────────────────────────────────────────────────────────────────────────┐
       │ PHASE 2: SUBDOMAIN ENUMERATION & LIVE PROBING                          │
       │  • Passive: subfinder, amass, assetfinder, CT log harvesting          │
       │  • Active: gobuster DNS brute-force / Bash resolver fallback           │
       │  • DNS Resolution: dnsx / dig validation                               │
       │  • HTTP Probing: httpx (status codes, titles, web tech)                │
       └────────────────────────────────────┬───────────────────────────────────┘
                                            │
                                            ▼
       ┌────────────────────────────────────────────────────────────────────────┐
       │ PHASE 3: PORT SCANNING & ATTACK SURFACE MAPPING                        │
       │  • Host Discovery (nmap -sn)                                           │
       │  • TCP SYN + Service Version Detection (nmap -sV -sC -O -A)            │
       │  • UDP Top-Port Scanning (nmap -sU)                                    │
       │  • High-Risk Port Analysis (Redis, Mongo, RDP, SMB, Telnet, VNC, etc.) │
       └────────────────────────────────────┬───────────────────────────────────┘
                                            │
                                            ▼
       ┌────────────────────────────────────────────────────────────────────────┐
       │ PHASE 4: WEB APPLICATION INTELLIGENCE                                  │
       │  • Security Headers Audit    • Cookie Flags (HttpOnly, Secure)         │
       │  • Information Disclosure    • Technology Fingerprinting (WhatWeb)     │
       │  • WAF Detection (wafw00f)   • robots.txt & sitemap.xml Spidering      │
       │  • Sensitive Files Fuzzing   • Directory Bruteforce (ffuf / gobuster)  │
       │  • Nikto Web Vulnerability Scan                                        │
       └────────────────────────────────────┬───────────────────────────────────┘
                                            │
                                            ▼
       ┌────────────────────────────────────────────────────────────────────────┐
       │ PHASE 5 & 5b: VULNERABILITY & EXPLOIT CORRELATION                      │
       │  • Nuclei Template Engine (Critical -> Low templates)                  │
       │  • Known Vulnerability Heuristics (EOL Apache, OpenSSH, vsftpd, etc.)  │
       │  • CORS Reflection & Clickjacking Tests                                │
       │  • NIST NVD API v2 Automated CVE Lookup                                │
       │  • Exploit-DB (searchsploit) Correlation & Severity Categorization     │
       └────────────────────────────────────┬───────────────────────────────────┘
                                            │
                                            ▼
       ┌────────────────────────────────────────────────────────────────────────┐
       │ PHASE 6: REPORTING & ARTIFACT SYNTHESIS                                │
       │  • Interactive Dark-Mode HTML Report (report.html)                     │
       │  • Machine-Readable Structured JSON (report.json)                      │
       │  • Clean Raw Artifact Directory & Complete Execution Log (recon.log)   │
       └────────────────────────────────────────────────────────────────────────┘
```

### Phase Breakdown

| Phase | Name | Description | Key Tools Used |
|---|---|---|---|
| **Phase 1** | **Passive Recon** | Gathers OSINT without alerting the target. Inspects WHOIS, DNS records, email security, TLS certificates, IP geolocation, and generates target-specific Google dorks. | `whois`, `dig`, `curl`, `openssl`, `crt.sh`, `ipinfo.io` |
| **Phase 2** | **Subdomains** | Discovers and validates all target subdomains through passive OSINT sources, certificate logs, active DNS brute-forcing, and HTTP probing. | `subfinder`, `amass`, `assetfinder`, `gobuster`, `dnsx`, `httpx` |
| **Phase 3** | **Port Scanning** | Discovers open ports, fingerprints running services and OS versions, audits top UDP services, and flags exposed sensitive infrastructure. | `nmap` |
| **Phase 4** | **Web Recon** | Probes HTTP/HTTPS services for header configurations, cookie security flags, technology stacks, WAF barriers, sensitive files (`.git`, `.env`, backups), and hidden paths. | `curl`, `whatweb`, `wafw00f`, `ffuf`, `gobuster`, `nikto` |
| **Phase 5** | **Vuln Correlation** | Runs template-based vulnerability scanning, detects CORS misconfigurations and Clickjacking flaws, and checks service versions against known high-impact exploits. | `nuclei`, `curl` |
| **Phase 5b** | **CVE & Exploit-DB** | Extracts exact software version signatures, queries the NIST NVD REST API v2 for CVE scores, and matches with Exploit-DB public exploits via Searchsploit. | NIST NVD API, `searchsploit`, `python3` |
| **Phase 6** | **Reporting** | Compiles all discovered endpoints, open ports, software signatures, and prioritized findings into visual HTML dashboards and structured JSON documents. | `python3`, HTML5/CSS3 |

---

## 📦 Installation & Setup

Reckon includes a smart, self-contained installer (`install.sh`) that works on **Debian, Ubuntu, Kali Linux, Parrot Security, Arch Linux, Fedora, CentOS, openSUSE, Alpine Linux, and macOS (Homebrew)**.

### 1. Quick Remote One-Liner

Install `reckon` and `reckon.sh` into `/usr/local/bin`:

```bash
curl -fsSL https://raw.githubusercontent.com/Kishan-Agarwal-28/reckon/main/install.sh | sudo bash
```

### 2. Install with All Extended Recon Tools

Automatically install system package dependencies **and** download/configure extended reconnaissance tools (`subfinder`, `httpx`, `nuclei`, `dnsx`, `nikto`, `whatweb`, `wafw00f`, `gobuster`, `ffuf`, `searchsploit`, `seclists`):

```bash
curl -fsSL https://raw.githubusercontent.com/Kishan-Agarwal-28/reckon/main/install.sh | sudo bash -s -- --tools
```

> **Tip:** If you only want to install core system dependencies (`nmap`, `dnsutils`, `whois`, `curl`, `python3`, `jq`, `openssl`), use `--deps`:
> ```bash
> curl -fsSL https://raw.githubusercontent.com/Kishan-Agarwal-28/reckon/main/install.sh | sudo bash -s -- --deps
> ```

### 3. Local Repository Installation

```bash
# Clone the repository
git clone https://github.com/Kishan-Agarwal-28/reckon.git
cd reckon

# Make installer executable and run
chmod +x install.sh reckon.sh
sudo ./install.sh

# Or install with extended toolsuite:
sudo ./install.sh --tools
```

The installer automatically detects the local `reckon.sh` file, verifies its syntax and integrity, installs it to `/usr/local/bin/reckon.sh`, and creates a symlink at `/usr/local/bin/reckon`.

### 4. Manual Package Manager Installation

If you prefer installing dependencies manually via your native package manager:

#### Debian / Ubuntu / Kali / Parrot
```bash
sudo apt update
sudo apt install -y nmap dnsutils whois curl openssl python3 jq coreutils \
    nikto whatweb wafw00f gobuster ffuf exploitdb seclists
```

#### Arch Linux / BlackArch / Manjaro
```bash
sudo pacman -Syu
sudo pacman -S --needed nmap bind whois curl openssl python jq \
    nikto whatweb wafw00f gobuster ffuf exploitdb
```

#### Fedora / RHEL / Rocky Linux
```bash
sudo dnf install -y nmap bind-utils whois curl openssl python3 jq coreutils
```

#### macOS (Homebrew)
```bash
brew install nmap whois curl openssl python3 jq bind
```

#### ProjectDiscovery Go Tools (Optional but Recommended)
If you have Go installed (`go version`):
```bash
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest
go install -v github.com/tomnomnom/assetfinder@latest
```

### 5. Uninstalling Reckon

To cleanly remove Reckon and its CLI symlinks from your system:

```bash
sudo ./install.sh --uninstall
# or
sudo rm -f /usr/local/bin/reckon /usr/local/bin/reckon.sh
```

---

## 💻 Command-Line Reference

Once installed, you can invoke Reckon using either `reckon` or `reckon.sh`.

```bash
reckon -t <target> [OPTIONS]
```

### Options & Flags

| Flag | Long Flag | Description | Default |
|---|---|---|---|
| `-t` | `--target <domain\|IP>` | **Required.** Target domain (e.g., `example.com`) or IPv4 address | *None* |
| `-o` | `--output <dir>` | Directory where artifacts and reports will be saved | `recon_<target>_<timestamp>` |
| `-T` | `--threads <n>` | Parallel thread count for DNS, bruteforce, and HTTP tools | `10` |
| `-p` | `--ports <list>` | Comma-separated list of ports to scan | Standard 22 common ports |
| `-P` | `--full-ports` | Scan all **65,535** TCP ports | `false` |
| `-s` | `--stealth` | Stealth scanning mode (slow timing `-T1`, packet fragmentation) | `false` |
| `-w` | `--wordlist <file>` | Custom wordlist for directory bruteforcing | `/usr/share/wordlists/dirb/common.txt` |
| `-d` | `--dns-wordlist <file>`| Custom wordlist for DNS subdomain brute-forcing | `subdomains-top1million-5000.txt` |
| `-r` | `--report <fmt>` | Report output format: `html`, `json`, or `both` | `both` |
| | `--skip-active` | Disable all active port/web scans (**passive OSINT only**) | `false` |
| | `--skip-bruteforce` | Skip DNS and directory bruteforce phases | `false` |
| | `--skip-cve` | Skip NIST NVD and Exploit-DB lookups | `false` |
| | `--nvd-key <key>` | **NIST NVD API Key** for accelerated rate limits (50 req/min) | *None (uses 6 req/min)* |
| `-v` | `--verbose` | Enable verbose/debug diagnostic output | `false` |
| `-h` | `--help` | Display help and usage manual | *None* |

---

### Practical Usage Scenarios

#### Scenario 1: Standard Full Reconnaissance Scan
Runs all passive, active, web, vulnerability, and CVE correlation phases:
```bash
sudo reckon -t example.com
```

#### Scenario 2: Passive OSINT Only (Zero Active Traffic to Target)
Ideal for external assessments where active port scanning or web probing is prohibited by rules of engagement:
```bash
reckon -t example.com --skip-active
```

#### Scenario 3: Stealth Penetration Testing Mode
Uses low scan speeds, small packet payloads, packet fragmentation, and disables noisy bruteforce operations:
```bash
sudo reckon -t 192.168.1.50 --stealth --skip-bruteforce
```

#### Scenario 4: Deep Infrastructure Assessment
Performs a full 65,535-port scan, increases thread concurrency, and utilizes custom wordlists:
```bash
sudo reckon -t target.corp \
  -o /var/log/audits/target_corp \
  -P \
  -T 25 \
  -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt \
  -d /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt \
  --report both
```

#### Scenario 5: High-Speed CVE Correlation with NVD API Key
NIST limits unauthenticated requests to 5 requests per 30-second window. Supplying an API key boosts limits to 50 requests per 30-second window, accelerating Phase 5b dramatically:
```bash
sudo reckon -t example.com --nvd-key "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
```

---

## 🔍 CVE & Exploit Intelligence Engine

One of Reckon's most powerful capabilities is its two-tier vulnerability correlation engine:

```
                  ┌───────────────────────────────┐
                  │ nmap Service / Version String │
                  │  (e.g., Apache 2.4.49, etc.)  │
                  └───────────────┬───────────────┘
                                  │
                 ┌────────────────┴────────────────┐
                 ▼                                 ▼
   ┌───────────────────────────┐     ┌───────────────────────────┐
   │    NIST NVD API v2        │     │  Exploit-DB Searchsploit  │
   │                           │     │                           │
   │  • CVSS v3.1 / v3.0 / v2  │     │  • Public POC Matching    │
   │  • Official CVE Summary   │     │  • Exploit Type Sorting   │
   │  • Direct NIST References │     │  • Remote / Web / Local   │
   └─────────────┬─────────────┘     └─────────────┬─────────────┘
                 │                                 │
                 └────────────────┬────────────────┘
                                  ▼
             ┌─────────────────────────────────────────┐
             │ Prioritized Terminal Table & Full JSON  │
             └─────────────────────────────────────────┘
```

1. **Automated Signature Extraction**: Reckon parses TCP service banners and versions from `nmap` output (e.g., Apache, Nginx, OpenSSH, vsFTPd, Samba, Microsoft IIS, MySQL, PostgreSQL, Redis, MongoDB).
2. **NVD REST API Query**: Reckon makes structured queries against `https://services.nvd.nist.gov/rest/json/cves/2.0`, retrieving base scores and sorting vulnerabilities by CVSS severity.
3. **Exploit-DB Mapping**: Reckon runs `searchsploit --json -w` against each detected technology and categorizes exploits into actionable priority buckets:
   - **Remote Code Execution (RCE)**
   - **Web Application Exploits**
   - **Local Privilege Escalation**
   - **Denial of Service**
4. **Interactive Summary**: Outputs direct hyperlinks to official CVE entries and Exploit-DB proof-of-concept scripts in both terminal logs and generated reports.

---

## 📂 Artifacts & Directory Structure

All findings, raw command outputs, and reports are saved in an organized workspace structure under `recon_<target>_<timestamp>/`:

```
recon_example_com_20260910_012345/
├── recon.log                        # Complete console stdout/stderr log
├── passive/
│   ├── whois.txt                    # Raw WHOIS registrar & contact details
│   ├── dns_records.txt              # A, AAAA, MX, NS, TXT, SOA, CAA records
│   ├── asn_<ip>.json                # Geolocation, ASN, and ISP intelligence
│   ├── crt_sh.json                  # Raw crt.sh JSON certificate records
│   ├── ct_subdomains.txt            # Extracted certificate transparency subdomains
│   ├── ssl_cert.txt                 # Full OpenSSL certificate dump & cipher details
│   └── google_dorks.txt             # Customized Google Dork search queries
├── dns/
│   ├── subfinder.txt                # Subfinder results
│   ├── amass.txt                    # Amass passive enumeration output
│   ├── assetfinder.txt              # Assetfinder discoveries
│   ├── gobuster_dns.txt             # DNS brute-forcing hits
│   ├── subdomains_unique.txt        # Deduplicated consolidated list of subdomains
│   ├── resolved_subdomains.txt      # Verified live resolving subdomains
│   └── live_http_subdomains.txt     # Subdomains responding to HTTP/HTTPS
├── ports/
│   ├── host_discovery.txt           # Host ping discovery (nmap -sn)
│   ├── nmap_tcp.txt                 # Formatted TCP scan with service versions
│   ├── nmap_tcp.xml                 # XML output for Metasploit/Burp/Nessus import
│   ├── nmap_tcp_grep.txt            # Greppable nmap scan output
│   └── nmap_udp.txt                 # UDP top-ports scan results
├── web/
│   ├── headers_http_<target>.txt    # HTTP response headers
│   ├── headers_https_<target>.txt   # HTTPS response headers
│   ├── whatweb_https_<target>.txt   # Technology stack fingerprint
│   ├── wafw00f_https_<target>.txt   # Web Application Firewall diagnosis
│   ├── robots_https_<target>.txt    # Disallowed paths from robots.txt
│   ├── sitemap_https_<target>.xml   # Extracted sitemap endpoints
│   ├── ffuf_dirs.json               # Discovered directories from ffuf
│   └── nikto.txt                    # Nikto web server vulnerability report
├── vulns/
│   ├── nuclei_targets.txt           # Targets queued for Nuclei
│   ├── nuclei_results.txt           # Template matches categorized by severity
│   ├── cve_exploits_report.txt      # Unified CVE & Exploit-DB report
│   └── searchsploit/
│       ├── nvd_<service>.json       # Raw NIST NVD JSON responses
│       └── ss_<service>.json        # Raw Searchsploit exploit records
└── reports/
    ├── report.html                  # Standalone Dark-Mode HTML Dashboard
    └── report.json                  # Machine-readable JSON summary and findings
```

---

## 📊 Reporting

Reckon automatically produces two comprehensive report formats upon scan completion:

### Interactive Dark-Mode HTML Report

The generated `reports/report.html` is a standalone single-file dashboard designed with modern dark UI styling, ready to present to stakeholders or include in penetration testing deliverables:

- **Executive KPI Cards**: Color-coded totals for Critical, High, Medium, Low, and Informational findings.
- **Surface Metrics**: Number of open ports, unique subdomains discovered, and resolved IP addresses.
- **Detailed Findings Table**: Filterable and sorted by severity with issue titles, descriptions, and discovery timestamps.
- **Zero External CDNs Required**: Self-contained CSS for reliable viewing even in isolated or offline air-gapped environments.

### Structured JSON Report Schema

The generated `reports/report.json` enables seamless integration with your security automation pipelines:

```json
{
  "meta": {
    "tool": "Ultimate Recon Tool v1.0",
    "target": "example.com",
    "timestamp": "2026-09-10T01:35:12+00:00",
    "duration": "00h 04m 32s",
    "output_dir": "recon_example_com_20260910_013512"
  },
  "summary": {
    "critical": 2,
    "high": 4,
    "medium": 7,
    "low": 3,
    "info": 18,
    "open_ports": 6,
    "subdomains": 24
  },
  "findings": [
    {
      "severity": "CRITICAL",
      "title": "DNS Zone Transfer Allowed",
      "detail": "Nameserver ns1.example.com allows AXFR — full zone exposed",
      "ts": "2026-09-10T01:36:04+00:00"
    },
    {
      "severity": "HIGH",
      "title": "Public Exploits Found",
      "detail": "3 exploit(s) in Exploit-DB for 'Apache 2.4.49' — see vulns/searchsploit/ss_Apache_2_4_49.json",
      "ts": "2026-09-10T01:38:22+00:00"
    }
  ]
}
```

---

## 🛠 Supported Tools Matrix

| Tool | Category | Status | Fallback Mechanism |
|---|---|---|---|
| `bash` (4.0+) | Core Engine | **Required** | Native shell execution |
| `nmap` | Network & Port Scanner | **Required** | Host & service detection |
| `dig` / `bind9-dnsutils` | DNS Resolver | **Required** | `host` / `nslookup` |
| `whois` | Domain Intelligence | **Required** | Registrar queries |
| `curl` | HTTP Client | **Required** | Network transfers & REST APIs |
| `python3` | Parser & Engine | **Required** | JSON parsing & report rendering |
| `openssl` | Cryptographic Client | **Required** | TLS/SSL certificate audits |
| `jq` | JSON Stream Processor | **Required** | Formatted JSON output |
| `subfinder` | Subdomain Discovery | *Recommended* | Passive DNS fallback |
| `amass` | Attack Surface Mapping | *Recommended* | crt.sh & assetfinder fallback |
| `assetfinder` | Subdomain Discovery | *Recommended* | CT logs fallback |
| `gobuster` | DNS & Directory Bruteforce | *Recommended* | Pure Bash DNS brute-force |
| `dnsx` | Multi-threaded DNS Toolkit | *Recommended* | Sequential `dig` resolver |
| `httpx` | Fast HTTP Probe | *Recommended* | Sequential `curl` probing |
| `whatweb` | Web Tech Fingerprinting | *Recommended* | HTTP header inspection |
| `wafw00f` | WAF Identification | *Recommended* | Response header heuristics |
| `ffuf` | Web Fuzzer | *Recommended* | `gobuster dir` / `curl` list |
| `nikto` | Web Server Scanner | *Recommended* | Sensitive files checklist |
| `nuclei` | Vulnerability Scanner | *Recommended* | Service heuristic checks |
| `searchsploit` | Exploit-DB Local Query | *Recommended* | NIST NVD API queries |

---

## 💡 Best Practices & Pro Tips

1. **Obtain a Free NIST NVD API Key**:
   Request a free API key at [nvd.nist.gov/developers/request-an-api-key](https://nvd.nist.gov/developers/request-an-api-key). Passing `--nvd-key <key>` speeds up Phase 5b by 10x (avoids 12-second rate-limiting pauses between service queries).
2. **Install SecLists**:
   Reckon looks for wordlists in standard SecLists locations (`/usr/share/seclists/...`). On Debian/Ubuntu/Kali, install SecLists via:
   ```bash
   sudo apt install -y seclists
   ```
3. **Running in Background with `nohup` or `tmux`**:
   For large scopes or full port scans (`-P`), run Reckon inside a persistent terminal session:
   ```bash
   tmux new -s recon
   sudo reckon -t target.com -P
   # Press Ctrl+B then D to detach
   ```
4. **Importing into Burp Suite or Metasploit**:
   Reckon creates standard `ports/nmap_tcp.xml`. You can import this directly into Metasploit via `db_import ports/nmap_tcp.xml` or into vulnerability management tools like DefectDojo.

---

## ⚖️ Legal & Ethical Disclaimer

> [!WARNING]
> **AUTHORIZED USE ONLY**  
> Reckon is developed strictly for authorized security assessments, penetration tests, research, and educational purposes. Scanning, testing, or auditing networks, domains, or systems without prior explicit written permission from the asset owner is illegal under the Computer Fraud and Abuse Act (CFAA), the UK Computer Misuse Act, and equivalent international laws.  
> The authors and contributors assume no liability and are not responsible for any misuse or damage caused by this program.

---

## 📄 License

This project is licensed under the **MIT License** — see the [LICENSE](LICENSE) file for details.

Copyright (c) 2026 Kishan Agarwal.
