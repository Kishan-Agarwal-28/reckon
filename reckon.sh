#!/usr/bin/env bash
# =============================================================================
#  ULTIMATE RECONNAISSANCE TOOL  v1.0
#  Author  : Security Research Toolkit
#  Purpose : End-to-end automated reconnaissance combining multiple tools
#            with correlated insights and full HTML/JSON reporting
#
#  LEGAL NOTICE:
#  This tool is intended ONLY for authorized security testing.
#  You MUST have explicit written permission before scanning any target.
#  Unauthorized use is illegal and unethical.
# =============================================================================

set -euo pipefail

# ─────────────────────────────────────────────────────────────────────────────
#  GLOBALS & CONFIGURATION
# ─────────────────────────────────────────────────────────────────────────────
VERSION="1.0"
SCRIPT_NAME="Ultimate Recon Tool"
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
START_TIME=$(date +%s)

# Colors
RED=$'\033[0;31m';    GREEN=$'\033[0;32m';  YELLOW=$'\033[1;33m'
BLUE=$'\033[0;34m';   CYAN=$'\033[0;36m';   MAGENTA=$'\033[0;35m'
WHITE=$'\033[1;37m';  BOLD=$'\033[1m';      DIM=$'\033[2m';  NC=$'\033[0m'

# Defaults (overridable via flags)
OUTPUT_DIR=""
TARGET=""
THREADS=10
TIMEOUT=30
RATE_LIMIT=150          # requests/sec for tools that support it
NMAP_SPEED=3            # 1-5 (T1-T5)
STEALTH_MODE=false
SKIP_ACTIVE=false
SKIP_BRUTEFORCE=false
WORDLIST="/usr/share/wordlists/dirb/common.txt"
DNS_WORDLIST="/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt"
PORTS="21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,1723,3306,3389,5900,8080,8443,8888"
FULL_PORT_SCAN=false
REPORT_FORMAT="both"    # html | json | both
VERBOSE=false

AUTO_CONFIRM=false

# Runtime state
declare -A TOOL_STATUS   # tracks which tools are available
declare -a OPEN_PORTS=()
declare -a SUBDOMAINS=()
declare -a LIVE_HOSTS=()
declare -a IP_LIST=()
FINDINGS_CRITICAL=0
FINDINGS_HIGH=0
FINDINGS_MEDIUM=0
FINDINGS_LOW=0
FINDINGS_INFO=0
JSON_FINDINGS="[]"

# CVE / Exploit tracking
declare -a DETECTED_SERVICES=()   # "product:version" pairs extracted from nmap
JSON_CVE_RESULTS="[]"              # aggregated CVE records for reporting
TOTAL_EXPLOITS_FOUND=0
NVD_API_KEY=""                     # optional — set via --nvd-key for higher rate limits
SKIP_CVE=false

# ─────────────────────────────────────────────────────────────────────────────
#  LOGGING HELPERS
# ─────────────────────────────────────────────────────────────────────────────
log()      { echo -e "${WHITE}[$(date +%H:%M:%S)]${NC} $*"; }
info()     { echo -e "${CYAN}[INFO]${NC}  $*"; }
success()  { echo -e "${GREEN}[✓]${NC}    $*"; }
warn()     { echo -e "${YELLOW}[!]${NC}    $*"; }
error()    { echo -e "${RED}[✗]${NC}    $*" >&2; }
debug()    { if [[ "$VERBOSE" == "true" ]]; then echo -e "${DIM}[DBG]   $*${NC}"; fi; }
section()  { echo -e "\n${BOLD}${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"; \
             echo -e "${BOLD}${MAGENTA}  ► $*${NC}"; \
             echo -e "${BOLD}${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"; }
finding()  {
    local severity="$1"; local title="$2"; local detail="$3"
    local color="$NC"
    case "$severity" in
        CRITICAL) color="$RED";    FINDINGS_CRITICAL=$((FINDINGS_CRITICAL + 1)) ;;
        HIGH)     color="$RED";    FINDINGS_HIGH=$((FINDINGS_HIGH + 1))     ;;
        MEDIUM)   color="$YELLOW"; FINDINGS_MEDIUM=$((FINDINGS_MEDIUM + 1))   ;;
        LOW)      color="$CYAN";   FINDINGS_LOW=$((FINDINGS_LOW + 1))      ;;
        INFO)     color="$WHITE";  FINDINGS_INFO=$((FINDINGS_INFO + 1))     ;;
    esac
    echo -e "${color}[${severity}]${NC} ${BOLD}${title}${NC}: ${detail}"
    # Append to JSON findings
    local escaped_detail; escaped_detail=$(echo "$detail" | sed 's/"/\\"/g' | tr -d '\n')
    local escaped_title;  escaped_title=$(echo "$title"  | sed 's/"/\\"/g' | tr -d '\n')
    JSON_FINDINGS=$(python3 -c "
import sys, json
try:
    arr = json.loads(sys.argv[1])
except Exception:
    arr = []
arr.append({'severity': sys.argv[2], 'title': sys.argv[3], 'detail': sys.argv[4], 'ts': '$(date -Iseconds)'})
print(json.dumps(arr))
" "$JSON_FINDINGS" "$severity" "$escaped_title" "$escaped_detail" 2>/dev/null || echo "$JSON_FINDINGS")
    return 0
}

# ─────────────────────────────────────────────────────────────────────────────
#  BANNER
# ─────────────────────────────────────────────────────────────────────────────
print_banner() {
cat << 'BANNER'

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
BANNER
    echo -e "${RED}${BOLD}  ⚠  AUTHORIZED USE ONLY — Unauthorized scanning is illegal  ⚠${NC}\n"
}

# ─────────────────────────────────────────────────────────────────────────────
#  USAGE
# ─────────────────────────────────────────────────────────────────────────────
usage() {
cat << EOF
${BOLD}USAGE:${NC}
  $(basename "$0") -t <target> [OPTIONS]

${BOLD}REQUIRED:${NC}
  -t, --target <domain|IP>    Target domain or IP address

${BOLD}OPTIONS:${NC}
  -o, --output <dir>          Output directory (default: recon_<target>_<ts>)
  -T, --threads <n>           Parallel threads (default: 10)
  -p, --ports <list>          Comma-separated ports (default: common ports)
  -P, --full-ports            Scan all 65535 ports
  -s, --stealth               Enable stealth/slow scanning mode
  -w, --wordlist <file>       Directory bruteforce wordlist
  -d, --dns-wordlist <file>   DNS subdomain wordlist
  -r, --report <fmt>          Report format: html|json|both (default: both)
  -y, --yes                   Skip interactive confirmation prompt
      --skip-active           Skip active scanning (passive recon only)
      --skip-bruteforce       Skip directory/DNS bruteforce
      --skip-cve              Skip NVD CVE & Exploit-DB lookups
      --nvd-key <key>         NVD API key for higher rate limits
  -v, --verbose               Verbose output
  -h, --help                  Show this help

${BOLD}EXAMPLES:${NC}
  $(basename "$0") -t example.com
  $(basename "$0") -t example.com -o /tmp/recon -T 20 -P
  $(basename "$0") -t 192.168.1.1 --stealth --skip-bruteforce
  $(basename "$0") -t example.com --report html -v

EOF
    exit 0
}

# ─────────────────────────────────────────────────────────────────────────────
#  ARGUMENT PARSING
# ─────────────────────────────────────────────────────────────────────────────
parse_args() {
    [[ $# -eq 0 ]] && { usage; }
    while [[ $# -gt 0 ]]; do
        case "$1" in
            -t|--target)          TARGET="$2";         shift 2 ;;
            -o|--output)          OUTPUT_DIR="$2";     shift 2 ;;
            -T|--threads)         THREADS="$2";        shift 2 ;;
            -p|--ports)           PORTS="$2";          shift 2 ;;
            -P|--full-ports)      FULL_PORT_SCAN=true; shift   ;;
            -s|--stealth)         STEALTH_MODE=true;   shift   ;;
            -w|--wordlist)        WORDLIST="$2";       shift 2 ;;
            -d|--dns-wordlist)    DNS_WORDLIST="$2";   shift 2 ;;
            -r|--report)          REPORT_FORMAT="$2";  shift 2 ;;
            -y|--yes)             AUTO_CONFIRM=true;   shift   ;;
               --skip-active)     SKIP_ACTIVE=true;        shift   ;;
               --skip-bruteforce) SKIP_BRUTEFORCE=true;    shift   ;;
               --skip-cve)        SKIP_CVE=true;           shift   ;;
               --nvd-key)         NVD_API_KEY="$2";        shift 2 ;;
            -v|--verbose)         VERBOSE=true;            shift   ;;
            -h|--help)            usage ;;
            *) error "Unknown option: $1"; usage ;;
        esac
    done
    if [[ -z "$TARGET" ]]; then
        error "Target is required. Use -t <target>"
        exit 1
    fi
}

# ─────────────────────────────────────────────────────────────────────────────
#  LEGAL CONFIRMATION
# ─────────────────────────────────────────────────────────────────────────────
legal_confirm() {
    if [[ "${AUTO_CONFIRM:-false}" == "true" ]]; then
        return 0
    fi
    echo -e "${RED}${BOLD}"
    echo "  ╔══════════════════════════════════════════════════════════════╗"
    echo "  ║                    ⚠  LEGAL WARNING  ⚠                     ║"
    echo "  ╠══════════════════════════════════════════════════════════════╣"
    echo "  ║  Scanning systems without WRITTEN AUTHORIZATION is illegal  ║"
    echo "  ║  under the Computer Fraud and Abuse Act (CFAA) and similar  ║"
    echo "  ║  laws worldwide. Misuse may result in criminal prosecution.  ║"
    echo "  ╚══════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
    echo -e "  Target: ${BOLD}${YELLOW}$TARGET${NC}\n"
    local CONFIRM=""
    if [[ -t 0 ]]; then
        read -r -p "  Do you have EXPLICIT WRITTEN PERMISSION to test this target? [yes/NO]: " CONFIRM || true
    elif tty -s 2>/dev/null && [[ -c /dev/tty ]]; then
        read -r -p "  Do you have EXPLICIT WRITTEN PERMISSION to test this target? [yes/NO]: " CONFIRM < /dev/tty || true
    else
        CONFIRM="yes"
    fi
    if [[ "${CONFIRM,,}" != "yes" ]]; then
        echo -e "\n${RED}  Aborted. Only proceed with proper authorization.${NC}\n"
        exit 1
    fi
    echo ""
}

# ─────────────────────────────────────────────────────────────────────────────
#  SETUP OUTPUT DIRECTORY STRUCTURE
# ─────────────────────────────────────────────────────────────────────────────
setup_output() {
    if [[ -z "$OUTPUT_DIR" ]]; then
        OUTPUT_DIR="recon_${TARGET//[^a-zA-Z0-9]/_}_${TIMESTAMP}"
    fi
    mkdir -p "${OUTPUT_DIR}"/{passive,dns,ports,web,vulns,screenshots,reports,raw}
    LOG_FILE="${OUTPUT_DIR}/recon.log"
    exec > >(tee -a "$LOG_FILE") 2>&1
    info "Output directory: ${BOLD}${OUTPUT_DIR}${NC}"
}

# ─────────────────────────────────────────────────────────────────────────────
#  TOOL DEPENDENCY CHECK
# ─────────────────────────────────────────────────────────────────────────────
check_tools() {
    section "Dependency Check"
    local required_tools=(nmap dig whois curl)
    local optional_tools=(subfinder amass assetfinder massdns httpx nuclei
                          whatweb wafw00f nikto gobuster ffuf dnsx
                          searchsploit jq python3 host nslookup nc timeout)
    local missing_required=()

    for tool in "${required_tools[@]}"; do
        if command -v "$tool" &>/dev/null; then
            TOOL_STATUS["$tool"]="available"
            success "$tool"
        else
            TOOL_STATUS["$tool"]="missing"
            missing_required+=("$tool")
            error "$tool (REQUIRED — missing)"
        fi
    done

    for tool in "${optional_tools[@]}"; do
        if command -v "$tool" &>/dev/null; then
            TOOL_STATUS["$tool"]="available"
            success "$tool"
        else
            TOOL_STATUS["$tool"]="missing"
            warn "$tool (optional — not found, skipping related checks)"
        fi
    done

    if [[ ${#missing_required[@]} -gt 0 ]]; then
        error "Missing required tools: ${missing_required[*]}"
        error "Install them and retry."
        exit 1
    fi
}

# ─────────────────────────────────────────────────────────────────────────────
#  HELPER: run tool with timeout & error handling
# ─────────────────────────────────────────────────────────────────────────────
run_tool() {
    local desc="$1"; shift
    debug "Running: $*"
    info "$desc"
    if ! timeout "$TIMEOUT" "$@" 2>/dev/null; then
        warn "$desc — timed out or returned error (continuing)"
        return 1
    fi
    return 0
}

# ─────────────────────────────────────────────────────────────────────────────
#  PHASE 1 — PASSIVE RECON
# ─────────────────────────────────────────────────────────────────────────────
phase_passive() {
    section "PHASE 1 — Passive Reconnaissance"
    local out="${OUTPUT_DIR}/passive"

    # ── WHOIS ─────────────────────────────────────────────────────────────────
    info "WHOIS lookup..."
    if whois "$TARGET" > "${out}/whois.txt" 2>/dev/null; then
        success "WHOIS data saved"
        # Extract key fields
        local registrar; registrar=$( (grep -i "registrar:" "${out}/whois.txt" 2>/dev/null || true) | head -1 | awk -F: '{print $2}' | xargs)
        local created;   created=$( (grep -iE "creation date|created:" "${out}/whois.txt" 2>/dev/null || true) | head -1 | awk -F: '{print $2}' | xargs)
        local expires;   expires=$( (grep -iE "expiry date|expir" "${out}/whois.txt" 2>/dev/null || true) | head -1 | awk -F: '{print $2}' | xargs)
        local registrant;registrant=$( (grep -iE "registrant name|registrant org" "${out}/whois.txt" 2>/dev/null || true) | head -1 | awk -F: '{print $2}' | xargs)
        if [[ -n "$registrar" ]];  then finding INFO "Registrar"  "$registrar"; fi
        if [[ -n "$created" ]];    then finding INFO "Domain Created" "$created"; fi
        if [[ -n "$expires" ]];    then finding INFO "Domain Expires" "$expires"; fi
        if [[ -n "$registrant" ]]; then finding INFO "Registrant" "$registrant"; fi
    fi

    # ── DNS RECORDS ───────────────────────────────────────────────────────────
    info "DNS enumeration..."
    local dns_out="${out}/dns_records.txt"
    {
        echo "=== A Records ===";     dig +short A     "$TARGET"   2>/dev/null
        echo "=== AAAA Records ===";  dig +short AAAA  "$TARGET"   2>/dev/null
        echo "=== MX Records ===";    dig +short MX    "$TARGET"   2>/dev/null
        echo "=== NS Records ===";    dig +short NS    "$TARGET"   2>/dev/null
        echo "=== TXT Records ===";   dig +short TXT   "$TARGET"   2>/dev/null
        echo "=== CNAME Records ==="; dig +short CNAME "$TARGET"   2>/dev/null
        echo "=== SOA Records ===";   dig +short SOA   "$TARGET"   2>/dev/null
        echo "=== CAA Records ===";   dig +short CAA   "$TARGET"   2>/dev/null
    } > "$dns_out"
    success "DNS records saved"

    # Capture A records for later use
    mapfile -t IP_LIST < <( (dig +short A "$TARGET" 2>/dev/null || true) | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' || true)
    if [[ ${#IP_LIST[@]} -gt 0 ]]; then
        finding INFO "Resolved IPs" "${IP_LIST[*]}"
    fi

    # SPF / DMARC checks
    local spf; spf=$( (dig +short TXT "$TARGET" 2>/dev/null || true) | grep -i "v=spf" || true)
    local dmarc; dmarc=$( (dig +short TXT "_dmarc.${TARGET}" 2>/dev/null || true) || true)
    if [[ -z "$spf" ]]; then
        finding MEDIUM "Missing SPF Record" "No SPF TXT record found for $TARGET — email spoofing may be possible"
    else
        finding INFO "SPF Record" "$spf"
    fi
    if [[ -z "$dmarc" ]]; then
        finding MEDIUM "Missing DMARC Record" "No DMARC record found — phishing risk increased"
    else
        finding INFO "DMARC Record" "$dmarc"
    fi

    # DNSSEC check
    local dnssec; dnssec=$( (dig +short DNSKEY "$TARGET" 2>/dev/null || true) | head -1)
    if [[ -z "$dnssec" ]]; then
        finding LOW "DNSSEC Not Configured" "DNSSEC is not enabled for $TARGET"
    else
        finding INFO "DNSSEC Enabled" "$TARGET has DNSSEC configured"
    fi

    # Zone transfer attempt
    info "Attempting DNS zone transfer..."
    local ns_list; mapfile -t ns_list < <(dig +short NS "$TARGET" 2>/dev/null)
    for ns in "${ns_list[@]}"; do
        ns=$(echo "$ns" | sed 's/\.$//')
        if dig AXFR "$TARGET" "@${ns}" 2>/dev/null | grep -q "Transfer failed\|XFR size" ; then
            : # no transfer
        else
            local zt; zt=$(dig AXFR "$TARGET" "@${ns}" 2>/dev/null)
            if echo "$zt" | grep -vq "Transfer failed"; then
                echo "$zt" > "${out}/zone_transfer_${ns}.txt"
                finding CRITICAL "DNS Zone Transfer Allowed" "Nameserver $ns allows AXFR — full zone exposed"
            fi
        fi
    done

    # ── ASN / IP REPUTATION ───────────────────────────────────────────────────
    if [[ ${#IP_LIST[@]} -gt 0 ]]; then
        info "ASN & IP reputation lookup..."
        for ip in "${IP_LIST[@]}"; do
            local asn_info; asn_info=$(curl -s --max-time 10 "https://ipinfo.io/${ip}/json" 2>/dev/null)
            if [[ -n "$asn_info" ]]; then
                echo "$asn_info" > "${out}/asn_${ip}.json"
                local org; org=$(echo "$asn_info" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('org','N/A'))" 2>/dev/null)
                local country; country=$(echo "$asn_info" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('country','N/A'))" 2>/dev/null)
                finding INFO "IP Info ($ip)" "Org: $org | Country: $country"
            fi
        done
    fi

    # ── SSL/TLS CERTIFICATE RECON ─────────────────────────────────────────────
    info "SSL/TLS certificate transparency lookup..."
    local crt_data; crt_data=$(curl -s --max-time 15 \
        "https://crt.sh/?q=%.${TARGET}&output=json" 2>/dev/null)
    if [[ -n "$crt_data" ]]; then
        echo "$crt_data" > "${out}/crt_sh.json"
        local cert_domains; cert_domains=$(echo "$crt_data" | \
            python3 -c "
import sys, json
try:
    data = json.load(sys.stdin)
    names = set()
    for entry in data:
        name = entry.get('name_value','')
        for n in name.split('\n'):
            n = n.strip().lstrip('*.')
            if n:
                names.add(n)
    print('\n'.join(sorted(names)))
except: pass
" 2>/dev/null)
        if [[ -n "$cert_domains" ]]; then
            echo "$cert_domains" > "${out}/ct_subdomains.txt"
            local ct_count; ct_count=$(echo "$cert_domains" | wc -l)
            finding INFO "Certificate Transparency" "$ct_count domains/subdomains found via crt.sh"
            # Merge into subdomain list
            while IFS= read -r sub; do
                SUBDOMAINS+=("$sub")
            done <<< "$cert_domains"
        fi
    fi

    # SSL certificate details via openssl
    if [[ ${#IP_LIST[@]} -gt 0 ]]; then
        info "Fetching SSL certificate details..."
        local ssl_out="${out}/ssl_cert.txt"
        echo | timeout 10 openssl s_client -connect "${TARGET}:443" \
              -servername "$TARGET" 2>/dev/null | \
              openssl x509 -noout -text 2>/dev/null > "$ssl_out" || true

        if [[ -s "$ssl_out" ]]; then
            # Check expiry
            local expiry; expiry=$( (openssl x509 -noout -enddate < "$ssl_out" 2>/dev/null || true) | cut -d= -f2)
            if [[ -n "$expiry" ]]; then
                local exp_epoch; exp_epoch=$(date -d "$expiry" +%s 2>/dev/null || date -j -f "%b %d %T %Y %Z" "$expiry" +%s 2>/dev/null || echo 0)
                local now_epoch; now_epoch=$(date +%s)
                local days_left=$(( (exp_epoch - now_epoch) / 86400 ))
                if [[ $days_left -lt 0 ]]; then
                    finding CRITICAL "SSL Certificate Expired" "Certificate expired $((days_left * -1)) days ago"
                elif [[ $days_left -lt 14 ]]; then
                    finding HIGH "SSL Certificate Expiring Soon" "Expires in $days_left days"
                elif [[ $days_left -lt 30 ]]; then
                    finding MEDIUM "SSL Certificate Expiring" "Expires in $days_left days"
                else
                    finding INFO "SSL Certificate Valid" "Expires in $days_left days ($expiry)"
                fi
            fi

            # Check cipher / protocol weak
            local proto; proto=$( (echo | timeout 10 openssl s_client -connect "${TARGET}:443" 2>/dev/null || true) | (grep "Protocol" 2>/dev/null || true) | head -1 | awk '{print $NF}')
            if [[ "$proto" == "TLSv1" || "$proto" == "SSLv3" || "$proto" == "SSLv2" ]]; then
                finding HIGH "Weak TLS Protocol" "Server supports $proto — deprecated and insecure"
            fi

            success "SSL certificate analyzed"
        fi
    fi

    # ── GOOGLE DORKS (passive — constructs queries, doesn't auto-run) ──────────
    info "Generating Google dork queries..."
    {
        echo "# Google Dorks for $TARGET — Run manually in a browser"
        echo ""
        echo "site:${TARGET}"
        echo "site:${TARGET} filetype:pdf"
        echo "site:${TARGET} filetype:xls OR filetype:xlsx OR filetype:csv"
        echo "site:${TARGET} filetype:sql OR filetype:db OR filetype:bak"
        echo "site:${TARGET} inurl:admin OR inurl:login OR inurl:panel"
        echo "site:${TARGET} inurl:config OR inurl:setup OR inurl:install"
        echo "site:${TARGET} \"index of /\" OR \"parent directory\""
        echo "site:${TARGET} intext:\"password\" OR intext:\"passwd\""
        echo "site:${TARGET} ext:php intitle:\"phpinfo()\""
        echo "site:${TARGET} inurl:.git OR inurl:.svn OR inurl:.env"
        echo "\"@${TARGET}\" email"
        echo "site:pastebin.com \"${TARGET}\""
        echo "site:github.com \"${TARGET}\""
    } > "${out}/google_dorks.txt"
    success "Google dorks written to ${out}/google_dorks.txt"
}

# ─────────────────────────────────────────────────────────────────────────────
#  PHASE 2 — SUBDOMAIN ENUMERATION
# ─────────────────────────────────────────────────────────────────────────────
phase_subdomains() {
    section "PHASE 2 — Subdomain Enumeration"
    local out="${OUTPUT_DIR}/dns"
    local combined="${out}/all_subdomains.txt"

    # ── Subfinder ─────────────────────────────────────────────────────────────
    if [[ "${TOOL_STATUS[subfinder]:-missing}" == "available" ]]; then
        info "Running subfinder..."
        timeout 120 subfinder -d "$TARGET" -silent -o "${out}/subfinder.txt" \
            -t "$THREADS" 2>/dev/null || true
        if [[ -f "${out}/subfinder.txt" ]]; then
            local cnt; cnt=$(wc -l < "${out}/subfinder.txt")
            success "subfinder: $cnt subdomains"
            cat "${out}/subfinder.txt" >> "$combined" 2>/dev/null || true
        fi
    fi

    # ── Amass (passive) ───────────────────────────────────────────────────────
    if [[ "${TOOL_STATUS[amass]:-missing}" == "available" ]]; then
        info "Running amass (passive)..."
        timeout 180 amass enum -passive -d "$TARGET" \
            -o "${out}/amass.txt" 2>/dev/null || true
        if [[ -f "${out}/amass.txt" ]]; then
            local cnt; cnt=$(wc -l < "${out}/amass.txt")
            success "amass: $cnt subdomains"
            cat "${out}/amass.txt" >> "$combined" 2>/dev/null || true
        fi
    fi

    # ── Assetfinder ───────────────────────────────────────────────────────────
    if [[ "${TOOL_STATUS[assetfinder]:-missing}" == "available" ]]; then
        info "Running assetfinder..."
        timeout 60 assetfinder --subs-only "$TARGET" \
            > "${out}/assetfinder.txt" 2>/dev/null || true
        if [[ -f "${out}/assetfinder.txt" ]]; then
            local cnt; cnt=$(wc -l < "${out}/assetfinder.txt")
            success "assetfinder: $cnt subdomains"
            cat "${out}/assetfinder.txt" >> "$combined" 2>/dev/null || true
        fi
    fi

    # ── DNS Brute Force ───────────────────────────────────────────────────────
    if [[ "$SKIP_BRUTEFORCE" == "false" && -f "$DNS_WORDLIST" ]]; then
        info "DNS brute-force with wordlist: $DNS_WORDLIST"
        if [[ "${TOOL_STATUS[gobuster]:-missing}" == "available" ]]; then
            timeout 300 gobuster dns -d "$TARGET" \
                -w "$DNS_WORDLIST" \
                -t "$THREADS" \
                -o "${out}/gobuster_dns.txt" \
                --quiet 2>/dev/null || true
            if [[ -f "${out}/gobuster_dns.txt" ]]; then
                grep "Found:" "${out}/gobuster_dns.txt" 2>/dev/null | awk '{print $2}' >> "$combined" 2>/dev/null || true
            fi
            success "DNS brute-force complete"
        else
            # Pure bash fallback DNS brute
            info "Falling back to bash DNS brute-force (slower)..."
            local bf_out="${out}/bash_dns_brute.txt"
            local count=0
            while IFS= read -r word; do
                local sub="${word}.${TARGET}"
                if host "$sub" &>/dev/null 2>&1; then
                    echo "$sub" | tee -a "$bf_out" >> "$combined"
                    count=$((count + 1))
                fi
            done < <(head -500 "$DNS_WORDLIST")
            success "Bash DNS brute-force: $count found"
        fi
    elif [[ ! -f "$DNS_WORDLIST" ]]; then
        warn "DNS wordlist not found at $DNS_WORDLIST — skipping brute-force"
    fi

    # ── CT log subdomains (already gathered in phase 1) ───────────────────────
    if [[ -f "${OUTPUT_DIR}/passive/ct_subdomains.txt" ]]; then
        cat "${OUTPUT_DIR}/passive/ct_subdomains.txt" >> "$combined" 2>/dev/null || true
    fi

    # ── Deduplicate & resolve ─────────────────────────────────────────────────
    if [[ -f "$combined" ]]; then
        sort -u "$combined" > "${out}/subdomains_unique.txt"
        local total; total=$(wc -l < "${out}/subdomains_unique.txt")
        success "Total unique subdomains: $total"
        finding INFO "Subdomains Discovered" "$total unique subdomains found"

        # DNS resolution with dnsx or dig fallback
        if [[ "${TOOL_STATUS[dnsx]:-missing}" == "available" ]]; then
            info "Resolving subdomains with dnsx..."
            dnsx -l "${out}/subdomains_unique.txt" \
                 -o "${out}/resolved_subdomains.txt" \
                 -silent -t "$THREADS" 2>/dev/null || true
        else
            info "Resolving subdomains (bash fallback)..."
            local resolved_out="${out}/resolved_subdomains.txt"
            while IFS= read -r sub; do
                if dig +short A "$sub" 2>/dev/null | grep -qE '^[0-9]'; then
                    echo "$sub" >> "$resolved_out"
                fi
            done < "${out}/subdomains_unique.txt"
        fi

        if [[ -f "${out}/resolved_subdomains.txt" ]]; then
            local resolved_count; resolved_count=$(wc -l < "${out}/resolved_subdomains.txt")
            success "Resolved: $resolved_count live subdomains"
            finding INFO "Live Subdomains" "$resolved_count subdomains resolve to an IP"
            mapfile -t SUBDOMAINS < "${out}/resolved_subdomains.txt"
        fi
    fi

    # ── HTTP probing on subdomains ─────────────────────────────────────────────
    if [[ "${TOOL_STATUS[httpx]:-missing}" == "available" && -f "${out}/resolved_subdomains.txt" ]]; then
        info "Probing subdomains for live HTTP/HTTPS services..."
        httpx -l "${out}/resolved_subdomains.txt" \
              -o "${out}/live_http_subdomains.txt" \
              -silent -threads "$THREADS" \
              -status-code -title -tech-detect 2>/dev/null || true
        if [[ -f "${out}/live_http_subdomains.txt" ]]; then
            local live_cnt; live_cnt=$(wc -l < "${out}/live_http_subdomains.txt")
            finding INFO "HTTP-Active Subdomains" "$live_cnt subdomains serve HTTP/HTTPS"
            mapfile -t LIVE_HOSTS < <(awk '{print $1}' "${out}/live_http_subdomains.txt")
        fi
    fi
}

# ─────────────────────────────────────────────────────────────────────────────
#  PHASE 3 — PORT SCANNING
# ─────────────────────────────────────────────────────────────────────────────
phase_ports() {
    [[ "$SKIP_ACTIVE" == "true" ]] && { info "Skipping active port scanning (--skip-active)"; return; }
    section "PHASE 3 — Port Scanning & Service Detection"
    local out="${OUTPUT_DIR}/ports"

    local nmap_speed="-T${NMAP_SPEED}"
    [[ "$STEALTH_MODE" == "true" ]] && nmap_speed="-T1 -f --data-length 25"

    local port_arg="-p ${PORTS}"
    [[ "$FULL_PORT_SCAN" == "true" ]] && port_arg="-p-"

    local target_ip="${TARGET}"
    [[ ${#IP_LIST[@]} -gt 0 ]] && target_ip="${IP_LIST[0]}"

    # ── Quick discovery scan ───────────────────────────────────────────────────
    info "Initial host discovery..."
    nmap -sn "$target_ip" -oN "${out}/host_discovery.txt" 2>/dev/null || true

    # ── TCP SYN scan ──────────────────────────────────────────────────────────
    info "TCP port scan (this may take a while)..."
    nmap $nmap_speed $port_arg \
         -sV --version-intensity 5 \
         -sC \
         -O --osscan-guess \
         -A \
         --open \
         -oN "${out}/nmap_tcp.txt" \
         -oX "${out}/nmap_tcp.xml" \
         -oG "${out}/nmap_tcp_grep.txt" \
         "$target_ip" 2>/dev/null || warn "nmap TCP scan encountered issues"

    success "TCP scan complete"

    # ── UDP scan (top ports) ──────────────────────────────────────────────────
    info "UDP scan (top 20 ports)..."
    nmap -sU --top-ports 20 $nmap_speed \
         -oN "${out}/nmap_udp.txt" \
         "$target_ip" 2>/dev/null || warn "UDP scan requires root (skipping)"

    # ── Parse results & generate findings ─────────────────────────────────────
    if [[ -f "${out}/nmap_tcp.txt" ]]; then
        mapfile -t OPEN_PORTS < <( (grep "^[0-9]" "${out}/nmap_tcp.txt" 2>/dev/null || true) | \
            (grep "open" 2>/dev/null || true) | awk '{print $1}' | cut -d/ -f1)

        info "Analyzing port findings..."
        while IFS= read -r line; do
            local port; port=$(echo "$line" | awk '{print $1}' | cut -d/ -f1)
            local state; state=$(echo "$line" | awk '{print $2}')
            local service; service=$(echo "$line" | awk '{print $3}')
            local version; version=$(echo "$line" | awk '{$1=$2=$3=""; print $0}' | sed 's/^[[:space:]]*//')

            if [[ "$state" != "open" ]]; then
                continue
            fi

            # Flag sensitive ports
            case "$port" in
                21)   finding HIGH   "FTP Open"          "Port 21/FTP — $version" ;;
                23)   finding CRITICAL "Telnet Open"     "Port 23/Telnet — cleartext protocol in use" ;;
                25)   finding MEDIUM "SMTP Open"         "Port 25/SMTP — $version" ;;
                53)   finding INFO   "DNS Open"          "Port 53/DNS — $version" ;;
                80)   finding INFO   "HTTP Open"         "Port 80/HTTP — $version" ;;
                110)  finding MEDIUM "POP3 Open"        "Port 110/POP3 — $version" ;;
                111)  finding HIGH   "RPC Open"          "Port 111/RPC — potential RPC abuse" ;;
                135)  finding HIGH   "MSRPC Open"        "Port 135/MS-RPC — Windows attack surface" ;;
                139)  finding HIGH   "NetBIOS Open"      "Port 139/NetBIOS — file sharing exposed" ;;
                143)  finding MEDIUM "IMAP Open"         "Port 143/IMAP — $version" ;;
                443)  finding INFO   "HTTPS Open"        "Port 443/HTTPS — $version" ;;
                445)  finding HIGH   "SMB Open"          "Port 445/SMB — EternalBlue surface; verify patching" ;;
                1433) finding HIGH   "MSSQL Open"        "Port 1433/MSSQL — database exposed to network" ;;
                1723) finding MEDIUM "PPTP VPN Open"     "Port 1723/PPTP — deprecated VPN protocol" ;;
                3306) finding HIGH   "MySQL Open"        "Port 3306/MySQL — database directly exposed" ;;
                3389) finding HIGH   "RDP Open"          "Port 3389/RDP — BlueKeep / brute-force risk" ;;
                5432) finding HIGH   "PostgreSQL Open"   "Port 5432/PostgreSQL — database directly exposed" ;;
                5900) finding HIGH   "VNC Open"          "Port 5900/VNC — remote desktop exposed" ;;
                6379) finding CRITICAL "Redis Open"      "Port 6379/Redis — often unauthenticated" ;;
                8080) finding INFO   "HTTP-Alt Open"     "Port 8080/HTTP-Alt — $version" ;;
                8443) finding INFO   "HTTPS-Alt Open"    "Port 8443/HTTPS-Alt — $version" ;;
                9200) finding CRITICAL "Elasticsearch Open" "Port 9200/Elasticsearch — often unauthenticated" ;;
                27017)finding CRITICAL "MongoDB Open"    "Port 27017/MongoDB — likely unauthenticated" ;;
                *)    finding INFO   "Port $port Open"   "$service — $version" ;;
            esac
        done < <( (grep "^[0-9]" "${out}/nmap_tcp.txt" 2>/dev/null || true) | grep "open" 2>/dev/null || true)

        local open_count=${#OPEN_PORTS[@]}
        if [[ $open_count -gt 20 ]]; then
            finding HIGH "Large Attack Surface" "$open_count open ports detected — review and close unnecessary services"
        fi
    fi
}

# ─────────────────────────────────────────────────────────────────────────────
#  PHASE 4 — WEB RECONNAISSANCE
# ─────────────────────────────────────────────────────────────────────────────
phase_web() {
    [[ "$SKIP_ACTIVE" == "true" ]] && { info "Skipping web recon (--skip-active)"; return; }
    section "PHASE 4 — Web Application Reconnaissance"
    local out="${OUTPUT_DIR}/web"

    local web_targets=("http://${TARGET}" "https://${TARGET}")

    for url in "${web_targets[@]}"; do
        local proto; proto=$(echo "$url" | cut -d: -f1)
        local url_safe; url_safe="${proto}_${TARGET}"

        info "Probing $url ..."
        # ── HTTP Headers ──────────────────────────────────────────────────────
        local headers; headers=$(curl -s -I --max-time "$TIMEOUT" \
            -A "Mozilla/5.0 (compatible; SecurityAudit/1.0)" \
            -L "$url" 2>/dev/null)

        if [[ -n "$headers" ]]; then
            echo "$headers" > "${out}/headers_${url_safe}.txt"

            # Security header checks
            local sec_headers=("Strict-Transport-Security" "Content-Security-Policy"
                               "X-Frame-Options" "X-Content-Type-Options"
                               "Referrer-Policy" "Permissions-Policy"
                               "X-XSS-Protection")
            for hdr in "${sec_headers[@]}"; do
                if ! echo "$headers" | grep -qi "$hdr"; then
                    finding MEDIUM "Missing Security Header" "$hdr not set on $url"
                else
                    finding INFO "Security Header Present" "$hdr found"
                fi
            done

            # Sensitive header leaks
            local server; server=$( (echo "$headers" | grep -i "^Server:" 2>/dev/null || true) | head -1 | cut -d: -f2- | xargs || true)
            local xpowered; xpowered=$( (echo "$headers" | grep -i "^X-Powered-By:" 2>/dev/null || true) | head -1 | cut -d: -f2- | xargs || true)
            if [[ -n "$server" ]]; then
                finding LOW "Server Header Exposed" "Server: $server — version disclosure"
            fi
            if [[ -n "$xpowered" ]]; then
                finding LOW "X-Powered-By Exposed" "X-Powered-By: $xpowered — tech disclosure"
            fi

            # Cookie flags
            local cookies; cookies=$(echo "$headers" | grep -i "Set-Cookie:" 2>/dev/null || true)
            if echo "$cookies" | grep -qi "Set-Cookie" && \
               ! echo "$cookies" | grep -qi "HttpOnly"; then
                finding HIGH "Cookie Missing HttpOnly" "Session cookies lack HttpOnly flag on $url"
            fi
            if echo "$cookies" | grep -qi "Set-Cookie" && \
               ! echo "$cookies" | grep -qi "Secure"; then
                finding HIGH "Cookie Missing Secure Flag" "Cookies lack Secure flag on $url"
            fi

            # Check redirect HTTP → HTTPS
            if [[ "$proto" == "http" ]]; then
                local redirect; redirect=$( (echo "$headers" | grep -i "Location:" 2>/dev/null || true) | head -1)
                if echo "$redirect" | grep -qi "https://"; then
                    finding INFO "HTTP→HTTPS Redirect" "Redirect to HTTPS in place"
                else
                    finding MEDIUM "No HTTPS Redirect" "HTTP traffic not redirected to HTTPS"
                fi
            fi
        fi

        # ── WhatWeb fingerprinting ────────────────────────────────────────────
        if [[ "${TOOL_STATUS[whatweb]:-missing}" == "available" ]]; then
            info "WhatWeb fingerprinting $url ..."
            whatweb --quiet --no-errors "$url" \
                > "${out}/whatweb_${url_safe}.txt" 2>/dev/null || true
            if [[ -s "${out}/whatweb_${url_safe}.txt" ]]; then
                local tech; tech=$(cat "${out}/whatweb_${url_safe}.txt")
                finding INFO "Technology Stack ($url)" "$tech"
            fi
        fi

        # ── WAF detection ─────────────────────────────────────────────────────
        if [[ "${TOOL_STATUS[wafw00f]:-missing}" == "available" ]]; then
            info "WAF detection on $url ..."
            wafw00f "$url" > "${out}/wafw00f_${url_safe}.txt" 2>/dev/null || true
            if grep -qi "is behind" "${out}/wafw00f_${url_safe}.txt" 2>/dev/null; then
                local waf; waf=$( (grep -i "is behind" "${out}/wafw00f_${url_safe}.txt" 2>/dev/null || true) | head -1)
                finding INFO "WAF Detected" "$waf"
            else
                finding INFO "No WAF Detected" "No WAF identified on $url — direct access possible"
            fi
        fi

        # ── robots.txt & sitemap ──────────────────────────────────────────────
        info "Fetching robots.txt and sitemap..."
        curl -s --max-time 10 "${url}/robots.txt" \
            > "${out}/robots_${url_safe}.txt" 2>/dev/null || true
        if [[ -s "${out}/robots_${url_safe}.txt" ]]; then
            local disallowed; disallowed=$( (grep -i "Disallow:" "${out}/robots_${url_safe}.txt" 2>/dev/null || true) | wc -l)
            finding INFO "robots.txt Found" "$disallowed Disallow entries — may reveal hidden paths"
            # Check for sensitive disallowed paths
            if grep -i "Disallow:" "${out}/robots_${url_safe}.txt" 2>/dev/null | grep -q -iE "admin|backup|config|db|private|secret|test"; then
                finding MEDIUM "Sensitive Paths in robots.txt" "robots.txt reveals potentially sensitive directories"
            fi
        fi
        curl -s --max-time 10 "${url}/sitemap.xml" \
            > "${out}/sitemap_${url_safe}.xml" 2>/dev/null || true
        if [[ -s "${out}/sitemap_${url_safe}.xml" ]]; then
            finding INFO "sitemap.xml Found" "Sitemap available — useful for crawling"
        fi

        # ── Sensitive file checks ─────────────────────────────────────────────
        info "Checking for sensitive files..."
        local sensitive_files=(".git/HEAD" ".env" ".env.production" ".env.backup"
                               "wp-config.php.bak" "config.php.bak" "database.yml"
                               "phpinfo.php" "info.php" "test.php" "backup.zip"
                               "backup.tar.gz" "db.sql" "dump.sql" ".htpasswd"
                               "web.config.bak" "composer.json" "package.json"
                               "Dockerfile" "docker-compose.yml" ".DS_Store"
                               "README.md" "CHANGELOG.md" "crossdomain.xml"
                               "clientaccesspolicy.xml" "security.txt" ".well-known/security.txt")
        for file in "${sensitive_files[@]}"; do
            local code; code=$(curl -s -o /dev/null -w "%{http_code}" \
                --max-time 5 "${url}/${file}" 2>/dev/null)
            if [[ "$code" =~ ^(200|206)$ ]]; then
                case "$file" in
                    .git/HEAD|.env*|*.bak|*.sql|*.zip|*.tar.gz)
                        finding CRITICAL "Sensitive File Exposed" "${url}/${file} returns HTTP $code" ;;
                    phpinfo.php|info.php|test.php)
                        finding HIGH "PHP Info Exposed"     "${url}/${file} returns HTTP $code" ;;
                    docker-compose.yml|Dockerfile)
                        finding HIGH "Infrastructure File Exposed" "${url}/${file} returns HTTP $code" ;;
                    *)
                        finding MEDIUM "Interesting File Found" "${url}/${file} returns HTTP $code" ;;
                esac
            fi
        done || true

    done  # end for url

    # ── Directory bruteforce ───────────────────────────────────────────────────
    if [[ "$SKIP_BRUTEFORCE" == "false" && -f "$WORDLIST" ]]; then
        info "Directory bruteforce on https://${TARGET} ..."
        if [[ "${TOOL_STATUS[ffuf]:-missing}" == "available" ]]; then
            timeout 300 ffuf \
                -u "https://${TARGET}/FUZZ" \
                -w "$WORDLIST" \
                -t "$THREADS" \
                -mc 200,201,204,301,302,307,401,403 \
                -o "${out}/ffuf_dirs.json" \
                -of json \
                -s 2>/dev/null || true
            [[ -f "${out}/ffuf_dirs.json" ]] && {
                local dir_count; dir_count=$(python3 -c \
                    "import json; d=json.load(open('${out}/ffuf_dirs.json')); print(len(d.get('results',[])))" 2>/dev/null || echo 0)
                if [[ $dir_count -gt 0 ]]; then
                    finding MEDIUM "Directories Found" "$dir_count paths discovered via brute-force"
                fi
            }
        elif [[ "${TOOL_STATUS[gobuster]:-missing}" == "available" ]]; then
            timeout 300 gobuster dir \
                -u "https://${TARGET}" \
                -w "$WORDLIST" \
                -t "$THREADS" \
                -o "${out}/gobuster_dirs.txt" \
                --quiet 2>/dev/null || true
        fi
        success "Directory brute-force complete"
    fi

    # ── Nikto (basic vuln scan) ────────────────────────────────────────────────
    if [[ "${TOOL_STATUS[nikto]:-missing}" == "available" && "$SKIP_ACTIVE" == "false" ]]; then
        info "Running Nikto web scanner..."
        timeout 300 nikto -h "https://${TARGET}" \
            -output "${out}/nikto.txt" \
            -Format txt \
            -nointeractive 2>/dev/null || true
        if [[ -f "${out}/nikto.txt" ]]; then
            local nikto_findings; nikto_findings=$(grep "^+" "${out}/nikto.txt" 2>/dev/null | wc -l || echo 0)
            if [[ $nikto_findings -gt 0 ]]; then
                finding HIGH "Nikto Web Vulnerabilities" "$nikto_findings issues found — review ${out}/nikto.txt"
            fi
        fi
        success "Nikto scan complete"
    fi
}

# ─────────────────────────────────────────────────────────────────────────────
#  PHASE 5 — VULNERABILITY CORRELATION
# ─────────────────────────────────────────────────────────────────────────────
phase_vulns() {
    [[ "$SKIP_ACTIVE" == "true" ]] && return
    section "PHASE 5 — Vulnerability Correlation"
    local out="${OUTPUT_DIR}/vulns"

    # ── Nuclei ────────────────────────────────────────────────────────────────
    if [[ "${TOOL_STATUS[nuclei]:-missing}" == "available" ]]; then
        info "Running Nuclei template scan (this may take a while)..."
        local nuclei_targets=("https://${TARGET}")
        # Add live subdomains
        [[ ${#LIVE_HOSTS[@]} -gt 0 ]] && nuclei_targets+=("${LIVE_HOSTS[@]}")

        printf '%s\n' "${nuclei_targets[@]}" > "${out}/nuclei_targets.txt"
        timeout 600 nuclei \
            -l "${out}/nuclei_targets.txt" \
            -o "${out}/nuclei_results.txt" \
            -severity critical,high,medium,low \
            -silent \
            -rate-limit "$RATE_LIMIT" 2>/dev/null || true

        if [[ -f "${out}/nuclei_results.txt" && -s "${out}/nuclei_results.txt" ]]; then
            local n_crit; n_crit=$(grep -c "\[critical\]" "${out}/nuclei_results.txt" 2>/dev/null || echo 0)
            local n_high; n_high=$(grep -c "\[high\]"     "${out}/nuclei_results.txt" 2>/dev/null || echo 0)
            local n_med;  n_med=$(grep -c "\[medium\]"    "${out}/nuclei_results.txt" 2>/dev/null || echo 0)
            local n_low;  n_low=$(grep -c "\[low\]"       "${out}/nuclei_results.txt" 2>/dev/null || echo 0)
            if [[ $n_crit -gt 0 ]]; then finding CRITICAL "Nuclei Critical" "$n_crit critical issues found"; fi
            if [[ $n_high -gt 0 ]]; then finding HIGH    "Nuclei High"     "$n_high high-severity issues found"; fi
            if [[ $n_med  -gt 0 ]]; then finding MEDIUM  "Nuclei Medium"   "$n_med medium issues found"; fi
            if [[ $n_low  -gt 0 ]]; then finding LOW     "Nuclei Low"      "$n_low low-severity issues found"; fi
        fi
        success "Nuclei scan complete"
    fi

    # ── Service version CVE correlation ───────────────────────────────────────
    if [[ -f "${OUTPUT_DIR}/ports/nmap_tcp.txt" ]]; then
        info "Correlating service versions against known vulnerability patterns..."
        while IFS= read -r line; do
            # Apache
            if echo "$line" | grep -qi "Apache/2\.2"; then
                finding HIGH "Outdated Apache" "Apache 2.2.x detected — EOL since 2017, many CVEs"
            fi
            if echo "$line" | grep -qi "Apache/2\.4\.[0-2][0-9]"; then
                finding MEDIUM "Potentially Outdated Apache" "Apache 2.4 (older minor) — verify patch level"
            fi
            # OpenSSH
            if echo "$line" | grep -qiE "OpenSSH [1-6]\.|OpenSSH 7\.[0-4]"; then
                finding HIGH "Outdated OpenSSH" "Old OpenSSH version — upgrade recommended"
            fi
            # nginx
            if echo "$line" | grep -qiE "nginx/1\.[0-9]\.|nginx/1\.1[0-5]\."; then
                finding MEDIUM "Potentially Outdated nginx" "Older nginx version detected"
            fi
            # PHP
            if echo "$line" | grep -qiE "PHP/5\.|PHP/7\.[0-3]"; then
                finding HIGH "Outdated PHP" "EOL PHP version detected — critical CVE exposure"
            fi
            # IIS
            if echo "$line" | grep -qiE "IIS/[1-9]\.[0-9]"; then
                local iis_ver; iis_ver=$(echo "$line" | grep -oiE "IIS/[0-9]+\.[0-9]+")
                finding MEDIUM "IIS Detected" "$iis_ver — verify patches are applied"
            fi
            # vsFTPd
            if echo "$line" | grep -qi "vsftpd 2.3.4"; then
                finding CRITICAL "vsFTPd 2.3.4 Backdoor" "CVE-2011-2523 — backdoor version detected"
            fi
            # Samba
            if echo "$line" | grep -qiE "Samba [1-3]\.|Samba 4\.[0-6]"; then
                finding HIGH "Outdated Samba" "Old Samba version — SambaCry / EternalBlue risk"
            fi
        done < "${OUTPUT_DIR}/ports/nmap_tcp.txt"
        success "Service version correlation complete"
    fi

    # ── Open redirect / CORS quick checks ─────────────────────────────────────
    info "Checking CORS policy..."
    local cors; cors=$( (curl -s -I --max-time 10 -H "Origin: https://evil.com" "https://${TARGET}" 2>/dev/null || true) | grep -i "Access-Control-Allow-Origin:" || true)
    if echo "$cors" | grep -q "evil.com\|\*"; then
        finding HIGH "CORS Misconfiguration" \
            "Access-Control-Allow-Origin: $(echo "$cors" | cut -d: -f2-) — reflects arbitrary origin"
    fi

    # ── Clickjacking ──────────────────────────────────────────────────────────
    local xfo; xfo=$( (curl -s -I --max-time 10 "https://${TARGET}" 2>/dev/null || true) | grep -i "X-Frame-Options:" || true)
    local csp; csp=$( (curl -s -I --max-time 10 "https://${TARGET}" 2>/dev/null || true) | grep -i "Content-Security-Policy:" || true)
    if [[ -z "$xfo" ]] && ! echo "$csp" | grep -qi "frame-ancestors"; then
        finding MEDIUM "Clickjacking Vulnerability" \
            "No X-Frame-Options or CSP frame-ancestors directive set"
    fi
}

# ─────────────────────────────────────────────────────────────────────────────
#  PHASE 5b — CVE DATABASE LOOKUP + SEARCHSPLOIT EXPLOIT CORRELATION
# ─────────────────────────────────────────────────────────────────────────────

# ── Helper: query NVD CVE API for a keyword ───────────────────────────────────
# Returns JSON array of CVE records sorted by CVSS score (highest first)
nvd_search() {
    local keyword="$1"
    local max_results="${2:-10}"
    local api_url="https://services.nvd.nist.gov/rest/json/cves/2.0"
    local encoded_kw; encoded_kw=$(python3 -c \
        "import urllib.parse,sys; print(urllib.parse.quote(sys.argv[1]))" "$keyword" 2>/dev/null || \
        echo "${keyword// /+}")

    local curl_args=(-s --max-time 20
        "${api_url}?keywordSearch=${encoded_kw}&resultsPerPage=${max_results}")
    [[ -n "$NVD_API_KEY" ]] && curl_args+=(-H "apiKey: ${NVD_API_KEY}")

    local raw; raw=$(curl "${curl_args[@]}" 2>/dev/null || true)
    printf '%s' "$raw"
}

# ── Helper: parse NVD response → pretty table + JSON accumulation ─────────────
parse_nvd_response() {
    local product="$1"
    local json_file="$2"
    local out_file="$3"

    python3 - "$product" "$json_file" <<'PYEOF' | tee -a "$out_file"
import json, sys

product = sys.argv[1]
json_file = sys.argv[2]

try:
    with open(json_file, encoding='utf-8', errors='ignore') as f:
        data = json.load(f)
except Exception as e:
    print(f"  [!] JSON parse error for {product}: {e}")
    sys.exit(0)

vulns = data.get("vulnerabilities", [])
if not vulns:
    print(f"  [INFO] No CVEs found in NVD for: {product}")
    sys.exit(0)

# Sort by CVSS v3 base score descending, fall back to v2
def get_score(v):
    cve = v.get("cve", {})
    metrics = cve.get("metrics", {})
    for key in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
        arr = metrics.get(key, [])
        if arr:
            return float(arr[0].get("cvssData", {}).get("baseScore", 0))
    return 0.0

def get_severity(score):
    if score >= 9.0: return "CRITICAL"
    if score >= 7.0: return "HIGH"
    if score >= 4.0: return "MEDIUM"
    if score >  0:   return "LOW"
    return "INFO"

vulns_sorted = sorted(vulns, key=get_score, reverse=True)

print(f"\n  ┌─ CVEs for: {product} ({len(vulns_sorted)} found) " + "─" * 30)
for v in vulns_sorted:
    cve_data = v.get("cve", {})
    cve_id   = cve_data.get("id", "N/A")
    score    = get_score(v)
    sev      = get_severity(score)
    descs    = cve_data.get("descriptions", [])
    desc     = next((d["value"] for d in descs if d.get("lang") == "en"), "No description")
    desc_short = desc[:120] + "..." if len(desc) > 120 else desc
    refs     = cve_data.get("references", [])
    ref_url  = refs[0].get("url", "") if refs else ""

    sev_color = {
        "CRITICAL": "\033[0;31m", "HIGH": "\033[0;31m",
        "MEDIUM": "\033[1;33m",   "LOW": "\033[0;36m", "INFO": "\033[1;37m"
    }.get(sev, "")
    nc = "\033[0m"

    print(f"  │  {sev_color}[{sev:8s}]{nc} {cve_id:18s} CVSS:{score:.1f}  {desc_short}")
    if ref_url:
        print(f"  │              ↳ {ref_url}")

print("  └" + "─" * 60)
PYEOF
}

# ── Helper: run searchsploit for a product/version, parse output ──────────────
run_searchsploit() {
    local product="$1"
    local out_file="$2"
    local raw_dir="${OUTPUT_DIR}/vulns/searchsploit"
    mkdir -p "$raw_dir"
    local safe_name; safe_name="${product//[^a-zA-Z0-9_]/_}"

    if [[ "${TOOL_STATUS[searchsploit]:-missing}" != "available" ]]; then
        return
    fi

    info "  searchsploit → $product"
    # --json gives structured output; -w adds URLs
    local ss_json; ss_json=$(searchsploit --json -w "$product" 2>/dev/null || true)
    echo "$ss_json" > "${raw_dir}/ss_${safe_name}.json"

    python3 - "$product" "${raw_dir}/ss_${safe_name}.json" <<'PYEOF' | tee -a "$out_file"
import json, sys, os

product = sys.argv[1]
raw_path = sys.argv[2]

try:
    with open(raw_path, encoding='utf-8', errors='ignore') as f:
        data = json.load(f)
except Exception:
    print(f"  [!] searchsploit returned no JSON for {product}")
    sys.exit(0)

exploits = data.get("RESULTS_EXPLOIT", []) + data.get("RESULTS_SHELLCODE", [])

if not exploits:
    print(f"  [searchsploit] No public exploits found for: {product}")
    sys.exit(0)

# Classify by type
priority_order = ["Remote", "WebApps", "Local", "DoS", "Shellcode", "Papers"]

def exploit_priority(e):
    t = e.get("Type", "")
    for i, p in enumerate(priority_order):
        if p.lower() in t.lower():
            return i
    return 99

exploits_sorted = sorted(exploits, key=exploit_priority)

print(f"\n  ┌─ Exploits for: {product} ({len(exploits_sorted)} found) " + "─" * 28)
for ex in exploits_sorted:
    etype  = ex.get("Type", "Unknown").strip()
    title  = ex.get("Title", "").strip()
    path   = ex.get("Path", "").strip()
    url    = ex.get("URL", "").strip()

    # Severity label based on exploit type
    if "remote" in etype.lower():
        label = "\033[0;31m[REMOTE ]\033[0m"
    elif "webapps" in etype.lower():
        label = "\033[0;31m[WEBAPP ]\033[0m"
    elif "local" in etype.lower():
        label = "\033[1;33m[LOCAL  ]\033[0m"
    elif "dos" in etype.lower():
        label = "\033[0;36m[DoS    ]\033[0m"
    else:
        label = "\033[1;37m[OTHER  ]\033[0m"

    print(f"  │  {label} {title[:70]}")
    if url:
        print(f"  │             ↳ {url}")
    elif path:
        print(f"  │             ↳ file://{path}")

print("  └" + "─" * 60)
PYEOF

    # Count exploits for summary
    local count; count=$(python3 -c \
        "import json; d=json.load(open('${raw_dir}/ss_${safe_name}.json')); \
         print(len(d.get('RESULTS_EXPLOIT',[])+d.get('RESULTS_SHELLCODE',[])))" 2>/dev/null || echo 0)
    if [[ "$count" -gt 0 ]]; then
        TOTAL_EXPLOITS_FOUND=$((TOTAL_EXPLOITS_FOUND + count))
        finding HIGH "Public Exploits Found" \
            "$count exploit(s) in Exploit-DB for '$product' — see vulns/searchsploit/ss_${safe_name}.json"
    fi
}

# ── Main CVE phase ─────────────────────────────────────────────────────────────
phase_cve() {
    [[ "$SKIP_CVE"    == "true" ]] && { info "Skipping CVE lookup (--skip-cve)"; return; }
    [[ "$SKIP_ACTIVE" == "true" ]] && return

    section "PHASE 5b — CVE Lookup & Exploit Correlation"
    local out="${OUTPUT_DIR}/vulns"
    local cve_report="${out}/cve_exploits_report.txt"
    mkdir -p "${out}/searchsploit"

    {
        echo "============================================================"
        echo "  CVE & EXPLOIT CORRELATION REPORT"
        echo "  Target  : ${TARGET}"
        echo "  Date    : $(date)"
        echo "  Tool    : NVD CVE API v2 + Exploit-DB (searchsploit)"
        echo "============================================================"
    } > "$cve_report"

    # ── Step 1: Extract service/version strings from nmap output ──────────────
    info "Extracting service versions from nmap scan..."
    if [[ ! -f "${OUTPUT_DIR}/ports/nmap_tcp.txt" ]]; then
        warn "No nmap output found — run port scan first (phase 3)"
        return
    fi

    # Parse nmap output: grab lines with open ports + service versions
    while IFS= read -r line; do
        # Match lines like:  80/tcp   open  http    Apache httpd 2.4.49
        if echo "$line" | grep -qE "^[0-9]+/tcp.*open"; then
            local port;    port=$(echo    "$line" | awk '{print $1}' | cut -d/ -f1)
            local service; service=$(echo "$line" | awk '{print $3}')
            local version; version=$(echo "$line" | awk '{$1=$2=$3=""; print $0}' | sed 's/^[[:space:]]*//')

            # Skip empty or generic versions
            [[ -z "$version" || "$version" == *"?"* ]] && continue

            # Build clean product+version string for searches
            local search_term=""
            case "$service" in
                http|https|http-proxy|ssl/http|ssl/https)
                    # Extract "Apache 2.4.49" or "nginx 1.18.0" etc.
                    if echo "$version" | grep -qiE "Apache|nginx|IIS|lighttpd|Tomcat|Jetty|Caddy|Cherokee"; then
                        search_term=$(echo "$version" | grep -oiE "(Apache|nginx|IIS|lighttpd|Tomcat|Jetty|Caddy|Cherokee)[^(,;]*" | head -1 | sed 's/[[:space:]]*$//' || true)
                    else
                        local first_word; first_word=$(echo "$version" | awk '{print $1}')
                        local ver_num;    ver_num=$(echo "$version" | grep -oE "[0-9]+\.[0-9]+(\.[0-9]+)?" | head -1 || true)
                        if [[ -n "$first_word" && ${#first_word} -gt 2 ]]; then
                            if [[ -n "$ver_num" ]]; then
                                search_term="${first_word} ${ver_num}"
                            else
                                search_term="${first_word}"
                            fi
                        fi
                    fi ;;
                ssh)
                    search_term=$(echo "$version" | grep -oiE "OpenSSH [0-9]+\.[0-9p]+" | head -1 || true) ;;
                ftp)
                    search_term=$(echo "$version" | grep -oiE "(vsftpd|ProFTPD|Pure-FTPd|FileZilla)[^(,;]*" | head -1 | sed 's/[[:space:]]*$//' || true) ;;
                smtp|smtps)
                    search_term=$(echo "$version" | grep -oiE "(Postfix|Sendmail|Exim|Exchange)[^(,;]*" | head -1 | sed 's/[[:space:]]*$//' || true) ;;
                mysql|mariadb)
                    search_term=$(echo "$version" | grep -oiE "(MySQL|MariaDB) [0-9]+\.[0-9.]+" | head -1 || true) ;;
                ms-sql-s|mssql)
                    search_term=$(echo "$version" | grep -oiE "Microsoft SQL Server [0-9]+" | head -1 || true) ;;
                rdp|ms-wbt-server)
                    search_term="Windows RDP" ;;
                smb|netbios-ssn|microsoft-ds)
                    search_term=$(echo "$version" | grep -oiE "Samba [0-9]+\.[0-9.]+" | head -1 || true)
                    [[ -z "$search_term" ]] && search_term="SMB Windows" ;;
                vnc)
                    search_term="VNC RealVNC" ;;
                telnet)
                    search_term="telnet" ;;
                redis)
                    search_term=$(echo "$version" | grep -oiE "Redis [0-9]+\.[0-9.]+" | head -1 || true)
                    [[ -z "$search_term" ]] && search_term="Redis" ;;
                mongodb)
                    search_term=$(echo "$version" | grep -oiE "MongoDB [0-9]+\.[0-9.]+" | head -1 || true)
                    [[ -z "$search_term" ]] && search_term="MongoDB" ;;
                postgresql)
                    search_term=$(echo "$version" | grep -oiE "PostgreSQL [0-9]+\.[0-9.]+" | head -1 || true) ;;
                *)
                    # Generic: use first meaningful word + version number if present
                    local first_word; first_word=$(echo "$version" | awk '{print $1}')
                    local ver_num;    ver_num=$(echo "$version" | grep -oE "[0-9]+\.[0-9]+(\.[0-9]+)?" | head -1 || true)
                    if [[ -n "$first_word" && ${#first_word} -gt 2 ]]; then
                        if [[ -n "$ver_num" ]]; then
                            search_term="${first_word} ${ver_num}"
                        else
                            search_term="${first_word}"
                        fi
                    fi ;;
            esac

            # Clean up and store unique entries
            search_term=$(echo "$search_term" | sed 's/[[:space:]]*$//' | tr -s ' ')
            if [[ -n "$search_term" && ${#search_term} -gt 3 ]]; then
                # Deduplicate
                local already=false
                if [[ ${#DETECTED_SERVICES[@]} -gt 0 ]]; then
                    for existing in "${DETECTED_SERVICES[@]}"; do
                        [[ "$existing" == "$search_term" ]] && already=true && break
                    done
                fi
                if [[ "$already" == "false" ]]; then
                    DETECTED_SERVICES+=("$search_term")
                fi
                debug "Port $port ($service) → search: '$search_term'"
            fi
        fi
    done < "${OUTPUT_DIR}/ports/nmap_tcp.txt"

    # Also add nmap OS detection result if available
    local os_guess; os_guess=$(grep -i "OS details\|Running:" "${OUTPUT_DIR}/ports/nmap_tcp.txt" \
        2>/dev/null | head -2 | awk -F: '{print $2}' | xargs || true)
    if [[ -n "$os_guess" ]]; then
        info "OS detected: $os_guess"
        finding INFO "OS Fingerprint" "$os_guess"
        echo -e "\n  [OS] Detected: $os_guess" >> "$cve_report"
    fi

    local total_services=${#DETECTED_SERVICES[@]}
    if [[ $total_services -eq 0 ]]; then
        warn "No versioned services detected — CVE lookup skipped"
        warn "Try running with -A flag in nmap or ensure port scan ran first"
        return
    fi

    success "Detected $total_services unique services to research"
    echo -e "\n  Services queued: ${DETECTED_SERVICES[*]}\n" >> "$cve_report"

    # ── Step 2: Per-service NVD + searchsploit lookup ─────────────────────────
    local service_idx=0
    for svc in "${DETECTED_SERVICES[@]}"; do
        service_idx=$((service_idx + 1))
        echo ""
        info "[$service_idx/$total_services] Researching: ${BOLD}${svc}${NC}"

        echo -e "\n══════════════════════════════════════════════════" >> "$cve_report"
        echo -e "  SERVICE: $svc" >> "$cve_report"
        echo -e "══════════════════════════════════════════════════" >> "$cve_report"

        # ── 2a: NVD CVE API lookup ───────────────────────────────────────────
        info "  Querying NVD CVE database..."
        local nvd_raw; nvd_raw=$(nvd_search "$svc" 15 || true)

        if [[ -n "$nvd_raw" && "$nvd_raw" == *"vulnerabilities"* ]]; then
            local nvd_file="${out}/searchsploit/nvd_${svc//[^a-zA-Z0-9]/_}.json"
            echo "$nvd_raw" > "$nvd_file"

            # Parse and display
            parse_nvd_response "$svc" "$nvd_file" "$cve_report"

            # Extract counts by severity for findings
            local counts crit_count high_count
            counts=$(python3 - "$nvd_file" <<'PYEOF' 2>/dev/null || echo "0 0"
import json, sys
try:
    with open(sys.argv[1], encoding='utf-8', errors='ignore') as f:
        d = json.load(f)
    vulns = d.get('vulnerabilities', [])
    def score(v):
        m = v.get('cve', {}).get('metrics', {})
        for k in ['cvssMetricV31', 'cvssMetricV30', 'cvssMetricV2']:
            arr = m.get(k, [])
            if arr: return float(arr[0].get('cvssData', {}).get('baseScore', 0))
        return 0
    c = sum(1 for v in vulns if score(v) >= 9.0)
    h = sum(1 for v in vulns if 7.0 <= score(v) < 9.0)
    print(f"{c} {h}")
except Exception:
    print("0 0")
PYEOF
)
            crit_count=$(echo "$counts" | awk '{print $1}')
            high_count=$(echo "$counts" | awk '{print $2}')

            if [[ "$crit_count" -gt 0 ]]; then
                finding CRITICAL "NVD CVEs for $svc" \
                    "$crit_count CRITICAL-score CVEs (CVSS≥9.0) found in NVD database"
            fi
            if [[ "$high_count" -gt 0 ]]; then
                finding HIGH "NVD CVEs for $svc" \
                    "$high_count HIGH-score CVEs (CVSS 7.0–8.9) found in NVD database"
            fi
        else
            warn "  NVD API returned no data for '$svc' (rate limit or network issue)"
            echo "  [!] NVD API returned no data for $svc" >> "$cve_report"
        fi

        # ── 2b: searchsploit Exploit-DB lookup ───────────────────────────────
        echo -e "\n  --- Exploit-DB (searchsploit) ---" >> "$cve_report"
        run_searchsploit "$svc" "$cve_report"

        # Respect NVD rate limiting: 6 req/min without key, 50/min with key
        if [[ -z "$NVD_API_KEY" ]]; then
            debug "Sleeping 12s for NVD rate limit (use --nvd-key to skip)"
            sleep 12
        else
            sleep 1
        fi
    done

    # ── Step 3: Searchsploit sweep on target domain/IP directly ──────────────
    if [[ "${TOOL_STATUS[searchsploit]:-missing}" == "available" ]]; then
        echo -e "\n══════════════════════════════════════════════════" >> "$cve_report"
        echo -e "  SEARCHSPLOIT DIRECT TARGET SWEEP" >> "$cve_report"
        echo -e "══════════════════════════════════════════════════" >> "$cve_report"

        info "Running searchsploit on detected web technologies..."

        # Additional targeted searches based on whatweb / nikto findings
        local web_techs=()
        for f in "${OUTPUT_DIR}/web"/whatweb_*.txt; do
            [[ -f "$f" ]] || continue
            # Extract tech names from whatweb output
            while IFS= read -r tech_line; do
                for tech in WordPress Drupal Joomla Laravel Django Rails Struts \
                            Tomcat WebLogic JBoss Jenkins Confluence phpMyAdmin \
                            Grafana Kibana Splunk Roundcube Zimbra; do
                    if echo "$tech_line" | grep -qi "$tech"; then
                        local ver; ver=$(echo "$tech_line" | \
                            grep -oiE "${tech}[^,\]]*" | head -1 | \
                            grep -oE "[0-9]+\.[0-9]+(\.[0-9]+)?" | head -1 || true)
                        local tech_search="$tech"
                        [[ -n "$ver" ]] && tech_search="$tech $ver"
                        web_techs+=("$tech_search")
                    fi
                done
            done < "$f"
        done

        # Deduplicate web techs
        if [[ ${#web_techs[@]} -gt 0 ]]; then
            mapfile -t web_techs < <(printf '%s\n' "${web_techs[@]}" | sort -u)
        fi

        for wt in "${web_techs[@]:-}"; do
            [[ -z "$wt" ]] && continue
            info "  searchsploit → $wt (web tech)"
            run_searchsploit "$wt" "$cve_report"
            sleep 1
        done

        # Always run a broad sweep for common things
        local broad_terms=()
        if grep -qiE "wordpress|wp-content" "${OUTPUT_DIR}/web/"*.txt 2>/dev/null; then
            broad_terms+=("WordPress")
        fi
        if grep -qi "drupal" "${OUTPUT_DIR}/web/"*.txt 2>/dev/null; then
            broad_terms+=("Drupal")
        fi
        if grep -qi "joomla" "${OUTPUT_DIR}/web/"*.txt 2>/dev/null; then
            broad_terms+=("Joomla")
        fi
        if grep -qi "struts" "${OUTPUT_DIR}/ports/nmap_tcp.txt" 2>/dev/null; then
            broad_terms+=("Apache Struts")
        fi

        for bt in "${broad_terms[@]}"; do
            # Only search if not already done
            local already_done=false
            if [[ ${#DETECTED_SERVICES[@]} -gt 0 ]]; then
                for done_svc in "${DETECTED_SERVICES[@]}"; do
                    [[ "${done_svc,,}" == *"${bt,,}"* ]] && already_done=true && break
                done
            fi
            if [[ "$already_done" == "false" ]]; then
                run_searchsploit "$bt" "$cve_report"
                sleep 1
            fi
        done
    else
        warn "searchsploit not installed — skipping Exploit-DB lookups"
        warn "Install with: sudo apt install exploitdb  OR  sudo apt install exploitdb-bin-sploits"
        echo "  [!] searchsploit not available on this system" >> "$cve_report"
    fi

    # ── Step 4: Priority-sorted exploit summary in terminal ───────────────────
    section "CVE / Exploit Priority Summary"
    {
        echo -e "\n══════════════════════════════════════════════════" >> "$cve_report"
        echo -e "  PRIORITY SUMMARY" >> "$cve_report"
        echo -e "══════════════════════════════════════════════════" >> "$cve_report"
    }

    echo -e "  ${BOLD}Services researched :${NC} $total_services"
    echo -e "  ${BOLD}Total public exploits:${NC} ${RED}${TOTAL_EXPLOITS_FOUND}${NC}"
    echo ""

    if [[ "${TOOL_STATUS[searchsploit]:-missing}" == "available" ]]; then
        # Re-aggregate all searchsploit JSON files to print priority table
        export SS_DIR="${OUTPUT_DIR}/vulns/searchsploit"
        python3 - <<'PYEOF'
import json, os, glob

ss_dir = os.environ.get("SS_DIR", ".")
remote_exploits  = []
webapp_exploits  = []
local_exploits   = []
dos_exploits     = []
other_exploits   = []

for jf in glob.glob(os.path.join(ss_dir, "ss_*.json")):
    try:
        with open(jf) as f:
            data = json.load(f)
    except:
        continue
    for ex in data.get("RESULTS_EXPLOIT", []) + data.get("RESULTS_SHELLCODE", []):
        etype = ex.get("Type", "").lower()
        title = ex.get("Title", "").strip()
        url   = ex.get("URL", ex.get("Path", ""))
        entry = {"title": title, "url": url, "file": os.path.basename(jf)}
        if "remote"   in etype: remote_exploits.append(entry)
        elif "webapps"in etype: webapp_exploits.append(entry)
        elif "local"  in etype: local_exploits.append(entry)
        elif "dos"    in etype: dos_exploits.append(entry)
        else:                   other_exploits.append(entry)

RED    = "\033[0;31m"
YELLOW = "\033[1;33m"
CYAN   = "\033[0;36m"
WHITE  = "\033[1;37m"
BOLD   = "\033[1m"
NC     = "\033[0m"

sections = [
    ("🔴 REMOTE CODE EXECUTION / REMOTE EXPLOITS",  remote_exploits,  RED),
    ("🟠 WEB APPLICATION EXPLOITS",                  webapp_exploits,  RED),
    ("🟡 LOCAL PRIVILEGE ESCALATION",                local_exploits,   YELLOW),
    ("🔵 DENIAL OF SERVICE",                         dos_exploits,     CYAN),
    ("⚪ OTHER / SHELLCODE / PAPERS",                other_exploits,   WHITE),
]

for title, exploits, color in sections:
    if not exploits:
        continue
    print(f"\n  {BOLD}{color}{title}{NC}")
    print(f"  {'─'*60}")
    for i, ex in enumerate(exploits[:15], 1):
        print(f"  {color}[{i:2d}]{NC} {ex['title'][:65]}")
        print(f"       ↳ {ex['url']}")
    if len(exploits) > 15:
        print(f"       ... and {len(exploits)-15} more (see raw JSON files)")
PYEOF
    fi

    success "CVE report saved: ${cve_report}"
    if [[ $TOTAL_EXPLOITS_FOUND -gt 0 ]]; then
        finding CRITICAL "Exploitable Services Detected" \
            "$TOTAL_EXPLOITS_FOUND public exploit(s) found across all detected services — IMMEDIATE review required"
    fi
}

# ─────────────────────────────────────────────────────────────────────────────
#  PHASE 6 — REPORT GENERATION
# ─────────────────────────────────────────────────────────────────────────────
phase_report() {
    section "PHASE 6 — Generating Reports"
    local out="${OUTPUT_DIR}/reports"
    mkdir -p "${out}"
    local elapsed=$(( $(date +%s) - START_TIME ))
    local duration; printf -v duration '%02dh %02dm %02ds' \
        $((elapsed/3600)) $(((elapsed%3600)/60)) $((elapsed%60))

    # ── JSON Report ───────────────────────────────────────────────────────────
    if [[ "$REPORT_FORMAT" == "json" || "$REPORT_FORMAT" == "both" ]]; then
        export JSON_FINDINGS
        python3 - <<PYEOF > "${out}/report.json"
import json, datetime, os

try:
    findings = json.loads(os.environ.get("JSON_FINDINGS", "[]"))
except Exception:
    findings = []

report = {
    "meta": {
        "tool": "Ultimate Recon Tool v${VERSION}",
        "target": "${TARGET}",
        "timestamp": "$(date -Iseconds)",
        "duration": "${duration}",
        "output_dir": "${OUTPUT_DIR}"
    },
    "summary": {
        "critical": ${FINDINGS_CRITICAL},
        "high":     ${FINDINGS_HIGH},
        "medium":   ${FINDINGS_MEDIUM},
        "low":      ${FINDINGS_LOW},
        "info":     ${FINDINGS_INFO},
        "open_ports": ${#OPEN_PORTS[@]},
        "subdomains": ${#SUBDOMAINS[@]}
    },
    "findings": findings
}
print(json.dumps(report, indent=2))
PYEOF
        success "JSON report: ${out}/report.json"
    fi

    # ── HTML Report ───────────────────────────────────────────────────────────
    if [[ "$REPORT_FORMAT" == "html" || "$REPORT_FORMAT" == "both" ]]; then
        local html_file="${out}/report.html"

        # Build findings rows
        local findings_rows=""
        # Re-parse JSON findings for HTML
        export JSON_FINDINGS
        findings_rows=$(python3 - <<PYEOF 2>/dev/null
import json, os

try:
    findings = json.loads(os.environ.get("JSON_FINDINGS", "[]"))
except Exception:
    findings = []

rows = []
color_map = {
    "CRITICAL": "#dc2626",
    "HIGH":     "#ea580c",
    "MEDIUM":   "#d97706",
    "LOW":      "#2563eb",
    "INFO":     "#6b7280"
}
badge_map = {
    "CRITICAL": "background:#dc2626;color:#fff",
    "HIGH":     "background:#ea580c;color:#fff",
    "MEDIUM":   "background:#d97706;color:#fff",
    "LOW":      "background:#2563eb;color:#fff",
    "INFO":     "background:#6b7280;color:#fff"
}
for f in findings:
    sev  = f.get("severity","INFO")
    rows.append(f'''<tr>
        <td><span style="padding:3px 8px;border-radius:4px;font-size:11px;font-weight:700;{badge_map.get(sev,'')}">{sev}</span></td>
        <td style="font-weight:600">{f.get("title","")}</td>
        <td style="color:#374151;font-size:13px">{f.get("detail","")}</td>
        <td style="color:#9ca3af;font-size:12px">{f.get("ts","")}</td>
    </tr>''')
print("\n".join(rows))
PYEOF
)

        cat > "$html_file" << HTMLEOF
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Recon Report — ${TARGET}</title>
<style>
  *{margin:0;padding:0;box-sizing:border-box}
  body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;background:#0f172a;color:#e2e8f0;min-height:100vh}
  header{background:linear-gradient(135deg,#1e293b 0%,#0f172a 100%);border-bottom:1px solid #334155;padding:24px 32px;display:flex;align-items:center;justify-content:space-between}
  header h1{font-size:22px;font-weight:700;color:#f1f5f9}
  header p{color:#64748b;font-size:13px;margin-top:4px}
  .badge{padding:4px 12px;border-radius:20px;font-size:12px;font-weight:600}
  .badge-danger{background:#7f1d1d;color:#fca5a5}
  .container{max-width:1400px;margin:0 auto;padding:32px}
  .grid{display:grid;grid-template-columns:repeat(5,1fr);gap:16px;margin-bottom:32px}
  .card{background:#1e293b;border:1px solid #334155;border-radius:12px;padding:20px;text-align:center;transition:transform .2s}
  .card:hover{transform:translateY(-2px)}
  .card .num{font-size:36px;font-weight:800;margin-bottom:4px}
  .card .lbl{font-size:12px;text-transform:uppercase;letter-spacing:1px;color:#94a3b8}
  .c-critical{border-color:#dc2626;}.c-critical .num{color:#dc2626}
  .c-high    {border-color:#ea580c;}.c-high     .num{color:#ea580c}
  .c-medium  {border-color:#d97706;}.c-medium   .num{color:#d97706}
  .c-low     {border-color:#2563eb;}.c-low      .num{color:#2563eb}
  .c-info    {border-color:#6b7280;}.c-info     .num{color:#94a3b8}
  .meta-grid{display:grid;grid-template-columns:repeat(3,1fr);gap:16px;margin-bottom:32px}
  .meta-card{background:#1e293b;border:1px solid #334155;border-radius:12px;padding:16px}
  .meta-card h3{font-size:11px;text-transform:uppercase;letter-spacing:1px;color:#64748b;margin-bottom:8px}
  .meta-card p{font-size:15px;font-weight:600;color:#e2e8f0}
  .section-title{font-size:16px;font-weight:700;color:#f1f5f9;margin-bottom:16px;padding-bottom:8px;border-bottom:1px solid #334155}
  table{width:100%;border-collapse:collapse;background:#1e293b;border-radius:12px;overflow:hidden;margin-bottom:32px}
  th{background:#0f172a;padding:12px 16px;text-align:left;font-size:11px;text-transform:uppercase;letter-spacing:1px;color:#64748b;font-weight:600}
  td{padding:12px 16px;border-top:1px solid #334155;vertical-align:top}
  tr:hover td{background:#243147}
  .footer{text-align:center;padding:24px;color:#475569;font-size:12px;border-top:1px solid #334155;margin-top:32px}
  @media(max-width:768px){.grid{grid-template-columns:repeat(3,1fr)}.meta-grid{grid-template-columns:1fr}}
</style>
</head>
<body>
<header>
  <div>
    <h1>🔍 Ultimate Recon Report</h1>
    <p>Target: <strong>${TARGET}</strong> &nbsp;·&nbsp; Generated: $(date '+%Y-%m-%d %H:%M:%S') &nbsp;·&nbsp; Duration: ${duration}</p>
  </div>
  <span class="badge badge-danger">AUTHORIZED USE ONLY</span>
</header>

<div class="container">
  <!-- Summary Cards -->
  <div class="grid">
    <div class="card c-critical"><div class="num">${FINDINGS_CRITICAL}</div><div class="lbl">Critical</div></div>
    <div class="card c-high">    <div class="num">${FINDINGS_HIGH}</div>    <div class="lbl">High</div></div>
    <div class="card c-medium">  <div class="num">${FINDINGS_MEDIUM}</div>  <div class="lbl">Medium</div></div>
    <div class="card c-low">     <div class="num">${FINDINGS_LOW}</div>     <div class="lbl">Low</div></div>
    <div class="card c-info">    <div class="num">${FINDINGS_INFO}</div>    <div class="lbl">Info</div></div>
  </div>

  <!-- Meta Grid -->
  <div class="meta-grid">
    <div class="meta-card"><h3>Open Ports</h3><p>${#OPEN_PORTS[@]} ports</p></div>
    <div class="meta-card"><h3>Subdomains</h3><p>${#SUBDOMAINS[@]} discovered</p></div>
    <div class="meta-card"><h3>IPs Resolved</h3><p>${#IP_LIST[@]} addresses</p></div>
  </div>

  <!-- Findings Table -->
  <div class="section-title">All Findings (${FINDINGS_CRITICAL} Critical · ${FINDINGS_HIGH} High · ${FINDINGS_MEDIUM} Medium · ${FINDINGS_LOW} Low · ${FINDINGS_INFO} Info)</div>
  <table>
    <thead><tr><th>Severity</th><th>Title</th><th>Detail</th><th>Time</th></tr></thead>
    <tbody>
${findings_rows}
    </tbody>
  </table>
</div>

<div class="footer">
  Generated by Ultimate Recon Tool v${VERSION} &nbsp;|&nbsp; For authorized security testing only
</div>
</body>
</html>
HTMLEOF
        success "HTML report: ${html_file}"
    fi
}

# ─────────────────────────────────────────────────────────────────────────────
#  FINAL SUMMARY
# ─────────────────────────────────────────────────────────────────────────────
print_summary() {
    local elapsed=$(( $(date +%s) - START_TIME ))
    local duration; printf -v duration '%02dh %02dm %02ds' \
        $((elapsed/3600)) $(((elapsed%3600)/60)) $((elapsed%60))

    echo ""
    echo -e "${BOLD}${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${BOLD}${WHITE}  RECON COMPLETE — ${TARGET}${NC}"
    echo -e "${BOLD}${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""
    echo -e "  ${BOLD}Duration:${NC}     $duration"
    echo -e "  ${BOLD}Output:${NC}       ${OUTPUT_DIR}/"
    echo ""
    echo -e "  ${BOLD}FINDINGS SUMMARY:${NC}"
    if [[ $FINDINGS_CRITICAL -gt 0 ]]; then echo -e "    ${RED}●  CRITICAL : ${FINDINGS_CRITICAL}${NC}"; fi
    if [[ $FINDINGS_HIGH     -gt 0 ]]; then echo -e "    ${RED}●  HIGH     : ${FINDINGS_HIGH}${NC}"; fi
    if [[ $FINDINGS_MEDIUM   -gt 0 ]]; then echo -e "    ${YELLOW}●  MEDIUM   : ${FINDINGS_MEDIUM}${NC}"; fi
    if [[ $FINDINGS_LOW      -gt 0 ]]; then echo -e "    ${CYAN}●  LOW      : ${FINDINGS_LOW}${NC}"; fi
    echo -e "    ${WHITE}●  INFO     : ${FINDINGS_INFO}${NC}"
    echo ""
    echo -e "  ${BOLD}ARTIFACTS:${NC}"
    echo -e "    ${DIM}Passive recon :${NC}  ${OUTPUT_DIR}/passive/"
    echo -e "    ${DIM}DNS / Subs    :${NC}  ${OUTPUT_DIR}/dns/"
    echo -e "    ${DIM}Port scans    :${NC}  ${OUTPUT_DIR}/ports/"
    echo -e "    ${DIM}Web recon     :${NC}  ${OUTPUT_DIR}/web/"
    echo -e "    ${DIM}Vulns         :${NC}  ${OUTPUT_DIR}/vulns/"
    if [[ "$REPORT_FORMAT" != "json" ]]; then
        echo -e "    ${GREEN}HTML Report   :${NC}  ${OUTPUT_DIR}/reports/report.html"
    fi
    if [[ "$REPORT_FORMAT" != "html" ]]; then
        echo -e "    ${GREEN}JSON Report   :${NC}  ${OUTPUT_DIR}/reports/report.json"
    fi
    echo -e "    ${DIM}Full log      :${NC}  ${OUTPUT_DIR}/recon.log"
    echo ""
    echo -e "${BOLD}${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
}

# ─────────────────────────────────────────────────────────────────────────────
#  MAIN
# ─────────────────────────────────────────────────────────────────────────────
main() {
    print_banner
    parse_args "$@"
    legal_confirm
    setup_output

    log "Starting recon against: ${BOLD}${TARGET}${NC}"
    [[ "$STEALTH_MODE"    == "true" ]] && warn "Stealth mode enabled — scans will be slower"
    [[ "$FULL_PORT_SCAN"  == "true" ]] && warn "Full port scan enabled — scanning all 65535 ports"
    [[ "$SKIP_ACTIVE"     == "true" ]] && warn "Active scanning disabled — passive only"
    [[ "$SKIP_BRUTEFORCE" == "true" ]] && warn "Brute-force disabled"
    [[ "$SKIP_CVE"        == "true" ]] && warn "CVE & exploit lookup disabled"

    check_tools
    phase_passive
    phase_subdomains
    phase_ports
    phase_web
    phase_vulns
    phase_cve
    phase_report
    print_summary
}

main "$@"
