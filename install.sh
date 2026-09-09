#!/usr/bin/env bash
# =============================================================================
#  install.sh — Universal Installer for Reckon (Ultimate Reconnaissance Tool)
#
#  Usage:
#    # One-liner remote installation:
#    curl -fsSL https://raw.githubusercontent.com/Kishan-Agarwal-28/reckon/main/install.sh | sudo bash
#
#    # Install core dependencies automatically:
#    curl -fsSL https://raw.githubusercontent.com/Kishan-Agarwal-28/reckon/main/install.sh | sudo bash -s -- --deps
#
#    # Install core dependencies + advanced recon tools (subfinder, httpx, nuclei, etc.):
#    curl -fsSL https://raw.githubusercontent.com/Kishan-Agarwal-28/reckon/main/install.sh | sudo bash -s -- --tools
#
#    # Local repository installation:
#    git clone https://github.com/Kishan-Agarwal-28/reckon.git
#    cd reckon && sudo ./install.sh
#
#    # Pass options directly to reckon after installation:
#    curl -fsSL https://raw.githubusercontent.com/Kishan-Agarwal-28/reckon/main/install.sh | sudo bash -s -- -t example.com
#
#    # Uninstall:
#    sudo ./install.sh --uninstall
# =============================================================================

set -euo pipefail

# ── Configuration ─────────────────────────────────────────────────────────────
REPO_USER="${RECKON_USER:-Kishan-Agarwal-28}"
REPO_NAME="${RECKON_REPO:-reckon}"
REPO_BRANCH="${RECKON_BRANCH:-main}"
REPO_RAW="https://raw.githubusercontent.com/${REPO_USER}/${REPO_NAME}/${REPO_BRANCH}"

INSTALL_DIR="${INSTALL_DIR:-/usr/local/bin}"
SCRIPT_NAME="reckon.sh"
ALIAS_NAME="reckon"
INSTALL_PATH="${INSTALL_DIR}/${SCRIPT_NAME}"
ALIAS_PATH="${INSTALL_DIR}/${ALIAS_NAME}"

# ── Color Palette ─────────────────────────────────────────────────────────────
RED=$'\033[0;31m'
GREEN=$'\033[0;32m'
YELLOW=$'\033[1;33m'
BLUE=$'\033[0;34m'
CYAN=$'\033[0;36m'
MAGENTA=$'\033[0;35m'
WHITE=$'\033[1;37m'
BOLD=$'\033[1m'
DIM=$'\033[2m'
RESET=$'\033[0m'

# ── Logging Functions ─────────────────────────────────────────────────────────
info()    { echo -e "${CYAN}[reckon installer]${RESET} $*"; }
success() { echo -e "${GREEN}[reckon installer]${RESET} ${GREEN}✓${RESET} $*"; }
warn()    { echo -e "${YELLOW}[reckon installer]${RESET} ${YELLOW}!${RESET} $*"; }
error()   { echo -e "${RED}[reckon installer]${RESET} ${RED}✗${RESET} $*" >&2; }
die()     { error "$*"; exit 1; }

# ── Banner ────────────────────────────────────────────────────────────────────
print_banner() {
    cat << 'BANNER'
  ____  _____ ____ _  _____  _   _ 
 |  _ \| ____/ ___| |/ / _ \| \ | |
 | |_) |  _|| |   | ' / | | |  \| |
 |  _ <| |__| |___| . \ |_| | |\  |
 |_| \_\_____\____|_|\_\___/|_| \_|
       Installer & Environment Setup
BANNER
}

# ── Help / Usage ──────────────────────────────────────────────────────────────
show_help() {
    cat << EOF
${BOLD}Reckon Installer${RESET} — Setup and dependency management script

${BOLD}USAGE:${RESET}
  sudo ./install.sh [OPTIONS]
  curl -fsSL ${REPO_RAW}/install.sh | sudo bash -s -- [OPTIONS]

${BOLD}INSTALLATION MODES:${RESET}
  (no arguments)       Install reckon and reckon.sh to ${INSTALL_DIR}
  --deps, -d           Install all required system packages via package manager
  --tools, -t          Install system packages + extended reconnaissance tools
  --uninstall, -u      Remove reckon and reckon.sh from system
  -h, --help           Show this help message

${BOLD}PASS-THROUGH EXECUTION:${RESET}
  Any argument starting with '-' that is not an installer flag will be passed
  directly to reckon once installation finishes (e.g., -t example.com -P).

${BOLD}ENVIRONMENT VARIABLES:${RESET}
  INSTALL_DIR          Installation target directory (default: /usr/local/bin)
  RECKON_BRANCH        GitHub branch to download from (default: main)
  RECKON_USER          GitHub user/organization (default: Kishan-Agarwal-28)

EOF
    exit 0
}

# ── Privilege Verification & Elevation ────────────────────────────────────────
check_privileges() {
    if [[ $EUID -ne 0 ]]; then
        if command -v sudo &>/dev/null && [[ -t 0 ]]; then
            warn "Root privileges required. Attempting elevation with sudo..."
            exec sudo -E bash "$0" "$@"
        else
            die "Please run this installer as root or with sudo:\n    sudo ./install.sh\n    or: curl -fsSL ... | sudo bash"
        fi
    fi
}

# ── Detect Operating System and Package Manager ───────────────────────────────
detect_os() {
    OS_TYPE="unknown"
    PKG_MGR="unknown"

    if [[ "$OSTYPE" == "darwin"* ]]; then
        OS_TYPE="macos"
        if command -v brew &>/dev/null; then
            PKG_MGR="brew"
        fi
    elif [[ -f /etc/os-release ]]; then
        # shellcheck disable=SC1091
        . /etc/os-release
        OS_ID="${ID:-unknown}"
        OS_LIKE="${ID_LIKE:-}"

        case "$OS_ID" in
            ubuntu|debian|linuxmint|pop|kali|parrot|raspbian)
                OS_TYPE="debian-family"
                PKG_MGR="apt"
                ;;
            arch|manjaro|endeavouros|blackarch)
                OS_TYPE="arch-family"
                PKG_MGR="pacman"
                ;;
            fedora|rhel|centos|rocky|alma)
                OS_TYPE="redhat-family"
                if command -v dnf &>/dev/null; then
                    PKG_MGR="dnf"
                else
                    PKG_MGR="yum"
                fi
                ;;
            opensuse*|sles*)
                OS_TYPE="suse-family"
                PKG_MGR="zypper"
                ;;
            alpine)
                OS_TYPE="alpine"
                PKG_MGR="apk"
                ;;
            *)
                if [[ "$OS_LIKE" == *"debian"* ]] || [[ "$OS_LIKE" == *"ubuntu"* ]]; then
                    OS_TYPE="debian-family"; PKG_MGR="apt"
                elif [[ "$OS_LIKE" == *"arch"* ]]; then
                    OS_TYPE="arch-family"; PKG_MGR="pacman"
                elif [[ "$OS_LIKE" == *"rhel"* ]] || [[ "$OS_LIKE" == *"fedora"* ]]; then
                    OS_TYPE="redhat-family"; PKG_MGR="dnf"
                else
                    OS_TYPE="generic-linux"
                fi
                ;;
        esac
    else
        OS_TYPE="$(uname -s 2>/dev/null || echo 'unknown')"
    fi
}

# ── Dependency Status Inspector ───────────────────────────────────────────────
CORE_DEPS=(bash curl nmap dig whois openssl python3 jq)
OPTIONAL_DEPS=(subfinder amass assetfinder httpx nuclei whatweb wafw00f nikto gobuster ffuf dnsx searchsploit)

check_all_deps() {
    MISSING_CORE=()
    MISSING_OPTIONAL=()

    for cmd in "${CORE_DEPS[@]}"; do
        if command -v "$cmd" &>/dev/null; then
            :
        else
            MISSING_CORE+=("$cmd")
        fi
    done

    for cmd in "${OPTIONAL_DEPS[@]}"; do
        if command -v "$cmd" &>/dev/null; then
            :
        else
            MISSING_OPTIONAL+=("$cmd")
        fi
    done
}

print_dep_table() {
    echo ""
    echo -e "${BOLD}${WHITE}System Dependency Audit:${RESET}"
    echo -e "${DIM}──────────────────────────────────────────────${RESET}"
    echo -e "${BOLD}Required Core Tools:${RESET}"
    for cmd in "${CORE_DEPS[@]}"; do
        if command -v "$cmd" &>/dev/null; then
            local ver=""
            case "$cmd" in
                bash)    ver=" (${BASH_VERSION%%-*})" ;;
                python3) ver=" ($(python3 --version 2>/dev/null | awk '{print $2}'))" ;;
                nmap)    ver=" ($(nmap --version 2>/dev/null | head -1 | awk '{print $3}'))" ;;
            esac
            echo -e "  ${GREEN}✓${RESET} ${cmd}${DIM}${ver}${RESET}"
        else
            echo -e "  ${RED}✗${RESET} ${cmd} ${RED}(missing - required)${RESET}"
        fi
    done

    echo -e "\n${BOLD}Extended Reconnaissance Tools:${RESET}"
    for cmd in "${OPTIONAL_DEPS[@]}"; do
        if command -v "$cmd" &>/dev/null; then
            echo -e "  ${GREEN}✓${RESET} ${cmd}"
        else
            echo -e "  ${YELLOW}○${RESET} ${cmd} ${DIM}(optional)${RESET}"
        fi
    done
    echo -e "${DIM}──────────────────────────────────────────────${RESET}"
    echo ""
}

# ── Install Core System Dependencies ──────────────────────────────────────────
install_system_dependencies() {
    info "Installing required core dependencies via ${PKG_MGR}..."
    case "$PKG_MGR" in
        apt)
            export DEBIAN_FRONTEND=noninteractive
            apt-get update -qq
            apt-get install -y --no-install-recommends \
                bash curl nmap whois openssl python3 jq coreutils bsdextrautils \
                dnsutils 2>/dev/null || apt-get install -y bind9-dnsutils
            ;;
        pacman)
            pacman -Sy --noconfirm --needed \
                bash curl nmap bind whois openssl python jq coreutils
            ;;
        dnf|yum)
            "$PKG_MGR" install -y \
                bash curl nmap bind-utils whois openssl python3 jq coreutils
            ;;
        zypper)
            zypper install -y \
                bash curl nmap bind-utils whois openssl python3 jq coreutils
            ;;
        apk)
            apk add --no-cache \
                bash curl nmap bind-tools whois openssl python3 jq coreutils
            ;;
        brew)
            brew install bash curl nmap whois openssl python3 jq bind
            ;;
        *)
            warn "Automated package management not supported for this system."
            warn "Please manually install: ${CORE_DEPS[*]}"
            return 1
            ;;
    esac
    success "Core system dependencies installed successfully"
}

# ── Install Extended Recon Tools ──────────────────────────────────────────────
install_extended_tools() {
    info "Installing extended reconnaissance toolsuite..."

    # Install tools available in Linux package repositories
    if [[ "$PKG_MGR" == "apt" ]]; then
        export DEBIAN_FRONTEND=noninteractive
        info "Installing available tools from APT (nikto, whatweb, wafw00f, gobuster, ffuf, exploitdb, seclists)..."
        apt-get install -y --no-install-recommends \
            nikto whatweb wafw00f gobuster ffuf exploitdb seclists 2>/dev/null || true
    elif [[ "$PKG_MGR" == "pacman" ]]; then
        pacman -Sy --noconfirm --needed \
            nikto whatweb wafw00f gobuster ffuf exploitdb 2>/dev/null || true
    fi

    # Install Python-based tools (wafw00f) if still missing
    if ! command -v wafw00f &>/dev/null && command -v pip3 &>/dev/null; then
        info "Installing wafw00f via pip3..."
        pip3 install --quiet --break-system-packages wafw00f 2>/dev/null || pip3 install --quiet wafw00f 2>/dev/null || true
    fi

    # ProjectDiscovery Go tools: subfinder, httpx, nuclei, dnsx
    local pd_tools=(subfinder httpx nuclei dnsx)
    local arch; arch="$(uname -m)"
    local os_arch=""

    case "$arch" in
        x86_64|amd64)  os_arch="amd64" ;;
        aarch64|arm64) os_arch="arm64" ;;
        *)             os_arch="" ;;
    esac

    for tool in "${pd_tools[@]}"; do
        if command -v "$tool" &>/dev/null; then
            success "$tool already installed ($(command -v "$tool"))"
            continue
        fi

        # Option A: If Go is installed, use go install
        if command -v go &>/dev/null; then
            info "Installing ${tool} via go install..."
            GOBIN="${INSTALL_DIR}" go install -v "github.com/projectdiscovery/${tool}/v2/cmd/${tool}@latest" 2>/dev/null || \
            GOBIN="${INSTALL_DIR}" go install -v "github.com/projectdiscovery/${tool}/cmd/${tool}@latest" 2>/dev/null || true
            if command -v "$tool" &>/dev/null; then
                success "Installed ${tool} via Go"
                continue
            fi
        fi

        # Option B: Direct GitHub release binary download for Linux x86_64 / arm64
        if [[ -n "$os_arch" && "$OSTYPE" != "darwin"* ]]; then
            info "Fetching latest binary release for ${tool} (${os_arch})..."
            local pd_tmp; pd_tmp="$(mktemp -d /tmp/pd_install.XXXXXX)"
            local dl_url=""

            # Query GitHub release API for latest archive matching linux_$os_arch.zip
            dl_url="$(curl -s "https://api.github.com/repos/projectdiscovery/${tool}/releases/latest" 2>/dev/null | \
                grep -o "https://[^\"]*${tool}_[0-9.]*_linux_${os_arch}\.zip" | head -1 || true)"

            if [[ -n "$dl_url" ]]; then
                if curl -fsSL -o "${pd_tmp}/${tool}.zip" "$dl_url" 2>/dev/null; then
                    if command -v unzip &>/dev/null; then
                        unzip -q -o "${pd_tmp}/${tool}.zip" -d "$pd_tmp" 2>/dev/null || true
                        if [[ -f "${pd_tmp}/${tool}" ]]; then
                            install -m 755 "${pd_tmp}/${tool}" "${INSTALL_DIR}/${tool}"
                            success "Installed ${tool} to ${INSTALL_DIR}/${tool}"
                        fi
                    fi
                fi
            fi
            rm -rf "$pd_tmp"
        fi
    done

    # Ensure Nuclei templates are downloaded if nuclei was installed
    if command -v nuclei &>/dev/null; then
        info "Updating Nuclei vulnerability templates..."
        nuclei -update-templates -silent 2>/dev/null || true
    fi

    # Assetfinder if missing and Go available
    if ! command -v assetfinder &>/dev/null && command -v go &>/dev/null; then
        info "Installing assetfinder via go install..."
        GOBIN="${INSTALL_DIR}" go install github.com/tomnomnom/assetfinder@latest 2>/dev/null || true
    fi

    success "Extended tools setup finished"
}

# ── Uninstall ─────────────────────────────────────────────────────────────────
uninstall_reckon() {
    info "Uninstalling Reckon from ${INSTALL_DIR}..."
    local removed=false

    if [[ -f "$INSTALL_PATH" || -L "$INSTALL_PATH" ]]; then
        rm -f "$INSTALL_PATH"
        success "Removed ${INSTALL_PATH}"
        removed=true
    fi

    if [[ -f "$ALIAS_PATH" || -L "$ALIAS_PATH" ]]; then
        rm -f "$ALIAS_PATH"
        success "Removed ${ALIAS_PATH}"
        removed=true
    fi

    if [[ "$removed" == "true" ]]; then
        echo ""
        echo -e "${GREEN}${BOLD}Reckon uninstalled successfully.${RESET}"
    else
        warn "No existing Reckon installation found at ${INSTALL_DIR}"
    fi
    exit 0
}

# ── Locate or Download reckon.sh ──────────────────────────────────────────────
fetch_reckon_script() {
    local source_dir=""
    local local_found=false

    # 1. Check if install.sh is running alongside a local reckon.sh
    if [[ -n "${BASH_SOURCE[0]:-}" && -f "${BASH_SOURCE[0]}" ]]; then
        source_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" 2>/dev/null && pwd || echo "")"
        if [[ -n "$source_dir" && -f "${source_dir}/${SCRIPT_NAME}" ]]; then
            info "Found local copy of ${SCRIPT_NAME} at ${source_dir}"
            LOCAL_SOURCE_FILE="${source_dir}/${SCRIPT_NAME}"
            local_found=true
        fi
    fi

    # 2. Check current working directory
    if [[ "$local_found" == "false" && -f "./${SCRIPT_NAME}" ]]; then
        info "Found local copy of ${SCRIPT_NAME} in current directory"
        LOCAL_SOURCE_FILE="./${SCRIPT_NAME}"
        local_found=true
    fi

    if [[ "$local_found" == "true" ]]; then
        TMP_SCRIPT="$(mktemp /tmp/reckon.XXXXXX.sh)"
        cp "$LOCAL_SOURCE_FILE" "$TMP_SCRIPT"
    else
        # 3. Download from GitHub raw URL
        info "Downloading ${SCRIPT_NAME} from ${REPO_RAW}/${SCRIPT_NAME} ..."
        TMP_SCRIPT="$(mktemp /tmp/reckon.XXXXXX.sh)"

        local http_code
        http_code="$(curl -fsSL \
            --retry 3 --retry-delay 2 \
            --max-time 30 \
            -w "%{http_code}" \
            -o "$TMP_SCRIPT" \
            "${REPO_RAW}/${SCRIPT_NAME}" 2>/dev/null || echo "000")"

        if [[ "$http_code" != "200" ]]; then
            die "Download failed (HTTP ${http_code}). Check your network connection or verify repository:\n    ${REPO_RAW}/${SCRIPT_NAME}"
        fi
    fi
}

# ── Verify Script Integrity ───────────────────────────────────────────────────
verify_script() {
    info "Verifying script integrity and syntax..."

    # Check for shebang
    if ! head -n 1 "$TMP_SCRIPT" | grep -qE '^#!\s*/bin/bash|^#!\s*/usr/bin/env\s+bash'; then
        die "Downloaded file is invalid or corrupted (missing bash shebang). Aborting."
    fi

    # Check bash syntax
    if ! bash -n "$TMP_SCRIPT" 2>&1; then
        die "The script contains syntax errors. Aborting installation."
    fi

    # Check Bash version support (requires Bash >= 4 for associative arrays)
    if [[ "${BASH_VERSINFO[0]:-0}" -lt 4 ]]; then
        warn "Reckon requires Bash version 4.0 or newer (detected: ${BASH_VERSION})."
        warn "Please ensure Bash 4+ is used to run reckon."
    fi
}

# ── Deploy Executable and Symlink ──────────────────────────────────────────────
deploy_reckon() {
    info "Installing Reckon to ${INSTALL_DIR} ..."
    mkdir -p "${INSTALL_DIR}"

    # Install primary script
    install -m 755 "$TMP_SCRIPT" "$INSTALL_PATH"
    success "Installed executable: ${INSTALL_PATH}"

    # Create 'reckon' alias symlink
    ln -sf "$INSTALL_PATH" "$ALIAS_PATH"
    success "Created CLI symlink:  ${ALIAS_PATH} -> ${SCRIPT_NAME}"

    # Check PATH presence
    if ! echo ":$PATH:" | grep -q ":${INSTALL_DIR}:"; then
        echo ""
        warn "${INSTALL_DIR} is not currently present in your PATH."
        warn "Add it to your profile by running:"
        warn "  echo 'export PATH=\"\$PATH:${INSTALL_DIR}\"' >> ~/.bashrc && source ~/.bashrc"
    fi
}

# ── Post-Install Summary ──────────────────────────────────────────────────────
print_success_summary() {
    echo ""
    echo -e "${GREEN}${BOLD}══════════════════════════════════════════════════════════════${RESET}"
    echo -e "${GREEN}${BOLD}         Reckon v1.0 Installed Successfully!                ${RESET}"
    echo -e "${GREEN}${BOLD}══════════════════════════════════════════════════════════════${RESET}"
    echo ""
    echo -e "  ${BOLD}Commands Available:${RESET}"
    echo -e "    ${CYAN}reckon${RESET}     (symlinked shorthand)"
    echo -e "    ${CYAN}reckon.sh${RESET}  (full script name)"
    echo ""
    echo -e "  ${BOLD}Quick Start:${RESET}"
    echo -e "    ${BOLD}reckon -h${RESET}                          Show full usage & options"
    echo -e "    ${BOLD}sudo reckon -t example.com${RESET}         Full automated recon scan"
    echo -e "    ${BOLD}reckon -t example.com --skip-active${RESET} Passive-only recon (no port scans)"
    echo -e "    ${BOLD}sudo reckon -t 192.168.1.1 -s${RESET}      Stealth mode scanning"
    echo ""
    echo -e "  ${BOLD}Generated Artifacts:${RESET}"
    echo -e "    ${DIM}• Dark-themed HTML Dashboard (${RESET}report.html${DIM})${RESET}"
    echo -e "    ${DIM}• Structured JSON Report (${RESET}report.json${DIM})${RESET}"
    echo -e "    ${DIM}• Exploits, DNS, Ports, Web raw artifacts in output folder${RESET}"
    echo ""
}

# ── Main Installer Routine ────────────────────────────────────────────────────
main() {
    # Allow help flag to be queried without root privileges
    for arg in "$@"; do
        if [[ "$arg" == "-h" || "$arg" == "--help" ]]; then
            print_banner
            show_help
        fi
    done

    print_banner
    check_privileges "$@"
    detect_os

    # Trap temporary file cleanup
    TMP_SCRIPT=""
    trap '[[ -n "$TMP_SCRIPT" && -f "$TMP_SCRIPT" ]] && rm -f "$TMP_SCRIPT"' EXIT

    # Parse arguments
    INSTALL_DEPS=false
    INSTALL_EXTENDED_TOOLS=false
    PASSTHROUGH_ARGS=()

    while [[ $# -gt 0 ]]; do
        case "$1" in
            -h|--help)
                show_help
                ;;
            -u|--uninstall|--remove)
                uninstall_reckon
                ;;
            -d|--deps|--install-deps)
                INSTALL_DEPS=true
                shift
                ;;
            -t|--tools|--all-tools)
                INSTALL_DEPS=true
                INSTALL_EXTENDED_TOOLS=true
                shift
                ;;
            *)
                # Pass-through arguments to reckon after installation
                PASSTHROUGH_ARGS=("$@")
                break
                ;;
        esac
    done

    # Check dependencies status
    check_all_deps

    # Interactive prompt if dependencies are missing and no explicit flags given
    if [[ "$INSTALL_DEPS" == "false" && ${#MISSING_CORE[@]} -gt 0 ]]; then
        print_dep_table
        if [[ -t 0 ]]; then
            echo -e "${YELLOW}Missing required core tools:${RESET} ${MISSING_CORE[*]}"
            read -r -p "Would you like the installer to install them automatically? [Y/n] " prompt_answer
            case "${prompt_answer,,}" in
                ""|y|yes) INSTALL_DEPS=true ;;
                *) warn "Proceeding without installing core dependencies. Note that Reckon may fail without them." ;;
            esac
        else
            warn "Missing required core tools: ${MISSING_CORE[*]}"
            warn "You can install them automatically using: curl ... | sudo bash -s -- --deps"
        fi
    fi

    # Execute dependency installations if enabled
    if [[ "$INSTALL_DEPS" == "true" ]]; then
        install_system_dependencies
    fi

    if [[ "$INSTALL_EXTENDED_TOOLS" == "true" ]]; then
        install_extended_tools
    fi

    # Display final dependency audit
    check_all_deps
    print_dep_table

    # Fetch and verify script
    fetch_reckon_script
    verify_script

    # Deploy executable
    deploy_reckon
    print_success_summary

    # Run pass-through commands if specified
    if [[ ${#PASSTHROUGH_ARGS[@]} -gt 0 ]]; then
        echo -e "${CYAN}Executing Reckon with provided arguments:${RESET} ${BOLD}${PASSTHROUGH_ARGS[*]}${RESET}\n"
        exec "$INSTALL_PATH" "${PASSTHROUGH_ARGS[@]}"
    fi
}

main "$@"