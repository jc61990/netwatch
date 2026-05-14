#!/usr/bin/env bash
# NetWatch — upgrade Prometheus stack binaries
#
# Usage:
#   sudo bash update.sh                              # upgrade all to versions in this script
#   sudo bash update.sh --snmp 0.27.0               # upgrade SNMP Exporter only
#   sudo bash update.sh --prom 2.53.3 --am 0.27.0   # upgrade Prometheus + Alertmanager
#
# After upgrading, commit the updated VERSION file to git:
#   git add VERSION && git commit -m "chore: upgrade snmp=0.27.0 prom=2.53.3"
set -euo pipefail

[[ $EUID -ne 0 ]] && echo "Run as root: sudo bash update.sh" && exit 1

META="/opt/netwatch/.install_meta"
VERSION_FILE="/opt/netwatch/VERSION"
BIN="/usr/local/bin"

BOLD='\033[1m'; GREEN='\033[0;32m'; CYAN='\033[0;36m'
YELLOW='\033[1;33m'; RED='\033[0;31m'; RESET='\033[0m'
ok()   { echo -e "  ${GREEN}[OK]${RESET}    $*"; }
warn() { echo -e "  ${YELLOW}[WARN]${RESET}  $*"; }
err()  { echo -e "  ${RED}[ERROR]${RESET} $*" >&2; exit 1; }
step() { echo -e "  ${BOLD}→${RESET} $*"; }

# Load installed versions from metadata
[[ -f "$META" ]] && source "$META"

# Fallback pins — keep in sync with install.sh
SNMP_VER="${SNMP_EXPORTER_VERSION:-0.27.0}"
PROM_VER="${PROMETHEUS_VERSION:-2.53.3}"
AM_VER="${ALERTMANAGER_VERSION:-0.27.0}"
ARCH="$(uname -m | sed 's/x86_64/amd64/;s/aarch64/arm64/')"

UPGRADE_SNMP=false
UPGRADE_PROM=false
UPGRADE_AM=false

while [[ $# -gt 0 ]]; do
    case "$1" in
        --snmp) SNMP_VER="$2"; UPGRADE_SNMP=true; shift 2 ;;
        --prom) PROM_VER="$2"; UPGRADE_PROM=true; shift 2 ;;
        --am)   AM_VER="$2";   UPGRADE_AM=true;   shift 2 ;;
        --all)  UPGRADE_SNMP=true; UPGRADE_PROM=true; UPGRADE_AM=true; shift ;;
        --help|-h)
            echo "Usage: sudo bash update.sh [--snmp X.Y.Z] [--prom X.Y.Z] [--am X.Y.Z] [--all]"
            exit 0 ;;
        *) echo "Unknown flag: $1  (try --help)"; exit 1 ;;
    esac
done

# No flags = upgrade all
if ! $UPGRADE_SNMP && ! $UPGRADE_PROM && ! $UPGRADE_AM; then
    UPGRADE_SNMP=true; UPGRADE_PROM=true; UPGRADE_AM=true
fi

echo -e "\n${BOLD}${CYAN}NetWatch — Binary Upgrade${RESET}"
echo -e "  Architecture: ${ARCH}"
$UPGRADE_SNMP && echo -e "  SNMP Exporter  →  ${SNMP_VER}"
$UPGRADE_PROM  && echo -e "  Prometheus     →  ${PROM_VER}"
$UPGRADE_AM    && echo -e "  Alertmanager   →  ${AM_VER}"
echo ""

fetch() {
    local name="$1" url="$2"; shift 2
    echo -e "${CYAN}Fetching ${name}...${RESET}"

    local tmp archive attempt
    tmp=$(mktemp -d)
    archive="${tmp}/archive.tar.gz"
    # shellcheck disable=SC2064
    trap "rm -rf ${tmp}" RETURN

    attempt=0
    while true; do
        attempt=$(( attempt + 1 ))
        step "Attempt ${attempt}/3..."

        if curl -fsSL --retry 2 --retry-delay 3 --connect-timeout 15 \
                --max-time 120 -o "${archive}" "${url}"; then

            local size
            size=$(stat -c%s "${archive}" 2>/dev/null || echo 0)
            if (( size < 1048576 )); then
                warn "Download too small (${size} bytes) — possible 404 or partial download"
                rm -f "${archive}"
                (( attempt >= 3 )) && err "Failed to download ${name} after 3 attempts.\n  URL: ${url}"
                sleep 5; continue
            fi

            if ! gzip -t "${archive}" 2>/dev/null; then
                warn "Downloaded file failed gzip integrity check"
                rm -f "${archive}"
                (( attempt >= 3 )) && err "Corrupt download for ${name} after 3 attempts."
                sleep 5; continue
            fi

            break
        else
            local ec=$?
            warn "curl failed (exit ${ec})"
            rm -f "${archive}"
            (( attempt >= 3 )) && err "Download failed after 3 attempts (curl exit ${ec}).\n  URL: ${url}"
            sleep 5
        fi
    done

    step "Extracting..."
    tar -xzf "${archive}" -C "${tmp}" --strip-components=1 2>/dev/null \
        || tar -xzf "${archive}" -C "${tmp}" 2>/dev/null \
        || err "Extraction failed for ${name}"

    for b in "$@"; do
        local bin_path
        bin_path=$(find "${tmp}" -type f -name "${b}" | head -1)
        [[ -z "${bin_path}" ]] && err "Binary '${b}' not found in ${name} archive"
        install -m 755 "${bin_path}" "${BIN}/${b}"
        ok "${BIN}/${b}"
    done
}

step "Stopping services..."
systemctl stop snmp_exporter prometheus alertmanager 2>/dev/null || true
echo ""

if $UPGRADE_SNMP; then
    fetch "SNMP Exporter v${SNMP_VER}" \
        "https://github.com/prometheus/snmp_exporter/releases/download/v${SNMP_VER}/snmp_exporter-${SNMP_VER}.linux-${ARCH}.tar.gz" \
        snmp_exporter
    echo ""
fi

if $UPGRADE_PROM; then
    fetch "Prometheus v${PROM_VER}" \
        "https://github.com/prometheus/prometheus/releases/download/v${PROM_VER}/prometheus-${PROM_VER}.linux-${ARCH}.tar.gz" \
        prometheus promtool
    echo ""
fi

if $UPGRADE_AM; then
    fetch "Alertmanager v${AM_VER}" \
        "https://github.com/prometheus/alertmanager/releases/download/v${AM_VER}/alertmanager-${AM_VER}.linux-${ARCH}.tar.gz" \
        alertmanager amtool
    echo ""
fi

step "Starting services..."
systemctl daemon-reload
for svc in snmp_exporter prometheus alertmanager; do
    if systemctl start "$svc" 2>/dev/null; then
        ok "$svc started"
    else
        warn "$svc failed to start — check: journalctl -u $svc -n 30"
    fi
done
echo ""

# Update .install_meta
if [[ -f "$META" ]]; then
    $UPGRADE_SNMP && sed -i "s/^SNMP_EXPORTER_VERSION=.*/SNMP_EXPORTER_VERSION=${SNMP_VER}/" "$META"
    $UPGRADE_PROM  && sed -i "s/^PROMETHEUS_VERSION=.*/PROMETHEUS_VERSION=${PROM_VER}/"       "$META"
    $UPGRADE_AM    && sed -i "s/^ALERTMANAGER_VERSION=.*/ALERTMANAGER_VERSION=${AM_VER}/"     "$META"
fi

# Read actual installed versions for components that weren't upgraded
cur_snmp="$SNMP_VER"
cur_prom="$PROM_VER"
cur_am="$AM_VER"
! $UPGRADE_SNMP && cur_snmp="$($BIN/snmp_exporter --version 2>&1 | grep -oP '\d+\.\d+\.\d+' | head -1 || echo "$SNMP_VER")"
! $UPGRADE_PROM  && cur_prom="$($BIN/prometheus --version 2>&1 | grep -oP '\d+\.\d+\.\d+' | head -1 || echo "$PROM_VER")"
! $UPGRADE_AM    && cur_am="$($BIN/alertmanager --version 2>&1 | grep -oP '\d+\.\d+\.\d+' | head -1 || echo "$AM_VER")"

# Write VERSION file
cat > "${VERSION_FILE}" << EOF
# NetWatch component versions
# Updated automatically by update.sh on $(date -u +"%Y-%m-%dT%H:%M:%SZ")
# Commit this file after each upgrade so git history tracks version changes

SNMP_EXPORTER_VERSION="${cur_snmp}"
PROMETHEUS_VERSION="${cur_prom}"
ALERTMANAGER_VERSION="${cur_am}"
GRAFANA_VERSION="$(grafana-server -v 2>/dev/null | awk '{print $2}' || echo 'see: grafana-server -v')"
EOF

ok "VERSION file updated → ${VERSION_FILE}"

# If running from a git repo, remind the user to commit
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if git -C "${SCRIPT_DIR}" rev-parse --git-dir &>/dev/null 2>&1; then
    # Copy updated VERSION back into the repo
    REPO_ROOT="$(git -C "${SCRIPT_DIR}" rev-parse --show-toplevel)"
    cp "${VERSION_FILE}" "${REPO_ROOT}/VERSION"
    echo ""
    echo -e "${YELLOW}  Tip: commit the VERSION file to record this upgrade in git:${RESET}"
    echo -e "  git -C ${REPO_ROOT} add VERSION"
    echo -e "  git -C ${REPO_ROOT} commit -m \"chore: upgrade snmp=${cur_snmp} prom=${cur_prom} am=${cur_am}\""
fi

echo ""
echo -e "${GREEN}${BOLD}Update complete.${RESET}"
