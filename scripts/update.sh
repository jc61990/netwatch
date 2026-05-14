#!/usr/bin/env bash
# NetWatch — upgrade Prometheus stack binaries to new versions
#
# Usage:
#   sudo bash update.sh                              # use versions from .install_meta
#   sudo bash update.sh --snmp 0.27.0               # upgrade SNMP Exporter only
#   sudo bash update.sh --prom 2.52.0 --am 0.28.0   # upgrade Prometheus + Alertmanager
#   sudo bash update.sh --snmp 0.27.0 --prom 2.52.0 --am 0.28.0
set -euo pipefail

[[ $EUID -ne 0 ]] && echo "Run as root: sudo bash update.sh" && exit 1

META="/opt/netwatch/.install_meta"
[[ -f "$META" ]] && source "$META"

# Defaults from metadata or fallback pins
SNMP_VER="${SNMP_EXPORTER_VERSION:-0.26.0}"
PROM_VER="${PROMETHEUS_VERSION:-2.51.2}"
AM_VER="${ALERTMANAGER_VERSION:-0.27.0}"
ARCH="amd64"
BIN="/usr/local/bin"

BOLD='\033[1m'; GREEN='\033[0;32m'; CYAN='\033[0;36m'; YELLOW='\033[1;33m'; RESET='\033[0m'

# ── Parse flags ───────────────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
    case "$1" in
        --snmp) SNMP_VER="$2"; shift 2 ;;
        --prom) PROM_VER="$2"; shift 2 ;;
        --am)   AM_VER="$2";   shift 2 ;;
        --help|-h)
            echo "Usage: sudo bash update.sh [--snmp X.Y.Z] [--prom X.Y.Z] [--am X.Y.Z]"
            exit 0 ;;
        *) echo "Unknown flag: $1"; exit 1 ;;
    esac
done

echo -e "\n${BOLD}${CYAN}NetWatch — Binary Update${RESET}"
echo -e "  SNMP Exporter → ${SNMP_VER}"
echo -e "  Prometheus    → ${PROM_VER}"
echo -e "  Alertmanager  → ${AM_VER}\n"

fetch() {
    local name="$1" url="$2"; shift 2
    echo -e "${CYAN}Fetching ${name}...${RESET}"
    local tmp; tmp=$(mktemp -d)
    wget -q --show-progress -O "${tmp}/archive.tar.gz" "$url"
    tar -xzf "${tmp}/archive.tar.gz" -C "$tmp" --strip-components=1
    for b in "$@"; do
        install -m 755 "${tmp}/${b}" "${BIN}/${b}"
        echo -e "  ${GREEN}[OK]${RESET}  ${BIN}/${b}"
    done
    rm -rf "$tmp"
}

echo "Stopping services..."
systemctl stop snmp_exporter prometheus alertmanager 2>/dev/null || true

fetch "SNMP Exporter v${SNMP_VER}" \
    "https://github.com/prometheus/snmp_exporter/releases/download/v${SNMP_VER}/snmp_exporter-${SNMP_VER}.linux-${ARCH}.tar.gz" \
    snmp_exporter

fetch "Prometheus v${PROM_VER}" \
    "https://github.com/prometheus/prometheus/releases/download/v${PROM_VER}/prometheus-${PROM_VER}.linux-${ARCH}.tar.gz" \
    prometheus promtool

fetch "Alertmanager v${AM_VER}" \
    "https://github.com/prometheus/alertmanager/releases/download/v${AM_VER}/alertmanager-${AM_VER}.linux-${ARCH}.tar.gz" \
    alertmanager amtool

echo -e "\nStarting services..."
systemctl daemon-reload
for svc in snmp_exporter prometheus alertmanager; do
    systemctl start "$svc" && echo -e "  ${GREEN}[OK]${RESET}  ${svc} started" \
        || echo -e "  ${YELLOW}[WARN]${RESET} ${svc} failed to start — check journalctl"
done

# Update metadata
if [[ -f "$META" ]]; then
    sed -i "s/^SNMP_EXPORTER_VERSION=.*/SNMP_EXPORTER_VERSION=${SNMP_VER}/" "$META"
    sed -i "s/^PROMETHEUS_VERSION=.*/PROMETHEUS_VERSION=${PROM_VER}/"       "$META"
    sed -i "s/^ALERTMANAGER_VERSION=.*/ALERTMANAGER_VERSION=${AM_VER}/"     "$META"
fi

echo -e "\n${GREEN}${BOLD}Update complete.${RESET}"
