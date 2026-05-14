#!/usr/bin/env bash
# =============================================================================
# NetWatch — Cisco IOS Monitoring Stack Installer
# Mode:     Non-interactive — installs binaries, drops placeholder configs
# Supports: Ubuntu 22.04+, Debian 12+, RHEL 9+, Rocky Linux, AlmaLinux
# Stack:    SNMP Exporter + Prometheus + Alertmanager + Grafana (systemd)
#
# Usage:
#   sudo bash install.sh
#
# After install, edit configs in /etc/netwatch/ then run:
#   sudo bash /opt/netwatch/reload.sh
# =============================================================================
set -euo pipefail

# ── Pinned versions ───────────────────────────────────────────────────────────
SNMP_EXPORTER_VERSION="0.27.0"
PROMETHEUS_VERSION="2.53.3"
ALERTMANAGER_VERSION="0.27.0"
# Auto-detect architecture (amd64 or arm64)
ARCH="$(uname -m | sed 's/x86_64/amd64/;s/aarch64/arm64/')"

# ── Paths ─────────────────────────────────────────────────────────────────────
INSTALL_DIR="/opt/netwatch"
CONFIG_DIR="/etc/netwatch"
DATA_DIR="/var/lib/netwatch"
BIN_DIR="/usr/local/bin"
SYSTEMD_DIR="/etc/systemd/system"

# ── Terminal colours ──────────────────────────────────────────────────────────
RED='\033[0;31m'; YELLOW='\033[1;33m'; GREEN='\033[0;32m'
CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'

info()    { echo -e "${CYAN}[INFO]${RESET}  $*"; }
success() { echo -e "${GREEN}[OK]${RESET}    $*"; }
warn()    { echo -e "${YELLOW}[WARN]${RESET}  $*"; }
error()   { echo -e "${RED}[ERROR]${RESET} $*" >&2; exit 1; }
die()     { echo -e "${RED}[ERROR]${RESET} $*" >&2; exit 1; }
header()  { echo -e "\n${BOLD}${CYAN}══ $* ══${RESET}\n"; }
step()    { echo -e "${BOLD}  →${RESET} $*"; }

# ── Root guard ────────────────────────────────────────────────────────────────
[[ $EUID -ne 0 ]] && error "Run as root: sudo bash install.sh"

# ── SSL / proxy options ───────────────────────────────────────────────────────
# If your network uses SSL inspection (corporate proxy with self-signed cert),
# set CURL_CA_BUNDLE to your corporate CA bundle, or pass --insecure to skip
# certificate verification entirely (not recommended for production).
#
#   sudo CURL_CA_BUNDLE=/etc/ssl/certs/corporate-ca.pem bash install.sh
#   sudo bash install.sh --insecure
#
CURL_EXTRA_OPTS=""
ALLOW_INSECURE=false

for arg in "$@"; do
    case "$arg" in
        --insecure|-k) ALLOW_INSECURE=true ;;
    esac
done

# Build CA bundle option — check common corporate CA locations
_detect_ca_bundle() {
    # 1. Explicit env var wins
    if [[ -n "${CURL_CA_BUNDLE:-}" ]]; then
        echo "--cacert ${CURL_CA_BUNDLE}"
        return
    fi
    # 2. Corporate CAs added via update-ca-certificates live here on Ubuntu/Debian
    if [[ -f /etc/ssl/certs/ca-certificates.crt ]]; then
        echo "--cacert /etc/ssl/certs/ca-certificates.crt"
        return
    fi
    # 3. RHEL/Rocky/Alma
    if [[ -f /etc/pki/tls/certs/ca-bundle.crt ]]; then
        echo "--cacert /etc/pki/tls/certs/ca-bundle.crt"
        return
    fi
    # No explicit bundle — let curl use its compiled-in default
    echo ""
}

if $ALLOW_INSECURE; then
    warn "SSL certificate verification DISABLED (--insecure). Use only on trusted networks."
    CURL_EXTRA_OPTS="-k"
else
    CURL_EXTRA_OPTS="$(_detect_ca_bundle)"
    if [[ -n "${CURL_EXTRA_OPTS}" ]]; then
        info "Using CA bundle: ${CURL_EXTRA_OPTS#--cacert }"
    fi
fi

# ─────────────────────────────────────────────────────────────────────────────
# 1. DISTRO DETECTION
# ─────────────────────────────────────────────────────────────────────────────
detect_distro() {
    header "Detecting OS"
    [[ -f /etc/os-release ]] || error "/etc/os-release not found — cannot detect OS."
    source /etc/os-release
    DISTRO_ID="${ID,,}"
    DISTRO_VERSION_ID="${VERSION_ID%%.*}"

    case "$DISTRO_ID" in
        ubuntu|debian)
            PKG_MANAGER="apt"
            PKG_UPDATE="apt-get update -qq"
            PKG_INSTALL="apt-get install -y -qq"
            ;;
        rhel|rocky|almalinux|centos|fedora)
            PKG_MANAGER="dnf"
            PKG_UPDATE="dnf makecache -q"
            PKG_INSTALL="dnf install -y -q"
            ;;
        *)
            error "Unsupported distro: $DISTRO_ID. Supported: Ubuntu, Debian, RHEL, Rocky, AlmaLinux."
            ;;
    esac

    success "Detected: ${PRETTY_NAME} (${PKG_MANAGER})"
}

# ─────────────────────────────────────────────────────────────────────────────
# 2. SYSTEM PREPARATION
# ─────────────────────────────────────────────────────────────────────────────
setup_system() {
    header "System preparation"

    step "Updating package index..."
    $PKG_UPDATE

    step "Installing dependencies..."
    if [[ "$PKG_MANAGER" == "apt" ]]; then
        $PKG_INSTALL curl wget tar gzip adduser net-tools snmp \
            apt-transport-https gnupg2 software-properties-common python3
    else
        $PKG_INSTALL curl wget tar gzip net-tools net-snmp net-snmp-utils python3
    fi

    step "Creating service accounts..."
    for svcuser in prometheus snmp_exporter; do
        if id "$svcuser" &>/dev/null; then
            info "User $svcuser already exists — skipping"
        else
            useradd --no-create-home --shell /bin/false "$svcuser"
            success "Created user: $svcuser"
        fi
    done

    step "Creating directories..."
    local DIRS=(
        "$INSTALL_DIR"
        "${CONFIG_DIR}/prometheus/rules"
        "${CONFIG_DIR}/snmp_exporter"
        "${CONFIG_DIR}/alertmanager"
        "${CONFIG_DIR}/grafana/provisioning/datasources"
        "${CONFIG_DIR}/grafana/provisioning/dashboards"
        "${DATA_DIR}/prometheus"
        "${DATA_DIR}/alertmanager"
    )
    for d in "${DIRS[@]}"; do mkdir -p "$d"; done

    chown -R prometheus:prometheus \
        "${CONFIG_DIR}/prometheus" \
        "${CONFIG_DIR}/alertmanager" \
        "${DATA_DIR}/prometheus" \
        "${DATA_DIR}/alertmanager"

    chown -R snmp_exporter:snmp_exporter "${CONFIG_DIR}/snmp_exporter"

    success "System prepared"
}

# ─────────────────────────────────────────────────────────────────────────────
# 3. BINARY INSTALLATION
# ─────────────────────────────────────────────────────────────────────────────
fetch_release() {
    # fetch_release "Label" "URL" "owner" "bin1" ["bin2" ...]
    local label="$1" url="$2" owner="$3"; shift 3
    local first_bin="$1"

    if [[ -f "${BIN_DIR}/${first_bin}" ]]; then
        info "${label} already installed at ${BIN_DIR}/${first_bin} — skipping"
        info "  Run scripts/update.sh to upgrade to a newer version"
        return
    fi

    step "Downloading ${label}..."
    local tmp archive
    tmp=$(mktemp -d)
    archive="${tmp}/archive.tar.gz"
    # shellcheck disable=SC2064
    trap "rm -rf ${tmp}" RETURN

    # ── Download with up to 3 attempts ────────────────────────────────────────
    local attempt=0
    while true; do
        attempt=$(( attempt + 1 ))
        step "  Attempt ${attempt}/3: ${url}"

        # shellcheck disable=SC2086
        if curl -fsSL ${CURL_EXTRA_OPTS} --connect-timeout 15 \
                --max-time 120 -o "${archive}" "${url}"; then

            # Sanity check: a valid gzip tarball is at least 1 MB
            local size
            size=$(stat -c%s "${archive}" 2>/dev/null || echo 0)
            if (( size < 1048576 )); then
                warn "  Download too small (${size} bytes) — likely a partial download or 404 page"
                rm -f "${archive}"
                if (( attempt >= 3 )); then
                    die "Failed to download ${label} after 3 attempts.\n  URL: ${url}\n  Check the version number and your internet connection."
                fi
                step "  Retrying in 5 seconds..."
                sleep 5
                continue
            fi

            # Verify the archive is a valid gzip before extracting
            if ! gzip -t "${archive}" 2>/dev/null; then
                warn "  Downloaded file is not a valid gzip archive"
                rm -f "${archive}"
                if (( attempt >= 3 )); then
                    die "Corrupt download for ${label} after 3 attempts.\n  URL: ${url}"
                fi
                sleep 5
                continue
            fi

            break  # success
        else
            local curl_exit=$?
            rm -f "${archive}"
            # Exit 60 = SSL certificate verification failed — retrying won't help
            if (( curl_exit == 60 )); then
                die "SSL certificate verification failed downloading ${label}.\n\n  Your network uses SSL inspection with a self-signed / corporate CA.\n  Fix options — pick one:\n\n  1. Add your corporate CA to the system trust store (recommended):\n       sudo cp /path/to/corporate-ca.crt /usr/local/share/ca-certificates/\n       sudo update-ca-certificates\n       sudo bash install.sh\n\n  2. Point curl at your CA bundle directly:\n       sudo CURL_CA_BUNDLE=/path/to/corporate-ca.pem bash install.sh\n\n  3. Disable SSL verification (only on a trusted network):\n       sudo bash install.sh --insecure"
            fi
            warn "  curl failed (exit ${curl_exit})"
            if (( attempt >= 3 )); then
                die "Failed to download ${label} after 3 attempts (curl exit ${curl_exit}).\n  URL: ${url}\n  Check DNS, firewall, and proxy settings."
            fi
            step "  Retrying in 5 seconds..."
            sleep 5
        fi
    done

    # ── Extract ───────────────────────────────────────────────────────────────
    step "  Extracting..."
    if ! tar -xzf "${archive}" -C "${tmp}" --strip-components=1 2>/dev/null; then
        # Some releases nest differently — try without strip
        if ! tar -xzf "${archive}" -C "${tmp}" 2>/dev/null; then
            die "Failed to extract ${label}. Archive may be corrupt."
        fi
    fi

    # ── Install binaries ──────────────────────────────────────────────────────
    for bin in "$@"; do
        # Find the binary anywhere under tmp (handles variable nesting)
        local bin_path
        bin_path=$(find "${tmp}" -type f -name "${bin}" | head -1)
        if [[ -z "${bin_path}" ]]; then
            die "Binary '${bin}' not found in ${label} archive. The release layout may have changed."
        fi
        install -o root -g root -m 755 "${bin_path}" "${BIN_DIR}/${bin}"
        # Fix ownership after install
        if id "${owner}" &>/dev/null; then
            chown "${owner}:${owner}" "${BIN_DIR}/${bin}"
        fi
        step "  Installed: ${BIN_DIR}/${bin}"
    done

    success "${label} installed"
}

install_binaries() {
    header "Installing Prometheus stack binaries"

    fetch_release "SNMP Exporter v${SNMP_EXPORTER_VERSION}" \
        "https://github.com/prometheus/snmp_exporter/releases/download/v${SNMP_EXPORTER_VERSION}/snmp_exporter-${SNMP_EXPORTER_VERSION}.linux-${ARCH}.tar.gz" \
        "snmp_exporter" \
        "snmp_exporter"

    fetch_release "Prometheus v${PROMETHEUS_VERSION}" \
        "https://github.com/prometheus/prometheus/releases/download/v${PROMETHEUS_VERSION}/prometheus-${PROMETHEUS_VERSION}.linux-${ARCH}.tar.gz" \
        "prometheus" \
        "prometheus" "promtool"

    fetch_release "Alertmanager v${ALERTMANAGER_VERSION}" \
        "https://github.com/prometheus/alertmanager/releases/download/v${ALERTMANAGER_VERSION}/alertmanager-${ALERTMANAGER_VERSION}.linux-${ARCH}.tar.gz" \
        "prometheus" \
        "alertmanager" "amtool"
}

install_grafana() {
    header "Installing Grafana"

    if command -v grafana-server &>/dev/null; then
        info "Grafana already installed — skipping"
        return
    fi

    if [[ "$PKG_MANAGER" == "apt" ]]; then
        step "Adding Grafana APT repository..."
        wget -q -O /usr/share/keyrings/grafana.key https://apt.grafana.com/gpg.key
        echo "deb [signed-by=/usr/share/keyrings/grafana.key] https://apt.grafana.com stable main" \
            > /etc/apt/sources.list.d/grafana.list
        apt-get update -qq
        apt-get install -y -qq grafana
    else
        step "Adding Grafana DNF repository..."
        cat > /etc/yum.repos.d/grafana.repo << 'EOF'
[grafana]
name=grafana
baseurl=https://rpm.grafana.com
repo_gpgcheck=1
enabled=1
gpgcheck=1
gpgkey=https://rpm.grafana.com/gpg.key
EOF
        dnf install -y -q grafana
    fi

    success "Grafana installed"
}

# ─────────────────────────────────────────────────────────────────────────────
# 4. PLACEHOLDER CONFIG FILES
# ─────────────────────────────────────────────────────────────────────────────
write_configs() {
    header "Writing placeholder config files"
    info "All files contain clearly marked CHANGEME placeholders."
    info "Edit them, then run: sudo bash ${INSTALL_DIR}/reload.sh"

    write_snmp_yml
    write_prometheus_yml
    write_alert_rules
    write_alertmanager_yml
    write_grafana_provisioning
}

write_snmp_yml() {
    local dest="${CONFIG_DIR}/snmp_exporter/snmp.yml"

    # Don't overwrite an existing config
    if [[ -f "$dest" ]]; then
        info "snmp.yml already exists — not overwriting (backup at ${dest}.bak)"
        cp "$dest" "${dest}.bak"
        return
    fi

    cat > "$dest" << 'EOF'
# =============================================================================
# NetWatch — SNMP Exporter config
# Edit this file, then run: sudo bash /opt/netwatch/reload.sh
# =============================================================================

auths:

  # ── SNMPv2c ────────────────────────────────────────────────────────────────
  # Delete this block if you are using SNMPv3 only.
  v2_netwatch:
    version: 2
    community: CHANGEME_community_string   # e.g. netwatch_ro

  # ── SNMPv3 (recommended for production) ───────────────────────────────────
  # Delete this block if you are using SNMPv2c only.
  v3_netwatch:
    version: 3
    username: CHANGEME_username            # e.g. netwatch
    security_level: authPriv
    auth_protocol: SHA
    auth_password: CHANGEME_auth_password
    priv_protocol: AES
    priv_password: CHANGEME_priv_password

# =============================================================================
# Modules — do not edit OIDs unless you know what you're doing
# =============================================================================
modules:

  # Interfaces: ifTable + ifXTable (64-bit counters, alias, speed)
  cisco_interfaces:
    walk:
      - 1.3.6.1.2.1.2.2.1        # ifTable
      - 1.3.6.1.2.1.31.1.1.1     # ifXTable
    lookups:
      - source_indexes: [ifIndex]
        lookup: 1.3.6.1.2.1.2.2.1.2      # ifDescr label
      - source_indexes: [ifIndex]
        lookup: 1.3.6.1.2.1.31.1.1.1.18  # ifAlias label
    overrides:
      ifOperStatus:   { type: gauge }
      ifAdminStatus:  { type: gauge }
      ifHCInOctets:   { type: counter }
      ifHCOutOctets:  { type: counter }
      ifInErrors:     { type: counter }
      ifOutErrors:    { type: counter }
      ifInDiscards:   { type: counter }
      ifOutDiscards:  { type: counter }

  # CPU (cpmCPUTotal) + memory (ciscoMemoryPool) + uptime
  cisco_resources:
    walk:
      - 1.3.6.1.2.1.1.3              # sysUpTime
      - 1.3.6.1.4.1.9.9.109.1.1.1.1  # cpmCPUTotal
      - 1.3.6.1.4.1.9.9.48.1.1.1     # ciscoMemoryPool
    lookups:
      - source_indexes: [ciscoMemoryPoolType]
        lookup: 1.3.6.1.4.1.9.9.48.1.1.1.2  # memory pool name label

  # Tunnel interfaces (subset of ifTable, filtered in Grafana by ifDescr~Tunnel.*)
  cisco_tunnels:
    walk:
      - 1.3.6.1.2.1.2.2.1.8       # ifOperStatus
      - 1.3.6.1.2.1.31.1.1.1.6    # ifHCInOctets
      - 1.3.6.1.2.1.31.1.1.1.10   # ifHCOutOctets
      - 1.3.6.1.2.1.31.1.1.1.18   # ifAlias
    lookups:
      - source_indexes: [ifIndex]
        lookup: 1.3.6.1.2.1.2.2.1.2  # ifDescr
    overrides:
      ifOperStatus:   { type: gauge }
      ifHCInOctets:   { type: counter }
      ifHCOutOctets:  { type: counter }

  # EIGRP neighbor table (CISCO-EIGRP-MIB)
  # Requires IOS 12.4(6)T+ or IOS-XE 3.x+
  # Verify: show snmp mib | include EIGRP
  cisco_eigrp:
    walk:
      - 1.3.6.1.4.1.9.9.449.1.4.1  # cEigrpPeerTable
    lookups:
      - source_indexes: [cEigrpVpnId, cEigrpAsNumber, cEigrpHandle]
        lookup: 1.3.6.1.4.1.9.9.449.1.4.1.1.1  # cEigrpPeerAddr label
    overrides:
      cEigrpPeerUpTime: { type: gauge }
      cEigrpRetrans:    { type: counter }
      cEigrpRetries:    { type: counter }

  # IP routing table — used for default route monitoring
  cisco_routing:
    walk:
      - 1.3.6.1.2.1.4.24.4.1  # ipCidrRouteTable
    overrides:
      ipCidrRouteType:  { type: gauge }
      ipCidrRouteProto: { type: gauge }
      ipCidrRouteAge:   { type: gauge }
EOF

    chmod 640 "$dest"
    chown snmp_exporter:snmp_exporter "$dest"
    success "snmp.yml written → ${dest}"
}

write_prometheus_yml() {
    local dest="${CONFIG_DIR}/prometheus/prometheus.yml"

    if [[ -f "$dest" ]]; then
        info "prometheus.yml already exists — not overwriting"
        cp "$dest" "${dest}.bak"
        return
    fi

    cat > "$dest" << EOF
# =============================================================================
# NetWatch — Prometheus config
# Edit the targets lists below to add your Cisco devices.
# After editing, run: sudo bash ${INSTALL_DIR}/reload.sh
# =============================================================================

global:
  scrape_interval:     60s
  evaluation_interval: 60s
  external_labels:
    monitor: 'netwatch'

alerting:
  alertmanagers:
    - static_configs:
        - targets: ['localhost:9093']

rule_files:
  - ${CONFIG_DIR}/prometheus/rules/*.yml

# =============================================================================
# Scrape jobs
# Each job targets a specific SNMP module.
# Add device IPs under each "targets:" list.
# Add a matching entry under "metric_relabel_configs" to set the site label.
# =============================================================================

scrape_configs:

  # ── Interface counters, status, errors, drops ─────────────────────────────
  - job_name: cisco_interfaces
    scrape_interval: 60s
    static_configs:
      - targets:
          - CHANGEME_device_ip_1   # e.g. 10.0.0.1
          - CHANGEME_device_ip_2   # e.g. 10.1.0.1
    params:
      module: [cisco_interfaces]
      auth:   [v2_netwatch]        # change to v3_netwatch if using SNMPv3
    relabel_configs:
      - source_labels: [__address__]
        target_label: __param_target
      - source_labels: [__param_target]
        target_label: instance
      - target_label: __address__
        replacement: localhost:9116
    metric_relabel_configs:
      # Add one block per device to assign a human-readable site label
      - source_labels: [instance]
        regex: 'CHANGEME_device_ip_1'
        target_label: site
        replacement: 'CHANGEME_site_name_1'   # e.g. New York
      - source_labels: [instance]
        regex: 'CHANGEME_device_ip_2'
        target_label: site
        replacement: 'CHANGEME_site_name_2'   # e.g. Chicago

  # ── CPU and memory ────────────────────────────────────────────────────────
  - job_name: cisco_resources
    scrape_interval: 60s
    static_configs:
      - targets:
          - CHANGEME_device_ip_1
          - CHANGEME_device_ip_2
    params:
      module: [cisco_resources]
      auth:   [v2_netwatch]
    relabel_configs:
      - source_labels: [__address__]
        target_label: __param_target
      - source_labels: [__param_target]
        target_label: instance
      - target_label: __address__
        replacement: localhost:9116
    metric_relabel_configs:
      - source_labels: [instance]
        regex: 'CHANGEME_device_ip_1'
        target_label: site
        replacement: 'CHANGEME_site_name_1'
      - source_labels: [instance]
        regex: 'CHANGEME_device_ip_2'
        target_label: site
        replacement: 'CHANGEME_site_name_2'

  # ── Tunnel / VPN status (polled more frequently) ──────────────────────────
  - job_name: cisco_tunnels
    scrape_interval: 30s
    static_configs:
      - targets:
          - CHANGEME_device_ip_1
          - CHANGEME_device_ip_2
    params:
      module: [cisco_tunnels]
      auth:   [v2_netwatch]
    relabel_configs:
      - source_labels: [__address__]
        target_label: __param_target
      - source_labels: [__param_target]
        target_label: instance
      - target_label: __address__
        replacement: localhost:9116
    metric_relabel_configs:
      - source_labels: [instance]
        regex: 'CHANGEME_device_ip_1'
        target_label: site
        replacement: 'CHANGEME_site_name_1'
      - source_labels: [instance]
        regex: 'CHANGEME_device_ip_2'
        target_label: site
        replacement: 'CHANGEME_site_name_2'

  # ── EIGRP neighbor table ──────────────────────────────────────────────────
  - job_name: cisco_eigrp
    scrape_interval: 60s
    static_configs:
      - targets:
          - CHANGEME_device_ip_1
          - CHANGEME_device_ip_2
    params:
      module: [cisco_eigrp]
      auth:   [v2_netwatch]
    relabel_configs:
      - source_labels: [__address__]
        target_label: __param_target
      - source_labels: [__param_target]
        target_label: instance
      - target_label: __address__
        replacement: localhost:9116
    metric_relabel_configs:
      - source_labels: [instance]
        regex: 'CHANGEME_device_ip_1'
        target_label: site
        replacement: 'CHANGEME_site_name_1'
      - source_labels: [instance]
        regex: 'CHANGEME_device_ip_2'
        target_label: site
        replacement: 'CHANGEME_site_name_2'

  # ── Routing table / default route (slow poll) ─────────────────────────────
  - job_name: cisco_routing
    scrape_interval: 120s
    static_configs:
      - targets:
          - CHANGEME_device_ip_1
          - CHANGEME_device_ip_2
    params:
      module: [cisco_routing]
      auth:   [v2_netwatch]
    relabel_configs:
      - source_labels: [__address__]
        target_label: __param_target
      - source_labels: [__param_target]
        target_label: instance
      - target_label: __address__
        replacement: localhost:9116
    metric_relabel_configs:
      - source_labels: [instance]
        regex: 'CHANGEME_device_ip_1'
        target_label: site
        replacement: 'CHANGEME_site_name_1'
      - source_labels: [instance]
        regex: 'CHANGEME_device_ip_2'
        target_label: site
        replacement: 'CHANGEME_site_name_2'
EOF

    chown prometheus:prometheus "$dest"
    chmod 640 "$dest"
    success "prometheus.yml written → ${dest}"
}

write_alert_rules() {
    local dest="${CONFIG_DIR}/prometheus/rules/cisco_alerts.yml"

    if [[ -f "$dest" ]]; then
        info "cisco_alerts.yml already exists — not overwriting"
        cp "$dest" "${dest}.bak"
        return
    fi

    cat > "$dest" << 'EOF'
# =============================================================================
# NetWatch — Cisco IOS Alert Rules
# Adjust threshold values to match your environment, then reload.
# =============================================================================

groups:

  # ── Physical interface and tunnel state ────────────────────────────────────
  - name: cisco_link_state
    interval: 30s
    rules:

      - alert: PhysicalInterfaceDown
        expr: ifOperStatus{ifDescr!~'Loopback.*|Null.*|Tunnel.*|Vlan.*'} == 2
        for: 2m
        labels:
          severity: critical
          category: link
        annotations:
          summary: 'Physical interface down — {{ $labels.instance }}'
          description: >
            Interface {{ $labels.ifDescr }} ({{ $labels.ifAlias }}) is operationally DOWN
            on {{ $labels.instance }} [site: {{ $labels.site }}].
            Check cable, SFP, and connected device.

      - alert: TunnelDown
        expr: ifOperStatus{ifDescr=~'Tunnel.*'} == 2
        for: 2m
        labels:
          severity: critical
          category: tunnel
        annotations:
          summary: 'Tunnel down — {{ $labels.ifDescr }} on {{ $labels.instance }}'
          description: >
            Tunnel {{ $labels.ifDescr }} ({{ $labels.ifAlias }}) is DOWN on
            {{ $labels.instance }} [site: {{ $labels.site }}].
            Check underlay reachability, crypto map, and peer configuration.

      - alert: HighInterfaceUtilization
        # Threshold: 85% inbound utilisation for 5 minutes
        # Adjust the > 0.85 value to suit your environment
        expr: (rate(ifHCInOctets[5m]) * 8) / (ifHighSpeed * 1e6) > 0.85
        for: 5m
        labels:
          severity: warning
          category: bandwidth
        annotations:
          summary: 'High utilization — {{ $labels.ifDescr }} at {{ $labels.instance }}'
          description: >
            {{ $labels.ifDescr }} inbound utilisation is {{ $value | humanizePercentage }}
            (threshold 85%) on {{ $labels.instance }}.

  # ── Interface errors and drops ─────────────────────────────────────────────
  - name: cisco_errors
    interval: 60s
    rules:

      - alert: InterfaceInputErrors
        # Threshold: > 5 input errors/sec sustained for 5 minutes
        expr: rate(ifInErrors[5m]) > 5
        for: 5m
        labels:
          severity: warning
          category: errors
        annotations:
          summary: 'Input errors — {{ $labels.ifDescr }} at {{ $labels.instance }}'
          description: >
            {{ $labels.ifDescr }} has {{ $value | humanize }} input errors/sec on
            {{ $labels.instance }}. Common causes: duplex mismatch, bad cable/SFP.

      - alert: InterfaceInputDrops
        # Threshold: > 10 inbound discards/sec for 5 minutes
        expr: rate(ifInDiscards[5m]) > 10
        for: 5m
        labels:
          severity: warning
          category: errors
        annotations:
          summary: 'Input drops — {{ $labels.ifDescr }} at {{ $labels.instance }}'
          description: >
            {{ $labels.ifDescr }} is discarding {{ $value | humanize }} inbound packets/sec
            on {{ $labels.instance }}. Check input queue depth and QoS policy.

      - alert: InterfaceOutputDrops
        # Threshold: > 10 outbound discards/sec for 5 minutes
        expr: rate(ifOutDiscards[5m]) > 10
        for: 5m
        labels:
          severity: warning
          category: errors
        annotations:
          summary: 'Output drops — {{ $labels.ifDescr }} at {{ $labels.instance }}'
          description: >
            {{ $labels.ifDescr }} is discarding {{ $value | humanize }} outbound packets/sec
            on {{ $labels.instance }}. Check output queue depth and QoS policy.

  # ── CPU and memory ─────────────────────────────────────────────────────────
  - name: cisco_resources
    interval: 60s
    rules:

      - alert: HighCPU
        # Warning threshold: 70% — adjust to match your device baseline
        expr: cpmCPUTotal5minRev > 70
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: 'High CPU — {{ $labels.instance }}'
          description: >
            CPU 5-min avg is {{ $value }}% on {{ $labels.instance }} (threshold 70%).
            Run: show processes cpu sorted

      - alert: CriticalCPU
        # Critical threshold: 90% — device may be unable to process routing traffic
        expr: cpmCPUTotal5minRev > 90
        for: 2m
        labels:
          severity: critical
        annotations:
          summary: 'Critical CPU — {{ $labels.instance }}'
          description: >
            CPU 5-min avg is {{ $value }}% on {{ $labels.instance }}.
            Device may drop routing protocol packets. Immediate investigation required.

      - alert: HighMemory
        # Warning threshold: 80% memory pool utilisation
        expr: ciscoMemoryPoolUsed / (ciscoMemoryPoolUsed + ciscoMemoryPoolFree) > 0.80
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: 'High memory — {{ $labels.instance }}'
          description: >
            Memory pool {{ $labels.ciscoMemoryPoolName }} is
            {{ $value | humanizePercentage }} used on {{ $labels.instance }}.
            Run: show processes memory sorted

  # ── EIGRP neighbor state ───────────────────────────────────────────────────
  - name: cisco_eigrp
    interval: 30s
    rules:

      - alert: EIGRPNeighborLost
        # Fires when an EIGRP neighbor entry disappears from the MIB table
        expr: absent_over_time(cEigrpPeerUpTime[5m])
        for: 2m
        labels:
          severity: critical
          category: routing
        annotations:
          summary: 'EIGRP neighbor lost — {{ $labels.instance }}'
          description: >
            An EIGRP neighbor entry disappeared from {{ $labels.instance }}.
            Check interface state, hello timers, K-values, and AS number match.

      - alert: EIGRPNeighborFlapping
        # Fires when peer uptime resets more than 3 times in 15 minutes
        expr: changes(cEigrpPeerUpTime[15m]) > 3
        for: 0m
        labels:
          severity: warning
          category: routing
        annotations:
          summary: 'EIGRP neighbor flapping — {{ $labels.instance }}'
          description: >
            EIGRP peer {{ $labels.cEigrpPeerAddr }} has reset {{ $value }} times
            in 15 minutes on {{ $labels.instance }}.
            Check interface stability and hold timers.

  # ── Default route monitoring ───────────────────────────────────────────────
  - name: cisco_routing
    interval: 120s
    rules:

      - alert: DefaultRouteGone
        # Fires when 0.0.0.0/0 is absent from the routing table
        expr: absent_over_time(
            ipCidrRouteType{ipCidrRouteDest='0.0.0.0',ipCidrRoutePfxLen='0'}[5m]
          )
        for: 2m
        labels:
          severity: critical
          category: routing
        annotations:
          summary: 'Default route missing — {{ $labels.instance }}'
          description: >
            No 0.0.0.0/0 entry in the routing table on {{ $labels.instance }}.
            Device may have lost WAN or internet connectivity.

      - alert: DefaultRouteNextHopChanged
        # Fires when the next-hop IP for 0.0.0.0/0 changes
        # This catches silent WAN failovers as well as misconfigurations
        expr: changes(
            ipCidrRouteNextHop{ipCidrRouteDest='0.0.0.0',ipCidrRoutePfxLen='0'}[10m]
          ) > 0
        for: 0m
        labels:
          severity: warning
          category: routing
        annotations:
          summary: 'Default route next-hop changed — {{ $labels.instance }}'
          description: >
            The next-hop for 0.0.0.0/0 changed on {{ $labels.instance }}.
            This may be an intentional failover or indicate a routing problem.
EOF

    chown prometheus:prometheus "$dest"
    chmod 640 "$dest"
    success "cisco_alerts.yml written → ${dest}"
}

write_alertmanager_yml() {
    local dest="${CONFIG_DIR}/alertmanager/alertmanager.yml"

    if [[ -f "$dest" ]]; then
        info "alertmanager.yml already exists — not overwriting"
        cp "$dest" "${dest}.bak"
        return
    fi

    cat > "$dest" << 'EOF'
# =============================================================================
# NetWatch — Alertmanager config (email / SMTP)
# Fill in all CHANGEME_ values, then run: sudo bash /opt/netwatch/reload.sh
# =============================================================================

global:
  resolve_timeout: 5m

  # ── SMTP settings ──────────────────────────────────────────────────────────
  smtp_smarthost:     'CHANGEME_smtp_host:587'    # e.g. smtp.office365.com:587
  smtp_from:          'CHANGEME_from@example.com'
  smtp_auth_username: 'CHANGEME_smtp_username'
  smtp_auth_password: 'CHANGEME_smtp_password'
  smtp_require_tls:   true

# ── Routing ────────────────────────────────────────────────────────────────────
# Critical alerts and key categories go to a dedicated NOC address.
# All other alerts go to the general network alerts mailbox.
route:
  group_by: ['alertname', 'instance', 'site', 'category']
  group_wait:      30s      # wait 30s before sending first notification
  group_interval:  5m       # wait 5m before sending updated notifications
  repeat_interval: 4h       # re-notify every 4h if still firing
  receiver: email_warnings
  routes:
    - match:
        severity: critical
      receiver: email_critical
      continue: false

    # Tunnels and routing issues always escalate regardless of severity label
    - match:
        category: tunnel
      receiver: email_critical
      continue: false

    - match:
        category: routing
      receiver: email_critical
      continue: false

# ── Receivers ──────────────────────────────────────────────────────────────────
receivers:

  # General warnings — high CPU, high memory, utilisation, errors
  - name: email_warnings
    email_configs:
      - to: 'CHANGEME_warnings@example.com'   # e.g. network-alerts@yourcompany.com
        subject: '[{{ .Status | toUpper }}] {{ .GroupLabels.alertname }} — {{ .GroupLabels.site }}'
        html: |
          <h3>{{ .GroupLabels.alertname }}</h3>
          <p><strong>Site:</strong> {{ .GroupLabels.site }}<br>
          <strong>Status:</strong> {{ .Status | toUpper }}</p>
          <table border="1" cellpadding="4" cellspacing="0">
          <tr><th>Alert</th><th>Instance</th><th>Details</th><th>Since</th></tr>
          {{ range .Alerts }}
          <tr>
            <td>{{ .Labels.alertname }}</td>
            <td>{{ .Labels.instance }}</td>
            <td>{{ .Annotations.description }}</td>
            <td>{{ .StartsAt.Format "2006-01-02 15:04:05 UTC" }}</td>
          </tr>
          {{ end }}
          </table>
        send_resolved: true

  # Critical alerts — interface/tunnel down, EIGRP lost, default route gone
  - name: email_critical
    email_configs:
      - to: 'CHANGEME_critical@example.com'   # e.g. noc@yourcompany.com
        subject: '[CRITICAL] {{ .GroupLabels.alertname }} — {{ .GroupLabels.instance }}'
        html: |
          <h2 style="color:red">CRITICAL ALERT</h2>
          <h3>{{ .GroupLabels.alertname }}</h3>
          <p><strong>Device:</strong> {{ .GroupLabels.instance }}<br>
          <strong>Site:</strong> {{ .GroupLabels.site }}<br>
          <strong>Category:</strong> {{ .GroupLabels.category }}</p>
          <hr>
          {{ range .Alerts }}
          <p><strong>{{ .Annotations.summary }}</strong><br>
          {{ .Annotations.description }}<br>
          <em>Since: {{ .StartsAt.Format "2006-01-02 15:04:05 UTC" }}</em></p>
          {{ end }}
          <p><a href="http://CHANGEME_grafana_host:3000">Open Grafana</a></p>
        send_resolved: true

# ── Inhibition rules ───────────────────────────────────────────────────────────
inhibit_rules:
  # Suppress interface/tunnel alerts when the whole device is unreachable
  - source_match:
      alertname: 'DeviceUnreachable'
    target_match_re:
      alertname: '.*'
    equal: ['instance']
EOF

    chown prometheus:prometheus "$dest"
    chmod 640 "$dest"
    success "alertmanager.yml written → ${dest}"
}

write_grafana_provisioning() {
    # Prometheus datasource
    cat > "${CONFIG_DIR}/grafana/provisioning/datasources/prometheus.yml" << 'EOF'
apiVersion: 1
datasources:
  - name: Prometheus
    type: prometheus
    access: proxy
    url: http://localhost:9090
    isDefault: true
    editable: true
    jsonData:
      timeInterval: "60s"
EOF

    # Dashboard provider
    cat > "${CONFIG_DIR}/grafana/provisioning/dashboards/provider.yml" << 'EOF'
apiVersion: 1
providers:
  - name: netwatch
    folder: NetWatch
    type: file
    disableDeletion: false
    updateIntervalSeconds: 30
    options:
      path: /etc/grafana/provisioning/dashboards
EOF

    # Sync into Grafana's own provisioning directory
    local gprov="/etc/grafana/provisioning"
    if [[ -d "$gprov" ]]; then
        cp "${CONFIG_DIR}/grafana/provisioning/datasources/prometheus.yml" \
           "${gprov}/datasources/netwatch-prometheus.yml"
        cp "${CONFIG_DIR}/grafana/provisioning/dashboards/provider.yml" \
           "${gprov}/dashboards/netwatch-provider.yml"
        chown -R grafana:grafana "${gprov}" 2>/dev/null || true
    fi

    success "Grafana provisioning written"
}

# ─────────────────────────────────────────────────────────────────────────────
# 5. SYSTEMD UNITS
# ─────────────────────────────────────────────────────────────────────────────
write_systemd_units() {
    header "Writing systemd service units"

    cat > "${SYSTEMD_DIR}/snmp_exporter.service" << EOF
[Unit]
Description=Prometheus SNMP Exporter
Documentation=https://github.com/prometheus/snmp_exporter
After=network.target

[Service]
User=snmp_exporter
Group=snmp_exporter
Type=simple
Restart=on-failure
RestartSec=5
ExecStart=${BIN_DIR}/snmp_exporter \\
  --config.file=${CONFIG_DIR}/snmp_exporter/snmp.yml \\
  --web.listen-address=127.0.0.1:9116
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

    cat > "${SYSTEMD_DIR}/prometheus.service" << EOF
[Unit]
Description=Prometheus
Documentation=https://prometheus.io/docs
After=network.target

[Service]
User=prometheus
Group=prometheus
Type=simple
Restart=on-failure
RestartSec=5
ExecStart=${BIN_DIR}/prometheus \\
  --config.file=${CONFIG_DIR}/prometheus/prometheus.yml \\
  --storage.tsdb.path=${DATA_DIR}/prometheus \\
  --storage.tsdb.retention.time=90d \\
  --web.listen-address=127.0.0.1:9090 \\
  --web.enable-lifecycle \\
  --log.level=warn
ExecReload=/bin/kill -HUP \$MAINPID
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

    cat > "${SYSTEMD_DIR}/alertmanager.service" << EOF
[Unit]
Description=Prometheus Alertmanager
Documentation=https://prometheus.io/docs/alerting/alertmanager/
After=network.target

[Service]
User=prometheus
Group=prometheus
Type=simple
Restart=on-failure
RestartSec=5
ExecStart=${BIN_DIR}/alertmanager \\
  --config.file=${CONFIG_DIR}/alertmanager/alertmanager.yml \\
  --storage.path=${DATA_DIR}/alertmanager \\
  --web.listen-address=127.0.0.1:9093 \\
  --log.level=warn
ExecReload=/bin/kill -HUP \$MAINPID
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

    success "Systemd units written"
}

# ─────────────────────────────────────────────────────────────────────────────
# 6. ENABLE SERVICES
# ─────────────────────────────────────────────────────────────────────────────
enable_services() {
    header "Enabling and starting services"
    systemctl daemon-reload

    for svc in snmp_exporter prometheus alertmanager grafana-server; do
        if systemctl is-enabled --quiet "$svc" 2>/dev/null; then
            info "${svc} already enabled"
        else
            systemctl enable "$svc" 2>/dev/null || true
        fi
        systemctl start "$svc" 2>/dev/null || systemctl restart "$svc" 2>/dev/null || true
        sleep 1
        if systemctl is-active --quiet "$svc"; then
            success "${svc} running"
        else
            warn "${svc} did not start cleanly — check: journalctl -u ${svc} -n 30"
            warn "  (This is expected if configs still have CHANGEME placeholders)"
        fi
    done
}

# ─────────────────────────────────────────────────────────────────────────────
# 7. FIREWALL
# ─────────────────────────────────────────────────────────────────────────────
configure_firewall() {
    # Prometheus and Alertmanager are bound to 127.0.0.1 — only Grafana needs a hole
    if command -v ufw &>/dev/null && ufw status 2>/dev/null | grep -q "^Status: active"; then
        ufw allow 3000/tcp comment "Grafana NetWatch" >/dev/null 2>&1 || true
        info "ufw: opened 3000/tcp for Grafana"
    elif command -v firewall-cmd &>/dev/null && firewall-cmd --state &>/dev/null; then
        firewall-cmd --permanent --add-port=3000/tcp >/dev/null 2>&1 || true
        firewall-cmd --reload >/dev/null 2>&1 || true
        info "firewalld: opened 3000/tcp for Grafana"
    fi
}

# ─────────────────────────────────────────────────────────────────────────────
# 8. HELPER SCRIPTS + METADATA
# ─────────────────────────────────────────────────────────────────────────────
install_helpers() {
    header "Installing helper scripts"
    local src_dir
    src_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/scripts"

    if [[ -d "$src_dir" ]]; then
        cp -r "${src_dir}/." "${INSTALL_DIR}/"
        chmod +x "${INSTALL_DIR}"/*.sh 2>/dev/null || true
        success "Helper scripts copied to ${INSTALL_DIR}/"
    else
        warn "scripts/ directory not found next to install.sh — skipping helper copy"
    fi

    cat > "${INSTALL_DIR}/.install_meta" << EOF
INSTALLED_AT=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
DISTRO_ID=${DISTRO_ID}
SNMP_EXPORTER_VERSION=${SNMP_EXPORTER_VERSION}
PROMETHEUS_VERSION=${PROMETHEUS_VERSION}
ALERTMANAGER_VERSION=${ALERTMANAGER_VERSION}
CONFIG_DIR=${CONFIG_DIR}
DATA_DIR=${DATA_DIR}
EOF

    # ── Write VERSION file so git history tracks component upgrades ───────────
    # Copy back to the source directory if install.sh is being run from the repo
    local repo_dir
    repo_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    local version_file="${INSTALL_DIR}/VERSION"

    cat > "${version_file}" << EOF
# NetWatch component versions
# Updated automatically by install.sh and update.sh on $(date -u +"%Y-%m-%dT%H:%M:%SZ")
# Commit this file after each upgrade so git history tracks version changes

SNMP_EXPORTER_VERSION="${SNMP_EXPORTER_VERSION}"
PROMETHEUS_VERSION="${PROMETHEUS_VERSION}"
ALERTMANAGER_VERSION="${ALERTMANAGER_VERSION}"
GRAFANA_VERSION="$(grafana-server -v 2>/dev/null | awk '{print $2}' || echo 'see: grafana-server -v')"
EOF

    # If running from the repo, keep the repo copy in sync too
    if [[ -f "${repo_dir}/VERSION" ]]; then
        cp "${version_file}" "${repo_dir}/VERSION"
        info "VERSION file updated at ${repo_dir}/VERSION — commit this to track the upgrade"
    fi
    success "VERSION file written → ${version_file}"
}

# ─────────────────────────────────────────────────────────────────────────────
# 9. SUMMARY
# ─────────────────────────────────────────────────────────────────────────────
print_summary() {
    local host_ip
    host_ip=$(hostname -I 2>/dev/null | awk '{print $1}' || echo "localhost")

    echo ""
    echo -e "${BOLD}${GREEN}╔══════════════════════════════════════════════════════════════╗${RESET}"
    echo -e "${BOLD}${GREEN}║            NetWatch installation complete!                   ║${RESET}"
    echo -e "${BOLD}${GREEN}╚══════════════════════════════════════════════════════════════╝${RESET}"
    echo ""
    echo -e "${BOLD}Next steps — edit these config files:${RESET}"
    echo ""
    echo -e "  ${CYAN}1. SNMP credentials${RESET}"
    echo -e "     ${CONFIG_DIR}/snmp_exporter/snmp.yml"
    echo -e "     → Replace CHANGEME_community_string (v2c) or v3 credentials"
    echo ""
    echo -e "  ${CYAN}2. Device IPs and site names${RESET}"
    echo -e "     ${CONFIG_DIR}/prometheus/prometheus.yml"
    echo -e "     → Replace every CHANGEME_device_ip_* and CHANGEME_site_name_*"
    echo ""
    echo -e "  ${CYAN}3. SMTP / email alerts${RESET}"
    echo -e "     ${CONFIG_DIR}/alertmanager/alertmanager.yml"
    echo -e "     → Replace CHANGEME_smtp_host, credentials, and recipient addresses"
    echo ""
    echo -e "  ${CYAN}4. Grafana link in critical emails${RESET}"
    echo -e "     ${CONFIG_DIR}/alertmanager/alertmanager.yml"
    echo -e "     → Replace CHANGEME_grafana_host with ${host_ip}"
    echo ""
    echo -e "${BOLD}Then reload:${RESET}"
    echo -e "     ${CYAN}sudo bash ${INSTALL_DIR}/reload.sh${RESET}"
    echo ""
    echo -e "${BOLD}Grafana:${RESET}  http://${host_ip}:3000  (admin / admin — change on first login)"
    echo ""
    echo -e "${BOLD}Helper scripts (in ${INSTALL_DIR}/):${RESET}"
    echo -e "     reload.sh        — validate configs and hot-reload all services"
    echo -e "     add-device.sh    — add a device to all scrape jobs"
    echo -e "     remove-device.sh — remove a device by IP"
    echo -e "     verify.sh        — check services, ports, SNMP, and Prometheus targets"
    echo -e "     update.sh        — upgrade binaries (--snmp/--prom/--am flags)"
    echo ""
    echo -e "${BOLD}Logs:${RESET}"
    echo -e "     journalctl -fu prometheus"
    echo -e "     journalctl -fu snmp_exporter"
    echo -e "     journalctl -fu alertmanager"
    echo -e "     journalctl -fu grafana-server"
    echo ""
    echo -e "${YELLOW}NOTE:${RESET} Services may show warnings in logs until CHANGEME placeholders are replaced."
    echo ""
}

# ─────────────────────────────────────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────────────────────────────────────
main() {
    clear
    echo -e "${BOLD}${CYAN}"
    echo "  ███╗   ██╗███████╗████████╗██╗    ██╗ █████╗ ████████╗ ██████╗██╗  ██╗"
    echo "  ████╗  ██║██╔════╝╚══██╔══╝██║    ██║██╔══██╗╚══██╔══╝██╔════╝██║  ██║"
    echo "  ██╔██╗ ██║█████╗     ██║   ██║ █╗ ██║███████║   ██║   ██║     ███████║"
    echo "  ██║╚██╗██║██╔══╝     ██║   ██║███╗██║██╔══██║   ██║   ██║     ██╔══██║"
    echo "  ██║ ╚████║███████╗   ██║   ╚███╔███╔╝██║  ██║   ██║   ╚██████╗██║  ██║"
    echo "  ╚═╝  ╚═══╝╚══════╝   ╚═╝    ╚══╝╚══╝ ╚═╝  ╚═╝   ╚═╝    ╚═════╝╚═╝  ╚═╝"
    echo -e "${RESET}"
    echo -e "${BOLD}  Cisco IOS Monitoring Stack — Non-Interactive Installer${RESET}"
    echo -e "  SNMP Exporter ${SNMP_EXPORTER_VERSION}  |  Prometheus ${PROMETHEUS_VERSION}  |  Alertmanager ${ALERTMANAGER_VERSION}  |  Grafana"
    echo -e "  Supports: Ubuntu 22.04+ · Debian 12+ · RHEL 9+ · Rocky · AlmaLinux"
    echo ""

    detect_distro
    setup_system
    install_binaries
    install_grafana
    write_configs
    write_systemd_units
    configure_firewall
    enable_services
    install_helpers
    print_summary
}

main "$@"
