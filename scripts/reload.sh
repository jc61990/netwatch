#!/usr/bin/env bash
# NetWatch — validate configs and hot-reload all services (no restart needed)
set -euo pipefail

BOLD='\033[1m'; GREEN='\033[0;32m'; RED='\033[0;31m'; YELLOW='\033[1;33m'; RESET='\033[0m'
ok()   { echo -e "  ${GREEN}[OK]${RESET}  $*"; }
fail() { echo -e "  ${RED}[FAIL]${RESET} $*"; exit 1; }
warn() { echo -e "  ${YELLOW}[WARN]${RESET} $*"; }

echo -e "\n${BOLD}NetWatch — Config reload${RESET}\n"

# Check for unfilled placeholders
echo "Checking for CHANGEME placeholders..."
for f in /etc/netwatch/prometheus/prometheus.yml \
          /etc/netwatch/snmp_exporter/snmp.yml \
          /etc/netwatch/alertmanager/alertmanager.yml; do
    if grep -q "CHANGEME" "$f" 2>/dev/null; then
        warn "${f} still contains CHANGEME placeholders — services may not work correctly"
    fi
done

echo "Validating Prometheus config..."
/usr/local/bin/promtool check config /etc/netwatch/prometheus/prometheus.yml \
    && ok "prometheus.yml valid" || fail "prometheus.yml has errors — not reloading"

echo "Validating alert rules..."
/usr/local/bin/promtool check rules /etc/netwatch/prometheus/rules/cisco_alerts.yml \
    && ok "cisco_alerts.yml valid" || fail "Alert rules have errors — not reloading"

echo "Validating Alertmanager config..."
/usr/local/bin/amtool check-config /etc/netwatch/alertmanager/alertmanager.yml \
    && ok "alertmanager.yml valid" || fail "alertmanager.yml has errors — not reloading"

echo "Reloading services..."
curl -sf -X POST http://127.0.0.1:9090/-/reload \
    && ok "Prometheus reloaded" || warn "Prometheus reload failed — is it running? (journalctl -u prometheus)"
curl -sf -X POST http://127.0.0.1:9093/-/reload \
    && ok "Alertmanager reloaded" || warn "Alertmanager reload failed"
systemctl restart snmp_exporter \
    && ok "snmp_exporter restarted" || warn "snmp_exporter restart failed"

echo ""
echo -e "${GREEN}Done.${RESET} All configs reloaded."
