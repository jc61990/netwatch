#!/usr/bin/env bash
# NetWatch — verify services, ports, SNMP connectivity, and Prometheus targets
set -euo pipefail

BOLD='\033[1m'; CYAN='\033[0;36m'; GREEN='\033[0;32m'; RED='\033[0;31m'; YELLOW='\033[1;33m'; RESET='\033[0m'
ok()   { echo -e "  ${GREEN}[OK]${RESET}    $*"; }
fail() { echo -e "  ${RED}[FAIL]${RESET}  $*"; FAILURES=$((FAILURES+1)); }
warn() { echo -e "  ${YELLOW}[WARN]${RESET}  $*"; }
FAILURES=0

echo -e "\n${BOLD}${CYAN}NetWatch — System Verification${RESET}\n"

# ── Services ──────────────────────────────────────────────────────────────────
echo -e "${BOLD}Services${RESET}"
for svc in snmp_exporter prometheus alertmanager grafana-server; do
    systemctl is-active --quiet "$svc" \
        && ok "${svc}" \
        || fail "${svc} NOT running  →  journalctl -u ${svc} -n 30"
done

# ── Ports ─────────────────────────────────────────────────────────────────────
echo -e "\n${BOLD}Listening ports${RESET}"
declare -A PORT_LABELS=([9116]="SNMP Exporter" [9090]="Prometheus" [9093]="Alertmanager" [3000]="Grafana")
for port in 9116 9090 9093 3000; do
    ss -tlnp 2>/dev/null | grep -q ":${port}" \
        && ok "${PORT_LABELS[$port]} (:${port})" \
        || fail "${PORT_LABELS[$port]} not listening on :${port}"
done

# ── Placeholder check ─────────────────────────────────────────────────────────
echo -e "\n${BOLD}Config placeholder check${RESET}"
CHANGEME_FOUND=0
for f in /etc/netwatch/prometheus/prometheus.yml \
          /etc/netwatch/snmp_exporter/snmp.yml \
          /etc/netwatch/alertmanager/alertmanager.yml; do
    count=$(grep -c "CHANGEME" "$f" 2>/dev/null || true)
    if [[ "$count" -gt 0 ]]; then
        warn "${f}: ${count} CHANGEME placeholder(s) remaining"
        CHANGEME_FOUND=1
    else
        ok "${f##*/} — no placeholders"
    fi
done

# ── Prometheus target health ───────────────────────────────────────────────────
echo -e "\n${BOLD}Prometheus targets${RESET}"
if curl -sf http://127.0.0.1:9090/api/v1/targets > /tmp/nw_targets.json 2>/dev/null; then
    python3 << 'PYEOF'
import json, sys

with open('/tmp/nw_targets.json') as f:
    data = json.load(f)

targets = data.get('data', {}).get('activeTargets', [])
if not targets:
    print("  No targets configured yet — edit prometheus.yml and reload")
    sys.exit(0)

seen = set()
up = down = 0
for t in sorted(targets, key=lambda x: (x['labels'].get('job',''), x['labels'].get('instance',''))):
    key = (t['labels'].get('job','?'), t['labels'].get('instance','?'))
    if key in seen:
        continue
    seen.add(key)
    job, inst, health = key[0], key[1], t['health']
    err = t.get('lastError', '')
    if health == 'up':
        up += 1
        print(f"  \033[0;32m[OK]\033[0m    {job:<25} {inst}{' — last scrape error: '+err if err else ''}")
    else:
        down += 1
        print(f"  \033[0;31m[FAIL]\033[0m  {job:<25} {inst}{(' — '+err) if err else ''}")

print(f"\n  Summary: {up} up, {down} down")
if down > 0:
    sys.exit(1)
PYEOF
else
    warn "Cannot reach Prometheus API at localhost:9090"
fi

# ── SNMP connectivity ──────────────────────────────────────────────────────────
echo -e "\n${BOLD}SNMP connectivity${RESET}"
DEVICES=$(grep -P "^\s+- \d+\.\d+\.\d+\.\d+" /etc/netwatch/prometheus/prometheus.yml 2>/dev/null \
    | awk '{print $2}' | sort -u)

if [[ -z "$DEVICES" ]]; then
    warn "No device IPs found in prometheus.yml — add devices first"
else
    COMMUNITY=$(awk '/v2_netwatch:/{found=1} found && /community:/{print $2; exit}' \
        /etc/netwatch/snmp_exporter/snmp.yml 2>/dev/null || echo "")

    for ip in $DEVICES; do
        if [[ "$ip" == *"CHANGEME"* ]]; then
            warn "Skipping placeholder IP: ${ip}"
            continue
        fi
        if command -v snmpget &>/dev/null && [[ -n "$COMMUNITY" ]] && [[ "$COMMUNITY" != *"CHANGEME"* ]]; then
            if snmpget -v2c -c "$COMMUNITY" -t 3 -r 1 "$ip" 1.3.6.1.2.1.1.1.0 &>/dev/null; then
                SYSNAME=$(snmpget -v2c -c "$COMMUNITY" -t 3 -r 1 -Ov "$ip" 1.3.6.1.2.1.1.5.0 2>/dev/null | tr -d '"' | awk '{print $NF}' || echo "unknown")
                ok "${ip}  SNMP OK  (sysName: ${SYSNAME})"
            else
                fail "${ip}  SNMP unreachable — check ACL, community string, UDP/161 routing"
            fi
        else
            # Fall back to hitting the SNMP Exporter HTTP API
            HTTP=$(curl -sf -o /dev/null -w "%{http_code}" \
                "http://127.0.0.1:9116/snmp?target=${ip}&module=cisco_resources&auth=v2_netwatch" 2>/dev/null || echo "000")
            [[ "$HTTP" == "200" ]] \
                && ok "${ip}  reachable via SNMP Exporter (HTTP ${HTTP})" \
                || fail "${ip}  SNMP Exporter returned HTTP ${HTTP}"
        fi
    done
fi

echo ""
if [[ "$FAILURES" -gt 0 ]]; then
    echo -e "${RED}${BOLD}${FAILURES} check(s) failed.${RESET}"
    exit 1
else
    echo -e "${GREEN}${BOLD}All checks passed.${RESET}"
fi
