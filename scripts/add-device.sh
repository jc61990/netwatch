#!/usr/bin/env bash
# NetWatch — add a Cisco device to all scrape jobs in prometheus.yml
set -euo pipefail

CONFIG="/etc/netwatch/prometheus/prometheus.yml"
BOLD='\033[1m'; CYAN='\033[0;36m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RESET='\033[0m'
[[ $EUID -ne 0 ]] && echo "Run as root: sudo bash add-device.sh" && exit 1

echo -e "${BOLD}${CYAN}NetWatch — Add device${RESET}\n"
read -rp "Management IP address: " IP
[[ -z "$IP" ]] && echo "No IP entered." && exit 1
read -rp "Site name (e.g. Chicago):  " SITE
read -rp "Hostname label (e.g. CHI-RTR-01): " HOSTNAME

# Guard against duplicates
if grep -qP "^\s+- ${IP}\b" "$CONFIG" 2>/dev/null; then
    echo -e "${YELLOW}Device ${IP} is already in ${CONFIG}${RESET}"
    exit 0
fi

# Use Python to insert cleanly into all target blocks and relabel sections
python3 - "$CONFIG" "$IP" "$SITE" "$HOSTNAME" << 'PYEOF'
import sys, re

config_path, ip, site, hostname = sys.argv[1:]

with open(config_path) as f:
    content = f.read()

target_line  = f"          - {ip}  # {hostname} [{site}]\n"
relabel_block = (
    f"      - source_labels: [instance]\n"
    f"        regex: '{re.escape(ip)}'\n"
    f"        target_label: site\n"
    f"        replacement: '{site}'\n"
)

# Append target to every "- targets:" block (before the next "    params:" line)
content = re.sub(
    r'(      - targets:\n(?:          - [^\n]+\n)+)',
    lambda m: m.group(1) + target_line,
    content
)

# Append site relabel to every "metric_relabel_configs:" block
content = re.sub(
    r'(    metric_relabel_configs:\n(?:      - source_labels: \[instance\]\n(?:        \S[^\n]*\n){3})*)',
    lambda m: m.group(1) + relabel_block,
    content
)

with open(config_path, 'w') as f:
    f.write(content)

print(f"Added: {ip}  ({hostname})  site='{site}'")
PYEOF

echo -e "\n${GREEN}[OK]${RESET}  Device added to ${CONFIG}"
echo "Run: sudo bash /opt/netwatch/reload.sh"
