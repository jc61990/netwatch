#!/usr/bin/env bash
# NetWatch — remove a device from all scrape jobs in prometheus.yml
set -euo pipefail

CONFIG="/etc/netwatch/prometheus/prometheus.yml"
[[ $EUID -ne 0 ]] && echo "Run as root: sudo bash remove-device.sh" && exit 1

echo "Current devices in ${CONFIG}:"
grep -P "^\s+- \d+\.\d+\.\d+\.\d+" "$CONFIG" 2>/dev/null \
    | awk '{print $2}' | sort -u | sed 's/^/  /'

echo ""
read -rp "IP to remove: " IP
[[ -z "$IP" ]] && exit 0

python3 - "$CONFIG" "$IP" << 'PYEOF'
import sys, re

config_path, ip = sys.argv[1:]
escaped = re.escape(ip)

with open(config_path) as f:
    content = f.read()

before = content

# Remove target line
content = re.sub(rf"          - {escaped}[^\n]*\n", "", content)

# Remove associated site relabel block
content = re.sub(
    rf"      - source_labels: \[instance\]\n"
    rf"        regex: '{escaped}'[^\n]*\n"
    rf"        target_label: site\n"
    rf"        replacement: '[^\n]*'\n",
    "", content
)

if content == before:
    print(f"  IP {ip} not found in config.")
    sys.exit(1)

with open(config_path, 'w') as f:
    f.write(content)

print(f"Removed: {ip}")
PYEOF

echo "Run: sudo bash /opt/netwatch/reload.sh"
