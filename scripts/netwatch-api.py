#!/usr/bin/env python3
"""
NetWatch Admin API
Lightweight Flask server that serves the admin UI and handles config read/write.

Endpoints:
  GET  /api/config           — read full config state
  POST /api/devices          — save device list → prometheus.yml
  POST /api/snmp             — save SNMP creds  → snmp.yml
  POST /api/thresholds       — save thresholds  → cisco_alerts.yml
  POST /api/email            — save SMTP config → alertmanager.yml
  POST /api/reload           — run reload.sh
  POST /api/test-snmp        — test SNMP connectivity to a device IP
  POST /api/test-email       — send a test alert email

Usage:
  sudo python3 netwatch-api.py          (runs on 0.0.0.0:9199 by default)
  sudo python3 netwatch-api.py --port 9199 --host 127.0.0.1

Install as systemd service:
  sudo cp netwatch-api.py /opt/netwatch/
  sudo systemctl enable --now netwatch-api
"""

import argparse
import json
import logging
import os
import re
import shutil
import smtplib
import subprocess
import sys
import threading
from datetime import datetime
from email.mime.text import MIMEText
from functools import wraps
from pathlib import Path

# ── Optional Flask import with helpful error ──────────────────────────────────
try:
    from flask import Flask, jsonify, request, send_from_directory
    from flask_cors import CORS
except ImportError:
    print("ERROR: Flask not installed.")
    print("       Run: pip3 install flask flask-cors")
    sys.exit(1)

# ── Config ────────────────────────────────────────────────────────────────────
CONFIG_DIR    = Path(os.environ.get("NETWATCH_CONFIG_DIR", "/etc/netwatch"))
INSTALL_DIR   = Path(os.environ.get("NETWATCH_INSTALL_DIR", "/opt/netwatch"))
UI_STATE_FILE = CONFIG_DIR / "netwatch-ui.json"
RELOAD_SCRIPT = INSTALL_DIR / "reload.sh"

PROMETHEUS_YML   = CONFIG_DIR / "prometheus" / "prometheus.yml"
SNMP_YML         = CONFIG_DIR / "snmp_exporter" / "snmp.yml"
ALERTS_YML       = CONFIG_DIR / "prometheus" / "rules" / "cisco_alerts.yml"
ALERTMANAGER_YML = CONFIG_DIR / "alertmanager" / "alertmanager.yml"

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)
log = logging.getLogger("netwatch-api")

app = Flask(__name__, static_folder=str(INSTALL_DIR))
CORS(app)

_reload_lock = threading.Lock()

# ── Helpers ───────────────────────────────────────────────────────────────────

def read_ui_state() -> dict:
    """Load persisted UI state, merging defaults for any missing keys."""
    defaults = {
        "devices": [],
        "snmp": {
            "version": "2",
            "community": "",
            "v3_username": "",
            "v3_auth_protocol": "SHA",
            "v3_auth_password": "",
            "v3_priv_protocol": "AES",
            "v3_priv_password": "",
        },
        "thresholds": {
            "cpu_warn": 70,
            "cpu_crit": 90,
            "mem_warn": 80,
            "util_warn": 85,
            "error_rate": 5,
            "drop_rate": 10,
        },
        "email": {
            "smtp_host": "",
            "smtp_port": 587,
            "smtp_from": "",
            "smtp_username": "",
            "smtp_password": "",
            "smtp_tls": True,
            "to_warnings": "",
            "to_critical": "",
            "grafana_url": "",
        },
    }
    if UI_STATE_FILE.exists():
        try:
            with open(UI_STATE_FILE) as f:
                saved = json.load(f)
            # Deep merge: saved values override defaults
            for key in defaults:
                if key in saved:
                    if isinstance(defaults[key], dict):
                        defaults[key].update(saved[key])
                    else:
                        defaults[key] = saved[key]
        except Exception as e:
            log.warning("Could not read UI state: %s", e)
    return defaults


def save_ui_state(state: dict):
    UI_STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
    tmp = UI_STATE_FILE.with_suffix(".tmp")
    with open(tmp, "w") as f:
        json.dump(state, f, indent=2)
    tmp.replace(UI_STATE_FILE)


def backup(path: Path):
    if path.exists():
        bak = path.with_suffix(path.suffix + f".bak.{datetime.utcnow().strftime('%Y%m%dT%H%M%S')}")
        shutil.copy2(path, bak)


def api_error(message: str, status: int = 400):
    return jsonify({"ok": False, "error": message}), status


def api_ok(message: str = "ok", **kwargs):
    return jsonify({"ok": True, "message": message, **kwargs})


# ── Config writers ────────────────────────────────────────────────────────────

def write_prometheus_yml(devices: list, snmp: dict, thresholds: dict):
    """Regenerate prometheus.yml from device list and SNMP auth ref."""
    backup(PROMETHEUS_YML)

    auth_ref = "v3_netwatch" if snmp.get("version") == "3" else "v2_netwatch"

    targets_block = ""
    relabels_block = ""
    for d in devices:
        ip   = d.get("ip", "").strip()
        site = d.get("site", "").strip()
        host = d.get("hostname", "").strip()
        if not ip:
            continue
        targets_block  += f"          - {ip}  # {host} [{site}]\n"
        relabels_block += (
            f"      - source_labels: [instance]\n"
            f"        regex: '{re.escape(ip)}'\n"
            f"        target_label: site\n"
            f"        replacement: '{site}'\n"
        )

    if not targets_block:
        targets_block  = "          # No devices configured yet\n"
        relabels_block = "      # No site labels configured yet\n"

    jobs = [
        ("cisco_interfaces", "60s"),
        ("cisco_resources",  "60s"),
        ("cisco_tunnels",    "30s"),
        ("cisco_eigrp",      "60s"),
        ("cisco_routing",    "120s"),
    ]

    job_blocks = ""
    for module, interval in jobs:
        job_blocks += f"""
  - job_name: {module}
    scrape_interval: {interval}
    static_configs:
      - targets:
{targets_block}    params:
      module: [{module}]
      auth:   [{auth_ref}]
    relabel_configs:
      - source_labels: [__address__]
        target_label: __param_target
      - source_labels: [__param_target]
        target_label: instance
      - target_label: __address__
        replacement: localhost:9116
    metric_relabel_configs:
{relabels_block}"""

    content = f"""# NetWatch prometheus.yml
# Generated by NetWatch Admin UI on {datetime.utcnow().isoformat()}Z
# Do not edit manually — use the admin UI or add-device.sh

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
  - {CONFIG_DIR}/prometheus/rules/*.yml

scrape_configs:
{job_blocks}
"""
    PROMETHEUS_YML.parent.mkdir(parents=True, exist_ok=True)
    PROMETHEUS_YML.write_text(content)
    try:
        os.chown(PROMETHEUS_YML, _uid("prometheus"), _gid("prometheus"))
        PROMETHEUS_YML.chmod(0o640)
    except Exception:
        pass


def write_snmp_yml(snmp: dict):
    backup(SNMP_YML)

    if snmp.get("version") == "3":
        auth_block = f"""  v3_netwatch:
    version: 3
    username: {snmp.get('v3_username', 'netwatch')}
    security_level: authPriv
    auth_protocol: {snmp.get('v3_auth_protocol', 'SHA')}
    auth_password: {snmp.get('v3_auth_password', '')}
    priv_protocol: {snmp.get('v3_priv_protocol', 'AES')}
    priv_password: {snmp.get('v3_priv_password', '')}"""
    else:
        auth_block = f"""  v2_netwatch:
    version: 2
    community: {snmp.get('community', '')}"""

    content = f"""# NetWatch snmp.yml
# Generated by NetWatch Admin UI on {datetime.utcnow().isoformat()}Z

auths:
{auth_block}

modules:

  cisco_interfaces:
    walk: [1.3.6.1.2.1.2.2.1, 1.3.6.1.2.1.31.1.1.1]
    lookups:
      - source_indexes: [ifIndex]
        lookup: 1.3.6.1.2.1.2.2.1.2
      - source_indexes: [ifIndex]
        lookup: 1.3.6.1.2.1.31.1.1.1.18
    overrides:
      ifOperStatus:   {{type: gauge}}
      ifAdminStatus:  {{type: gauge}}
      ifHCInOctets:   {{type: counter}}
      ifHCOutOctets:  {{type: counter}}
      ifInErrors:     {{type: counter}}
      ifOutErrors:    {{type: counter}}
      ifInDiscards:   {{type: counter}}
      ifOutDiscards:  {{type: counter}}

  cisco_resources:
    walk: [1.3.6.1.2.1.1.3, 1.3.6.1.4.1.9.9.109.1.1.1.1, 1.3.6.1.4.1.9.9.48.1.1.1]
    lookups:
      - source_indexes: [ciscoMemoryPoolType]
        lookup: 1.3.6.1.4.1.9.9.48.1.1.1.2

  cisco_tunnels:
    walk: [1.3.6.1.2.1.2.2.1.8, 1.3.6.1.2.1.31.1.1.1.6, 1.3.6.1.2.1.31.1.1.1.10, 1.3.6.1.2.1.31.1.1.1.18]
    lookups:
      - source_indexes: [ifIndex]
        lookup: 1.3.6.1.2.1.2.2.1.2
    overrides:
      ifOperStatus:   {{type: gauge}}
      ifHCInOctets:   {{type: counter}}
      ifHCOutOctets:  {{type: counter}}

  cisco_eigrp:
    walk: [1.3.6.1.4.1.9.9.449.1.4.1]
    lookups:
      - source_indexes: [cEigrpVpnId, cEigrpAsNumber, cEigrpHandle]
        lookup: 1.3.6.1.4.1.9.9.449.1.4.1.1.1
    overrides:
      cEigrpPeerUpTime: {{type: gauge}}
      cEigrpRetrans:    {{type: counter}}
      cEigrpRetries:    {{type: counter}}

  cisco_routing:
    walk: [1.3.6.1.2.1.4.24.4.1]
    overrides:
      ipCidrRouteType:  {{type: gauge}}
      ipCidrRouteProto: {{type: gauge}}
      ipCidrRouteAge:   {{type: gauge}}
"""
    SNMP_YML.parent.mkdir(parents=True, exist_ok=True)
    SNMP_YML.write_text(content)
    try:
        import pwd, grp
        uid = pwd.getpwnam("snmp_exporter").pw_uid
        gid = grp.getgrnam("snmp_exporter").gr_gid
        os.chown(SNMP_YML, uid, gid)
        SNMP_YML.chmod(0o640)
    except Exception:
        pass


def write_alert_rules(thresholds: dict):
    backup(ALERTS_YML)

    cpu_warn  = thresholds.get("cpu_warn",  70)
    cpu_crit  = thresholds.get("cpu_crit",  90)
    mem_warn  = thresholds.get("mem_warn",  80)
    util_warn = thresholds.get("util_warn", 85)
    err_rate  = thresholds.get("error_rate", 5)
    drop_rate = thresholds.get("drop_rate", 10)

    content = f"""# NetWatch cisco_alerts.yml
# Generated by NetWatch Admin UI on {datetime.utcnow().isoformat()}Z
# CPU warn={cpu_warn}%  crit={cpu_crit}%  MEM warn={mem_warn}%  UTIL warn={util_warn}%

groups:

  - name: cisco_link_state
    interval: 30s
    rules:

      - alert: PhysicalInterfaceDown
        expr: ifOperStatus{{ifDescr!~'Loopback.*|Null.*|Tunnel.*|Vlan.*'}} == 2
        for: 2m
        labels: {{severity: critical, category: link}}
        annotations:
          summary: 'Physical interface down — {{{{ $labels.instance }}}}'
          description: '{{{{ $labels.ifDescr }}}} ({{{{ $labels.ifAlias }}}}) is DOWN on {{{{ $labels.instance }}}} [{{{{ $labels.site }}}}]'

      - alert: TunnelDown
        expr: ifOperStatus{{ifDescr=~'Tunnel.*'}} == 2
        for: 2m
        labels: {{severity: critical, category: tunnel}}
        annotations:
          summary: 'Tunnel down — {{{{ $labels.ifDescr }}}} on {{{{ $labels.instance }}}}'
          description: '{{{{ $labels.ifDescr }}}} ({{{{ $labels.ifAlias }}}}) DOWN on {{{{ $labels.instance }}}} [{{{{ $labels.site }}}}]'

      - alert: HighInterfaceUtilization
        expr: (rate(ifHCInOctets[5m]) * 8) / (ifHighSpeed * 1e6) > {util_warn / 100}
        for: 5m
        labels: {{severity: warning, category: bandwidth}}
        annotations:
          summary: 'High utilization — {{{{ $labels.ifDescr }}}} at {{{{ $labels.instance }}}}'
          description: '{{{{ $labels.ifDescr }}}} inbound utilization {{{{ $value | humanizePercentage }}}} (threshold {util_warn}%) on {{{{ $labels.instance }}}}'

  - name: cisco_errors
    interval: 60s
    rules:

      - alert: InterfaceInputErrors
        expr: rate(ifInErrors[5m]) > {err_rate}
        for: 5m
        labels: {{severity: warning, category: errors}}
        annotations:
          summary: 'Input errors — {{{{ $labels.ifDescr }}}} at {{{{ $labels.instance }}}}'
          description: '{{{{ $labels.ifDescr }}}} has {{{{ $value | humanize }}}} input errors/sec on {{{{ $labels.instance }}}}'

      - alert: InterfaceInputDrops
        expr: rate(ifInDiscards[5m]) > {drop_rate}
        for: 5m
        labels: {{severity: warning, category: errors}}
        annotations:
          summary: 'Input drops — {{{{ $labels.ifDescr }}}} at {{{{ $labels.instance }}}}'
          description: '{{{{ $labels.ifDescr }}}} discarding {{{{ $value | humanize }}}} inbound packets/sec on {{{{ $labels.instance }}}}'

      - alert: InterfaceOutputDrops
        expr: rate(ifOutDiscards[5m]) > {drop_rate}
        for: 5m
        labels: {{severity: warning, category: errors}}
        annotations:
          summary: 'Output drops — {{{{ $labels.ifDescr }}}} at {{{{ $labels.instance }}}}'
          description: '{{{{ $labels.ifDescr }}}} discarding {{{{ $value | humanize }}}} outbound packets/sec on {{{{ $labels.instance }}}}'

  - name: cisco_resources
    interval: 60s
    rules:

      - alert: HighCPU
        expr: cpmCPUTotal5minRev > {cpu_warn}
        for: 5m
        labels: {{severity: warning}}
        annotations:
          summary: 'High CPU — {{{{ $labels.instance }}}}'
          description: 'CPU 5-min avg is {{{{ $value }}}}% on {{{{ $labels.instance }}}} (threshold {cpu_warn}%)'

      - alert: CriticalCPU
        expr: cpmCPUTotal5minRev > {cpu_crit}
        for: 2m
        labels: {{severity: critical}}
        annotations:
          summary: 'Critical CPU — {{{{ $labels.instance }}}}'
          description: 'CPU 5-min avg is {{{{ $value }}}}% on {{{{ $labels.instance }}}} — device may drop routing traffic'

      - alert: HighMemory
        expr: ciscoMemoryPoolUsed / (ciscoMemoryPoolUsed + ciscoMemoryPoolFree) > {mem_warn / 100}
        for: 5m
        labels: {{severity: warning}}
        annotations:
          summary: 'High memory — {{{{ $labels.instance }}}}'
          description: 'Memory {{{{ $labels.ciscoMemoryPoolName }}}} is {{{{ $value | humanizePercentage }}}} used on {{{{ $labels.instance }}}} (threshold {mem_warn}%)'

  - name: cisco_eigrp
    interval: 30s
    rules:

      - alert: EIGRPNeighborLost
        expr: absent_over_time(cEigrpPeerUpTime[5m])
        for: 2m
        labels: {{severity: critical, category: routing}}
        annotations:
          summary: 'EIGRP neighbor lost — {{{{ $labels.instance }}}}'
          description: 'An EIGRP neighbor disappeared from {{{{ $labels.instance }}}}'

      - alert: EIGRPNeighborFlapping
        expr: changes(cEigrpPeerUpTime[15m]) > 3
        for: 0m
        labels: {{severity: warning, category: routing}}
        annotations:
          summary: 'EIGRP neighbor flapping — {{{{ $labels.instance }}}}'
          description: 'EIGRP peer {{{{ $labels.cEigrpPeerAddr }}}} reset {{{{ $value }}}} times in 15 min on {{{{ $labels.instance }}}}'

  - name: cisco_routing
    interval: 120s
    rules:

      - alert: DefaultRouteGone
        expr: absent_over_time(ipCidrRouteType{{ipCidrRouteDest='0.0.0.0',ipCidrRoutePfxLen='0'}}[5m])
        for: 2m
        labels: {{severity: critical, category: routing}}
        annotations:
          summary: 'Default route missing — {{{{ $labels.instance }}}}'
          description: 'No 0.0.0.0/0 in routing table on {{{{ $labels.instance }}}}'

      - alert: DefaultRouteNextHopChanged
        expr: changes(ipCidrRouteNextHop{{ipCidrRouteDest='0.0.0.0',ipCidrRoutePfxLen='0'}}[10m]) > 0
        for: 0m
        labels: {{severity: warning, category: routing}}
        annotations:
          summary: 'Default route next-hop changed — {{{{ $labels.instance }}}}'
          description: 'Next-hop for 0.0.0.0/0 changed on {{{{ $labels.instance }}}}'
"""
    ALERTS_YML.parent.mkdir(parents=True, exist_ok=True)
    ALERTS_YML.write_text(content)
    try:
        os.chown(ALERTS_YML, _uid("prometheus"), _gid("prometheus"))
        ALERTS_YML.chmod(0o640)
    except Exception:
        pass


def write_alertmanager_yml(email: dict):
    backup(ALERTMANAGER_YML)

    smtp_host = email.get("smtp_host", "")
    smtp_port = email.get("smtp_port", 587)
    smtp_from = email.get("smtp_from", "")
    smtp_user = email.get("smtp_username", "")
    smtp_pass = email.get("smtp_password", "")
    smtp_tls  = str(email.get("smtp_tls", True)).lower()
    to_warn   = email.get("to_warnings", "")
    to_crit   = email.get("to_critical", "")
    gf_url    = email.get("grafana_url", "http://localhost:3000")

    content = f"""# NetWatch alertmanager.yml
# Generated by NetWatch Admin UI on {datetime.utcnow().isoformat()}Z

global:
  resolve_timeout: 5m
  smtp_smarthost:     '{smtp_host}:{smtp_port}'
  smtp_from:          '{smtp_from}'
  smtp_auth_username: '{smtp_user}'
  smtp_auth_password: '{smtp_pass}'
  smtp_require_tls:   {smtp_tls}

route:
  group_by: ['alertname', 'instance', 'site', 'category']
  group_wait:      30s
  group_interval:  5m
  repeat_interval: 4h
  receiver: email_warnings
  routes:
    - match: {{severity: critical}}
      receiver: email_critical
    - match: {{category: tunnel}}
      receiver: email_critical
    - match: {{category: routing}}
      receiver: email_critical

receivers:

  - name: email_warnings
    email_configs:
      - to: '{to_warn}'
        subject: '[{{{{ .Status | toUpper }}}}] {{{{ .GroupLabels.alertname }}}} — {{{{ .GroupLabels.site }}}}'
        html: |
          <h3>{{{{ .GroupLabels.alertname }}}}</h3>
          <p><strong>Site:</strong> {{{{ .GroupLabels.site }}}}</p>
          <table border="1" cellpadding="4">
          <tr><th>Alert</th><th>Instance</th><th>Detail</th></tr>
          {{{{- range .Alerts }}}}
          <tr><td>{{{{ .Labels.alertname }}}}</td><td>{{{{ .Labels.instance }}}}</td><td>{{{{ .Annotations.description }}}}</td></tr>
          {{{{- end }}}}
          </table>
        send_resolved: true

  - name: email_critical
    email_configs:
      - to: '{to_crit}'
        subject: '[CRITICAL] {{{{ .GroupLabels.alertname }}}} — {{{{ .GroupLabels.instance }}}}'
        html: |
          <h2 style="color:red">CRITICAL ALERT</h2>
          {{{{- range .Alerts }}}}
          <p><strong>{{{{ .Annotations.summary }}}}</strong><br>
          {{{{ .Annotations.description }}}}</p>
          {{{{- end }}}}
          <p><a href="{gf_url}">Open Grafana</a></p>
        send_resolved: true

inhibit_rules:
  - source_match: {{alertname: 'DeviceUnreachable'}}
    target_match_re: {{alertname: '.*'}}
    equal: ['instance']
"""
    ALERTMANAGER_YML.parent.mkdir(parents=True, exist_ok=True)
    ALERTMANAGER_YML.write_text(content)
    try:
        os.chown(ALERTMANAGER_YML, _uid("prometheus"), _gid("prometheus"))
        ALERTMANAGER_YML.chmod(0o640)
    except Exception:
        pass


def _uid(username):
    import pwd
    return pwd.getpwnam(username).pw_uid

def _gid(groupname):
    import grp
    return grp.getgrnam(groupname).gr_gid


# ── API routes ────────────────────────────────────────────────────────────────

@app.route("/api/config", methods=["GET"])
def get_config():
    state = read_ui_state()
    # Mask passwords in response
    safe = json.loads(json.dumps(state))
    if safe["snmp"].get("v3_auth_password"):
        safe["snmp"]["v3_auth_password"] = "••••••••"
    if safe["snmp"].get("v3_priv_password"):
        safe["snmp"]["v3_priv_password"] = "••••••••"
    if safe["email"].get("smtp_password"):
        safe["email"]["smtp_password"] = "••••••••"
    return jsonify(safe)


@app.route("/api/devices", methods=["POST"])
def save_devices():
    data = request.get_json(force=True)
    devices = data.get("devices", [])

    # Validate
    for i, d in enumerate(devices):
        if not d.get("ip"):
            return api_error(f"Device {i+1} is missing an IP address.")
        if not re.match(r"^\d{1,3}(\.\d{1,3}){3}$", d["ip"].strip()):
            return api_error(f"Invalid IP address: {d['ip']}")
        if not d.get("site"):
            return api_error(f"Device {d['ip']} is missing a site name.")

    state = read_ui_state()
    state["devices"] = devices
    save_ui_state(state)

    try:
        write_prometheus_yml(devices, state["snmp"], state["thresholds"])
        return api_ok("Devices saved. Run Reload to apply.", count=len(devices))
    except Exception as e:
        log.exception("Failed to write prometheus.yml")
        return api_error(f"Config write failed: {e}", 500)


@app.route("/api/snmp", methods=["POST"])
def save_snmp():
    data = request.get_json(force=True)
    snmp = data.get("snmp", {})

    state = read_ui_state()

    # Don't overwrite masked passwords with placeholder
    for field in ("v3_auth_password", "v3_priv_password"):
        if snmp.get(field) == "••••••••":
            snmp[field] = state["snmp"].get(field, "")

    state["snmp"] = snmp
    save_ui_state(state)

    try:
        write_snmp_yml(snmp)
        write_prometheus_yml(state["devices"], snmp, state["thresholds"])
        return api_ok("SNMP credentials saved. Run Reload to apply.")
    except Exception as e:
        log.exception("Failed to write snmp.yml")
        return api_error(f"Config write failed: {e}", 500)


@app.route("/api/thresholds", methods=["POST"])
def save_thresholds():
    data = request.get_json(force=True)
    thresholds = data.get("thresholds", {})

    # Validate numeric ranges
    checks = [
        ("cpu_warn",  1, 99),
        ("cpu_crit",  1, 99),
        ("mem_warn",  1, 99),
        ("util_warn", 1, 99),
        ("error_rate", 0, 10000),
        ("drop_rate",  0, 10000),
    ]
    for key, lo, hi in checks:
        val = thresholds.get(key)
        if val is not None:
            try:
                v = int(val)
                if not (lo <= v <= hi):
                    return api_error(f"{key} must be between {lo} and {hi}.")
                thresholds[key] = v
            except (TypeError, ValueError):
                return api_error(f"{key} must be a number.")

    if thresholds.get("cpu_warn", 0) >= thresholds.get("cpu_crit", 100):
        return api_error("CPU warning threshold must be less than CPU critical threshold.")

    state = read_ui_state()
    state["thresholds"] = thresholds
    save_ui_state(state)

    try:
        write_alert_rules(thresholds)
        return api_ok("Thresholds saved. Run Reload to apply.")
    except Exception as e:
        log.exception("Failed to write alert rules")
        return api_error(f"Config write failed: {e}", 500)


@app.route("/api/email", methods=["POST"])
def save_email():
    data = request.get_json(force=True)
    email = data.get("email", {})

    state = read_ui_state()

    # Don't overwrite masked password
    if email.get("smtp_password") == "••••••••":
        email["smtp_password"] = state["email"].get("smtp_password", "")

    state["email"] = email
    save_ui_state(state)

    try:
        write_alertmanager_yml(email)
        return api_ok("Email settings saved. Run Reload to apply.")
    except Exception as e:
        log.exception("Failed to write alertmanager.yml")
        return api_error(f"Config write failed: {e}", 500)


@app.route("/api/reload", methods=["POST"])
def do_reload():
    if not _reload_lock.acquire(blocking=False):
        return api_error("A reload is already in progress.", 429)
    try:
        if not RELOAD_SCRIPT.exists():
            # Inline reload without script
            results = []
            for cmd, label in [
                (["promtool", "check", "config", str(PROMETHEUS_YML)], "promtool check"),
                (["curl", "-sf", "-X", "POST", "http://127.0.0.1:9090/-/reload"], "Prometheus reload"),
                (["curl", "-sf", "-X", "POST", "http://127.0.0.1:9093/-/reload"], "Alertmanager reload"),
                (["systemctl", "restart", "snmp_exporter"], "snmp_exporter restart"),
            ]:
                r = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
                results.append({"step": label, "ok": r.returncode == 0, "output": r.stdout + r.stderr})
            all_ok = all(r["ok"] for r in results)
            return jsonify({"ok": all_ok, "steps": results})
        else:
            r = subprocess.run(
                ["bash", str(RELOAD_SCRIPT)],
                capture_output=True, text=True, timeout=30
            )
            return jsonify({
                "ok": r.returncode == 0,
                "output": r.stdout + r.stderr,
                "returncode": r.returncode,
            })
    except subprocess.TimeoutExpired:
        return api_error("Reload timed out.", 504)
    except Exception as e:
        log.exception("Reload failed")
        return api_error(str(e), 500)
    finally:
        _reload_lock.release()


@app.route("/api/test-snmp", methods=["POST"])
def test_snmp():
    data = request.get_json(force=True)
    ip = data.get("ip", "").strip()

    if not ip or not re.match(r"^\d{1,3}(\.\d{1,3}){3}$", ip):
        return api_error("Invalid IP address.")

    state = read_ui_state()
    snmp  = state.get("snmp", {})

    if snmp.get("version") == "3":
        cmd = [
            "snmpget", "-v3",
            "-u", snmp.get("v3_username", "netwatch"),
            "-l", "authPriv",
            "-a", snmp.get("v3_auth_protocol", "SHA"),
            "-A", snmp.get("v3_auth_password", ""),
            "-x", snmp.get("v3_priv_protocol", "AES"),
            "-X", snmp.get("v3_priv_password", ""),
            "-t", "3", "-r", "1",
            ip, "1.3.6.1.2.1.1.5.0",   # sysName
        ]
    else:
        community = snmp.get("community", "public")
        cmd = ["snmpget", "-v2c", "-c", community, "-t", "3", "-r", "1",
               ip, "1.3.6.1.2.1.1.5.0"]

    if not shutil.which("snmpget"):
        # Fall back to HTTP test via SNMP Exporter
        try:
            import urllib.request
            auth = "v3_netwatch" if snmp.get("version") == "3" else "v2_netwatch"
            url = f"http://127.0.0.1:9116/snmp?target={ip}&module=cisco_resources&auth={auth}"
            with urllib.request.urlopen(url, timeout=8) as resp:
                ok = resp.status == 200
            return jsonify({"ok": ok, "method": "snmp_exporter",
                            "message": "Reachable via SNMP Exporter" if ok else "SNMP Exporter returned error"})
        except Exception as e:
            return api_error(f"snmpget not installed and SNMP Exporter test failed: {e}")

    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=8)
        if r.returncode == 0:
            sysname = r.stdout.strip().split("=")[-1].strip().strip('"')
            return api_ok(f"SNMP reachable — sysName: {sysname}", sysname=sysname)
        else:
            return jsonify({"ok": False, "error": r.stderr.strip() or "No response (timeout or auth failure)"})
    except subprocess.TimeoutExpired:
        return api_error("SNMP test timed out — device unreachable or UDP/161 blocked.")
    except Exception as e:
        return api_error(str(e))


@app.route("/api/test-email", methods=["POST"])
def test_email():
    state = read_ui_state()
    em = state.get("email", {})

    host     = em.get("smtp_host", "")
    port     = int(em.get("smtp_port", 587))
    frm      = em.get("smtp_from", "")
    user     = em.get("smtp_username", "")
    pwd      = em.get("smtp_password", "")
    use_tls  = em.get("smtp_tls", True)
    to_crit  = em.get("to_critical", "")

    if not host or not to_crit:
        return api_error("SMTP host and critical recipient address must be configured first.")

    msg = MIMEText(
        "This is a test alert from NetWatch.\n\n"
        "If you received this, your SMTP configuration is working correctly.",
        "plain"
    )
    msg["Subject"] = "[NetWatch] Test Alert — SMTP configuration verified"
    msg["From"]    = frm
    msg["To"]      = to_crit

    try:
        if use_tls:
            server = smtplib.SMTP(host, port, timeout=10)
            server.starttls()
        else:
            server = smtplib.SMTP(host, port, timeout=10)
        if user and pwd:
            server.login(user, pwd)
        server.sendmail(frm, [to_crit], msg.as_string())
        server.quit()
        return api_ok(f"Test email sent to {to_crit}")
    except smtplib.SMTPAuthenticationError:
        return api_error("SMTP authentication failed — check username and password.")
    except smtplib.SMTPConnectError as e:
        return api_error(f"Could not connect to {host}:{port} — {e}")
    except Exception as e:
        return api_error(f"Email send failed: {e}")


@app.route("/api/status", methods=["GET"])
def get_status():
    """Quick health check — service states and pending CHANGEME count."""
    services = {}
    for svc in ("snmp_exporter", "prometheus", "alertmanager", "grafana-server"):
        try:
            r = subprocess.run(
                ["systemctl", "is-active", svc],
                capture_output=True, text=True, timeout=3
            )
            services[svc] = r.stdout.strip()
        except Exception:
            services[svc] = "unknown"

    changeme = 0
    for f in (PROMETHEUS_YML, SNMP_YML, ALERTMANAGER_YML):
        try:
            changeme += f.read_text().count("CHANGEME")
        except Exception:
            pass

    return jsonify({
        "services": services,
        "changeme_remaining": changeme,
        "config_dir": str(CONFIG_DIR),
    })


# ── Serve the dashboard HTML ──────────────────────────────────────────────────
@app.route("/", methods=["GET"])
@app.route("/dashboard", methods=["GET"])
def serve_dashboard():
    dashboard = INSTALL_DIR / "netwatch-dashboard.html"
    if dashboard.exists():
        return dashboard.read_text(), 200, {"Content-Type": "text/html"}
    return "<h2>netwatch-dashboard.html not found in " + str(INSTALL_DIR) + "</h2>", 404


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="NetWatch Admin API")
    parser.add_argument("--host",  default="0.0.0.0",  help="Bind address (default: 0.0.0.0)")
    parser.add_argument("--port",  default=9199, type=int, help="Port (default: 9199)")
    parser.add_argument("--debug", action="store_true",   help="Enable Flask debug mode")
    args = parser.parse_args()

    log.info("NetWatch Admin API starting on %s:%d", args.host, args.port)
    log.info("Config dir: %s", CONFIG_DIR)
    log.info("Install dir: %s", INSTALL_DIR)
    app.run(host=args.host, port=args.port, debug=args.debug)
