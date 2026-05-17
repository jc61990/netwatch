#!/usr/bin/env python3
"""
NetWatch Admin API — v2
Full config management: devices, SNMP profiles, sites, thresholds,
email/SMTP with per-site routing, polling intervals, Prometheus retention.

Endpoints:
  GET  /api/config              — full config state (passwords masked)
  GET  /api/status              — service health + CHANGEME count
  POST /api/devices             — save device list → prometheus.yml
  POST /api/snmp-profiles       — save named SNMP profiles → snmp.yml
  POST /api/sites               — save site list → alertmanager.yml routing
  POST /api/thresholds          — save alert thresholds → cisco_alerts.yml
  POST /api/email               — save global SMTP + per-site routing → alertmanager.yml
  POST /api/polling             — save polling intervals + retention → prometheus.yml
  POST /api/reload              — hot-reload all services
  POST /api/test-snmp           — test SNMP (auto v3→v2c fallback)
  POST /api/test-email          — send a test alert email
  GET  /                        — serve netwatch-dashboard.html

Usage:
  sudo /opt/netwatch/venv/bin/python netwatch-api.py
"""

import argparse, json, logging, os, re, shutil, smtplib, subprocess, sys, threading
from datetime import datetime
from pathlib import Path
from email.mime.text import MIMEText

try:
    from flask import Flask, jsonify, request
    from flask_cors import CORS
except ImportError:
    print("ERROR: pip install flask flask-cors  (or use the venv)")
    sys.exit(1)

# ── Paths ─────────────────────────────────────────────────────────────────────
CONFIG_DIR    = Path(os.environ.get("NETWATCH_CONFIG_DIR",  "/etc/netwatch"))
INSTALL_DIR   = Path(os.environ.get("NETWATCH_INSTALL_DIR", "/opt/netwatch"))
UI_STATE_FILE = CONFIG_DIR / "netwatch-ui.json"
RELOAD_SCRIPT = INSTALL_DIR / "reload.sh"

PROMETHEUS_YML   = CONFIG_DIR / "prometheus"    / "prometheus.yml"
SNMP_YML         = CONFIG_DIR / "snmp_exporter" / "snmp.yml"
ALERTS_YML       = CONFIG_DIR / "prometheus"    / "rules" / "cisco_alerts.yml"
ALERTMANAGER_YML = CONFIG_DIR / "alertmanager"  / "alertmanager.yml"

logging.basicConfig(level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s", datefmt="%Y-%m-%dT%H:%M:%S")
log = logging.getLogger("netwatch-api")

app = Flask(__name__, static_folder=str(INSTALL_DIR))
CORS(app)
_reload_lock = threading.Lock()
MASK = "••••••••"

# ── Defaults ──────────────────────────────────────────────────────────────────
DEFAULTS = {
    "devices": [],
    "snmp_profiles": [
        {"name":"default-v2c","version":"2","community":""},
        {"name":"default-v3","version":"3","v3_username":"",
         "v3_auth_protocol":"SHA","v3_auth_password":"",
         "v3_priv_protocol":"AES","v3_priv_password":""},
    ],
    "sites": [],
    "thresholds": {
        "cpu_warn":70,"cpu_crit":90,"mem_warn":80,
        "util_warn":85,"error_rate":5,"drop_rate":10,
    },
    "email": {
        "smtp_host":"","smtp_port":587,"smtp_from":"",
        "smtp_username":"","smtp_password":"","smtp_tls":True,
        "default_warnings":"","default_critical":"","grafana_url":"",
    },
    "polling": {
        "interfaces_interval":"60s","resources_interval":"60s",
        "tunnels_interval":"30s","eigrp_interval":"60s",
        "routing_interval":"120s","global_scrape":"60s","retention":"90d",
    },
}

# ── State ─────────────────────────────────────────────────────────────────────
def read_state() -> dict:
    state = json.loads(json.dumps(DEFAULTS))
    if UI_STATE_FILE.exists():
        try:
            saved = json.loads(UI_STATE_FILE.read_text())
            for k in state:
                if k in saved:
                    if isinstance(state[k], dict):
                        state[k].update(saved[k])
                    else:
                        state[k] = saved[k]
        except Exception as e:
            log.warning("Could not read UI state: %s", e)
    return state

def save_state(state: dict):
    UI_STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
    tmp = UI_STATE_FILE.with_suffix(".tmp")
    tmp.write_text(json.dumps(state, indent=2))
    tmp.replace(UI_STATE_FILE)

def backup(path: Path):
    if path.exists():
        bak = path.with_suffix(
            path.suffix + f".bak.{datetime.utcnow().strftime('%Y%m%dT%H%M%S')}")
        shutil.copy2(path, bak)

def mask_state(state: dict) -> dict:
    s = json.loads(json.dumps(state))
    for p in s.get("snmp_profiles", []):
        for f in ("community","v3_auth_password","v3_priv_password"):
            if p.get(f): p[f] = MASK
    if s["email"].get("smtp_password"):
        s["email"]["smtp_password"] = MASK
    return s

def restore_masked(new: dict, old: dict, fields: list):
    for f in fields:
        if new.get(f) == MASK:
            new[f] = old.get(f, "")

def safe_name(s: str) -> str:
    return re.sub(r"[^a-zA-Z0-9_\-]", "_", s)

def api_ok(msg="ok", **kw):   return jsonify({"ok":True,  "message":msg, **kw})
def api_err(msg, code=400):   return jsonify({"ok":False, "error":msg}), code

# ── Config writers ─────────────────────────────────────────────────────────────
def write_snmp_yml(profiles: list):
    backup(SNMP_YML)
    auth_block = "auths:\n"
    for p in profiles:
        n = safe_name(p["name"])
        if p.get("version") == "3":
            auth_block += (
                f"  {n}:\n    version: 3\n"
                f"    username: {p.get('v3_username','netwatch')}\n"
                f"    security_level: authPriv\n"
                f"    auth_protocol: {p.get('v3_auth_protocol','SHA')}\n"
                f"    auth_password: {p.get('v3_auth_password','')}\n"
                f"    priv_protocol: {p.get('v3_priv_protocol','AES')}\n"
                f"    priv_password: {p.get('v3_priv_password','')}\n"
            )
        else:
            auth_block += (
                f"  {n}:\n    version: 2\n"
                f"    community: {p.get('community','')}\n"
            )

    modules = r"""
modules:

  cisco_interfaces:
    walk: [1.3.6.1.2.1.2.2.1, 1.3.6.1.2.1.31.1.1.1]
    lookups:
      - source_indexes: [ifIndex]
        lookup: 1.3.6.1.2.1.2.2.1.2
      - source_indexes: [ifIndex]
        lookup: 1.3.6.1.2.1.31.1.1.1.18
    overrides:
      ifOperStatus:  {type: gauge}
      ifAdminStatus: {type: gauge}
      ifHCInOctets:  {type: counter}
      ifHCOutOctets: {type: counter}
      ifInErrors:    {type: counter}
      ifOutErrors:   {type: counter}
      ifInDiscards:  {type: counter}
      ifOutDiscards: {type: counter}

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
      ifOperStatus:  {type: gauge}
      ifHCInOctets:  {type: counter}
      ifHCOutOctets: {type: counter}

  cisco_eigrp:
    walk: [1.3.6.1.4.1.9.9.449.1.4.1]
    lookups:
      - source_indexes: [cEigrpVpnId, cEigrpAsNumber, cEigrpHandle]
        lookup: 1.3.6.1.4.1.9.9.449.1.4.1.1.1
    overrides:
      cEigrpPeerUpTime: {type: gauge}
      cEigrpRetrans:    {type: counter}
      cEigrpRetries:    {type: counter}

  cisco_routing:
    walk: [1.3.6.1.2.1.4.24.4.1]
    overrides:
      ipCidrRouteType:  {type: gauge}
      ipCidrRouteProto: {type: gauge}
      ipCidrRouteAge:   {type: gauge}
"""
    SNMP_YML.parent.mkdir(parents=True, exist_ok=True)
    SNMP_YML.write_text(
        f"# NetWatch snmp.yml — generated {datetime.utcnow().isoformat()}Z\n\n"
        f"{auth_block}{modules}")


def write_prometheus_yml(devices: list, profiles: list, polling: dict):
    backup(PROMETHEUS_YML)
    modules = [
        ("cisco_interfaces", polling.get("interfaces_interval","60s")),
        ("cisco_resources",  polling.get("resources_interval", "60s")),
        ("cisco_tunnels",    polling.get("tunnels_interval",   "30s")),
        ("cisco_eigrp",      polling.get("eigrp_interval",    "60s")),
        ("cisco_routing",    polling.get("routing_interval",  "120s")),
    ]
    gs = polling.get("global_scrape","60s")

    jobs = ""
    for module, interval in modules:
        jobs += f"""
  - job_name: {module}
    scrape_interval: {interval}
    metrics_path: /snmp
    params:
      module: [{module}]
    static_configs:
"""
        if devices:
            for d in devices:
                ip   = d.get("ip","").strip()
                site = d.get("site","").strip()
                host = d.get("hostname","").strip()
                prof = safe_name(d.get("snmp_profile","default-v2c"))
                fb   = safe_name(d.get("snmp_fallback_profile","")) if d.get("snmp_fallback_profile") else ""
                if not ip: continue
                jobs += f"      - targets: [{ip}]\n"
                jobs += f"        labels:\n          site: '{site}'\n"
                jobs += f"          hostname: '{host}'\n"
                jobs += f"          snmp_profile: '{prof}'\n"
                if fb:
                    jobs += f"          snmp_fallback: '{fb}'\n"
        else:
            jobs += "      - targets: []  # no devices configured\n"

        jobs += f"""    relabel_configs:
      - source_labels: [__address__]
        target_label: __param_target
      - source_labels: [__param_target]
        target_label: instance
      - source_labels: [snmp_profile]
        target_label: __param_auth
      - target_label: __address__
        replacement: localhost:9116
"""

    content = (
        f"# NetWatch prometheus.yml — generated {datetime.utcnow().isoformat()}Z\n"
        f"# Retention: {polling.get('retention','90d')}"
        f" (set in prometheus systemd unit via --storage.tsdb.retention.time)\n\n"
        f"global:\n"
        f"  scrape_interval:     {gs}\n"
        f"  evaluation_interval: {gs}\n"
        f"  external_labels:\n    monitor: 'netwatch'\n\n"
        f"alerting:\n  alertmanagers:\n"
        f"    - static_configs:\n        - targets: ['localhost:9093']\n\n"
        f"rule_files:\n  - {CONFIG_DIR}/prometheus/rules/*.yml\n\n"
        f"scrape_configs:\n{jobs}\n"
    )
    PROMETHEUS_YML.parent.mkdir(parents=True, exist_ok=True)
    PROMETHEUS_YML.write_text(content)


def write_alert_rules(thresholds: dict):
    backup(ALERTS_YML)
    cw  = thresholds.get("cpu_warn",  70)
    cc  = thresholds.get("cpu_crit",  90)
    mw  = thresholds.get("mem_warn",  80)
    uw  = thresholds.get("util_warn", 85)
    er  = thresholds.get("error_rate", 5)
    dr  = thresholds.get("drop_rate", 10)

    content = f"""# NetWatch cisco_alerts.yml — generated {datetime.utcnow().isoformat()}Z
# cpu_warn={cw}% cpu_crit={cc}% mem_warn={mw}% util_warn={uw}%
groups:

  - name: cisco_link_state
    interval: 30s
    rules:
      - alert: PhysicalInterfaceDown
        expr: ifOperStatus{{ifDescr!~'Loopback.*|Null.*|Tunnel.*|Vlan.*'}} == 2
        for: 2m
        labels: {{severity: critical, category: link}}
        annotations:
          summary: 'Interface down — {{{{ $labels.instance }}}}'
          description: '{{{{ $labels.ifDescr }}}} DOWN on {{{{ $labels.instance }}}} [{{{{ $labels.site }}}}]'

      - alert: TunnelDown
        expr: ifOperStatus{{ifDescr=~'Tunnel.*'}} == 2
        for: 2m
        labels: {{severity: critical, category: tunnel}}
        annotations:
          summary: 'Tunnel down — {{{{ $labels.ifDescr }}}} on {{{{ $labels.instance }}}}'
          description: '{{{{ $labels.ifDescr }}}} DOWN on {{{{ $labels.instance }}}} [{{{{ $labels.site }}}}]'

      - alert: HighInterfaceUtilization
        expr: (rate(ifHCInOctets[5m]) * 8) / (ifHighSpeed * 1e6) > {uw/100}
        for: 5m
        labels: {{severity: warning, category: bandwidth}}
        annotations:
          summary: 'High utilization — {{{{ $labels.ifDescr }}}} at {{{{ $labels.instance }}}}'
          description: '{{{{ $labels.ifDescr }}}} inbound {{{{ $value | humanizePercentage }}}} (threshold {uw}%)'

  - name: cisco_errors
    interval: 60s
    rules:
      - alert: InterfaceInputErrors
        expr: rate(ifInErrors[5m]) > {er}
        for: 5m
        labels: {{severity: warning, category: errors}}
        annotations:
          summary: 'Input errors — {{{{ $labels.instance }}}}'
          description: '{{{{ $labels.ifDescr }}}} {{{{ $value | humanize }}}} errors/sec on {{{{ $labels.instance }}}}'

      - alert: InterfaceInputDrops
        expr: rate(ifInDiscards[5m]) > {dr}
        for: 5m
        labels: {{severity: warning, category: errors}}
        annotations:
          summary: 'Input drops — {{{{ $labels.ifDescr }}}} at {{{{ $labels.instance }}}}'

      - alert: InterfaceOutputDrops
        expr: rate(ifOutDiscards[5m]) > {dr}
        for: 5m
        labels: {{severity: warning, category: errors}}
        annotations:
          summary: 'Output drops — {{{{ $labels.ifDescr }}}} at {{{{ $labels.instance }}}}'

  - name: cisco_resources
    interval: 60s
    rules:
      - alert: HighCPU
        expr: cpmCPUTotal5minRev > {cw}
        for: 5m
        labels: {{severity: warning}}
        annotations:
          summary: 'High CPU — {{{{ $labels.instance }}}}'
          description: 'CPU {{{{ $value }}}}% on {{{{ $labels.instance }}}} (threshold {cw}%)'

      - alert: CriticalCPU
        expr: cpmCPUTotal5minRev > {cc}
        for: 2m
        labels: {{severity: critical}}
        annotations:
          summary: 'Critical CPU — {{{{ $labels.instance }}}}'
          description: 'CPU {{{{ $value }}}}% on {{{{ $labels.instance }}}}'

      - alert: HighMemory
        expr: ciscoMemoryPoolUsed / (ciscoMemoryPoolUsed + ciscoMemoryPoolFree) > {mw/100}
        for: 5m
        labels: {{severity: warning}}
        annotations:
          summary: 'High memory — {{{{ $labels.instance }}}}'
          description: 'Memory {{{{ $value | humanizePercentage }}}} on {{{{ $labels.instance }}}} (threshold {mw}%)'

  - name: cisco_eigrp
    interval: 30s
    rules:
      - alert: EIGRPNeighborLost
        expr: absent_over_time(cEigrpPeerUpTime[5m])
        for: 2m
        labels: {{severity: critical, category: routing}}
        annotations:
          summary: 'EIGRP neighbor lost — {{{{ $labels.instance }}}}'

      - alert: EIGRPNeighborFlapping
        expr: changes(cEigrpPeerUpTime[15m]) > 3
        for: 0m
        labels: {{severity: warning, category: routing}}
        annotations:
          summary: 'EIGRP flapping — {{{{ $labels.instance }}}}'

  - name: cisco_routing
    interval: 120s
    rules:
      - alert: DefaultRouteGone
        expr: absent_over_time(ipCidrRouteType{{ipCidrRouteDest='0.0.0.0',ipCidrRoutePfxLen='0'}}[5m])
        for: 2m
        labels: {{severity: critical, category: routing}}
        annotations:
          summary: 'Default route missing — {{{{ $labels.instance }}}}'

      - alert: DefaultRouteNextHopChanged
        expr: changes(ipCidrRouteNextHop{{ipCidrRouteDest='0.0.0.0',ipCidrRoutePfxLen='0'}}[10m]) > 0
        for: 0m
        labels: {{severity: warning, category: routing}}
        annotations:
          summary: 'Default route next-hop changed — {{{{ $labels.instance }}}}'
"""
    ALERTS_YML.parent.mkdir(parents=True, exist_ok=True)
    ALERTS_YML.write_text(content)


def write_alertmanager_yml(email: dict, sites: list):
    backup(ALERTMANAGER_YML)
    host     = email.get("smtp_host","")
    port     = email.get("smtp_port",587)
    frm      = email.get("smtp_from","")
    user     = email.get("smtp_username","")
    pwd      = email.get("smtp_password","")
    tls      = str(email.get("smtp_tls",True)).lower()
    def_warn = email.get("default_warnings","")
    def_crit = email.get("default_critical","")
    gf_url   = email.get("grafana_url","http://localhost:3000")

    site_routes    = ""
    site_receivers = ""

    for site in sites:
        sid   = safe_name(site.get("id", site.get("name","unknown")))
        sname = site.get("name", sid)
        sw    = site.get("email_warnings","") or def_warn
        sc    = site.get("email_critical","") or def_crit
        if not sw and not sc:
            continue
        site_routes += (
            f"    - match:\n        site: '{sname}'\n"
            f"      routes:\n"
            f"        - match: {{severity: critical}}\n"
            f"          receiver: site_{sid}_critical\n"
            f"        - receiver: site_{sid}_warnings\n"
        )
        for label, addr, rname in [
            ("warnings", sw, f"site_{sid}_warnings"),
            ("critical", sc, f"site_{sid}_critical"),
        ]:
            site_receivers += (
                f"\n  - name: {rname}\n"
                f"    email_configs:\n"
                f"      - to: '{addr}'\n"
                f"        subject: '[{{{{ .Status | toUpper }}}}] {{{{ .GroupLabels.alertname }}}} — {sname}'\n"
                f"        send_resolved: true\n"
                f"        html: |\n"
                f"          <h3>{{{{{{ .GroupLabels.alertname }}}}}}</h3>\n"
                f"          <p><strong>Site:</strong> {sname}</p>\n"
                f"          {{{{{{- range .Alerts }}}}}}\n"
                f"          <p>{{{{{{ .Annotations.description }}}}}}</p>\n"
                f"          {{{{{{- end }}}}}}\n"
                f"          <p><a href=\"{gf_url}\">Open Grafana</a></p>\n"
            )

    content = (
        f"# NetWatch alertmanager.yml — generated {datetime.utcnow().isoformat()}Z\n\n"
        f"global:\n"
        f"  resolve_timeout: 5m\n"
        f"  smtp_smarthost:     '{host}:{port}'\n"
        f"  smtp_from:          '{frm}'\n"
        f"  smtp_auth_username: '{user}'\n"
        f"  smtp_auth_password: '{pwd}'\n"
        f"  smtp_require_tls:   {tls}\n\n"
        f"route:\n"
        f"  group_by: ['alertname','instance','site','category']\n"
        f"  group_wait:      30s\n"
        f"  group_interval:  5m\n"
        f"  repeat_interval: 4h\n"
        f"  receiver: default_warnings\n"
        f"  routes:\n"
        f"{site_routes}"
        f"    - match: {{severity: critical}}\n      receiver: default_critical\n"
        f"    - match: {{category: tunnel}}\n      receiver: default_critical\n"
        f"    - match: {{category: routing}}\n      receiver: default_critical\n\n"
        f"receivers:\n\n"
        f"  - name: default_warnings\n"
        f"    email_configs:\n"
        f"      - to: '{def_warn}'\n"
        f"        subject: '[{{{{ .Status | toUpper }}}}] {{{{ .GroupLabels.alertname }}}} — {{{{ .GroupLabels.site }}}}'\n"
        f"        send_resolved: true\n\n"
        f"  - name: default_critical\n"
        f"    email_configs:\n"
        f"      - to: '{def_crit}'\n"
        f"        subject: '[CRITICAL] {{{{ .GroupLabels.alertname }}}} — {{{{ .GroupLabels.instance }}}}'\n"
        f"        send_resolved: true\n"
        f"        html: |\n"
        f"          <h2 style=\"color:red\">CRITICAL ALERT</h2>\n"
        f"          {{{{- range .Alerts }}}}\n"
        f"          <p><strong>{{{{ .Annotations.summary }}}}</strong><br>\n"
        f"          {{{{ .Annotations.description }}}}</p>\n"
        f"          {{{{- end }}}}\n"
        f"          <p><a href=\"{gf_url}\">Open Grafana</a></p>\n"
        f"{site_receivers}\n"
        f"inhibit_rules:\n"
        f"  - source_match: {{alertname: 'DeviceUnreachable'}}\n"
        f"    target_match_re: {{alertname: '.*'}}\n"
        f"    equal: ['instance']\n"
    )
    ALERTMANAGER_YML.parent.mkdir(parents=True, exist_ok=True)
    ALERTMANAGER_YML.write_text(content)


# ── API routes ─────────────────────────────────────────────────────────────────
@app.route("/api/config")
def get_config():
    return jsonify(mask_state(read_state()))

@app.route("/api/status")
def get_status():
    svcs = {}
    for s in ("snmp_exporter","prometheus","alertmanager","netwatch-api"):
        try:
            r = subprocess.run(["systemctl","is-active",s],
                               capture_output=True, text=True, timeout=3)
            svcs[s] = r.stdout.strip()
        except Exception:
            svcs[s] = "unknown"
    cm = 0
    for f in (PROMETHEUS_YML, SNMP_YML, ALERTMANAGER_YML):
        try: cm += f.read_text().count("CHANGEME")
        except Exception: pass
    return jsonify({"services":svcs,"changeme_remaining":cm,"config_dir":str(CONFIG_DIR)})

@app.route("/api/devices", methods=["POST"])
def save_devices():
    devices = request.get_json(force=True).get("devices",[])
    for i,d in enumerate(devices):
        if not d.get("ip"):           return api_err(f"Device {i+1} missing IP.")
        if not re.match(r"^\d{1,3}(\.\d{1,3}){3}$", d["ip"].strip()):
            return api_err(f"Invalid IP: {d['ip']}")
        if not d.get("site"):         return api_err(f"{d['ip']} missing site.")
    state = read_state()
    state["devices"] = devices
    save_state(state)
    try:
        write_prometheus_yml(devices, state["snmp_profiles"], state["polling"])
        return api_ok(f"Saved {len(devices)} device(s). Reload to apply.", count=len(devices))
    except Exception as e:
        return api_err(str(e), 500)

@app.route("/api/snmp-profiles", methods=["POST"])
def save_snmp_profiles():
    profiles = request.get_json(force=True).get("snmp_profiles",[])
    if not profiles: return api_err("At least one SNMP profile required.")
    state    = read_state()
    old_map  = {p["name"]:p for p in state.get("snmp_profiles",[])}
    for p in profiles:
        if not p.get("name"): return api_err("Every profile needs a name.")
        restore_masked(p, old_map.get(p["name"],{}),
                       ["community","v3_auth_password","v3_priv_password"])
    state["snmp_profiles"] = profiles
    save_state(state)
    try:
        write_snmp_yml(profiles)
        write_prometheus_yml(state["devices"], profiles, state["polling"])
        return api_ok("SNMP profiles saved. Reload to apply.")
    except Exception as e:
        return api_err(str(e), 500)

@app.route("/api/sites", methods=["POST"])
def save_sites():
    sites = request.get_json(force=True).get("sites",[])
    for s in sites:
        if not s.get("name"): return api_err("Every site needs a name.")
        if not s.get("id"):   s["id"] = safe_name(s["name"].lower())
    state = read_state()
    state["sites"] = sites
    save_state(state)
    try:
        write_alertmanager_yml(state["email"], sites)
        return api_ok(f"Saved {len(sites)} site(s). Reload to apply.", count=len(sites))
    except Exception as e:
        return api_err(str(e), 500)

@app.route("/api/thresholds", methods=["POST"])
def save_thresholds():
    thresholds = request.get_json(force=True).get("thresholds",{})
    for key,lo,hi in [("cpu_warn",1,99),("cpu_crit",1,99),("mem_warn",1,99),
                      ("util_warn",1,99),("error_rate",0,10000),("drop_rate",0,10000)]:
        v = thresholds.get(key)
        if v is not None:
            try:
                v = int(v)
                if not (lo <= v <= hi): return api_err(f"{key} must be {lo}–{hi}.")
                thresholds[key] = v
            except (TypeError,ValueError): return api_err(f"{key} must be a number.")
    if thresholds.get("cpu_warn",0) >= thresholds.get("cpu_crit",100):
        return api_err("CPU warning must be less than CPU critical.")
    state = read_state()
    state["thresholds"] = thresholds
    save_state(state)
    try:
        write_alert_rules(thresholds)
        return api_ok("Thresholds saved. Reload to apply.")
    except Exception as e:
        return api_err(str(e), 500)

@app.route("/api/email", methods=["POST"])
def save_email():
    email = request.get_json(force=True).get("email",{})
    state = read_state()
    restore_masked(email, state["email"], ["smtp_password"])
    state["email"] = email
    save_state(state)
    try:
        write_alertmanager_yml(email, state["sites"])
        return api_ok("Email settings saved. Reload to apply.")
    except Exception as e:
        return api_err(str(e), 500)

@app.route("/api/polling", methods=["POST"])
def save_polling():
    polling = request.get_json(force=True).get("polling",{})
    iv_re = re.compile(r"^\d+[smh]$")
    for k in ["interfaces_interval","resources_interval","tunnels_interval",
              "eigrp_interval","routing_interval","global_scrape"]:
        v = polling.get(k,"")
        if v and not iv_re.match(v):
            return api_err(f"{k}: invalid format '{v}' — use e.g. 30s, 2m, 1h")
    ret = polling.get("retention","")
    if ret and not re.match(r"^\d+[dwmy]$", ret):
        return api_err(f"retention: invalid format '{ret}' — use e.g. 90d, 12w, 1y")
    state = read_state()
    state["polling"] = polling
    save_state(state)
    try:
        write_prometheus_yml(state["devices"], state["snmp_profiles"], polling)
        return api_ok("Polling settings saved. Reload to apply. Note: retention changes require restarting the prometheus systemd unit.")
    except Exception as e:
        return api_err(str(e), 500)

@app.route("/api/reload", methods=["POST"])
def do_reload():
    if not _reload_lock.acquire(blocking=False):
        return api_err("Reload already in progress.", 429)
    try:
        if RELOAD_SCRIPT.exists():
            r = subprocess.run(["bash", str(RELOAD_SCRIPT)],
                               capture_output=True, text=True, timeout=30)
            return jsonify({"ok": r.returncode==0,
                            "output": r.stdout+r.stderr, "returncode": r.returncode})
        results = []
        for cmd, label in [
            (["promtool","check","config",str(PROMETHEUS_YML)], "promtool check"),
            (["curl","-sf","-X","POST","http://127.0.0.1:9090/-/reload"], "Prometheus reload"),
            (["curl","-sf","-X","POST","http://127.0.0.1:9093/-/reload"], "Alertmanager reload"),
            (["systemctl","restart","snmp_exporter"], "snmp_exporter restart"),
        ]:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
            results.append({"step":label,"ok":r.returncode==0,"output":r.stdout+r.stderr})
        return jsonify({"ok": all(r["ok"] for r in results), "steps": results})
    except subprocess.TimeoutExpired:
        return api_err("Reload timed out.", 504)
    except Exception as e:
        return api_err(str(e), 500)
    finally:
        _reload_lock.release()

@app.route("/api/test-snmp", methods=["POST"])
def test_snmp():
    data         = request.get_json(force=True)
    ip           = data.get("ip","").strip()
    profile_name = data.get("profile","")

    if not ip or not re.match(r"^\d{1,3}(\.\d{1,3}){3}$", ip):
        return api_err("Invalid IP address.")

    state    = read_state()
    all_prof = state.get("snmp_profiles",[])
    prof_map = {p["name"]:p for p in all_prof}

    if profile_name and profile_name in prof_map:
        test_list = [prof_map[profile_name]]
    else:
        # auto: v3 first, then v2c
        test_list  = [p for p in all_prof if p.get("version")=="3"]
        test_list += [p for p in all_prof if p.get("version")!="3"]

    if not test_list:
        return api_err("No SNMP profiles configured.")

    has_snmpget = bool(shutil.which("snmpget"))

    for p in test_list:
        pname = p["name"]
        if not has_snmpget:
            try:
                import urllib.request
                n   = safe_name(pname)
                url = f"http://127.0.0.1:9116/snmp?target={ip}&module=cisco_resources&auth={n}"
                with urllib.request.urlopen(url, timeout=8) as resp:
                    if resp.status == 200:
                        return api_ok(f"Reachable via SNMP Exporter (profile: {pname})",
                                      profile_used=pname, method="snmp_exporter")
            except Exception:
                continue

        if p.get("version") == "3":
            cmd = ["snmpget","-v3",
                   "-u", p.get("v3_username","netwatch"), "-l","authPriv",
                   "-a", p.get("v3_auth_protocol","SHA"), "-A", p.get("v3_auth_password",""),
                   "-x", p.get("v3_priv_protocol","AES"), "-X", p.get("v3_priv_password",""),
                   "-t","3","-r","1", ip, "1.3.6.1.2.1.1.5.0"]
        else:
            cmd = ["snmpget","-v2c","-c", p.get("community","public"),
                   "-t","3","-r","1", ip, "1.3.6.1.2.1.1.5.0"]
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=8)
            if r.returncode == 0:
                sysname = r.stdout.strip().split("=")[-1].strip().strip('"')
                return api_ok(f"OK via '{pname}' — sysName: {sysname}",
                              profile_used=pname, sysname=sysname)
        except subprocess.TimeoutExpired:
            continue

    return jsonify({"ok":False,
                    "error":f"All {len(test_list)} profile(s) failed or timed out for {ip}"})

@app.route("/api/test-email", methods=["POST"])
def test_email():
    em   = read_state()["email"]
    host = em.get("smtp_host","")
    to   = em.get("default_critical","") or em.get("default_warnings","")
    if not host or not to:
        return api_err("Configure SMTP host and at least one recipient first.")
    msg = MIMEText("NetWatch test email — SMTP configuration verified.", "plain")
    msg["Subject"] = "[NetWatch] Test alert — SMTP OK"
    msg["From"]    = em.get("smtp_from","")
    msg["To"]      = to
    try:
        srv = smtplib.SMTP(host, int(em.get("smtp_port",587)), timeout=10)
        if em.get("smtp_tls", True): srv.starttls()
        if em.get("smtp_username") and em.get("smtp_password"):
            srv.login(em["smtp_username"], em["smtp_password"])
        srv.sendmail(em.get("smtp_from",""), [to], msg.as_string())
        srv.quit()
        return api_ok(f"Test email sent to {to}")
    except smtplib.SMTPAuthenticationError:
        return api_err("SMTP authentication failed.")
    except Exception as e:
        return api_err(f"Email failed: {e}")

@app.route("/api/prometheus/query", methods=["GET","POST"])
def prom_query():
    """Proxy a Prometheus instant query to avoid CORS issues."""
    import urllib.request, urllib.parse
    params = request.args.to_dict()
    if request.method == "POST":
        params.update(request.get_json(force=True, silent=True) or {})
    qs  = urllib.parse.urlencode(params)
    url = f"http://127.0.0.1:9090/api/v1/query?{qs}"
    try:
        with urllib.request.urlopen(url, timeout=10) as r:
            return app.response_class(r.read(), status=r.status,
                                      mimetype="application/json")
    except Exception as e:
        return api_err(f"Prometheus unreachable: {e}", 502)

@app.route("/api/prometheus/query_range", methods=["GET","POST"])
def prom_query_range():
    """Proxy a Prometheus range query."""
    import urllib.request, urllib.parse
    params = request.args.to_dict()
    if request.method == "POST":
        params.update(request.get_json(force=True, silent=True) or {})
    qs  = urllib.parse.urlencode(params)
    url = f"http://127.0.0.1:9090/api/v1/query_range?{qs}"
    try:
        with urllib.request.urlopen(url, timeout=15) as r:
            return app.response_class(r.read(), status=r.status,
                                      mimetype="application/json")
    except Exception as e:
        return api_err(f"Prometheus unreachable: {e}", 502)

@app.route("/api/prometheus/alerts", methods=["GET"])
def prom_alerts():
    """Proxy Prometheus active alerts."""
    import urllib.request
    try:
        with urllib.request.urlopen("http://127.0.0.1:9090/api/v1/alerts", timeout=5) as r:
            return app.response_class(r.read(), status=r.status,
                                      mimetype="application/json")
    except Exception as e:
        return api_err(f"Prometheus unreachable: {e}", 502)

@app.route("/api/prometheus/targets", methods=["GET"])
def prom_targets():
    """Proxy Prometheus scrape targets."""
    import urllib.request
    try:
        with urllib.request.urlopen("http://127.0.0.1:9090/api/v1/targets", timeout=5) as r:
            return app.response_class(r.read(), status=r.status,
                                      mimetype="application/json")
    except Exception as e:
        return api_err(f"Prometheus unreachable: {e}", 502)



def serve_dashboard():
    p = INSTALL_DIR / "netwatch-dashboard.html"
    if p.exists():
        return p.read_text(), 200, {"Content-Type":"text/html"}
    return f"<h2>netwatch-dashboard.html not found in {INSTALL_DIR}</h2>", 404

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="NetWatch Admin API v2")
    parser.add_argument("--host",  default="0.0.0.0")
    parser.add_argument("--port",  default=9199, type=int)
    parser.add_argument("--debug", action="store_true")
    args = parser.parse_args()
    log.info("NetWatch Admin API v2 on %s:%d", args.host, args.port)
    app.run(host=args.host, port=args.port, debug=args.debug)
