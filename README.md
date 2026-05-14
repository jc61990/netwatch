# NetWatch — Cisco IOS Monitoring Stack

Self-hosted network monitoring for Cisco IOS / IOS-XE devices.
Replaces Auvik. No Docker required — runs as native systemd services.

## Stack

| Component | Role | Port |
|---|---|---|
| SNMP Exporter | Polls devices via SNMP | 127.0.0.1:9116 |
| Prometheus | Metrics storage (90d) | 127.0.0.1:9090 |
| Alertmanager | Email routing | 127.0.0.1:9093 |
| Grafana | Dashboards | :3000 (public) |
| netwatch-api.py | Admin UI backend | :9199 |

## Component versions

Current pinned versions are in [`VERSION`](./VERSION).
This file is updated automatically by `install.sh` and `update.sh` — commit it after each upgrade to track version history in git.

```bash
# See what's installed
cat /opt/netwatch/VERSION

# Upgrade all components to the latest pins in update.sh
sudo bash /opt/netwatch/update.sh

# Upgrade a specific component
sudo bash /opt/netwatch/update.sh --snmp 0.28.0
sudo bash /opt/netwatch/update.sh --prom 2.54.0

# Then commit the version bump
git add VERSION && git commit -m "chore: upgrade prom=2.54.0"
```

## Quick start

```bash
# 1. Install everything
sudo bash install.sh

# 2. Start the admin API
pip3 install flask flask-cors
sudo python3 /opt/netwatch/netwatch-api.py &

# 3. Open the dashboard in a browser
#    http://<server>:9199/

# 4. Configure via the ⚙ Admin tab:
#    Devices → SNMP → Thresholds → Email → Reload Services
```

## Metrics collected

- Interface bandwidth & utilization (ifHCIn/OutOctets)
- Interface errors & drops (ifInErrors, ifInDiscards, ifOutDiscards)
- Interface oper/admin status (ifOperStatus)
- CPU 5-min average (cpmCPUTotal5minRev)
- Memory pool utilization (ciscoMemoryPool)
- Tunnel status (ifOperStatus filtered to Tunnel.*)
- EIGRP neighbor state & uptime (CISCO-EIGRP-MIB)
- Default route presence & next-hop (ipCidrRouteTable)

## Alert thresholds (defaults, adjustable in Admin UI)

| Alert | Default | Severity |
|---|---|---|
| CPU warning | 70% | warning |
| CPU critical | 90% | critical |
| Memory warning | 80% | warning |
| Interface utilization | 85% | warning |
| Input error rate | 5/s | warning |
| Drop rate | 10 pps | warning |
| Interface down | — | critical |
| Tunnel down | — | critical |
| EIGRP neighbor lost | — | critical |
| Default route gone | — | critical |

## Admin UI

Open the dashboard at `http://<server>:9199/`. The **⚙ Admin** tab connects to `netwatch-api.py` on port 9199.

| Panel | What you can set |
|---|---|
| Devices | Add/remove/edit monitored IPs, site names, hostnames; per-device SNMP test |
| SNMP | v2c community string or v3 username/auth/priv credentials |
| Thresholds | Sliders for all six alert thresholds |
| Email / SMTP | Host, port, credentials, warning and critical recipients, test send |

After any save, click **Reload Services** to apply without restarting.

## Files

```
VERSION                   Component version pins — commit after upgrades
netwatch-dashboard.html   Single-file dashboard + admin UI
install.sh                Non-interactive installer
scripts/
  netwatch-api.py         Flask admin API (port 9199)
  update.sh               Upgrade binaries; updates VERSION file
  add-device.sh           CLI: add a device to all scrape jobs
  remove-device.sh        CLI: remove a device by IP
  reload.sh               Validate + hot-reload Prometheus & Alertmanager
  verify.sh               Health check: services, ports, SNMP reachability
configs/
  prometheus/             prometheus.yml + cisco_alerts.yml
  snmp_exporter/          snmp.yml.example (real snmp.yml is gitignored)
  alertmanager/           alertmanager.yml.example
  grafana/                Datasource + dashboard provisioning
```

## Security

- Prometheus, Alertmanager, SNMP Exporter bind to `127.0.0.1` only
- Only Grafana (:3000) and the admin API (:9199) are externally reachable
- `snmp.yml` and `alertmanager.yml` (contain credentials) are gitignored — see `.gitignore`
- Restrict port 9199 to your management network via firewall

## Supported platforms

Ubuntu 22.04+ · Debian 12+ · RHEL 9 · Rocky Linux 9 · AlmaLinux 9
