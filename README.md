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

## Quick start

```bash
# 1. Install everything
sudo bash install.sh

# 2. Start the admin API
pip3 install flask flask-cors
sudo python3 /opt/netwatch/netwatch-api.py &

# 3. Open the dashboard
# Copy netwatch-dashboard.html to /opt/netwatch/
# Then visit http://<server>:9199/

# 4. Configure via the ⚙ Admin tab
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

## Alert thresholds (defaults)

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

Open `netwatch-dashboard.html` in a browser. The **⚙ Admin** tab connects to `netwatch-api.py` on port 9199.

- **Devices** — add/remove/edit monitored devices, test SNMP per device
- **SNMP** — set v2c community string or v3 credentials
- **Thresholds** — sliders for all alert thresholds
- **Email / SMTP** — configure recipients and test delivery

After any save, click **Reload Services** to apply changes without restarting.

## Files

```
netwatch-dashboard.html   Single-file dashboard + admin UI
install.sh                Non-interactive installer
scripts/
  netwatch-api.py         Flask admin API (port 9199)
  add-device.sh           CLI: add a device to all scrape jobs
  remove-device.sh        CLI: remove a device by IP
  reload.sh               Validate + hot-reload Prometheus & Alertmanager
  verify.sh               Health check: services, ports, SNMP reachability
  update.sh               Update binaries (--snmp / --prom / --am flags)
configs/
  prometheus/             prometheus.yml + cisco_alerts.yml
  snmp_exporter/          snmp.yml.example (real snmp.yml is gitignored)
  alertmanager/           alertmanager.yml.example
  grafana/                Datasource + dashboard provisioning
```

## Security notes

- Prometheus, Alertmanager, and SNMP Exporter bind to `127.0.0.1` only
- Only Grafana (:3000) and the admin API (:9199) are externally reachable
- `snmp.yml` and `alertmanager.yml` (contain credentials) are gitignored
- Restrict `:9199` to your management network via firewall

## Supported platforms

Ubuntu 22.04+ · Debian 12+ · RHEL 9 · Rocky Linux 9 · AlmaLinux 9
