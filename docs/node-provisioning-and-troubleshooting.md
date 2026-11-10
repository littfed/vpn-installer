# Node Provisioning and Troubleshooting Runbook

This guide describes how to add, diagnose, and maintain nodes in the vpn-installer fleet.

---

## 1. Automated Fleet Node Provisioning

To provision and register a new foreign exit node into the fleet from the master server (`zzz.littfed.ru`):

```bash
vpn node add <REMOTE_IP> [--name <NODE_NAME>] [--user root] [--password <PASSWORD> | --key <KEY_PATH>] [--port 22]
```

### What `vpn node add` performs automatically:
1. Connects to the remote target host over SSH.
2. Performs pre-flight verification of OS (Ubuntu 22.04/24.04, Debian 11/12) and privileges.
3. Automatically takes a pre-install baseline snapshot of the clean OS state (`iptables`, `ip route`, `ufw`, `resolv.conf`).
4. Installs and configures Docker Engine, Sing-Box, AmneziaWG, Caddy decoy, and MTProto proxy.
5. Executes post-flight assertion checks for all listening sockets, interfaces (`awg0`), and forwarding rules (`10.8.0.0/16`).
6. Fetches the remote node's `manifest.json`.
7. Registers the new node into `/opt/vpn-installer/nodes.json` on the master.
8. Reloads the adaptive subscription server so clients immediately see the new node across Web Portal, AmneziaWG ZIP, Sing-Box, and Clash endpoints.

---

## 2. Fleet Node Inspection and Management

### List Active Nodes:
```bash
vpn node list
# Or machine-readable JSON:
vpn node list --json
```

### Remove a Node:
```bash
vpn node remove <NODE_NAME_OR_IP>
```

### Run Synthetic Probe from Russia:
```bash
vpn node test [--node <NODE_NAME>]
```

---

## 3. Node Self-Diagnostics (`vpn doctor`)

Run `vpn doctor` on any node to perform an exhaustive health audit:

```bash
vpn doctor
# Or output JSON metrics:
vpn doctor --json
```

### Inspected subsystems:
- **System**: Kernel IPv4 forwarding status.
- **Config**: Validity of `manifest.json`, `config.json`, and TLS certificates.
- **Containers**: Status of `sing-box-vpn`, `amneziawg`, `caddy-decoy`, and `mtproto-proxy`.
- **Sockets**: Verification of 80/TCP, 443/TCP, 443/UDP, 8443/TCP, 8443/UDP, and 48291/UDP.
- **AmneziaWG**: Interface `awg0` status, IP assignment (`10.8.0.1/16`), and peer configurations.
- **Firewall**: Validation of `iptables FORWARD` for `10.8.0.0/16`, `MASQUERADE`, and port hopping (`20000:30000/UDP`).

---

## 4. OS Baseline Snapshot & Rollback

### Capture a Manual Baseline Snapshot:
```bash
vpn baseline snapshot [TAG]
```

### List Available Snapshots:
```bash
vpn baseline list
vpn baseline show [TAG|latest]
```

### Rollback to Clean Baseline OS State:
```bash
vpn rollback-baseline [TAG|latest]
# Or via installer:
/opt/vpn-installer/scripts/install.sh --rollback
```

Restores initial `iptables-save`, `ip6tables-save`, UFW configuration, and sysctl settings, halting any VPN containers.

---

## 5. Troubleshooting Common Issues

### Issue: AmneziaWG client connects but has no Internet
- Run `vpn doctor` and check `[Firewall] FORWARD Rule 10.8.0.0/16`.
- If UFW has `DEFAULT_FORWARD_POLICY="DROP"`, ensure the following rule is in place:
  ```bash
  iptables -I FORWARD 1 -s 10.8.0.0/16 -j ACCEPT
  iptables -I FORWARD 2 -d 10.8.0.0/16 -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
  ```
- Or simply run `/opt/vpn-installer/scripts/firewall-setup.sh`.

### Issue: Sing-Box exits on startup
- Check container logs: `docker logs sing-box-vpn`.
- Validate configuration against binary:
  ```bash
  docker compose exec -T sing-box sing-box check -c /etc/sing-box/config.json
  ```
- Ensure certificates exist in `/opt/vpn-installer/certs/fullchain.pem` and `/opt/vpn-installer/certs/privkey.pem`.
