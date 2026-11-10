# 0007: Deterministic Node Provisioning, Baseline Snapshots, and Deep Diagnostics

## Context
Deploying foreign exit nodes into the fleet previously relied on manual or ad-hoc orchestration, exposing fragility when operating on heterogeneous cloud VPS environments (differing network interface names `ens3`/`eth0`, differing default UFW/iptables policies, cloud-init DNS overrides, and kernel module availability). Furthermore, missing post-flight assertion checks led to silent degradation where containers ran but packets were dropped at the kernel `FORWARD` chain.

## Decision
1. **OS Baseline Snapshot & Rollback**:
   Before modifying any system state, the installer captures a complete baseline snapshot into `/opt/vpn-installer/backup/baseline-<timestamp>/` recording `iptables-save`, `ip6tables-save`, `ip route`, `ip rule`, `ufw status`, `resolv.conf`, `ss -tulpn`, and a JSON metadata descriptor. An automated command `vpn rollback-baseline [target]` restores the system to its pristine pre-installation state.

2. **Structured Logging & Post-Flight Assertions**:
   All installation activities are logged to `/opt/vpn-installer/install.log`. Every phase undergoes strict post-flight assertions validating that:
   - Docker and Docker Compose are functional.
   - Core containers (`sing-box-vpn`, `amneziawg`, `caddy-decoy`, `mtproto-proxy`) are healthy.
   - Sockets (80/TCP, 443/TCP, 443/UDP, 8443/TCP, 8443/UDP, 48291/UDP) are actively listening.
   - Kernel `net.ipv4.ip_forward = 1` and iptables FORWARD/MASQUERADE rules for `10.8.0.0/16` are active.
   Any assertion failure halts execution immediately with an explicit error dump rather than failing silently.

3. **Fleet Manager (`vpn node`)**:
   Fleet orchestration is centralized on the master server via `vpn node add <ip>`, `vpn node list`, and `vpn node remove`. The `vpn node add` command connects to target servers via SSH, executes verified installation, retrieves `manifest.json`, registers the node into `nodes.json`, and reloads the subscription endpoint atomically.

4. **Deep Diagnostics Suite (`vpn doctor`)**:
   Provides end-to-end node health verification across all subsystems with console and `--json` scoring, listing exact remediations for any detected issue.

## Consequences
- Single-command, deterministic fleet expansion with zero manual JSON editing.
- Instant recovery and rollback to clean OS state if a node needs decommissioning or troubleshooting.
- Immediate visibility into infrastructure errors through assertions, `install.log`, and `vpn doctor`.
