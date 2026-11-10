# 04: Automated Fleet Provisioning & Join (`vpn node add`)

**What to build:** A single deterministic command `vpn node add <ip>` on the master server that automatically connects to a remote target server over SSH, executes a validated installation with baseline snapshots and assertions, retrieves the node manifest, updates the master `nodes.json` registry, and verifies connectivity.

**Blocked by:** 01: OS Baseline Snapshot & Rollback Engine, 02: Step-by-Step Installation Journal & Post-Flight Assertions, 03: Deep Diagnostics Suite (`vpn doctor`)

**Status:** completed

- [x] Command implemented in CLI:
  `vpn node add <ip> [--name <node-name>] [--user <user>] [--password <pwd> | --key <path>] [--port <ssh-port>]`
- [x] Connects to remote host via SSH, verifies root/sudo access and supported OS (Ubuntu/Debian)
- [x] Uploads installer assets and runs `scripts/install.sh` on the remote host with baseline snapshot and post-flight assertions
- [x] Downloads generated `/opt/vpn-installer/manifest.json` from the new node
- [x] Atomically registers the new node into `/opt/vpn-installer/nodes.json` on the master server
- [x] Restarts the subscription server (`vpn-sub-server`) and executes a canary probe against the new node to verify end-to-end reachability
- [x] Supports `vpn node list` and `vpn node remove <name>` to inspect and manage fleet nodes cleanly
