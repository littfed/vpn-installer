# 01: OS Baseline Snapshot & Rollback Engine

**What to build:** An automated snapshot mechanism in the installer that captures the complete baseline network and firewall state of a fresh operating system before applying any changes, along with a rollback command `vpn rollback-baseline` to restore the pristine state if needed.

**Blocked by:** None (can start immediately)

**Status:** completed

- [x] Before modifying any system settings, `scripts/install.sh` saves the initial OS state into `/opt/vpn-installer/backup/baseline-<timestamp>/`
- [x] Baseline snapshot captures `iptables-save`, `ip6tables-save`, `ip route show`, `ip rule show`, `ufw status verbose`, `/etc/resolv.conf`, and `ss -tulpn`
- [x] A metadata file `baseline.json` records OS release, kernel version, default gateway interface, and timestamp
- [x] Command `vpn rollback-baseline` (and `scripts/install.sh --rollback`) restores the captured iptables/ufw state and network rules, verifying clean restoration
- [x] Unit/integration tests verify snapshot creation and successful rollback behavior
