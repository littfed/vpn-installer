# 02: Step-by-Step Installation Journal & Post-Flight Assertions

**What to build:** Comprehensive, structured logging of every installer phase to `/opt/vpn-installer/install.log` combined with strict post-flight assertions after each service is configured. If any assertion fails (e.g., listening socket not found, container exiting, FORWARD chain dropping traffic), the installer halts immediately with a human-readable diagnostic report instead of failing silently.

**Blocked by:** 01: OS Baseline Snapshot & Rollback Engine

**Status:** completed

- [x] All installation commands, outputs, and errors are redirected to `/opt/vpn-installer/install.log` while showing a clean high-level progress spinner/steps in stdout
- [x] Explicit post-flight assertion checks are added after each component:
  - Docker daemon and compose availability
  - AmneziaWG interface `awg0` up with correct subnet and listening on 48291/UDP
  - Sing-box container running and validated via `sing-box check`
  - Caddy decoy container running and bound to port 80/TCP and 127.0.0.1:8443
  - MTProto proxy container running and bound to 8443/TCP
  - Kernel packet forwarding enabled and iptables FORWARD rules active for `10.8.0.0/16`
- [x] If any assertion fails, the installer logs the failure, prints the exact error context from `install.log`, and exits with code 1 without continuing broken steps
- [x] Installer supports `--verbose` flag to mirror full log stream to console
