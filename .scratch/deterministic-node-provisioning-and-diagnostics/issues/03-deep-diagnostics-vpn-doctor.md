# 03: Deep Diagnostics Suite (`vpn doctor`)

**What to build:** An in-depth system diagnostic command `vpn doctor` that validates the entire node health from end-to-end: container lifecycles, network interfaces, open sockets, firewall rules, sing-box/caddy configuration validity, and egress routing, presenting clear green/red indicators and actionable remediations.

**Blocked by:** 02: Step-by-Step Installation Journal & Post-Flight Assertions

**Status:** completed

- [x] Command `vpn doctor` inspects all core subsystems:
  - Docker containers: `sing-box-vpn`, `amneziawg`, `caddy-decoy`, `mtproto-proxy`, `vpn-sub-server`
  - Network sockets: 80/TCP, 443/TCP, 443/UDP, 8443/TCP, 8443/UDP, 48291/UDP
  - AmneziaWG: `awg show` peer count, interface `awg0` IP (`10.8.0.1/16`)
  - Firewall & Routing: `net.ipv4.ip_forward`, iptables FORWARD rules for `10.8.0.0/16`, iptables NAT MASQUERADE
  - Config checks: validates `config.json` against sing-box binary, checks Caddy syntax
- [x] Outputs formatted CLI report with `[OK]`, `[WARN]`, and `[FAIL]` status lines
- [x] Supports `--json` flag for machine-readable health metrics
- [x] If any test fails, outputs actionable recovery steps (e.g., exact command to restart or apply missing rule)
