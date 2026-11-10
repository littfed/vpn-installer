# 0004: Host Hardening and Integration with server-setup

## Context
Deploying public VPN nodes exposes servers to continuous brute-force attacks, port scanning, and abuse reports (e.g. SMTP spam or BitTorrent DMCA complaints). However, modifying host SSH ports or disabling password authentication without explicit confirmation risks locking administrators out of their VPS.

## Decision
The installer automatically enforces non-destructive network baseline hardening: UFW firewall configuration (allowing only 80, 443, 8443, and the UDP Port Hopping range 20000-30000) and sing-box L7 outbound blocks for SMTP (ports 25, 465, 587) and BitTorrent traffic. Advanced system hardening (SSH key-only auth, custom SSH ports, fail2ban, unattended-upgrades) is presented as an interactive prompt during setup, with support for delegating deep OS provisioning to the `littfed/server-setup` repository.

## Consequences
- Prevents VPS termination by cloud providers due to spam abuse or torrent notices.
- Zero risk of locking out administrators during automated installation.
- Clean separation between proxy container lifecycle and underlying OS security hardening.
