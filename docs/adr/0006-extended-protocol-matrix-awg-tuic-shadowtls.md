# 0006: Extended Protocol Matrix: TUIC v5, AmneziaWG, ShadowTLS, and Emergency Egress

## Context
Operating under advancing TSPU filtering in Russia requires expanding beyond VLESS Reality and Hysteria 2. Users need support for home routers (Keenetic, OpenWrt), low-latency 0-RTT mobile UDP connections, deep TLS camouflage, and survival under direct IP address blacklists. Meanwhile, legacy enterprise VPN protocols like Cisco AnyConnect (OpenConnect) are actively targeted and degraded by TSPU DPI signatures.

## Decision
1. **Adopt TUIC v5 in Core**: Enable TUIC v5 natively inside the existing `sing-box` container on port `8443/UDP`, using Google BBR congestion control and reusing the node's TLS certificate with SHA-256 fingerprint. Re-use canonical User Identity `uuid` and `password`. Integrate into `proxy-auto` / `AUTO-FASTEST` and canary monitoring.
2. **Modular AmneziaWG (AWG)**: Introduce AmneziaWG via a containerized `amneziawg-go` service in Docker Compose (`network_mode: host`, `NET_ADMIN`). Generate cryptographically randomized obfuscation parameters (AWG 2.0 / 3.1: `H1–H4`, `Jc`, `Jmin/Jmax`, `S1/S2`) per node. Store Curve25519 keypairs and `10.8.0.X/32` IPs in `users.json`. Serve configurations via `?format=awg` and CLI QR/conf export. Probe health from Russia via synthetic UDP handshake packets.
3. **Emergency Egress (CDN)**: Reserve XHTTP / SplitHTTP as a CDN-fronted emergency fallback requiring a Cloudflare-proxied domain to survive node IP blacklisting.
4. **ShadowTLS v3 + SS-2022**: Implement ShadowTLS v3 as an ultra-covert fallback relaying real TLS handshakes to white-listed SNI targets.
5. **Exclude OpenConnect (ocserv)**: Formally reject OpenConnect (`wontfix`) due to inherent TLS/DTLS signature vulnerability to TSPU DPI and lack of anti-censorship camouflage.
6. **Two-Phase Delivery**: Roll out implementation in two distinct stages: Phase 1 (TUIC v5 zero-daemon core integration) followed by Phase 2 (AmneziaWG container and router subscription export).

## Consequences
- TUIC v5 adds zero daemon overhead, leveraging the existing sing-box process.
- AmneziaWG operates as an isolated containerized service, preserving host kernel stability.
- Subscription delivery cleanly separates application proxy configs (Clash, sing-box) from native L3 wireguard configs (`?format=awg`).
- Development efforts remain focused on high-resilience protocols rather than obsolete corporate VPN protocols.
