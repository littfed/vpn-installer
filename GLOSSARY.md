# VPN Installer

A resilient, multi-protocol censorship-circumvention deployment suite and user management system designed to operate under strict DPI filtering (TSPU / RKN).

## Language

**Node**:
A physical or virtual server (VPS) running the vpn-installer engine and proxy daemons.
_Avoid_: Server, host, instance, box

**Protocol Stack**:
The combination of transport, encryption, and camouflage layers used to tunnel network traffic (e.g. VLESS-Reality, Hysteria 2).
_Avoid_: VPN type, connection method

**VLESS Reality**:
A lightweight TLS-camouflage transport that mimics an external legitimate HTTPS website by relaying handshakes and verifying short authentication keys.
_Avoid_: VLESS-XTLS, Reality VPN

**Decoy Site**:
A legitimate web server (Caddy/Nginx) presenting an authentic, innocuous website to scanners and censors on standard HTTP/HTTPS ports.
_Avoid_: Camouflage site, fake site, mask site

**WARP Egress**:
An outbound WireGuard interface routing traffic through Cloudflare's residential/CDN Anycast network to prevent datacenter ASN bans on AI services.
_Avoid_: WARP proxy, Cloudflare tunnel

**Port Hopping**:
A dynamic UDP port translation mechanism (via iptables/nftables) distributing traffic across a broad port range to defeat per-port UDP throttling.
_Avoid_: Port bouncing, dynamic ports

**Subscription**:
A centralized, token-authenticated delivery endpoint or profile file distributing server connection records to client applications.
_Avoid_: Config link, server list

**Identity**:
A user's unified credential set containing their canonical UUID, passwords, tokens, and AmneziaWG WireGuard keypair/tunnel IP across all enabled protocols on a node or pool.
_Avoid_: User account, client config, profile

**AmneziaWG**:
An obfuscated Layer 3 WireGuard variant injecting junk packets (Jc, Jmin, Jmax) and randomised packet headers (H1-H4) to defeat DPI signature analysis.
_Avoid_: AWG tunnel, WireGuard proxy, Amnezia VPN

**TUIC**:
A 0-RTT, high-concurrency proxy protocol running over native QUIC datagrams, used as a low-latency UDP transport complementary to Hysteria 2.
_Avoid_: TUIC proxy, QUIC VPN

**ShadowTLS**:
A camouflage proxy that transparently forwards initial TLS handshakes to a legitimate external domain before handing off authenticated streams to a local Shadowsocks-2022 backend.
_Avoid_: Shadow tunnel, TLS faker

**Emergency Egress**:
A CDN-fronted fallback transport (XHTTP / SplitHTTP / WebSocket) proxying traffic through public CDN edge nodes (e.g. Cloudflare) to survive direct IP address blacklisting by censors.
_Avoid_: CDN VPN, Cloudflare bypass, unblocker
