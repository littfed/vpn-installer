Status: ready-for-agent

# Specification: Core VPN Installer (Phase 1 Single-Node MVP)

## Problem Statement

Users and system administrators seeking reliable, private internet access from inside the Russian Federation face severe, continuously escalating censorship mechanisms enforced by TSPU (Technical Means of Counteracting Threats) and Roskomnadzor (RKN). 

Standard VPN protocols (WireGuard, OpenVPN, IPsec) and classic obfuscated proxies (vanilla Shadowsocks) are systematically blocked by DPI heuristics (packet size signatures, handshake opcodes, Shannon entropy analysis, and active probing). Furthermore, foreign AI services (OpenAI ChatGPT, Anthropic Claude, Google Gemini, Cursor) enforce blanket geographic and datacenter ASN blocks against hosting providers (Hetzner, OVH, DigitalOcean). At the same time, essential Russian domestic services (online banking, Gosuslugi, public infrastructure) reject foreign traffic and require domestic certificates. 

Existing open-source VPN scripts are fragile, monolithic, hard-to-maintain shell scripts that suffer from IP leaks, lack idempotent user lifecycle management, choose easily blocked SNI domains, and lack unified multi-protocol support with automatic failover and decoy web server integration.

## Solution

A robust, modular, single-command installation and lifecycle management suite (`vpn-installer`) that deploys and orchestrates a hardened, multi-protocol censorship-resistant proxy node on Ubuntu/Debian servers. 

The node leverages `sing-box` running in host-network Docker Compose as its core engine, simultaneously providing:
1. **VLESS + XTLS Reality (Vision)** on port `443/TCP` as the primary censorship-proof transport.
2. **Hysteria 2** on port `443/UDP` with port hopping (`20000-30000/UDP`) for high-loss mobile networks.
3. **Shadowsocks-2022** on high ports as a lightweight fallback.
4. **Cloudflare WARP Egress** directly inside sing-box to transparently route all AI traffic through clean Cloudflare Anycast IPs without client-side overhead.
5. **Caddy Web Server** on port `80/TCP` (for automated Let's Encrypt HTTP-01 challenges) and `127.0.0.1:8443` (serving an authentic decoy site for regular browsers and scanning probes forwarded by Reality).
6. **MTProto Proxy (`mtg` v2)** on port `8443/TCP` with Fake-TLS for zero-install Telegram access.
7. **Idempotent CLI User Management** (`vpn user add/list/show/suspend/delete/kick`) backed by decoupled JSON storage and zero-downtime hot reloads via SIGHUP.
8. **Adaptive Subscription Delivery** providing client-specific profiles (Clash.Meta YAML, Sing-box JSON with split-tunneling, or Base64 URI lists) based on incoming User-Agent headers.

## User Stories

1. As a system administrator, I want to install the entire VPN stack via a single shell command on a fresh Ubuntu or Debian VPS, so that I can set up a secure proxy in less than two minutes without manual toolchain compilation.
2. As a system administrator, I want Docker and Docker Compose to be automatically installed if missing, so that I don't have to troubleshoot container engine dependencies manually.
3. As a user in Russia, I want my primary connection to use VLESS Reality on port 443/TCP, so that my traffic is indistinguishable from standard HTTPS traffic to legitimate international services and immune to TSPU DPI filtering.
4. As a user on mobile cellular networks (LTE/5G), I want Hysteria 2 with Port Hopping, so that my connection maintains high throughput and low latency even during aggressive UDP throttling and packet loss.
5. As an AI developer and power user, I want all requests to OpenAI, Claude, Gemini, and Cursor to exit through Cloudflare WARP on the server, so that I never get blocked by datacenter ASN blacklists or Cloudflare Turnstile captchas.
6. As a user in Russia, I want domestic services (Gosuslugi, Russian banks, Ozon, Yandex) to route directly through my local connection without VPN, so that banking apps and state portals remain fully accessible without certificate errors or geo-blocks.
7. As a privacy-conscious user, I want my DNS requests to be protected against ISP DNS poisoning and eavesdropping, so that my provider cannot track my browsing history or spoof DNS responses.
8. As a Telegram user, I want an MTProto Proxy link with Fake-TLS, so that I can connect Telegram directly in one click on any device without installing a separate VPN application.
9. As a system administrator, I want port 443 to serve a legitimate decoy website to any unauthorized probe or web browser, so that active probing by censors reveals an innocuous, functional website with a valid Let's Encrypt certificate.
10. As a system administrator, I want Caddy to handle Let's Encrypt certificate acquisition via HTTP-01 on port 80, so that certificate issuance and renewal never conflict with VLESS Reality on port 443.
11. As a system administrator, I want to add new users via a simple command (`vpn user add <name>`), so that unified credentials (UUID, passwords, sub-keys, and TG secrets) are generated instantly.
12. As a system administrator, I want to view all user connection links and console QR codes via `vpn user show <name>`, so that I can share them easily with friends or team members.
13. As a system administrator, I want to temporarily suspend a user's access via `vpn user suspend <name>` without deleting their identity, so that I can pause accounts without forcing them to re-import configs later.
14. As a system administrator, I want to immediately terminate active connections of a suspended or deleted user via `vpn user kick <name>`, so that revoked users cannot hold existing TCP sessions open.
15. As a user with multiple client apps (Clash.Meta, Sing-box, Streisand, v2rayNG), I want a single subscription link that dynamically returns the exact configuration format required by my app, so that I don't have to manually convert configuration files.
16. As a system administrator, I want configuration reloads to be hot and atomic using SIGHUP with prior validation via `sing-box check`, so that a typo in user configuration never causes downtime or crashes the running proxy.
17. As a system administrator, I want outbound SMTP ports (25, 465, 587) and BitTorrent traffic to be blocked on the node, so that my server is never terminated by cloud hosting providers due to spam abuse or DMCA copyright notices.
18. As a system administrator, I want a backup command (`vpn backup`), so that I can export all node identities, keys, and configurations into an archive and restore them on a new server in seconds with `vpn restore`.
19. As a system administrator, I want an interactive prompt offering host hardening via the `littfed/server-setup` project, so that I can harden SSH and OS security without risking an accidental lockout.
20. As a system administrator, I want a verification command (`vpn test-leak`), so that I can audit the node for IP, DNS, and WebRTC leaks directly from the terminal.
21. As a system administrator, I want a clean uninstaller command (`vpn uninstall`), so that I can remove all containers, firewall rules, and binaries completely when decommissioning the node.

## Implementation Decisions

### Modules to Build
1. **`scripts/install.sh`**: Entrypoint bootstrap installer script. Validates OS, installs Docker and system packages, pulls containers, writes `/opt/vpn-installer/` structure, and links the CLI.
2. **`bin/vpn`**: Main modular Bash CLI command suite providing subcommands:
   - `vpn user [add|list|show|suspend|enable|delete|kick]`
   - `vpn backup [create|restore]`
   - `vpn system [status|harden|test-leak]`
   - `vpn service [start|stop|restart|reload|logs]`
   - `vpn uninstall`
3. **`templates/config.json.template`**: Sing-box production server configuration template with inbounds (VLESS-Reality 443 TCP, Hysteria 2 443 UDP, Shadowsocks-2022 9443 TCP/UDP), outbounds (direct, WARP wireguard, block), and L7 routing rules for AI domains.
4. **`templates/docker-compose.yml`**: Docker Compose definition running `sing-box` (host network, NET_ADMIN), `mtg` (host network), and `caddy` (ports 80:80, 127.0.0.1:8443:8443).
5. **`templates/Caddyfile`**: Caddy configuration managing port 80 HTTP-01 challenges, reverse proxying `/sub/<token>` subscription delivery, and serving the static decoy site.
6. **`templates/html/`**: Pre-packaged clean HTML/CSS static website template for the decoy site.
7. **`scripts/generate-warp-keys.py`**: Standalone zero-dependency Python script to register with Cloudflare WARP API and generate WireGuard private key and 3-byte client ID (`reserved`).
8. **`scripts/sub-server.py`**: Minimal Python or shell subscription responder that detects client `User-Agent` and renders Clash.Meta YAML, Sing-box JSON, or Base64 URI lists on demand.

### Architecture & Schemas
- **Installation Root**: `/opt/vpn-installer/` (chmod 700).
- **`manifest.json`**: Node metadata, Reality keypair (PrivateKey, PublicKey, ShortId), Hysteria passwords, server public IP, and decoy domain.
- **`users.json`**: JSON database storing user identities:
  ```json
  {
    "users": [
      {
        "name": "alice",
        "uuid": "e0a75d9e-29f1-4db4-bb14-e0c1f516a5b3",
        "password": "generated-password",
        "sub_key": "base64-shadowsocks-key",
        "tg_secret": "ee000102...",
        "sub_token": "random-32char-hex-token",
        "status": "active",
        "created_at": "2026-11-10T10:00:00Z"
      }
    ]
  }
  ```
- **Sync & Hot Reload Pipeline**:
  `users.json` modified -> render temporary `/opt/vpn-installer/config.json.tmp` -> validate with `docker compose exec sing-box sing-box check -c /etc/sing-box/config.json.tmp` -> atomic `mv` to `config.json` -> send `docker compose exec sing-box kill -HUP 1`.

## Testing Decisions

### What Makes a Good Test
- Tests must verify observable system behavior from the outside (exit codes, valid JSON output, open ports, successful handshake responses, and correct file system state), never internal script implementation mechanics.
- Every CLI subcommand must have idempotency checks (running an add/install command twice should not corrupt configuration).

### Modules and Interfaces Tested
1. **CLI User Management Suite**:
   - `vpn user add testuser`: creates valid identity in `users.json`, updates `config.json`, passes `sing-box check`.
   - `vpn user suspend testuser`: sets status to `suspended`, removes user from active `config.json`, triggers SIGHUP.
   - `vpn user enable testuser`: restores user to `config.json`.
   - `vpn user delete testuser`: purges identity from `users.json` and `config.json`.
2. **Configuration Synthesizer**:
   - Validates that synthesized `config.json` always passes schema validation via `sing-box check`.
   - Validates that Cloudflare WARP outbound contains valid base64 keys and 3-byte reserved integers.
3. **Firewall & Port Multiplexing**:
   - Verifies port 443/TCP (Reality), port 443/UDP (Hysteria 2), port 80/TCP (Caddy), and port 8443/TCP (MTG) are listening.
   - Verifies iptables port hopping rule redirects `20000:30000 UDP` to `443 UDP`.
4. **Decoy Web Server & Fallback**:
   - Verifies unauthenticated HTTP GET to port 80 returns HTTP 200 or 301.
   - Verifies unauthenticated TLS ClientHello to port 443 is forwarded to Caddy and responds with HTTP 200 without exposing proxy headers.
5. **Subscription Formatter**:
   - Verifies `curl -H "User-Agent: Clash.Meta" https://domain/sub/<token>` returns valid Clash YAML.
   - Verifies `curl -H "User-Agent: sing-box" https://domain/sub/<token>` returns valid Sing-box JSON with split-tunneling rules.
   - Verifies generic `curl` returns valid Base64 URI list.

## Out of Scope

- Multi-node distributed fleet orchestration and automatic inter-server mesh (deferred to Phase 2).
- Web-based graphical administration dashboard (the project is strictly CLI-driven in Phase 1).
- Direct billing, payment gateway integration, and commercial accounting.
- Kernel-level custom DKMS module compilation for AmneziaWG (AWG in Phase 1 is provided via containerized or standalone wireguard configurations; native sing-box protocols VLESS Reality and Hysteria 2 are the primary focus).

## Further Notes

- All configuration templates and schemas strictly conform to [GLOSSARY.md](file:///C:/mimocode/vpn-installer/GLOSSARY.md) and ADRs 0001–0005.
- The project repository is hosted at `https://github.com/littfed/vpn-installer`.
