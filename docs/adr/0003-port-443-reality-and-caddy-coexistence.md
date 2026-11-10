# 0003: Port 443 Coexistence for VLESS Reality and Caddy Decoy Site

## Context
Both VLESS Reality and the decoy web server need to handle port 443/TCP. Furthermore, the decoy server requires automated Let's Encrypt certificate acquisition and renewal without colliding with Reality or exposing proxy artifacts to censors.

## Decision
Sing-box VLESS Reality binds to external port `443/TCP`. Unauthenticated connections (regular browsers and scanning probes) are forwarded locally via Reality's fallback handshake mechanism to Caddy listening on `127.0.0.1:8443`. Caddy additionally binds to external port `80/TCP` exclusively for ACME HTTP-01 challenges, enabling automated, zero-touch Let's Encrypt issuance and renewal without needing direct ownership of port 443.

## Consequences
- Legitimate HTTPS visitors and probe scanners receive authentic TLS handshakes and valid Let's Encrypt certificates.
- Active probes cannot distinguish the proxy from a real web server.
- Certificate renewals never interrupt or conflict with active VLESS Reality proxy sessions.
