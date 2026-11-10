# 0001: Sing-box in Docker Compose as Core Multi-Protocol Engine

## Context
Deploying censorship-resistant proxies in Russia requires combining multiple protocols (VLESS Reality for DPI immunity, Hysteria 2 for lossy mobile networks, Shadowsocks-2022 as fallback) and preventing datacenter IP bans from AI providers (OpenAI, Claude). Managing disparate native systemd daemons creates dependency conflicts, port fragmentation, and brittle rollbacks.

## Decision
We run `sing-box` inside Docker Compose in `network_mode: host` with `NET_ADMIN` capability. Sing-box acts as the unified multi-inbound proxy engine and hosts an integrated Cloudflare WARP WireGuard outbound (`type: wireguard`) to transparently route AI domains (`geosite-openai`, `geosite-anthropic`) through clean Cloudflare Anycast IPs without client-side overhead.

## Consequences
- Single container instance serves VLESS-Reality (TCP 443), Hysteria 2 (UDP 443), and Shadowsocks-2022 (TCP/UDP 9443).
- Zero host runtime contamination; atomic updates via Docker images.
- Host network mode eliminates Docker bridge NAT overhead and allows direct iptables Port Hopping.
