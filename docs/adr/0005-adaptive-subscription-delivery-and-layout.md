# 0005: Adaptive Subscription Delivery and Filesystem Layout

## Context
Clients connect from diverse operating systems using heterogeneous proxy applications (Clash.Meta/Mihomo, Sing-box TUN, Streisand, v2rayNG, NekoBox), each expecting different configuration formats (YAML, JSON, or Base64 URI lists). Hardcoding a single configuration format forces users to convert files manually. Additionally, system files must follow a predictable, isolated hierarchy on the host.

## Decision
The installation resides in `/opt/vpn-installer/` with CLI executable symlinked to `/usr/local/bin/vpn`. When subscription delivery is enabled (`--enable-sub-web`), Caddy serves `/sub/<token>` and uses dynamic User-Agent sniffing to return Clash.Meta YAML, Sing-box JSON with pre-configured split-tunneling, or Base64 URI lists automatically, with optional manual query override (`?format=clash`).

## Consequences
- Single subscription link works seamlessly across iOS, Android, Windows, macOS, and Linux clients.
- Clean application isolation under `/opt/vpn-installer/` adhering to the Filesystem Hierarchy Standard.
- Non-breaking user experience when importing profiles into different client apps.
