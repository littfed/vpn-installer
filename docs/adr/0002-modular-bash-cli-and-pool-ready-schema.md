# 0002: Modular Bash CLI and Pool-Ready Schema for Single-Node MVP

## Context
The installer must be immediately deployable on clean Linux servers without requiring compilation toolchains, Python runtimes, or complex orchestration frameworks, while supporting user management, configuration exports, and backups. Additionally, the system must not require breaking changes when transitioning from a single node to a multi-server pool.

## Decision
We implement Phase 1 as a modular Bash CLI suite (`vpn-installer.sh` installed as `/usr/local/bin/vpn`), orchestrating Docker Compose and generating configs atomically. User identities are decoupled into `users.json` with an atomic synchronization pipeline: validate with `sing-box check` -> write -> signal `SIGHUP`. The schema uses unified user UUIDs across all protocols, structured to be node-agnostic and ready for multi-server fleet synchronization in Phase 2.

## Consequences
- Immediate installation via a single command (`curl -sSL ... | bash`).
- Fast, idempotent user management (`vpn user add/suspend/delete/kick`).
- Hot configuration reloads in under 200 ms without crashing sing-box.
- Seamless forward compatibility with future multi-node pool architectures.
