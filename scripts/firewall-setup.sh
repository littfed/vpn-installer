#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

VPN_DIR="${VPN_DIR:-/opt/vpn-installer}"
SKIP_ROOT_CHECK="${SKIP_ROOT_CHECK:-0}"
TEARDOWN=0

for arg in "$@"; do
    case "$arg" in
        --teardown|-d)
            TEARDOWN=1
            ;;
    esac
done

detect_ssh_port() {
    if [[ -n "${SSH_PORT:-}" ]]; then
        echo "$SSH_PORT"
        return
    fi

    # Try sshd_config
    local config_files=("/etc/ssh/sshd_config")
    if [[ -d "/etc/ssh/sshd_config.d" ]]; then
        for f in /etc/ssh/sshd_config.d/*.conf; do
            [[ -f "$f" ]] && config_files+=("$f")
        done
    fi

    for cf in "${config_files[@]}"; do
        if [[ -f "$cf" ]]; then
            local port_match
            port_match=$(grep -E -i '^[[:space:]]*Port[[:space:]]+[0-9]+' "$cf" 2>/dev/null | tail -n1 | awk '{print $2}' || true)
            if [[ -n "$port_match" && "$port_match" =~ ^[0-9]+$ ]]; then
                echo "$port_match"
                return
            fi
        fi
    done

    # Try SSH_CONNECTION / SSH_CLIENT
    if [[ -n "${SSH_CONNECTION:-}" ]]; then
        local s_port
        s_port=$(echo "$SSH_CONNECTION" | awk '{print $4}' 2>/dev/null || true)
        if [[ -n "$s_port" && "$s_port" =~ ^[0-9]+$ ]]; then
            echo "$s_port"
            return
        fi
    fi

    echo "22"
}

teardown_firewall() {
    echo "[+] Tearing down vpn-installer firewall and port-hopping rules..."

    # Teardown iptables NAT PREROUTING redirect
    if command -v iptables >/dev/null 2>&1; then
        while iptables -t nat -C PREROUTING -p udp --dport 20000:30000 -j REDIRECT --to-ports 443 2>/dev/null; do
            iptables -t nat -D PREROUTING -p udp --dport 20000:30000 -j REDIRECT --to-ports 443 2>/dev/null || break
        done
        while iptables -t nat -C POSTROUTING -s 10.8.0.0/16 -j MASQUERADE 2>/dev/null; do
            iptables -t nat -D POSTROUTING -s 10.8.0.0/16 -j MASQUERADE 2>/dev/null || break
        done
        while iptables -t nat -C POSTROUTING -s 10.8.0.0/24 -j MASQUERADE 2>/dev/null; do
            iptables -t nat -D POSTROUTING -s 10.8.0.0/24 -j MASQUERADE 2>/dev/null || break
        done
    fi

    if command -v ip6tables >/dev/null 2>&1; then
        while ip6tables -t nat -C PREROUTING -p udp --dport 20000:30000 -j REDIRECT --to-ports 443 2>/dev/null; do
            ip6tables -t nat -D PREROUTING -p udp --dport 20000:30000 -j REDIRECT --to-ports 443 2>/dev/null || break
        done
    fi

    # Teardown UFW rules
    if command -v ufw >/dev/null 2>&1; then
        ufw delete allow 80/tcp 2>/dev/null || true
        ufw delete allow 443/tcp 2>/dev/null || true
        ufw delete allow 443/udp 2>/dev/null || true
        ufw delete allow 8443/tcp 2>/dev/null || true
        ufw delete allow 8443/udp 2>/dev/null || true
        ufw delete allow 48291/udp 2>/dev/null || true
        ufw delete allow 20000:30000/udp 2>/dev/null || true
    fi

    echo "[✓] Firewall rules cleared."
}

setup_firewall() {
    local ssh_port
    ssh_port=$(detect_ssh_port)
    echo "[+] Detected SSH port: ${ssh_port}"

    # 1. Setup UFW rules if ufw is installed
    if command -v ufw >/dev/null 2>&1; then
        echo "[+] Configuring UFW rules..."
        ufw default deny incoming 2>/dev/null || true
        ufw default allow outgoing 2>/dev/null || true

        # Essential ports: SSH, HTTP, HTTPS/VLESS, Hysteria2, MTProto, Port Hopping Range
        ufw allow "${ssh_port}/tcp" 2>/dev/null || true
        ufw allow 80/tcp 2>/dev/null || true
        ufw allow 443/tcp 2>/dev/null || true
        ufw allow 443/udp 2>/dev/null || true
        ufw allow 8443/tcp 2>/dev/null || true
        ufw allow 8443/udp 2>/dev/null || true
        ufw allow 48291/udp 2>/dev/null || true
        ufw allow 20000:30000/udp 2>/dev/null || true

        # Enable UFW non-interactively if inactive
        ufw --force enable 2>/dev/null || true
    fi

    # 2. Setup iptables Port Hopping rule (20000:30000/UDP -> 443)
    if command -v iptables >/dev/null 2>&1; then
        echo "[+] Configuring iptables UDP port hopping (20000:30000 -> 443)..."
        if ! iptables -t nat -C PREROUTING -p udp --dport 20000:30000 -j REDIRECT --to-ports 443 2>/dev/null; then
            iptables -t nat -A PREROUTING -p udp --dport 20000:30000 -j REDIRECT --to-ports 443
        fi
    fi

    if command -v ip6tables >/dev/null 2>&1; then
        if ! ip6tables -t nat -C PREROUTING -p udp --dport 20000:30000 -j REDIRECT --to-ports 443 2>/dev/null; then
            ip6tables -t nat -A PREROUTING -p udp --dport 20000:30000 -j REDIRECT --to-ports 443 2>/dev/null || true
        fi
    fi

    # 3. Enable IP forwarding and NAT MASQUERADE for AmneziaWG (10.8.0.0/16)
    sysctl -w net.ipv4.ip_forward=1 >/dev/null 2>&1 || true

    if command -v iptables >/dev/null 2>&1; then
        local def_if
        def_if=$(ip route 2>/dev/null | grep -E '^default' | awk '{print $5}' | head -n1 || true)
        if [[ -z "$def_if" ]]; then
            def_if="eth0"
        fi
        while iptables -t nat -C POSTROUTING -s 10.8.0.0/24 -o "$def_if" -j MASQUERADE 2>/dev/null; do
            iptables -t nat -D POSTROUTING -s 10.8.0.0/24 -o "$def_if" -j MASQUERADE 2>/dev/null || break
        done
        if ! iptables -t nat -C POSTROUTING -s 10.8.0.0/16 -o "$def_if" -j MASQUERADE 2>/dev/null; then
            iptables -t nat -A POSTROUTING -s 10.8.0.0/16 -o "$def_if" -j MASQUERADE 2>/dev/null || true
        fi
    fi

    # 4. Persist iptables rules if tool available
    if command -v netfilter-persistent >/dev/null 2>&1; then
        netfilter-persistent save 2>/dev/null || true
    elif [[ -d /etc/iptables ]] && command -v iptables-save >/dev/null 2>&1; then
        iptables-save > /etc/iptables/rules.v4 2>/dev/null || true
    fi

    echo "[✓] Firewall and Port Hopping configuration applied."
}

if [[ "$TEARDOWN" -eq 1 ]]; then
    teardown_firewall
else
    setup_firewall
fi
