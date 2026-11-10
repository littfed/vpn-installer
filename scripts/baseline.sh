#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

VPN_DIR="${VPN_DIR:-/opt/vpn-installer}"
BACKUP_DIR="${VPN_DIR}/backup"
SKIP_ROOT_CHECK="${SKIP_ROOT_CHECK:-0}"

run_python() {
    if command -v python3 >/dev/null 2>&1 && python3 -c "import sys" >/dev/null 2>&1; then
        python3 "$@"
    elif command -v python >/dev/null 2>&1 && python -c "import sys" >/dev/null 2>&1; then
        python "$@"
    else
        return 1
    fi
}

check_root() {
    if [[ "$SKIP_ROOT_CHECK" == "1" ]]; then
        return 0
    fi
    if [[ "$(id -u)" -ne 0 ]]; then
        echo "[x] Root privileges required for network baseline operations." >&2
        exit 1
    fi
}

cmd_snapshot() {
    local custom_tag="${1:-}"
    local timestamp
    timestamp="$(date -u +%Y%m%d_%H%M%S)"
    local target_dir
    if [[ -n "$custom_tag" ]]; then
        target_dir="${BACKUP_DIR}/baseline-${custom_tag}"
    else
        target_dir="${BACKUP_DIR}/baseline-${timestamp}"
    fi

    echo "[+] Capturing clean OS network and firewall baseline snapshot into ${target_dir}..."
    mkdir -p "$target_dir"

    # 1. IPTABLES v4 & v6
    if command -v iptables-save >/dev/null 2>&1; then
        iptables-save > "${target_dir}/iptables.rules.v4" 2>/dev/null || true
    fi
    if command -v ip6tables-save >/dev/null 2>&1; then
        ip6tables-save > "${target_dir}/iptables.rules.v6" 2>/dev/null || true
    fi

    # 2. IP ROUTE & RULES
    if command -v ip >/dev/null 2>&1; then
        ip route show > "${target_dir}/ip_route.txt" 2>/dev/null || true
        ip -6 route show > "${target_dir}/ip6_route.txt" 2>/dev/null || true
        ip rule show > "${target_dir}/ip_rule.txt" 2>/dev/null || true
        ip -6 rule show > "${target_dir}/ip6_rule.txt" 2>/dev/null || true
        ip addr show > "${target_dir}/ip_addr.txt" 2>/dev/null || true
    fi

    # 3. UFW STATUS
    if command -v ufw >/dev/null 2>&1; then
        ufw status verbose > "${target_dir}/ufw_status.txt" 2>/dev/null || true
        if [[ -f /etc/default/ufw ]]; then
            cp -f /etc/default/ufw "${target_dir}/etc_default_ufw" 2>/dev/null || true
        fi
    fi

    # 4. RESOLV.CONF
    if [[ -f /etc/resolv.conf ]]; then
        cp -f /etc/resolv.conf "${target_dir}/resolv.conf" 2>/dev/null || true
    fi

    # 5. OPEN PORTS
    if command -v ss >/dev/null 2>&1; then
        ss -tulpn > "${target_dir}/listening_ports.txt" 2>/dev/null || true
    fi

    # 6. SYSCTL FORWARDING
    local ip_fwd="0"
    if [[ -f /proc/sys/net/ipv4/ip_forward ]]; then
        ip_fwd="$(cat /proc/sys/net/ipv4/ip_forward 2>/dev/null || echo "0")"
    fi
    echo "$ip_fwd" > "${target_dir}/sysctl_ip_forward.txt"

    # 7. GENERATE BASELINE.JSON
    local os_id="unknown"
    local os_ver="unknown"
    if [[ -f /etc/os-release ]]; then
        os_id="$(grep -E '^ID=' /etc/os-release 2>/dev/null | head -n1 | cut -d'=' -f2 | tr -d '"' || echo "unknown")"
        os_ver="$(grep -E '^VERSION_ID=' /etc/os-release 2>/dev/null | head -n1 | cut -d'=' -f2 | tr -d '"' || echo "unknown")"
    fi

    local kernel_ver
    kernel_ver="$(uname -r 2>/dev/null || echo "unknown")"

    local def_if=""
    local def_gw=""
    if command -v ip >/dev/null 2>&1; then
        def_if="$(ip route 2>/dev/null | grep -E '^default' | awk '{print $5}' | head -n1 || true)"
        def_gw="$(ip route 2>/dev/null | grep -E '^default' | awk '{print $3}' | head -n1 || true)"
    fi

    local ufw_active=false
    if [[ -f "${target_dir}/ufw_status.txt" ]] && grep -qi 'Status: active' "${target_dir}/ufw_status.txt"; then
        ufw_active=true
    fi

    run_python -c '
import json, sys, time
out, ts, os_id, os_ver, k_ver, d_if, d_gw, ufw_act, ip_fwd = sys.argv[1:10]
meta = {
    "timestamp": ts,
    "epoch": int(time.time()),
    "os": f"{os_id} {os_ver}".strip(),
    "kernel": k_ver,
    "default_interface": d_if,
    "default_gateway": d_gw,
    "ufw_active": ufw_act.lower() == "true",
    "ip_forward": int(ip_fwd) if ip_fwd.isdigit() else 0
}
with open(out, "w", encoding="utf-8") as f:
    json.dump(meta, f, indent=2)
' "${target_dir}/baseline.json" "$timestamp" "$os_id" "$os_ver" "$kernel_ver" "$def_if" "$def_gw" "$ufw_active" "$ip_fwd" 2>/dev/null || {
        cat << EOF > "${target_dir}/baseline.json"
{
  "timestamp": "${timestamp}",
  "os": "${os_id} ${os_ver}",
  "kernel": "${kernel_ver}",
  "default_interface": "${def_if}",
  "default_gateway": "${def_gw}",
  "ufw_active": ${ufw_active},
  "ip_forward": ${ip_fwd}
}
EOF
    }

    # 8. UPDATE LATEST LINK
    mkdir -p "$BACKUP_DIR"
    rm -f "${BACKUP_DIR}/baseline-latest"
    ln -s "$(basename "$target_dir")" "${BACKUP_DIR}/baseline-latest" 2>/dev/null || \
        echo "$(basename "$target_dir")" > "${BACKUP_DIR}/baseline-latest"

    echo "[✓] Baseline snapshot saved to ${target_dir}"
}

cmd_list() {
    echo "=== Available OS Baseline Snapshots ==="
    if [[ ! -d "$BACKUP_DIR" ]]; then
        echo "No baseline snapshots found."
        return 0
    fi
    for d in "${BACKUP_DIR}"/baseline-*; do
        if [[ -d "$d" && ! -L "$d" ]]; then
            local bname
            bname="$(basename "$d")"
            local meta_file="${d}/baseline.json"
            if [[ -f "$meta_file" ]]; then
                echo -n "  - ${bname}: "
                run_python -c '
import json, sys
try:
    with open(sys.argv[1]) as f:
        m = json.load(f)
    print(f"OS: {m.get(\"os\")}, Interface: {m.get(\"default_interface\")}, UFW: {m.get(\"ufw_active\")}")
except Exception:
    print("Valid snapshot")
' "$meta_file" 2>/dev/null || echo "Snapshot recorded"
            else
                echo "  - ${bname}"
            fi
        fi
    done
}

cmd_show() {
    local target="${1:-latest}"
    local target_dir
    if [[ "$target" == "latest" ]]; then
        if [[ -L "${BACKUP_DIR}/baseline-latest" ]]; then
            local lnk
            lnk="$(readlink "${BACKUP_DIR}/baseline-latest" 2>/dev/null || true)"
            target_dir="${BACKUP_DIR}/${lnk}"
        elif [[ -f "${BACKUP_DIR}/baseline-latest" ]]; then
            local cname
            cname="$(cat "${BACKUP_DIR}/baseline-latest" 2>/dev/null || true)"
            target_dir="${BACKUP_DIR}/${cname}"
        else
            echo "Error: No latest snapshot found." >&2
            return 1
        fi
    elif [[ -d "$target" ]]; then
        target_dir="$target"
    elif [[ -d "${BACKUP_DIR}/${target}" ]]; then
        target_dir="${BACKUP_DIR}/${target}"
    elif [[ -d "${BACKUP_DIR}/baseline-${target}" ]]; then
        target_dir="${BACKUP_DIR}/baseline-${target}"
    else
        echo "Error: Snapshot directory not found: $target" >&2
        return 1
    fi

    echo "=== Baseline Snapshot Details: $(basename "$target_dir") ==="
    if [[ -f "${target_dir}/baseline.json" ]]; then
        cat "${target_dir}/baseline.json"
    fi
    echo ""
    echo "Files in snapshot:"
    ls -lh "$target_dir"
}

cmd_rollback() {
    local target="${1:-latest}"
    local target_dir=""

    if [[ "$target" == "latest" ]]; then
        if [[ -L "${BACKUP_DIR}/baseline-latest" ]]; then
            local lnk
            lnk="$(readlink "${BACKUP_DIR}/baseline-latest" 2>/dev/null || true)"
            target_dir="${BACKUP_DIR}/${lnk}"
        elif [[ -f "${BACKUP_DIR}/baseline-latest" ]]; then
            local cname
            cname="$(cat "${BACKUP_DIR}/baseline-latest" 2>/dev/null || true)"
            target_dir="${BACKUP_DIR}/${cname}"
        fi
        if [[ -z "$target_dir" || ! -d "$target_dir" ]]; then
            # Try to pick the most recent baseline directory
            local latest_d
            latest_d="$(ls -td "${BACKUP_DIR}"/baseline-* 2>/dev/null | head -n1 || true)"
            if [[ -n "$latest_d" && -d "$latest_d" ]]; then
                target_dir="$latest_d"
            fi
        fi
    elif [[ -d "$target" ]]; then
        target_dir="$target"
    elif [[ -d "${BACKUP_DIR}/${target}" ]]; then
        target_dir="${BACKUP_DIR}/${target}"
    elif [[ -d "${BACKUP_DIR}/baseline-${target}" ]]; then
        target_dir="${BACKUP_DIR}/baseline-${target}"
    fi

    if [[ -z "$target_dir" || ! -d "$target_dir" ]]; then
        echo "Error: Baseline snapshot not found to rollback." >&2
        return 1
    fi

    echo "[+] Rolling back network and firewall configuration to baseline: $(basename "$target_dir")..."

    # 1. STOP VPN CONTAINERS TO RELEASE BINDINGS
    if command -v docker >/dev/null 2>&1 && [[ -f "${VPN_DIR}/docker-compose.yml" ]]; then
        echo "[+] Halting running Docker Compose containers..."
        (cd "$VPN_DIR" && docker compose down 2>/dev/null || true)
    fi

    # 2. RESTORE IPTABLES v4
    if [[ -f "${target_dir}/iptables.rules.v4" ]] && command -v iptables-restore >/dev/null 2>&1; then
        echo "[+] Restoring IPv4 iptables rules from baseline..."
        iptables-restore < "${target_dir}/iptables.rules.v4" 2>/dev/null || {
            echo "[!] Warning: iptables-restore IPv4 returned non-zero code. Flushing VPN-specific chains..."
            # Fallback teardown if needed
            if [[ -f "${REPO_ROOT}/scripts/firewall-setup.sh" ]]; then
                "${REPO_ROOT}/scripts/firewall-setup.sh" --teardown 2>/dev/null || true
            fi
        }
    else
        # If no iptables snapshot was saved, run clean firewall teardown
        if [[ -f "${REPO_ROOT}/scripts/firewall-setup.sh" ]]; then
            "${REPO_ROOT}/scripts/firewall-setup.sh" --teardown 2>/dev/null || true
        elif [[ -f "${VPN_DIR}/scripts/firewall-setup.sh" ]]; then
            "${VPN_DIR}/scripts/firewall-setup.sh" --teardown 2>/dev/null || true
        fi
    fi

    # 3. RESTORE IPTABLES v6
    if [[ -f "${target_dir}/iptables.rules.v6" ]] && command -v ip6tables-restore >/dev/null 2>&1; then
        echo "[+] Restoring IPv6 iptables rules from baseline..."
        ip6tables-restore < "${target_dir}/iptables.rules.v6" 2>/dev/null || true
    fi

    # 4. RESTORE UFW
    local ufw_was_active=false
    if [[ -f "${target_dir}/baseline.json" ]]; then
        ufw_was_active="$(grep -i '"ufw_active"' "${target_dir}/baseline.json" 2>/dev/null | grep -i 'true' >/dev/null && echo true || echo false)"
    elif [[ -f "${target_dir}/ufw_status.txt" ]]; then
        ufw_was_active="$(grep -qi 'Status: active' "${target_dir}/ufw_status.txt" 2>/dev/null && echo true || echo false)"
    fi

    if command -v ufw >/dev/null 2>&1; then
        if [[ "$ufw_was_active" == "false" ]]; then
            echo "[+] Disabling UFW to match baseline inactive state..."
            ufw disable 2>/dev/null || true
        else
            echo "[+] UFW was active in baseline. Restoring configuration..."
            if [[ -f "${target_dir}/etc_default_ufw" ]]; then
                cp -f "${target_dir}/etc_default_ufw" /etc/default/ufw 2>/dev/null || true
            fi
            ufw reload 2>/dev/null || true
        fi
    fi

    # 5. RESTORE SYSCTL FORWARDING
    local saved_fwd="0"
    if [[ -f "${target_dir}/sysctl_ip_forward.txt" ]]; then
        saved_fwd="$(cat "${target_dir}/sysctl_ip_forward.txt" 2>/dev/null || echo "0")"
    fi
    if command -v sysctl >/dev/null 2>&1; then
        echo "[+] Restoring net.ipv4.ip_forward = ${saved_fwd}..."
        sysctl -w net.ipv4.ip_forward="${saved_fwd}" >/dev/null 2>&1 || true
    fi

    # 6. RESTORE RESOLV.CONF
    if [[ -f "${target_dir}/resolv.conf" && -f /etc/resolv.conf ]]; then
        echo "[+] Restoring /etc/resolv.conf..."
        cp -f "${target_dir}/resolv.conf" /etc/resolv.conf 2>/dev/null || true
    fi

    echo "[✓] Rollback complete! System restored to baseline state: $(basename "$target_dir")"
}

main() {
    local action="${1:-snapshot}"
    shift || true

    case "$action" in
        snapshot|save)
            check_root
            cmd_snapshot "$@"
            ;;
        rollback|restore)
            check_root
            cmd_rollback "$@"
            ;;
        list|ls)
            cmd_list "$@"
            ;;
        show|info)
            cmd_show "$@"
            ;;
        *)
            echo "Usage: $0 {snapshot|rollback [target]|list|show [target]}" >&2
            exit 1
            ;;
    esac
}

main "$@"
