#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

VPN_DIR="${VPN_DIR:-/opt/vpn-installer}"
MANIFEST_FILE="${VPN_DIR}/manifest.json"
USERS_FILE="${VPN_DIR}/users.json"
CONFIG_FILE="${VPN_DIR}/config.json"
TEMPLATE_FILE="${VPN_DIR}/templates/config.json.template"
COMPOSE_FILE="${VPN_DIR}/docker-compose.yml"
MOCK_SIGHUP_FILE="${MOCK_SIGHUP_FILE:-}"

run_python() {
    if command -v python3 >/dev/null 2>&1 && python3 -c "import sys" >/dev/null 2>&1; then
        python3 "$@"
    elif command -v python >/dev/null 2>&1 && python -c "import sys" >/dev/null 2>&1; then
        python "$@"
    else
        echo "Error: Python runtime not found." >&2
        return 1
    fi
}

if [[ ! -f "$TEMPLATE_FILE" && -f "${REPO_ROOT}/templates/config.json.template" ]]; then
    TEMPLATE_FILE="${REPO_ROOT}/templates/config.json.template"
fi

sync_users() {
    local tmp_config="${CONFIG_FILE}.tmp.$$"

    # Clean up temporary config on unexpected exit
    trap 'rm -f "$tmp_config"' EXIT INT TERM

    # Render temporary config with active users
    run_python -c '
import json, sys, os

manifest_file = sys.argv[1]
users_file = sys.argv[2]
config_file = sys.argv[3]
template_file = sys.argv[4]
output_file = sys.argv[5]

# Load active users
active_users = []
if os.path.exists(users_file):
    try:
        with open(users_file, "r", encoding="utf-8") as f:
            data = json.load(f)
            for u in data.get("users", []):
                if u.get("status") == "active":
                    active_users.append(u)
    except Exception as e:
        sys.exit(f"Error reading {users_file}: {e}")

# Load base config
if os.path.exists(config_file):
    with open(config_file, "r", encoding="utf-8") as f:
        config = json.load(f)
elif os.path.exists(template_file):
    with open(template_file, "r", encoding="utf-8") as f:
        t_text = f.read()
    if os.path.exists(manifest_file):
        with open(manifest_file, "r", encoding="utf-8") as mf:
            m = json.load(mf)
            node_uuid = m.get("node_uuid", "")
            reality = m.get("protocols", {}).get("vless_reality", {})
            hy2 = m.get("protocols", {}).get("hysteria2", {})
            t_text = t_text.replace("__NODE_UUID__", node_uuid)
            t_text = t_text.replace("__REALITY_SNI__", reality.get("sni", ""))
            t_text = t_text.replace("__REALITY_PRIVATE_KEY__", reality.get("private_key", ""))
            t_text = t_text.replace("__REALITY_SHORT_ID__", reality.get("short_id", ""))
            t_text = t_text.replace("__HYSTERIA2_PASSWORD__", hy2.get("password", ""))
            t_text = t_text.replace("__HYSTERIA2_OBFS_PASSWORD__", hy2.get("obfs_password", ""))
    config = json.loads(t_text)
else:
    sys.exit("Error: Neither config.json nor config.json.template was found.")

# Update inbounds with active users
for inbound in config.get("inbounds", []):
    ib_type = inbound.get("type")
    if ib_type == "vless":
        if active_users:
            inbound["users"] = [
                {
                    "name": u["name"],
                    "uuid": u["uuid"],
                    "flow": "xtls-rprx-vision"
                }
                for u in active_users
            ]
        else:
            inbound["users"] = [
                {
                    "name": "default-admin",
                    "uuid": "00000000-0000-0000-0000-000000000000",
                    "flow": "xtls-rprx-vision"
                }
            ]
    elif ib_type == "hysteria2":
        if active_users:
            inbound["users"] = [
                {
                    "name": u["name"],
                    "password": u["password"]
                }
                for u in active_users
            ]
        else:
            inbound["users"] = [
                {
                    "name": "default-admin",
                    "password": "disabled"
                }
            ]
    elif ib_type == "shadowsocks":
        if active_users:
            inbound["users"] = [
                {
                    "name": u["name"],
                    "password": u.get("sub_key", "")
                }
                for u in active_users
            ]
        else:
            inbound["users"] = [
                {
                    "name": "default-admin",
                    "password": "disabled"
                }
            ]
    elif ib_type == "tuic":
        if active_users:
            inbound["users"] = [
                {
                    "name": u["name"],
                    "uuid": u["uuid"],
                    "password": u["password"]
                }
                for u in active_users
            ]
        else:
            inbound["users"] = [
                {
                    "name": "default-admin",
                    "uuid": "00000000-0000-0000-0000-000000000000",
                    "password": "disabled"
                }
            ]

with open(output_file, "w", encoding="utf-8") as f:
    json.dump(config, f, indent=2, ensure_ascii=False)
' "$MANIFEST_FILE" "$USERS_FILE" "$CONFIG_FILE" "$TEMPLATE_FILE" "$tmp_config"

    # Validation: syntax check
    if ! run_python -m json.tool "$tmp_config" >/dev/null 2>&1; then
        echo "Error: Generated sing-box configuration failed JSON syntax validation." >&2
        rm -f "$tmp_config"
        return 1
    fi

    # Validation: sing-box schema check (if container or binary available)
    if [[ -f "$COMPOSE_FILE" ]] && command -v docker >/dev/null 2>&1; then
        if docker compose -f "$COMPOSE_FILE" ps sing-box 2>/dev/null | grep -E -q "Up|running"; then
            if ! docker compose -f "$COMPOSE_FILE" exec -T sing-box sing-box check -c /dev/stdin < "$tmp_config" 2>/dev/null; then
                echo "Error: sing-box check failed inside running container." >&2
                rm -f "$tmp_config"
                return 1
            fi
        fi
    elif command -v sing-box >/dev/null 2>&1; then
        if ! sing-box check -c "$tmp_config" 2>/dev/null; then
            echo "Error: sing-box check validation failed." >&2
            rm -f "$tmp_config"
            return 1
        fi
    fi

    # Atomic write to target config
    cp -f "$tmp_config" "$CONFIG_FILE"
    if [[ -d "${VPN_DIR}/config" ]]; then
        cp -f "$tmp_config" "${VPN_DIR}/config/sing-box.json" 2>/dev/null || true
    fi

    # Remove temporary config and clear trap
    rm -f "$tmp_config"
    trap - EXIT INT TERM

    # Hot reload: send SIGHUP
    if [[ -n "$MOCK_SIGHUP_FILE" ]]; then
        mkdir -p "$(dirname "$MOCK_SIGHUP_FILE")"
        echo "SIGHUP $(date)" >> "$MOCK_SIGHUP_FILE"
    fi

    if [[ -f "$COMPOSE_FILE" ]] && command -v docker >/dev/null 2>&1; then
        if docker compose -f "$COMPOSE_FILE" ps sing-box 2>/dev/null | grep -E -q "Up|running"; then
            docker compose -f "$COMPOSE_FILE" kill -s HUP sing-box 2>/dev/null || true
        fi
    fi

    return 0
}

sync_users "$@"
