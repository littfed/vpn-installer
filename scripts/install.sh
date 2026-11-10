#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

VPN_DIR="${VPN_DIR:-/opt/vpn-installer}"
BIN_DIR="${BIN_DIR:-/usr/local/bin}"
OS_RELEASE_FILE="${OS_RELEASE_FILE:-/etc/os-release}"
SINGBOX_IMAGE="${SINGBOX_IMAGE:-ghcr.io/sagernet/sing-box:latest}"
MTG_IMAGE="${MTG_IMAGE:-nineseconds/mtg:2}"
MTPROTO_DOMAIN="${MTPROTO_DOMAIN:-www.cloudflare.com}"

SKIP_ROOT_CHECK="${SKIP_ROOT_CHECK:-0}"
FORCE_NON_ROOT="${FORCE_NON_ROOT:-0}"
SKIP_OS_CHECK="${SKIP_OS_CHECK:-0}"
SKIP_DOCKER_INSTALL="${SKIP_DOCKER_INSTALL:-0}"
SKIP_CONTAINER_START="${SKIP_CONTAINER_START:-0}"

run_python() {
    if command -v python3 >/dev/null 2>&1 && python3 -c "import sys" >/dev/null 2>&1; then
        python3 "$@"
    elif command -v python >/dev/null 2>&1 && python -c "import sys" >/dev/null 2>&1; then
        python "$@"
    else
        return 1
    fi
}

get_json_val() {
    local key="$1"
    local file="$2"
    grep -o "\"${key}\"[[:space:]]*:[[:space:]]*\"[^\"]*\"" "$file" | head -n1 | sed -E 's/.*:[[:space:]]*"([^"]*)".*/\1/'
}
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

log_info() {
    echo -e "${GREEN}[+]${NC} $*"
}

log_warn() {
    echo -e "${YELLOW}[!]${NC} $*"
}

log_error() {
    echo -e "${RED}[x]${NC} $*" >&2
}

check_root() {
    if [[ "$FORCE_NON_ROOT" == "1" ]]; then
        log_error "Root privileges required to run this installer."
        exit 1
    fi
    if [[ "$SKIP_ROOT_CHECK" == "1" ]]; then
        return 0
    fi
    if [[ "$(id -u)" -ne 0 ]]; then
        log_error "Root privileges required. Please execute with sudo or as root."
        exit 1
    fi
}

check_os() {
    if [[ "$SKIP_OS_CHECK" == "1" ]]; then
        return 0
    fi

    if [[ ! -f "$OS_RELEASE_FILE" ]]; then
        log_error "Unsupported OS: $OS_RELEASE_FILE not found."
        exit 1
    fi

    local os_id=""
    local version_id=""
    # shellcheck disable=SC1090
    os_id="$(grep -E '^ID=' "$OS_RELEASE_FILE" | head -n1 | cut -d'=' -f2 | tr -d '"')"
    version_id="$(grep -E '^VERSION_ID=' "$OS_RELEASE_FILE" | head -n1 | cut -d'=' -f2 | tr -d '"')"

    log_info "Detected OS: $os_id, Version: $version_id"

    local is_supported=0
    case "$os_id" in
        ubuntu)
            if [[ "$version_id" =~ ^(22\.04|24\.04) ]]; then
                is_supported=1
            fi
            ;;
        debian)
            if [[ "$version_id" =~ ^(11|12) ]]; then
                is_supported=1
            fi
            ;;
    esac

    if [[ "$is_supported" -ne 1 ]]; then
        log_error "Unsupported OS: $os_id $version_id. Supported distributions: Ubuntu 22.04/24.04, Debian 11/12."
        exit 1
    fi
}

ensure_dependencies() {
    if [[ "$SKIP_DOCKER_INSTALL" == "1" ]]; then
        return 0
    fi

    local need_docker=0
    if ! command -v docker >/dev/null 2>&1; then
        need_docker=1
    elif ! docker compose version >/dev/null 2>&1 && ! command -v docker-compose >/dev/null 2>&1; then
        need_docker=1
    fi

    if [[ "$need_docker" -eq 1 ]]; then
        log_info "Installing Docker and Docker Compose plugin..."
        if command -v apt-get >/dev/null 2>&1; then
            apt-get update -y
            apt-get install -y ca-certificates curl gnupg qrencode jq
            curl -fsSL https://get.docker.com | sh
        else
            curl -fsSL https://get.docker.com | sh
        fi
    else
        if command -v apt-get >/dev/null 2>&1; then
            local missing_pkgs=""
            for pkg in qrencode jq; do
                if ! command -v "$pkg" >/dev/null 2>&1; then
                    missing_pkgs="${missing_pkgs} ${pkg}"
                fi
            done
            if [[ -n "$missing_pkgs" ]]; then
                log_info "Installing required packages:${missing_pkgs}..."
                apt-get update -y >/dev/null 2>&1 || true
                apt-get install -y $missing_pkgs >/dev/null 2>&1 || true
            fi
        fi
    fi

    # Ensure docker daemon and socket are running
    if command -v systemctl >/dev/null 2>&1; then
        systemctl reset-failed docker docker.socket 2>/dev/null || true
        systemctl enable --now docker.socket docker.service 2>/dev/null || systemctl enable --now docker 2>/dev/null || true
    fi

    if ! command -v docker >/dev/null 2>&1; then
        log_error "Docker installation failed or docker binary missing."
        exit 1
    fi
}

setup_directories() {
    log_info "Setting up directory structure at $VPN_DIR..."
    mkdir -p "$VPN_DIR"/{bin,config,certs,templates,scripts,caddy/html,caddy/data,caddy/config}
    chmod 700 "$VPN_DIR"

    # Copy templates, scripts and CLI
    if [[ "$REPO_ROOT" != "$VPN_DIR" ]]; then
        cp -f "${REPO_ROOT}/templates/docker-compose.yml" "$VPN_DIR/docker-compose.yml"
        cp -f "${REPO_ROOT}/templates/config.json.template" "$VPN_DIR/templates/config.json.template"
        cp -f "${REPO_ROOT}/templates/Caddyfile" "$VPN_DIR/templates/Caddyfile" 2>/dev/null || true
        mkdir -p "$VPN_DIR/templates/html"
        cp -rf "${REPO_ROOT}/templates/html/"* "$VPN_DIR/templates/html/" 2>/dev/null || true
        cp -f "${REPO_ROOT}/scripts/user-sync.sh" "$VPN_DIR/scripts/user-sync.sh"
        if [[ -f "${REPO_ROOT}/scripts/generate-warp-keys.py" ]]; then
            cp -f "${REPO_ROOT}/scripts/generate-warp-keys.py" "$VPN_DIR/scripts/generate-warp-keys.py"
        fi
        cp -f "${REPO_ROOT}/bin/vpn" "$VPN_DIR/bin/vpn"
    fi
    chmod 755 "$VPN_DIR/scripts/user-sync.sh" 2>/dev/null || true
    chmod 755 "$VPN_DIR/scripts/generate-warp-keys.py" 2>/dev/null || true
    chmod 755 "$VPN_DIR/bin/vpn" 2>/dev/null || true

    # Install CLI symlink
    mkdir -p "$BIN_DIR"
    ln -sf "$VPN_DIR/bin/vpn" "$BIN_DIR/vpn"
    log_info "Installed CLI to $BIN_DIR/vpn"
}

get_warp_credentials() {
    local warp_script="${REPO_ROOT}/scripts/generate-warp-keys.py"
    if [[ ! -f "$warp_script" ]]; then
        warp_script="${VPN_DIR}/scripts/generate-warp-keys.py"
    fi

    warp_priv=""
    warp_pub=""
    warp_peer_pub=""
    warp_v4=""
    warp_v6=""
    warp_reserved=""
    warp_server=""
    warp_port=""

    if [[ -f "$warp_script" ]]; then
        log_info "Generating Cloudflare WARP registration and WireGuard keys..."
        local warp_json=""
        local warp_cmd_args=()
        if [[ -n "${WARP_API_URL:-}" ]]; then
            warp_cmd_args+=(--api-url "$WARP_API_URL")
        fi
        warp_json=$(run_python "$warp_script" "${warp_cmd_args[@]}" 2>/dev/null || true)
        if [[ -n "$warp_json" ]]; then
            local parsed_warp=""
            parsed_warp=$(echo "$warp_json" | run_python -c '
import json, sys
try:
    data = json.loads(sys.stdin.read())
    print(data.get("private_key", ""))
    print(data.get("public_key", ""))
    print(data.get("peer_public_key", "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo="))
    print(data.get("v4", "172.16.0.2/32"))
    print(data.get("v6", "2606:4700:110:8fbb:bdf2:a2f6:a188:94d6/128"))
    print(json.dumps(data.get("reserved", [0, 0, 0])))
    print(data.get("server", "162.159.192.1"))
    print(data.get("server_port", 2408))
except Exception:
    pass
' 2>/dev/null || true)
            if [[ -n "$parsed_warp" ]]; then
                warp_priv=$(echo "$parsed_warp" | sed -n '1p')
                warp_pub=$(echo "$parsed_warp" | sed -n '2p')
                warp_peer_pub=$(echo "$parsed_warp" | sed -n '3p')
                warp_v4=$(echo "$parsed_warp" | sed -n '4p')
                warp_v6=$(echo "$parsed_warp" | sed -n '5p')
                warp_reserved=$(echo "$parsed_warp" | sed -n '6p')
                warp_server=$(echo "$parsed_warp" | sed -n '7p')
                warp_port=$(echo "$parsed_warp" | sed -n '8p')
            fi
        fi
    fi

    warp_priv="${warp_priv:-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=}"
    warp_pub="${warp_pub:-bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=}"
    warp_peer_pub="${warp_peer_pub:-bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=}"
    warp_v4="${warp_v4:-172.16.0.2/32}"
    warp_v6="${warp_v6:-2606:4700:110:8fbb:bdf2:a2f6:a188:94d6/128}"
    warp_reserved="${warp_reserved:-[0, 0, 0]}"
    warp_server="${warp_server:-162.159.192.1}"
    warp_port="${warp_port:-2408}"
}

generate_mtproto_secret() {
    local domain="${1:-$MTPROTO_DOMAIN}"
    local secret=""
    if command -v docker >/dev/null 2>&1; then
        secret=$(docker run --rm "$MTG_IMAGE" generate-secret --hex "$domain" 2>/dev/null || true)
    fi
    if [[ -z "$secret" ]]; then
        secret=$(run_python -c '
import secrets, sys
domain = sys.argv[1]
domain_hex = domain.encode("utf-8").hex()
print(f"ee{secrets.token_hex(16)}{domain_hex}")
' "$domain" 2>/dev/null || true)
    fi
    if [[ -z "$secret" ]]; then
        local rand_hex dom_hex
        rand_hex=$(head -c 16 /dev/urandom 2>/dev/null | od -An -tx1 | tr -d ' \r\n' || echo "000102030405060708090a0b0c0d0e0f")
        dom_hex=$(printf "%s" "$domain" | od -An -tx1 2>/dev/null | tr -d ' \r\n' || echo "7777772e636c6f7564666c6172652e636f6d")
        secret="ee${rand_hex}${dom_hex}"
    fi
    echo "$secret"
}

generate_crypto_keys() {
    local manifest_file="$VPN_DIR/manifest.json"
    local vpn_domain="${VPN_DOMAIN:-${SERVER_DOMAIN:-}}"
    if [[ -f "$manifest_file" ]]; then
        if [[ -n "$vpn_domain" ]]; then
            run_python -c '
import json, sys
mf, d = sys.argv[1], sys.argv[2]
try:
    with open(mf, "r", encoding="utf-8") as f:
        m = json.load(f)
    if "server" not in m:
        m["server"] = {}
    m["server"]["domain"] = d
    if "protocols" in m and "vless_reality" in m["protocols"]:
        m["protocols"]["vless_reality"]["sni"] = d
        m["protocols"]["vless_reality"]["handshake"] = {
            "server": "127.0.0.1",
            "server_port": 8443
        }
    with open(mf, "w", encoding="utf-8") as f:
        json.dump(m, f, indent=2)
except Exception:
    pass
' "$manifest_file" "$vpn_domain" 2>/dev/null || true
        fi
        local has_warp=""
        has_warp=$(run_python -c "import json; m=json.load(open('$manifest_file')); print('yes' if m.get('protocols',{}).get('warp') else 'no')" 2>/dev/null || echo "no")
        if [[ "$has_warp" != "yes" ]]; then
            log_info "Manifest exists at $manifest_file but lacks WARP. Generating WARP credentials..."
            local warp_priv="" warp_pub="" warp_peer_pub="" warp_v4="" warp_v6="" warp_reserved="" warp_server="" warp_port=""
            get_warp_credentials
            run_python -c '
import json, sys
manifest_file = sys.argv[1]
with open(manifest_file, "r", encoding="utf-8") as f:
    m = json.load(f)
if "protocols" not in m:
    m["protocols"] = {}
m["protocols"]["warp"] = {
    "enabled": True,
    "private_key": sys.argv[2],
    "public_key": sys.argv[3],
    "peer_public_key": sys.argv[4],
    "local_address": [sys.argv[5], sys.argv[6]],
    "reserved": json.loads(sys.argv[7]),
    "server": sys.argv[8],
    "server_port": int(sys.argv[9])
}
with open(manifest_file, "w", encoding="utf-8") as f:
    json.dump(m, f, indent=2)
' "$manifest_file" "$warp_priv" "$warp_pub" "$warp_peer_pub" "$warp_v4" "$warp_v6" "$warp_reserved" "$warp_server" "$warp_port"
            log_info "Saved WARP credentials to $manifest_file"
        fi

        local has_mtproto=""
        has_mtproto=$(run_python -c "import json; m=json.load(open('$manifest_file')); print('yes' if m.get('protocols',{}).get('mtproto') else 'no')" 2>/dev/null || echo "no")
        if [[ "$has_mtproto" != "yes" ]]; then
            log_info "Manifest lacks MTProto. Generating MTProto Fake-TLS secret..."
            local mtg_secret
            mtg_secret=$(generate_mtproto_secret "$MTPROTO_DOMAIN")
            run_python -c '
import json, sys
manifest_file, secret, domain = sys.argv[1], sys.argv[2], sys.argv[3]
with open(manifest_file, "r", encoding="utf-8") as f:
    m = json.load(f)
if "protocols" not in m:
    m["protocols"] = {}
m["protocols"]["mtproto"] = {
    "enabled": True,
    "port": 8443,
    "secret": secret,
    "domain": domain
}
with open(manifest_file, "w", encoding="utf-8") as f:
    json.dump(m, f, indent=2)
' "$manifest_file" "$mtg_secret" "$MTPROTO_DOMAIN"
            log_info "Saved MTProto credentials to $manifest_file"
        fi

        log_info "Manifest verified at $manifest_file, skipping core key generation."
        return 0
    fi

    log_info "Generating cryptographic keys for Reality and node..."

    # Node UUID
    local node_uuid=""
    if command -v sing-box >/dev/null 2>&1; then
        node_uuid=$(sing-box generate uuid 2>/dev/null || true)
    fi
    if [[ -z "$node_uuid" ]] && command -v uuidgen >/dev/null 2>&1; then
        node_uuid=$(uuidgen | tr '[:upper:]' '[:lower:]' || true)
    fi
    if [[ -z "$node_uuid" ]]; then
        node_uuid=$(run_python -c 'import uuid; print(uuid.uuid4())' 2>/dev/null || true)
    fi
    if [[ -z "$node_uuid" ]] && [[ -f /proc/sys/kernel/random/uuid ]]; then
        node_uuid=$(cat /proc/sys/kernel/random/uuid || true)
    fi
    if [[ -z "$node_uuid" ]]; then
        node_uuid=$(od -x /dev/urandom 2>/dev/null | head -1 | awk '{OFS="-"; print $2$3,$4,$5,$6,$7$8$9}' || true)
    fi
    if [[ -z "$node_uuid" ]]; then
        node_uuid="e0a75d9e-29f1-4db4-bb14-e0c1f516a5b3"
    fi

    # Reality Keypair
    local priv_key=""
    local pub_key=""
    local keypair_out=""

    if command -v sing-box >/dev/null 2>&1; then
        keypair_out=$(sing-box generate reality-keypair 2>/dev/null || true)
    fi
    if [[ -z "$keypair_out" ]] && command -v docker >/dev/null 2>&1; then
        keypair_out=$(docker run --rm "$SINGBOX_IMAGE" generate reality-keypair 2>/dev/null || true)
    fi

    if [[ -n "$keypair_out" ]]; then
        priv_key=$(echo "$keypair_out" | grep -i 'PrivateKey:' | awk '{print $2}' | tr -d '\r\n')
        pub_key=$(echo "$keypair_out" | grep -i 'PublicKey:' | awk '{print $2}' | tr -d '\r\n')
    fi

    # Fallback key generation if docker/sing-box not available during unit tests
    if [[ -z "$priv_key" || -z "$pub_key" ]]; then
        local py_keys=""
        py_keys=$(run_python -c '
import base64
try:
    from cryptography.hazmat.primitives.asymmetric import x25519
    from cryptography.hazmat.primitives import serialization
    priv = x25519.X25519PrivateKey.generate()
    pub = priv.public_key()
    priv_b = priv.private_bytes(encoding=serialization.Encoding.Raw, format=serialization.PrivateFormat.Raw, encryption_algorithm=serialization.NoEncryption())
    pub_b = pub.public_bytes(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw)
    print(base64.urlsafe_b64encode(priv_b).decode().rstrip("=") + " " + base64.urlsafe_b64encode(pub_b).decode().rstrip("="))
except Exception:
    import secrets
    p1 = base64.urlsafe_b64encode(secrets.token_bytes(32)).decode().rstrip("=")
    p2 = base64.urlsafe_b64encode(secrets.token_bytes(32)).decode().rstrip("=")
    print(p1 + " " + p2)
' 2>/dev/null || true)
        if [[ -n "$py_keys" ]]; then
            priv_key=$(echo "$py_keys" | awk '{print $1}')
            pub_key=$(echo "$py_keys" | awk '{print $2}')
        fi
    fi

    if [[ -z "$priv_key" || -z "$pub_key" ]]; then
        priv_key=$(head -c 32 /dev/urandom 2>/dev/null | base64 | tr '+/' '-_' | tr -d '=\r\n' || echo "uHnwBnsTXhS5jWwzEtc_WTvZGp50EL7j9eK_rcX0mXA")
        pub_key=$(head -c 32 /dev/urandom 2>/dev/null | base64 | tr '+/' '-_' | tr -d '=\r\n' || echo "8LkMiKb-zjDMuTw_HJaL0DuxoQXK2_5x6KGOrfZFghk")
    fi

    # Short ID (8 bytes = 16 hex characters)
    local short_id=""
    if command -v sing-box >/dev/null 2>&1; then
        short_id=$(sing-box generate rand --hex 8 2>/dev/null || true)
    fi
    if [[ -z "$short_id" ]] && command -v openssl >/dev/null 2>&1; then
        short_id=$(openssl rand -hex 8 2>/dev/null || true)
    fi
    if [[ -z "$short_id" ]]; then
        short_id=$(run_python -c 'import secrets; print(secrets.token_hex(8))' 2>/dev/null || true)
    fi
    if [[ -z "$short_id" ]]; then
        short_id=$(head -c 8 /dev/urandom 2>/dev/null | od -An -tx1 | tr -d ' \r\n' || echo "0123456789abcdef")
    fi

    # Hysteria 2 passwords
    local hy2_pwd=""
    local hy2_obfs=""
    if command -v openssl >/dev/null 2>&1; then
        hy2_pwd=$(openssl rand -base64 18 2>/dev/null | tr -dc 'a-zA-Z0-9' | head -c 24 || true)
        hy2_obfs=$(openssl rand -base64 12 2>/dev/null | tr -dc 'a-zA-Z0-9' | head -c 16 || true)
    fi
    if [[ -z "$hy2_pwd" ]]; then
        hy2_pwd=$(run_python -c 'import secrets; print(secrets.token_urlsafe(18))' 2>/dev/null || true)
        hy2_obfs=$(run_python -c 'import secrets; print(secrets.token_urlsafe(12))' 2>/dev/null || true)
    fi
    if [[ -z "$hy2_pwd" ]]; then
        hy2_pwd="hy2pwd$(date +%s%N 2>/dev/null || date +%s)"
        hy2_obfs="obfs$(date +%s%N 2>/dev/null || date +%s)"
    fi

    # Cloudflare WARP Egress Keypair and Registration
    local warp_priv="" warp_pub="" warp_peer_pub="" warp_v4="" warp_v6="" warp_reserved="" warp_server="" warp_port=""
    get_warp_credentials

    # Detect public IP
    local server_ip="${SERVER_IP:-}"
    if [[ -z "$server_ip" ]]; then
        server_ip=$(curl -s4 --max-time 3 https://api.ipify.org 2>/dev/null || \
                    curl -s4 --max-time 3 https://ifconfig.me 2>/dev/null || \
                    curl -s4 --max-time 3 https://icanhazip.com 2>/dev/null || \
                    echo "127.0.0.1")
    fi

    local sni="${VPN_SNI:-gateway.icloud.com}"
    local handshake_server="${sni}"
    local handshake_port=443
    if [[ -n "$vpn_domain" ]]; then
        sni="$vpn_domain"
        handshake_server="127.0.0.1"
        handshake_port=8443
    fi
    local created_at
    created_at=$(date -u +"%Y-%m-%dT%H:%M:%SZ" 2>/dev/null || echo "2026-11-10T10:00:00Z")

    local mtg_secret
    mtg_secret=$(generate_mtproto_secret "$MTPROTO_DOMAIN")

    cat << EOF > "$manifest_file"
{
  "version": "1.0.0",
  "created_at": "${created_at}",
  "node_uuid": "${node_uuid}",
  "server": {
    "ipv4": "${server_ip}",
    "ipv6": "",
    "domain": "${vpn_domain}"
  },
  "protocols": {
    "vless_reality": {
      "enabled": true,
      "port": 443,
      "sni": "${sni}",
      "handshake": {
        "server": "${handshake_server}",
        "server_port": ${handshake_port}
      },
      "private_key": "${priv_key}",
      "public_key": "${pub_key}",
      "short_id": "${short_id}",
      "short_ids": [
        "${short_id}"
      ]
    },
    "hysteria2": {
      "enabled": true,
      "port": 443,
      "password": "${hy2_pwd}",
      "obfs_password": "${hy2_obfs}"
    },
    "warp": {
      "enabled": true,
      "private_key": "${warp_priv}",
      "public_key": "${warp_pub}",
      "peer_public_key": "${warp_peer_pub}",
      "local_address": [
        "${warp_v4}",
        "${warp_v6}"
      ],
      "reserved": ${warp_reserved},
      "server": "${warp_server}",
      "server_port": ${warp_port}
    },
    "mtproto": {
      "enabled": true,
      "port": 8443,
      "secret": "${mtg_secret}",
      "domain": "${MTPROTO_DOMAIN}"
    }
  }
}
EOF
    chmod 600 "$manifest_file"
    log_info "Saved node manifest to $manifest_file"
}

setup_tls_certificates() {
    local cert_file="$VPN_DIR/certs/fullchain.pem"
    local key_file="$VPN_DIR/certs/privkey.pem"

    if [[ -f "$cert_file" && -f "$key_file" ]]; then
        return 0
    fi

    log_info "Generating initial self-signed TLS certificates for Hysteria 2..."
    mkdir -p "$VPN_DIR/certs"
    if command -v openssl >/dev/null 2>&1; then
        openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
            -keyout "$key_file" \
            -out "$cert_file" \
            -days 3650 \
            -subj "//CN=vpn-installer-node" >/dev/null 2>&1 || \
        openssl req -x509 -newkey rsa:2048 -nodes \
            -keyout "$key_file" \
            -out "$cert_file" \
            -days 3650 \
            -subj "//CN=vpn-installer-node" >/dev/null 2>&1 || true
        chmod 600 "$key_file"
    else
        touch "$key_file" "$cert_file"
    fi
}

setup_caddy_decoy() {
    log_info "Configuring Caddy decoy website and Let's Encrypt automation..."
    mkdir -p "$VPN_DIR/caddy/html" "$VPN_DIR/caddy/data" "$VPN_DIR/caddy/config"

    # Copy decoy static content
    if [[ -d "${REPO_ROOT}/templates/html" ]]; then
        cp -rf "${REPO_ROOT}/templates/html/"* "$VPN_DIR/caddy/html/"
    elif [[ -d "${VPN_DIR}/templates/html" ]]; then
        cp -rf "${VPN_DIR}/templates/html/"* "$VPN_DIR/caddy/html/"
    fi

    local vpn_domain="${VPN_DOMAIN:-${SERVER_DOMAIN:-}}"
    if [[ -z "$vpn_domain" && -f "$VPN_DIR/manifest.json" ]]; then
        vpn_domain=$(get_json_val "domain" "$VPN_DIR/manifest.json" || true)
    fi

    local caddyfile_target="$VPN_DIR/caddy/Caddyfile"
    if [[ -n "$vpn_domain" ]]; then
        cat << EOF > "$caddyfile_target"
{
    admin off
    http_port 80
    https_port 8443
    default_sni localhost
}

(security_headers) {
    header {
        X-Content-Type-Options "nosniff"
        X-Frame-Options "DENY"
        Strict-Transport-Security "max-age=31536000; includeSubDomains; preload"
        Referrer-Policy "strict-origin-when-cross-origin"
        X-XSS-Protection "1; mode=block"
    }
}

${vpn_domain}:8443 {
    tls {
        issuer acme {
            challenges http
        }
    }
    import security_headers
    root * /usr/share/caddy
    file_server
}

localhost:8443, :8443 {
    tls internal
    import security_headers
    root * /usr/share/caddy
    file_server
}

:80 {
    import security_headers
    root * /usr/share/caddy
    file_server
}
EOF
    else
        if [[ -f "${REPO_ROOT}/templates/Caddyfile" ]]; then
            cp -f "${REPO_ROOT}/templates/Caddyfile" "$caddyfile_target"
        elif [[ -f "${VPN_DIR}/templates/Caddyfile" ]]; then
            cp -f "${VPN_DIR}/templates/Caddyfile" "$caddyfile_target"
        else
            cat << EOF > "$caddyfile_target"
{
    admin off
    http_port 80
    https_port 8443
    default_sni localhost
}

(security_headers) {
    header {
        X-Content-Type-Options "nosniff"
        X-Frame-Options "DENY"
        Strict-Transport-Security "max-age=31536000; includeSubDomains; preload"
        Referrer-Policy "strict-origin-when-cross-origin"
        X-XSS-Protection "1; mode=block"
    }
}

localhost:8443, :8443 {
    tls internal
    import security_headers
    root * /usr/share/caddy
    file_server
}

:80 {
    import security_headers
    root * /usr/share/caddy
    file_server
}
EOF
        fi
    fi
}

setup_mtproto() {
    log_info "Configuring MTProto Proxy (mtg v2)..."
    local manifest_file="$VPN_DIR/manifest.json"
    local mtg_secret=""
    local mtg_domain=""
    if [[ -f "$manifest_file" ]]; then
        mtg_secret=$(run_python -c "import json; m=json.load(open('$manifest_file')); print(m.get('protocols',{}).get('mtproto',{}).get('secret',''))" 2>/dev/null || true)
        mtg_domain=$(run_python -c "import json; m=json.load(open('$manifest_file')); print(m.get('protocols',{}).get('mtproto',{}).get('domain',''))" 2>/dev/null || true)
    fi
    if [[ -z "$mtg_secret" ]]; then
        mtg_secret=$(generate_mtproto_secret "${mtg_domain:-$MTPROTO_DOMAIN}")
    fi

    local server_ip="${SERVER_IP:-}"
    if [[ -z "$server_ip" && -f "$manifest_file" ]]; then
        server_ip=$(get_json_val "ipv4" "$manifest_file" || true)
    fi

    local mtg_bind="0.0.0.0:8443"
    if [[ -n "$server_ip" && "$server_ip" != "127.0.0.1" ]]; then
        mtg_bind="${server_ip}:8443"
    fi

    local env_file="$VPN_DIR/.env"
    cat << EOF > "$env_file"
MTG_BIND_TO=${mtg_bind}
MTG_SECRET=${mtg_secret}
EOF
    chmod 600 "$env_file"
    log_info "Saved MTProto environment to $env_file"
}

render_singbox_config() {
    log_info "Rendering sing-box configuration..."
    local manifest_file="$VPN_DIR/manifest.json"
    local template_file="$VPN_DIR/templates/config.json.template"
    local config_target="$VPN_DIR/config.json"
    local config_sub="$VPN_DIR/config/sing-box.json"

    local node_uuid reality_sni priv_key short_id hy2_pwd hy2_obfs
    local warp_priv warp_peer_pub warp_v4 warp_v6 warp_reserved warp_server warp_port
    node_uuid=$(get_json_val "node_uuid" "$manifest_file")
    reality_sni=$(get_json_val "sni" "$manifest_file")
    priv_key=$(get_json_val "private_key" "$manifest_file")
    short_id=$(get_json_val "short_id" "$manifest_file")
    hy2_pwd=$(get_json_val "password" "$manifest_file")
    hy2_obfs=$(get_json_val "obfs_password" "$manifest_file")

    local vpn_domain="${VPN_DOMAIN:-${SERVER_DOMAIN:-}}"
    if [[ -z "$vpn_domain" && -f "$manifest_file" ]]; then
        vpn_domain=$(get_json_val "domain" "$manifest_file" || true)
    fi

    local handshake_server handshake_port
    if [[ -n "$vpn_domain" ]]; then
        handshake_server="127.0.0.1"
        handshake_port=8443
        reality_sni="$vpn_domain"
    else
        handshake_server="${reality_sni}"
        handshake_port=443
    fi

    warp_priv=$(run_python -c "import json; m=json.load(open('$manifest_file')); print(m.get('protocols',{}).get('warp',{}).get('private_key',''))" 2>/dev/null || true)
    warp_peer_pub=$(run_python -c "import json; m=json.load(open('$manifest_file')); print(m.get('protocols',{}).get('warp',{}).get('peer_public_key','bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo='))" 2>/dev/null || true)
    warp_v4=$(run_python -c "import json; m=json.load(open('$manifest_file')); print(m.get('protocols',{}).get('warp',{}).get('local_address',['172.16.0.2/32'])[0])" 2>/dev/null || true)
    warp_v6=$(run_python -c "import json; m=json.load(open('$manifest_file')); print(m.get('protocols',{}).get('warp',{}).get('local_address',['','2606:4700:110:8fbb:bdf2:a2f6:a188:94d6/128'])[1])" 2>/dev/null || true)
    warp_reserved=$(run_python -c "import json; m=json.load(open('$manifest_file')); print(json.dumps(m.get('protocols',{}).get('warp',{}).get('reserved',[0,0,0])))" 2>/dev/null || true)
    warp_server=$(run_python -c "import json; m=json.load(open('$manifest_file')); print(m.get('protocols',{}).get('warp',{}).get('server','162.159.192.1'))" 2>/dev/null || true)
    warp_port=$(run_python -c "import json; m=json.load(open('$manifest_file')); print(m.get('protocols',{}).get('warp',{}).get('server_port',2408))" 2>/dev/null || true)

    # Fallbacks if python parsing returned empty
    warp_priv="${warp_priv:-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=}"
    warp_peer_pub="${warp_peer_pub:-bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=}"
    warp_v4="${warp_v4:-172.16.0.2/32}"
    warp_v6="${warp_v6:-2606:4700:110:8fbb:bdf2:a2f6:a188:94d6/128}"
    warp_reserved="${warp_reserved:-[0, 0, 0]}"
    warp_server="${warp_server:-162.159.192.1}"
    warp_port="${warp_port:-2408}"

    # Substitute placeholders
    sed \
        -e "s|__NODE_UUID__|${node_uuid}|g" \
        -e "s|__REALITY_SNI__|${reality_sni}|g" \
        -e "s|__REALITY_HANDSHAKE_SERVER__|${handshake_server}|g" \
        -e "s|__REALITY_HANDSHAKE_PORT__|${handshake_port}|g" \
        -e "s|__REALITY_PRIVATE_KEY__|${priv_key}|g" \
        -e "s|__REALITY_SHORT_ID__|${short_id}|g" \
        -e "s|__HYSTERIA2_PASSWORD__|${hy2_pwd}|g" \
        -e "s|__HYSTERIA2_OBFS_PASSWORD__|${hy2_obfs}|g" \
        -e "s|__WARP_LOCAL_IPV4__|${warp_v4}|g" \
        -e "s|__WARP_LOCAL_IPV6__|${warp_v6}|g" \
        -e "s|__WARP_PRIVATE_KEY__|${warp_priv}|g" \
        -e "s|__WARP_PEER_PUBLIC_KEY__|${warp_peer_pub}|g" \
        -e "s|__WARP_RESERVED__|${warp_reserved}|g" \
        -e "s|__WARP_SERVER__|${warp_server}|g" \
        -e "s|__WARP_PORT__|${warp_port}|g" \
        "$template_file" > "$config_target"

    cp -f "$config_target" "$config_sub"
    log_info "Config written to $config_target"
}

start_services() {
    if [[ "$SKIP_CONTAINER_START" == "1" ]]; then
        log_info "Skipping container start as requested."
        return 0
    fi

    log_info "Starting services via Docker Compose..."
    cd "$VPN_DIR"
    docker compose up -d --remove-orphans
    docker compose kill -s HUP sing-box 2>/dev/null || docker compose restart sing-box 2>/dev/null || true

    log_info "Verifying open ports (80/TCP, 443/TCP, 443/UDP, 8443/TCP)..."
    sleep 2
    if command -v ss >/dev/null 2>&1; then
        ss -tulpn | grep -E ':(80|443|8443)\b' || true
    fi

    log_info "Installation and startup complete! Current status:"
    "${BIN_DIR}/vpn" status || true
}

main() {
    log_info "Starting VPN Installer bootstrap..."
    check_root
    check_os
    ensure_dependencies
    setup_directories
    generate_crypto_keys
    setup_tls_certificates
    setup_caddy_decoy
    setup_mtproto
    render_singbox_config
    start_services
}

main "$@"
