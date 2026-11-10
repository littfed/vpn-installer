#!/usr/bin/env python3
"""
scripts/sub-server.py - Adaptive Subscription Responder for vpn-installer.

Serves /sub/<token> requests by inspecting the User-Agent header or ?format= override:
- Clash.Meta / clash-verge / ClashX -> Clash YAML with url-test, fallback, and select groups
- sing-box -> Client config.json with L3 TUN, split DNS (Yandex DoH for .ru), and split routing
- Generic (Streisand, v2rayNG, curl, browser) -> Base64-encoded URI list (vless://, hysteria2://)
- Unknown or invalid token -> HTTP 404
"""

import argparse
import base64
import json
import os
import re
import sys
from http import HTTPStatus
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs


def build_clash_yaml(manifest, user):
    username = user.get("name", "user")
    uuid = user.get("uuid", "")
    password = user.get("password", "")

    server_domain = (
        manifest.get("server", {}).get("domain")
        or manifest.get("server", {}).get("ipv4")
        or "127.0.0.1"
    )

    vless = manifest.get("protocols", {}).get("vless_reality", {})
    reality_port = vless.get("port", 443)
    reality_sni = vless.get("sni", "gateway.icloud.com")
    reality_pbk = vless.get("public_key", "")
    reality_sid = vless.get("short_id", "")

    hy2 = manifest.get("protocols", {}).get("hysteria2", {})
    hy2_port = hy2.get("port", 443)
    hy2_obfs = hy2.get("obfs_password", "")

    yaml_text = f"""# vpn-installer adaptive subscription - Clash.Meta / Mihomo
port: 7890
socks-port: 7891
allow-lan: false
mode: rule
log-level: info
unified-delay: true

proxies:
  - name: "VLESS-Reality"
    type: vless
    server: {server_domain}
    port: {reality_port}
    uuid: {uuid}
    network: tcp
    tls: true
    udp: true
    flow: xtls-rprx-vision
    servername: {reality_sni}
    reality-opts:
      public-key: {reality_pbk}
      short-id: {reality_sid}
    client-fingerprint: chrome

  - name: "Hysteria2"
    type: hysteria2
    server: {server_domain}
    port: {hy2_port}
    password: {password}
    sni: {reality_sni}
    skip-cert-verify: true
    obfs: salamander
    obfs-password: {hy2_obfs}

proxy-groups:
  - name: "AUTO-FASTEST"
    type: url-test
    url: "https://www.gstatic.com/generate_204"
    interval: 300
    tolerance: 50
    proxies:
      - "VLESS-Reality"
      - "Hysteria2"

  - name: "FALLBACK"
    type: fallback
    url: "https://www.gstatic.com/generate_204"
    interval: 300
    proxies:
      - "VLESS-Reality"
      - "Hysteria2"

  - name: "PROXY"
    type: select
    proxies:
      - "AUTO-FASTEST"
      - "FALLBACK"
      - "VLESS-Reality"
      - "Hysteria2"

rules:
  - GEOIP,private,DIRECT,no-resolve
  - GEOSITE,ru,DIRECT
  - GEOIP,ru,DIRECT
  - MATCH,PROXY
"""
    return yaml_text.strip() + "\n"


def build_singbox_json(manifest, user):
    username = user.get("name", "user")
    uuid = user.get("uuid", "")
    password = user.get("password", "")

    server_domain = (
        manifest.get("server", {}).get("domain")
        or manifest.get("server", {}).get("ipv4")
        or "127.0.0.1"
    )

    vless = manifest.get("protocols", {}).get("vless_reality", {})
    reality_port = vless.get("port", 443)
    reality_sni = vless.get("sni", "gateway.icloud.com")
    reality_pbk = vless.get("public_key", "")
    reality_sid = vless.get("short_id", "")

    hy2 = manifest.get("protocols", {}).get("hysteria2", {})
    hy2_port = hy2.get("port", 443)
    hy2_obfs = hy2.get("obfs_password", "")

    config = {
        "log": {
            "level": "info",
            "timestamp": True
        },
        "dns": {
            "servers": [
                {
                    "tag": "dns-remote",
                    "type": "https",
                    "server": "1.1.1.1",
                    "path": "/dns-query",
                    "detour": "vless-proxy"
                },
                {
                    "tag": "dns-direct",
                    "type": "https",
                    "server": "77.88.8.8",
                    "path": "/dns-query"
                }
            ],
            "rules": [
                {
                    "rule_set": "geosite-category-ads-all",
                    "action": "reject"
                },
                {
                    "rule_set": "geosite-ru",
                    "server": "dns-direct"
                },
                {
                    "rule_set": "geosite-openai",
                    "server": "dns-remote"
                }
            ],
            "final": "dns-remote",
            "strategy": "prefer_ipv4",
            "reverse_mapping": True
        },
        "inbounds": [
            {
                "type": "tun",
                "tag": "tun-in",
                "interface_name": "sing-tun",
                "address": [
                    "172.19.0.1/30"
                ],
                "auto_route": True,
                "strict_route": True,
                "stack": "system"
            }
        ],
        "outbounds": [
            {
                "type": "vless",
                "tag": "vless-proxy",
                "server": server_domain,
                "server_port": reality_port,
                "uuid": uuid,
                "flow": "xtls-rprx-vision",
                "tls": {
                    "enabled": True,
                    "server_name": reality_sni,
                    "utls": {
                        "enabled": True,
                        "fingerprint": "chrome"
                    },
                    "reality": {
                        "enabled": True,
                        "public_key": reality_pbk,
                        "short_id": reality_sid
                    }
                }
            },
            {
                "type": "hysteria2",
                "tag": "hy2-proxy",
                "server": server_domain,
                "server_port": hy2_port,
                "password": password,
                "tls": {
                    "enabled": True,
                    "server_name": reality_sni,
                    "insecure": True
                },
                "obfs": {
                    "type": "salamander",
                    "password": hy2_obfs
                }
            },
            {
                "type": "direct",
                "tag": "direct"
            },
            {
                "type": "block",
                "tag": "block"
            }
        ],
        "route": {
            "default_domain_resolver": "dns-direct",
            "rule_set": [
                {
                    "tag": "geosite-category-ads-all",
                    "type": "remote",
                    "format": "binary",
                    "url": "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/sing/geo/geosite/category-ads-all.srs",
                    "download_detour": "direct"
                },
                {
                    "tag": "geosite-ru",
                    "type": "remote",
                    "format": "binary",
                    "url": "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/sing/geo/geosite/category-ru.srs",
                    "download_detour": "direct"
                },
                {
                    "tag": "geoip-ru",
                    "type": "remote",
                    "format": "binary",
                    "url": "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/sing/geo/geoip/ru.srs",
                    "download_detour": "direct"
                },
                {
                    "tag": "geosite-openai",
                    "type": "remote",
                    "format": "binary",
                    "url": "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/sing/geo/geosite/openai.srs",
                    "download_detour": "vless-proxy"
                }
            ],
            "rules": [
                {
                    "action": "sniff"
                },
                {
                    "protocol": "dns",
                    "action": "hijack-dns"
                },
                {
                    "port": 53,
                    "action": "hijack-dns"
                },
                {
                    "rule_set": "geosite-category-ads-all",
                    "outbound": "block"
                },
                {
                    "ip_is_private": True,
                    "outbound": "direct"
                },
                {
                    "rule_set": [
                        "geosite-ru",
                        "geoip-ru"
                    ],
                    "outbound": "direct"
                }
            ],
            "final": "vless-proxy",
            "auto_detect_interface": True
        }
    }
    return json.dumps(config, indent=2, ensure_ascii=False) + "\n"


def build_base64_uris(manifest, user):
    username = user.get("name", "user")
    uuid = user.get("uuid", "")
    password = user.get("password", "")

    server_domain = (
        manifest.get("server", {}).get("domain")
        or manifest.get("server", {}).get("ipv4")
        or "127.0.0.1"
    )

    vless = manifest.get("protocols", {}).get("vless_reality", {})
    reality_port = vless.get("port", 443)
    reality_sni = vless.get("sni", "gateway.icloud.com")
    reality_pbk = vless.get("public_key", "")
    reality_sid = vless.get("short_id", "")

    hy2 = manifest.get("protocols", {}).get("hysteria2", {})
    hy2_port = hy2.get("port", 443)
    hy2_obfs = hy2.get("obfs_password", "")

    vless_uri = f"vless://{uuid}@{server_domain}:{reality_port}?security=reality&flow=xtls-rprx-vision&pbk={reality_pbk}&sni={reality_sni}&sid={reality_sid}&fp=chrome#{username}-Reality"
    hy2_uri = f"hysteria2://{password}@{server_domain}:{hy2_port}/?sni={reality_sni}&obfs=salamander&obfs-password={hy2_obfs}&insecure=1#{username}-Hy2"

    raw_text = f"{vless_uri}\n{hy2_uri}\n"
    return base64.b64encode(raw_text.encode("utf-8")).decode("utf-8") + "\n"


class SubscriptionHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        # Concise logging
        sys.stderr.write(f"[sub-server] {self.address_string()} - {format % args}\n")

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/")
        query = parse_qs(parsed.query)

        # Match /sub/<token>
        m = re.match(r"^/sub/([a-zA-Z0-9_-]+)$", path)
        if not m:
            self.send_response(HTTPStatus.NOT_FOUND)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.end_headers()
            self.wfile.write(b"Not Found\n")
            return

        token = m.group(1)
        vpn_dir = self.server.vpn_dir
        users_file = os.path.join(vpn_dir, "users.json")
        manifest_file = os.path.join(vpn_dir, "manifest.json")

        if not os.path.isfile(users_file):
            self.send_response(HTTPStatus.NOT_FOUND)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.end_headers()
            self.wfile.write(b"Not Found\n")
            return

        try:
            with open(users_file, "r", encoding="utf-8") as uf:
                users_data = json.load(uf)
        except Exception:
            self.send_response(HTTPStatus.INTERNAL_SERVER_ERROR)
            self.end_headers()
            return

        manifest_data = {}
        if os.path.isfile(manifest_file):
            try:
                with open(manifest_file, "r", encoding="utf-8") as mf:
                    manifest_data = json.load(mf)
            except Exception:
                pass

        # Find active user with matching sub_token
        target_user = None
        for u in users_data.get("users", []):
            if u.get("sub_token") == token:
                if u.get("status") == "active":
                    target_user = u
                break

        if not target_user:
            # Return 404 without leaking service presence
            self.send_response(HTTPStatus.NOT_FOUND)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.end_headers()
            self.wfile.write(b"Not Found\n")
            return

        # Determine target format
        fmt = query.get("format", [None])[0]
        user_agent = self.headers.get("User-Agent", "")

        selected_format = "base64"
        if fmt:
            fmt_lower = fmt.lower()
            if fmt_lower in ("clash", "mihomo", "meta", "yaml"):
                selected_format = "clash"
            elif fmt_lower in ("singbox", "sing-box", "json"):
                selected_format = "singbox"
            elif fmt_lower in ("base64", "b64", "uri", "uris"):
                selected_format = "base64"
        else:
            ua_lower = user_agent.lower()
            if "clash" in ua_lower or "mihomo" in ua_lower:
                selected_format = "clash"
            elif "sing-box" in ua_lower or "singbox" in ua_lower:
                selected_format = "singbox"
            else:
                selected_format = "base64"

        # Generate response payload
        if selected_format == "clash":
            payload = build_clash_yaml(manifest_data, target_user).encode("utf-8")
            content_type = "application/x-yaml; charset=utf-8"
            filename = "vpn-clash.yaml"
        elif selected_format == "singbox":
            payload = build_singbox_json(manifest_data, target_user).encode("utf-8")
            content_type = "application/json; charset=utf-8"
            filename = "config.json"
        else:
            payload = build_base64_uris(manifest_data, target_user).encode("utf-8")
            content_type = "text/plain; charset=utf-8"
            filename = "subscription.txt"

        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Content-Disposition", f'inline; filename="{filename}"')
        self.send_header("Profile-Update-Interval", "24")
        self.send_header("Subscription-Userinfo", "upload=0; download=0; total=1073741824000; expire=0")
        self.end_headers()
        self.wfile.write(payload)


class SubServer(HTTPServer):
    def __init__(self, server_address, RequestHandlerClass, vpn_dir):
        super().__init__(server_address, RequestHandlerClass)
        self.vpn_dir = vpn_dir


def main():
    parser = argparse.ArgumentParser(description="VPN Installer Subscription Responder")
    parser.add_argument("--host", default=os.environ.get("SUB_HOST", "127.0.0.1"), help="Host IP to bind to")
    parser.add_argument("--port", type=int, default=int(os.environ.get("SUB_PORT", "8088")), help="Port to listen on")
    parser.add_argument("--vpn-dir", default=os.environ.get("VPN_DIR", "/opt/vpn-installer"), help="VPN directory path")
    args = parser.parse_args()

    server_address = (args.host, args.port)
    httpd = SubServer(server_address, SubscriptionHandler, args.vpn_dir)
    sys.stderr.write(f"[sub-server] Serving subscriptions on {args.host}:{args.port} (vpn-dir={args.vpn_dir})\n")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()


if __name__ == "__main__":
    main()
