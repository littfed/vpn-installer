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
import hashlib
from http import HTTPStatus
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs


def get_cert_sha256(vpn_dir=None):
    if not vpn_dir:
        return ""
    cert_path = os.path.join(vpn_dir, "certs", "fullchain.pem")
    if os.path.isfile(cert_path):
        try:
            with open(cert_path, "r", encoding="utf-8") as cf:
                b64 = "".join([line.strip() for line in cf if not line.startswith("-----")])
                return hashlib.sha256(base64.b64decode(b64)).hexdigest().lower()
        except Exception:
            pass
    return ""


def load_node_health(vpn_dir=None):
    if not vpn_dir:
        return {}
    health_file = os.path.join(vpn_dir, "node-health.json")
    if os.path.isfile(health_file):
        try:
            with open(health_file, "r", encoding="utf-8") as hf:
                return json.load(hf)
        except Exception:
            pass
    return {}


def get_nodes(manifest, vpn_dir=None):
    nodes = None
    if vpn_dir:
        nodes_file = os.path.join(vpn_dir, "nodes.json")
        if os.path.isfile(nodes_file):
            try:
                with open(nodes_file, "r", encoding="utf-8") as nf:
                    data = json.load(nf)
                    if data.get("nodes"):
                        nodes = data["nodes"]
            except Exception:
                pass
    if nodes is None:
        if manifest.get("nodes"):
            nodes = manifest["nodes"]
        else:
            server_domain = (
                manifest.get("server", {}).get("domain")
                or manifest.get("server", {}).get("ipv4")
                or "127.0.0.1"
            )
            nodes = [
                {
                    "name": server_domain,
                    "server": server_domain,
                    "protocols": manifest.get("protocols", {})
                }
            ]

    local_pin = get_cert_sha256(vpn_dir)
    if local_pin:
        for node in nodes:
            hy2 = node.setdefault("protocols", {}).setdefault("hysteria2", {})
            if not hy2.get("pin_sha256"):
                hy2["pin_sha256"] = local_pin

    return nodes


def build_clash_yaml(manifest, user, vpn_dir=None):
    username = user.get("name", "user")
    uuid = user.get("uuid", "")
    password = user.get("password", "")
    nodes = get_nodes(manifest, vpn_dir)
    health_data = load_node_health(vpn_dir)
    nodes_health = health_data.get("nodes", {})

    proxies_list = []
    proxy_names = []
    healthy_names = []
    degraded_names = []

    for idx, node in enumerate(nodes):
        node_name = node.get("name", f"Node-{idx+1}")
        host = node.get("server") or node.get("domain") or node.get("ipv4") or "127.0.0.1"
        vless = node.get("protocols", {}).get("vless_reality", {})
        hy2 = node.get("protocols", {}).get("hysteria2", {})

        nh = nodes_health.get(node_name, {}).get("protocols", {})
        vless_status = nh.get("vless_reality", {}).get("status", "healthy")
        hy2_status = nh.get("hysteria2", {}).get("status", "healthy")
        tuic_status = nh.get("tuic", {}).get("status", "healthy")

        if vless.get("enabled", True) and vless.get("public_key"):
            vless_name = f"{node_name} - Reality" if len(nodes) > 1 else "VLESS-Reality"
            proxy_names.append(vless_name)
            if vless_status == "healthy":
                healthy_names.append(vless_name)
            else:
                degraded_names.append(vless_name)
            proxies_list.append(f"""  - name: "{vless_name}"
    type: vless
    server: {host}
    port: {vless.get("port", 443)}
    uuid: {uuid}
    network: tcp
    tls: true
    udp: true
    flow: xtls-rprx-vision
    servername: {vless.get("sni", "gateway.icloud.com")}
    reality-opts:
      public-key: {vless.get("public_key", "")}
      short-id: {vless.get("short_id", "")}
    client-fingerprint: chrome""")

        if hy2.get("enabled", True):
            hy2_name = f"{node_name} - Hysteria2" if len(nodes) > 1 else "Hysteria2"
            proxy_names.append(hy2_name)
            if hy2_status == "healthy":
                healthy_names.append(hy2_name)
            else:
                degraded_names.append(hy2_name)
            hy2_pin = hy2.get("pin_sha256") or hy2.get("pinned_peer_cert_sha256") or ""
            fingerprint_line = f"\n    fingerprint: \"{hy2_pin}\"" if hy2_pin else ""
            proxies_list.append(f"""  - name: "{hy2_name}"
    type: hysteria2
    server: {host}
    port: {hy2.get("port", 443)}
    password: {password}
    sni: {hy2.get("sni", vless.get("sni", "gateway.icloud.com"))}
    skip-cert-verify: true{fingerprint_line}
    obfs: salamander
    obfs-password: {hy2.get("obfs_password", "")}""")

        tuic = node.get("protocols", {}).get("tuic")
        if tuic and tuic.get("enabled", True):
            tuic_name = f"{node_name} - TUIC" if len(nodes) > 1 else "TUIC-v5"
            proxy_names.append(tuic_name)
            if tuic_status == "healthy":
                healthy_names.append(tuic_name)
            else:
                degraded_names.append(tuic_name)
            tuic_sni = tuic.get("sni", hy2.get("sni", vless.get("sni", "gateway.icloud.com")))
            proxies_list.append(f"""  - name: "{tuic_name}"
    type: tuic
    server: {host}
    port: {tuic.get("port", 8443)}
    uuid: {uuid}
    password: {password}
    sni: {tuic_sni}
    skip-cert-verify: true
    congestion-controller: bbr
    alpn:
      - h3""")

    proxies_yaml = "\n\n".join(proxies_list)

    # Active pool excludes degraded/offline if any healthy node exists
    active_pool = healthy_names if healthy_names else proxy_names
    fallback_pool = healthy_names + degraded_names if healthy_names else proxy_names

    auto_entries = "\n".join([f'      - "{p}"' for p in active_pool])
    fallback_entries = "\n".join([f'      - "{p}"' for p in fallback_pool])
    select_entries = "\n".join([f'      - "{p}"' for p in fallback_pool])

    yaml_text = f"""# vpn-installer adaptive subscription - Clash.Meta / Mihomo
port: 7890
socks-port: 7891
allow-lan: false
mode: rule
log-level: info
unified-delay: true

proxies:
{proxies_yaml}

proxy-groups:
  - name: "AUTO-FASTEST"
    type: url-test
    url: "https://www.gstatic.com/generate_204"
    interval: 300
    tolerance: 50
    proxies:
{auto_entries}

  - name: "FALLBACK"
    type: fallback
    url: "https://www.gstatic.com/generate_204"
    interval: 300
    proxies:
{fallback_entries}

  - name: "PROXY"
    type: select
    proxies:
      - "AUTO-FASTEST"
      - "FALLBACK"
{select_entries}

rules:
  - GEOIP,private,DIRECT,no-resolve
  - GEOSITE,ru,DIRECT
  - GEOIP,ru,DIRECT
  - MATCH,PROXY
"""
    return yaml_text.strip() + "\n"


def build_singbox_json(manifest, user, vpn_dir=None):
    username = user.get("name", "user")
    uuid = user.get("uuid", "")
    password = user.get("password", "")
    nodes = get_nodes(manifest, vpn_dir)
    health_data = load_node_health(vpn_dir)
    nodes_health = health_data.get("nodes", {})

    outbounds = []
    proxy_tags = []
    healthy_tags = []
    degraded_tags = []

    for idx, node in enumerate(nodes):
        node_name = node.get("name", f"Node-{idx+1}")
        host = node.get("server") or node.get("domain") or node.get("ipv4") or "127.0.0.1"
        vless = node.get("protocols", {}).get("vless_reality", {})
        hy2 = node.get("protocols", {}).get("hysteria2", {})

        nh = nodes_health.get(node_name, {}).get("protocols", {})
        vless_status = nh.get("vless_reality", {}).get("status", "healthy")
        hy2_status = nh.get("hysteria2", {}).get("status", "healthy")
        tuic_status = nh.get("tuic", {}).get("status", "healthy")

        if vless.get("enabled", True) and vless.get("public_key"):
            vless_tag = f"{node_name}-Reality" if len(nodes) > 1 else "vless-proxy"
            proxy_tags.append(vless_tag)
            if vless_status == "healthy":
                healthy_tags.append(vless_tag)
            else:
                degraded_tags.append(vless_tag)
            outbounds.append({
                "type": "vless",
                "tag": vless_tag,
                "server": host,
                "server_port": vless.get("port", 443),
                "uuid": uuid,
                "flow": "xtls-rprx-vision",
                "tls": {
                    "enabled": True,
                    "server_name": vless.get("sni", "gateway.icloud.com"),
                    "utls": {
                        "enabled": True,
                        "fingerprint": "chrome"
                    },
                    "reality": {
                        "enabled": True,
                        "public_key": vless.get("public_key", ""),
                        "short_id": vless.get("short_id", "")
                    }
                }
            })

        if hy2.get("enabled", True):
            hy2_tag = f"{node_name}-Hy2" if len(nodes) > 1 else "hy2-proxy"
            proxy_tags.append(hy2_tag)
            if hy2_status == "healthy":
                healthy_tags.append(hy2_tag)
            else:
                degraded_tags.append(hy2_tag)
            outbounds.append({
                "type": "hysteria2",
                "tag": hy2_tag,
                "server": host,
                "server_port": hy2.get("port", 443),
                "password": password,
                "tls": {
                    "enabled": True,
                    "server_name": hy2.get("sni", vless.get("sni", "gateway.icloud.com")),
                    "insecure": True
                },
                "obfs": {
                    "type": "salamander",
                    "password": hy2.get("obfs_password", "")
                }
            })

        tuic = node.get("protocols", {}).get("tuic")
        if tuic and tuic.get("enabled", True):
            tuic_tag = f"{node_name}-TUIC" if len(nodes) > 1 else "tuic-proxy"
            proxy_tags.append(tuic_tag)
            if tuic_status == "healthy":
                healthy_tags.append(tuic_tag)
            else:
                degraded_tags.append(tuic_tag)
            tuic_sni = tuic.get("sni", hy2.get("sni", vless.get("sni", "gateway.icloud.com")))
            outbounds.append({
                "type": "tuic",
                "tag": tuic_tag,
                "server": host,
                "server_port": tuic.get("port", 8443),
                "uuid": uuid,
                "password": password,
                "congestion_control": "bbr",
                "tls": {
                    "enabled": True,
                    "server_name": tuic_sni,
                    "alpn": [
                        "h3"
                    ],
                    "insecure": True
                }
            })

    if len(proxy_tags) > 1:
        active_tags = healthy_tags if healthy_tags else proxy_tags
        selector_tags = healthy_tags + degraded_tags if healthy_tags else proxy_tags
        outbounds.append({
            "type": "urltest",
            "tag": "proxy-auto",
            "outbounds": list(active_tags),
            "url": "https://www.gstatic.com/generate_204",
            "interval": "5m",
            "tolerance": 50
        })
        outbounds.append({
            "type": "selector",
            "tag": "proxy",
            "outbounds": ["proxy-auto"] + list(selector_tags),
            "default": "proxy-auto"
        })
        final_proxy = "proxy"
        dns_detour = "proxy-auto"
    else:
        final_proxy = proxy_tags[0] if proxy_tags else "direct"
        dns_detour = final_proxy

    outbounds.append({"type": "direct", "tag": "direct"})
    outbounds.append({"type": "block", "tag": "block"})

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
                    "detour": dns_detour
                },
                {
                    "tag": "dns-direct",
                    "type": "udp",
                    "server": "77.88.8.8"
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
                "strict_route": False
            },
            {
                "type": "mixed",
                "tag": "mixed-in",
                "listen": "127.0.0.1",
                "listen_port": 20808
            }
        ],
        "outbounds": outbounds,
        "http_clients": [
            {
                "tag": "direct-client"
            }
        ],
        "route": {
            "default_domain_resolver": "dns-direct",
            "default_http_client": "direct-client",
            "rule_set": [
                {
                    "tag": "geosite-category-ads-all",
                    "type": "remote",
                    "format": "binary",
                    "url": "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/sing/geo/geosite/category-ads-all.srs"
                },
                {
                    "tag": "geosite-ru",
                    "type": "remote",
                    "format": "binary",
                    "url": "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/sing/geo/geosite/category-ru.srs"
                },
                {
                    "tag": "geoip-ru",
                    "type": "remote",
                    "format": "binary",
                    "url": "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/sing/geo/geoip/ru.srs"
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
            "final": final_proxy,
            "auto_detect_interface": True
        }
    }
    return json.dumps(config, indent=2, ensure_ascii=False) + "\n"


def build_awg_conf(manifest, user, vpn_dir=None, target_node=None):
    nodes = get_nodes(manifest, vpn_dir)
    awg_user = user.get("awg", {})
    client_priv = awg_user.get("private_key", "")
    client_ip = awg_user.get("ip", "10.8.0.2/32")

    selected_node = None
    for n in nodes:
        if target_node and n.get("name", "").lower() == target_node.lower():
            selected_node = n
            break
        if not selected_node and n.get("protocols", {}).get("amneziawg", {}).get("enabled", True):
            selected_node = n

    if not selected_node and nodes:
        selected_node = nodes[0]

    awg_proto = selected_node.get("protocols", {}).get("amneziawg", {}) if selected_node else {}
    server_host = selected_node.get("server") or selected_node.get("domain") or selected_node.get("ipv4") or "127.0.0.1"
    server_port = awg_proto.get("port", 48291)
    server_pub = awg_proto.get("public_key", "")

    jc = awg_proto.get("jc", 5)
    jmin = awg_proto.get("jmin", 40)
    jmax = awg_proto.get("jmax", 70)
    s1 = awg_proto.get("s1", 35)
    s2 = awg_proto.get("s2", 55)
    h1 = awg_proto.get("h1", 123456)
    h2 = awg_proto.get("h2", 234567)
    h3 = awg_proto.get("h3", 345678)
    h4 = awg_proto.get("h4", 456789)

    lines = [
        "[Interface]",
        f"PrivateKey = {client_priv}",
        f"Address = {client_ip}",
        "DNS = 1.1.1.1, 77.88.8.8",
        f"Jc = {jc}",
        f"Jmin = {jmin}",
        f"Jmax = {jmax}",
        f"S1 = {s1}",
        f"S2 = {s2}",
        f"H1 = {h1}",
        f"H2 = {h2}",
        f"H3 = {h3}",
        f"H4 = {h4}",
        "",
        "[Peer]",
        f"PublicKey = {server_pub}",
        f"Endpoint = {server_host}:{server_port}",
        "AllowedIPs = 0.0.0.0/0, ::/0",
        "PersistentKeepalive = 25",
        ""
    ]
    return "\n".join(lines)


def build_base64_uris(manifest, user, vpn_dir=None):
    username = user.get("name", "user")
    uuid = user.get("uuid", "")
    password = user.get("password", "")
    nodes = get_nodes(manifest, vpn_dir)
    health_data = load_node_health(vpn_dir)
    nodes_health = health_data.get("nodes", {})

    uris = []
    for idx, node in enumerate(nodes):
        node_name = node.get("name", f"Node-{idx+1}")
        host = node.get("server") or node.get("domain") or node.get("ipv4") or "127.0.0.1"
        vless = node.get("protocols", {}).get("vless_reality", {})
        hy2 = node.get("protocols", {}).get("hysteria2", {})

        nh = nodes_health.get(node_name, {}).get("protocols", {})
        vless_status = nh.get("vless_reality", {}).get("status", "healthy")
        hy2_status = nh.get("hysteria2", {}).get("status", "healthy")

        suffix = f"-{node_name}" if len(nodes) > 1 else ""
        vless_flag = "-DEGRADED" if vless_status == "degraded" else ""
        hy2_flag = "-DEGRADED" if hy2_status == "degraded" else ""

        if vless.get("enabled", True) and vless.get("public_key"):
            uris.append(
                f"vless://{uuid}@{host}:{vless.get('port', 443)}?security=reality&flow=xtls-rprx-vision&pbk={vless.get('public_key', '')}&sni={vless.get('sni', 'gateway.icloud.com')}&sid={vless.get('short_id', '')}&fp=chrome#{username}-Reality{suffix}{vless_flag}"
            )
        if hy2.get("enabled", True):
            hy2_pin = hy2.get("pin_sha256") or hy2.get("pinned_peer_cert_sha256") or ""
            if hy2_pin:
                tls_pin_params = f"&pinSHA256={hy2_pin}&pinnedPeerCertSha256={hy2_pin}"
            else:
                tls_pin_params = "&insecure=1"
            uris.append(
                f"hysteria2://{password}@{host}:{hy2.get('port', 443)}/?sni={hy2.get('sni', vless.get('sni', 'gateway.icloud.com'))}&obfs=salamander&obfs-password={hy2.get('obfs_password', '')}{tls_pin_params}#{username}-Hy2{suffix}{hy2_flag}"
            )
        tuic = node.get("protocols", {}).get("tuic")
        tuic_status = nh.get("tuic", {}).get("status", "healthy")
        tuic_flag = "-DEGRADED" if tuic_status == "degraded" else ""
        if tuic and tuic.get("enabled", True):
            tuic_sni = tuic.get("sni", hy2.get("sni", vless.get("sni", "gateway.icloud.com")))
            uris.append(
                f"tuic://{uuid}:{password}@{host}:{tuic.get('port', 8443)}/?sni={tuic_sni}&congestion_control=bbr&alpn=h3&allow_insecure=1#{username}-TUIC{suffix}{tuic_flag}"
            )

    raw_text = "\n".join(uris) + "\n"
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
            elif fmt_lower in ("awg", "amnezia", "amneziawg", "conf"):
                selected_format = "awg"
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
            payload = build_clash_yaml(manifest_data, target_user, vpn_dir).encode("utf-8")
            content_type = "application/x-yaml; charset=utf-8"
            filename = "vpn-clash.yaml"
        elif selected_format == "singbox":
            payload = build_singbox_json(manifest_data, target_user, vpn_dir).encode("utf-8")
            content_type = "application/json; charset=utf-8"
            filename = "config.json"
        elif selected_format == "awg":
            target_node = query.get("node", [None])[0]
            payload = build_awg_conf(manifest_data, target_user, vpn_dir, target_node).encode("utf-8")
            content_type = "text/plain; charset=utf-8"
            username = target_user.get("name", "vpn")
            filename = f"{username}-awg.conf"
        else:
            payload = build_base64_uris(manifest_data, target_user, vpn_dir).encode("utf-8")
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
