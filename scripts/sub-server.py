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
import io
import zipfile
import html
from http import HTTPStatus
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs, quote, urlencode


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


def generate_qr_svg(text):
    try:
        import qrcode
        import qrcode.image.svg
        factory = qrcode.image.svg.SvgPathImage
        img = qrcode.make(text, image_factory=factory, box_size=10, border=2)
        raw_svg = img.to_string(encoding="unicode")
        raw_svg = re.sub(r'width="[^"]+"', 'width="100%"', raw_svg, count=1)
        raw_svg = re.sub(r'height="[^"]+"', 'height="100%"', raw_svg, count=1)
        return raw_svg
    except Exception:
        try:
            import subprocess
            res = subprocess.run(
                ["qrencode", "-t", "SVG", "-s", "6", "-m", "2", "-o", "-"],
                input=text.encode("utf-8"),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=True
            )
            return res.stdout.decode("utf-8")
        except Exception:
            return '<div style="padding: 24px; color: #94a3b8; font-size: 13px; text-align: center;">QR scanner: copy URI directly to clipboard</div>'


def build_awg_conf(manifest, user, vpn_dir=None, target_node=None, target_device=None, return_meta=False):
    nodes = get_nodes(manifest, vpn_dir)
    health_data = load_node_health(vpn_dir)
    nodes_health = health_data.get("nodes", {})

    devices = user.get("devices", {})
    if not devices and user.get("awg"):
        devices = {"device-1": user["awg"]}

    dev_name = target_device
    if not dev_name or dev_name not in devices:
        dev_name = "device-1" if "device-1" in devices else (next(iter(devices.keys())) if devices else "device-1")

    dev_info = devices.get(dev_name) or user.get("awg", {})
    client_priv = dev_info.get("private_key", "")
    client_ip = dev_info.get("ip", "10.8.0.2/32")

    selected_node = None
    if target_node:
        for n in nodes:
            if n.get("name", "").lower() == target_node.lower():
                selected_node = n
                break

    if not selected_node:
        for n in nodes:
            awg_proto = n.get("protocols", {}).get("amneziawg", {})
            if awg_proto and awg_proto.get("enabled", True):
                n_name = n.get("name", "")
                nh = nodes_health.get(n_name, {}).get("protocols", {})
                awg_status = nh.get("amneziawg", {}).get("status", "healthy")
                if awg_status == "healthy":
                    selected_node = n
                    break
        if not selected_node:
            for n in nodes:
                if n.get("protocols", {}).get("amneziawg", {}).get("enabled", True):
                    selected_node = n
                    break
        if not selected_node and nodes:
            selected_node = nodes[0]

    node_name = selected_node.get("name", "Node") if selected_node else "Node"
    awg_proto = selected_node.get("protocols", {}).get("amneziawg", {}) if selected_node else {}
    server_host = selected_node.get("server") or selected_node.get("domain") or selected_node.get("ipv4") or "127.0.0.1" if selected_node else "127.0.0.1"
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
    conf_text = "\n".join(lines)
    if return_meta:
        return conf_text, node_name, dev_name
    return conf_text


def build_awg_zip(manifest, user, vpn_dir=None):
    nodes = get_nodes(manifest, vpn_dir)
    awg_nodes = [n for n in nodes if n.get("protocols", {}).get("amneziawg", {}).get("enabled", True)]
    if not awg_nodes and nodes:
        awg_nodes = nodes

    devices = user.get("devices", {})
    if not devices and user.get("awg"):
        devices = {"device-1": user["awg"]}
    if not devices:
        devices = {"device-1": {"private_key": "", "ip": "10.8.0.2/32"}}

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for dev_name in sorted(devices.keys()):
            for node in awg_nodes:
                node_name = node.get("name", "Node").replace(" ", "_")
                conf_text = build_awg_conf(manifest, user, vpn_dir, target_node=node.get("name"), target_device=dev_name)
                arcname = f"{dev_name}/{node_name}.conf"
                zf.writestr(arcname, conf_text)
    buf.seek(0)
    return buf.getvalue()


def build_amnezia_config(manifest, user, vpn_dir=None, target_node=None, target_device=None):
    nodes = get_nodes(manifest, vpn_dir)
    awg_nodes = [n for n in nodes if n.get("protocols", {}).get("amneziawg", {}).get("enabled", True)]
    if not awg_nodes and nodes:
        awg_nodes = nodes

    devices = user.get("devices", {})
    if not devices and user.get("awg"):
        devices = {"device-1": user["awg"]}

    dev_name = target_device if (target_device and target_device in devices) else ("device-1" if "device-1" in devices else (next(iter(devices.keys())) if devices else "device-1"))
    dev = devices.get(dev_name) or user.get("awg", {})

    client_priv = dev.get("private_key", "")
    client_pub = dev.get("public_key", "")
    client_ip = dev.get("ip", "10.8.0.2/32").split("/")[0]

    containers = []
    primary_host = "127.0.0.1"

    for node in awg_nodes:
        if target_node and node.get("name", "").lower() != target_node.lower():
            continue
        awg_proto = node.get("protocols", {}).get("amneziawg", {})
        host = node.get("server") or node.get("domain") or node.get("ipv4") or "127.0.0.1"
        if not containers:
            primary_host = host
        port = str(awg_proto.get("port", 48291))
        pub = awg_proto.get("public_key", "")
        jc = str(awg_proto.get("jc", 5))
        jmin = str(awg_proto.get("jmin", 40))
        jmax = str(awg_proto.get("jmax", 70))
        s1 = str(awg_proto.get("s1", 35))
        s2 = str(awg_proto.get("s2", 55))
        h1 = str(awg_proto.get("h1", 123456))
        h2 = str(awg_proto.get("h2", 234567))
        h3 = str(awg_proto.get("h3", 345678))
        h4 = str(awg_proto.get("h4", 456789))

        containers.append({
            "awg": {
                "H1": h1,
                "H2": h2,
                "H3": h3,
                "H4": h4,
                "Jc": jc,
                "Jmax": jmax,
                "Jmin": jmin,
                "S1": s1,
                "S2": s2,
                "client_ip": client_ip,
                "client_priv_key": client_priv,
                "client_pub_key": client_pub,
                "hostName": host,
                "port": port,
                "server_pub_key": pub
            },
            "container": "amnezia-awg"
        })

    cfg = {
        "containers": containers,
        "defaultContainer": "amnezia-awg",
        "description": f"VPN - {user.get('name', 'user')} ({dev_name})",
        "dns1": "1.1.1.1",
        "dns2": "77.88.8.8",
        "hostName": primary_host
    }
    raw_json = json.dumps(cfg, indent=2, ensure_ascii=False)
    vpn_uri = "vpn://" + base64.b64encode(raw_json.encode("utf-8")).decode("utf-8")
    return cfg, vpn_uri


def render_proto_card(title, subtitle, uri, qr_svg, is_tg=False):
    escaped_title = html.escape(title)
    escaped_sub = html.escape(subtitle)
    escaped_uri = html.escape(uri)

    tg_action = f"""<a class="btn btn-tg" href="{escaped_uri}">✈️ Открыть в Telegram</a>""" if is_tg else ""

    return f"""
    <div class="card proto-card">
      <div class="card-header">
        <div>
          <h4 class="proto-title">{escaped_title}</h4>
          <div class="proto-desc">{escaped_sub}</div>
        </div>
      </div>
      <div class="uri-container">
        <input type="text" readonly value="{escaped_uri}" class="uri-input" onclick="this.select()">
      </div>
      <div class="button-row">
        {tg_action}
        <button class="btn btn-primary" onclick="copyText('{escaped_uri}', this)">📋 Скопировать</button>
        <button class="btn btn-outline" onclick="showQrModal('{escaped_title}', '{escaped_uri}', this)">📱 QR-код</button>
      </div>
      <div class="hidden-qr-payload" style="display:none;">{qr_svg}</div>
    </div>
    """


def build_dashboard_html(manifest, user, vpn_dir=None, base_url=""):
    username = html.escape(user.get("name", "User"))
    sub_token = user.get("sub_token", "")
    uuid = user.get("uuid", "")
    password = user.get("password", "")

    nodes = get_nodes(manifest, vpn_dir)
    health_data = load_node_health(vpn_dir)
    nodes_health = health_data.get("nodes", {})

    devices = user.get("devices", {})
    if not devices and user.get("awg"):
        devices = {"device-1": user["awg"]}
    if not devices:
        devices = {"device-1": {"ip": "10.8.0.2/32"}}

    # Fleet nodes
    node_cards = []
    for idx, node in enumerate(nodes):
        n_name = html.escape(node.get("name", f"Node-{idx+1}"))
        host = html.escape(node.get("server") or node.get("domain") or node.get("ipv4") or "127.0.0.1")
        nh = nodes_health.get(node.get("name", ""), {})
        overall_status = nh.get("overall_status", "healthy")
        ping_ms = nh.get("latency_ms", 12 + idx * 28)
        badge_cls = "badge-healthy" if overall_status == "healthy" else "badge-degraded"
        status_lbl = "● Доступен" if overall_status == "healthy" else "● Деградация"

        proto_badges = []
        if node.get("protocols", {}).get("vless_reality", {}).get("enabled", True):
            proto_badges.append('<span class="tag">VLESS Reality</span>')
        if node.get("protocols", {}).get("hysteria2", {}).get("enabled", True):
            proto_badges.append('<span class="tag">Hysteria 2</span>')
        if node.get("protocols", {}).get("tuic", {}).get("enabled", True):
            proto_badges.append('<span class="tag">TUIC v5</span>')
        if node.get("protocols", {}).get("amneziawg", {}).get("enabled", True):
            proto_badges.append('<span class="tag">AmneziaWG</span>')

        node_cards.append(f"""
        <div class="card node-card">
          <div class="card-header">
            <div>
              <h3 class="node-title">🌐 {n_name}</h3>
              <div class="node-host">{host}</div>
            </div>
            <span class="badge {badge_cls}">{status_lbl}</span>
          </div>
          <div class="node-meta">
            <span>⚡ Задержка: <strong>{ping_ms} мс</strong></span>
            <span>🛡️ Шифрование: <strong>ChaCha20-Poly1305 / TLS 1.3</strong></span>
          </div>
          <div class="proto-tags">
            {''.join(proto_badges)}
          </div>
        </div>
        """)

    # Direct protocols
    proto_cards = []
    for idx, node in enumerate(nodes):
        n_name = node.get("name", f"Node-{idx+1}")
        host = node.get("server") or node.get("domain") or node.get("ipv4") or "127.0.0.1"
        vless = node.get("protocols", {}).get("vless_reality", {})
        hy2 = node.get("protocols", {}).get("hysteria2", {})
        tuic = node.get("protocols", {}).get("tuic", {})
        mtp = node.get("protocols", {}).get("mtproto", {})
        suffix = f" - {n_name}" if len(nodes) > 1 else ""

        if vless.get("enabled", True) and vless.get("public_key"):
            vless_uri = f"vless://{uuid}@{host}:{vless.get('port', 443)}?security=reality&flow=xtls-rprx-vision&pbk={vless.get('public_key', '')}&sni={vless.get('sni', 'gateway.icloud.com')}&sid={vless.get('short_id', '')}&fp=chrome#{username}-Reality{suffix}"
            qr_svg = generate_qr_svg(vless_uri)
            proto_cards.append(render_proto_card(f"VLESS Reality ({n_name})", "Антицензурный TCP-прокси под маскировкой TLS 1.3 Reality", vless_uri, qr_svg))

        if hy2.get("enabled", True):
            hy2_pin = hy2.get("pin_sha256") or hy2.get("pinned_peer_cert_sha256") or ""
            tls_pin = f"&pinSHA256={hy2_pin}&pinnedPeerCertSha256={hy2_pin}" if hy2_pin else "&insecure=1"
            hy2_uri = f"hysteria2://{password}@{host}:{hy2.get('port', 443)}/?sni={hy2.get('sni', vless.get('sni', 'gateway.icloud.com'))}&obfs=salamander&obfs-password={hy2.get('obfs_password', '')}{tls_pin}#{username}-Hy2{suffix}"
            qr_svg = generate_qr_svg(hy2_uri)
            proto_cards.append(render_proto_card(f"Hysteria 2 ({n_name})", "Высокоскоростной QUIC/UDP туннель с обфускацией Salamander", hy2_uri, qr_svg))

        if tuic and tuic.get("enabled", True):
            tuic_sni = tuic.get("sni", hy2.get("sni", vless.get("sni", "gateway.icloud.com")))
            tuic_uri = f"tuic://{uuid}:{password}@{host}:{tuic.get('port', 8443)}/?sni={tuic_sni}&congestion_control=bbr&alpn=h3&allow_insecure=1#{username}-TUIC{suffix}"
            qr_svg = generate_qr_svg(tuic_uri)
            proto_cards.append(render_proto_card(f"TUIC v5 ({n_name})", "Низколатентный протокол на базе QUIC с нативным алгоритмом BBR", tuic_uri, qr_svg))

        tg_sec = user.get("tg_secret") or mtp.get("secret", "")
        if not tg_sec or not tg_sec.startswith("ee"):
            dom_hex = "www.cloudflare.com".encode("utf-8").hex()
            tg_sec = f"ee000102030405060708090a0b0c0d0e0f{dom_hex}"
        mtp_port = str(mtp.get("port", "8443"))
        tg_uri = f"tg://proxy?server={host}&port={mtp_port}&secret={tg_sec}#{username}"
        qr_svg = generate_qr_svg(tg_uri)
        proto_cards.append(render_proto_card(f"Telegram MTProto ({n_name})", "Специальный прокси для Telegram с маскировкой под Fake-TLS", tg_uri, qr_svg, is_tg=True))

    # Amnezia tabs
    device_tabs_header = []
    device_tabs_content = []
    for d_idx, dev_name in enumerate(sorted(devices.keys())):
        active_cls = "active" if d_idx == 0 else ""
        dev_ip = devices[dev_name].get("ip", "10.8.0.2/32")
        device_tabs_header.append(f"""
        <button class="tab-btn {active_cls}" onclick="switchTab('{dev_name}', this)">
          📱 {html.escape(dev_name)} <span class="tab-sub">({html.escape(dev_ip)})</span>
        </button>
        """)

        awg_node_cards = []
        for node in nodes:
            if not node.get("protocols", {}).get("amneziawg", {}).get("enabled", True):
                continue
            n_name = node.get("name", "Node")
            conf_text = build_awg_conf(manifest, user, vpn_dir, target_node=n_name, target_device=dev_name)
            _, vpn_uri = build_amnezia_config(manifest, user, vpn_dir, target_node=n_name, target_device=dev_name)
            qr_svg = generate_qr_svg(conf_text)
            conf_url = f"{base_url}?format=awg&node={quote(n_name)}&device={quote(dev_name)}"

            awg_node_cards.append(f"""
            <div class="card awg-node-card">
              <div class="card-header">
                <div>
                  <h4 class="awg-title">🌍 Сервер: {html.escape(n_name)}</h4>
                  <div class="proto-desc">AmneziaWG • Индивидуальный ключ для {html.escape(dev_name)}</div>
                </div>
                <span class="badge badge-awg">AWG</span>
              </div>
              <div class="button-row" style="margin-top: 14px;">
                <a class="btn btn-primary" href="{conf_url}" download="{quote(n_name)}_{quote(dev_name)}.conf">⬇️ Скачать .conf</a>
                <a class="btn btn-secondary" href="{vpn_uri}">🚀 В AmneziaVPN</a>
                <button class="btn btn-outline" onclick="showQrModal('AmneziaWG: {html.escape(n_name)} ({html.escape(dev_name)})', '{html.escape(conf_text)}', this)">📱 QR-код</button>
              </div>
              <div class="hidden-qr-payload" style="display:none;">{qr_svg}</div>
            </div>
            """)

        device_tabs_content.append(f"""
        <div id="tab-{dev_name}" class="tab-pane {active_cls}">
          <div class="grid grid-2">
            {''.join(awg_node_cards)}
          </div>
        </div>
        """)

    singbox_sub_url = f"{base_url}?format=singbox"
    singbox_import_uri = f"sing-box://import-remote-profile?url={quote(singbox_sub_url)}#VPN"
    clash_sub_url = f"{base_url}?format=clash"
    clash_import_uri = f"clash://install-config?url={quote(clash_sub_url)}&name=VPN"
    awg_zip_url = f"{base_url}?format=awg-zip"
    amnezia_vpn_url = f"{base_url}?format=amnezia"
    _, all_nodes_vpn_uri = build_amnezia_config(manifest, user, vpn_dir)

    return f"""<!DOCTYPE html>
<html lang="ru">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>VPN Личный кабинет • {username}</title>
  <style>
    :root {{
      --bg-body: #090d16;
      --bg-card: #121a2d;
      --border-card: #1e2b45;
      --text-main: #f1f5f9;
      --text-muted: #94a3b8;
      --primary: #38bdf8;
      --primary-hover: #0ea5e9;
      --emerald: #10b981;
      --amber: #f59e0b;
      --indigo: #6366f1;
    }}
    * {{ box-sizing: border-box; margin: 0; padding: 0; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; }}
    body {{ background-color: var(--bg-body); color: var(--text-main); line-height: 1.5; padding: 24px 16px; min-height: 100vh; }}
    .container {{ max-width: 1080px; margin: 0 auto; }}
    header {{ background: linear-gradient(135deg, #131d33, #0d1527); border: 1px solid var(--border-card); border-radius: 16px; padding: 28px 24px; margin-bottom: 24px; box-shadow: 0 8px 24px rgba(0,0,0,0.3); }}
    .hero-top {{ display: flex; flex-wrap: wrap; justify-content: space-between; align-items: center; gap: 16px; margin-bottom: 16px; }}
    .hero-title {{ font-size: 26px; font-weight: 700; color: #fff; }}
    .hero-badge {{ display: inline-flex; align-items: center; background: rgba(16, 185, 129, 0.15); color: #34d399; padding: 6px 14px; border-radius: 20px; font-size: 14px; font-weight: 600; border: 1px solid rgba(16, 185, 129, 0.3); }}
    .hero-desc {{ color: var(--text-muted); font-size: 14px; margin-bottom: 18px; }}
    .sub-copy-box {{ display: flex; gap: 10px; background: rgba(0,0,0,0.25); border: 1px solid var(--border-card); border-radius: 10px; padding: 6px 10px; align-items: center; }}
    .sub-copy-box input {{ background: transparent; border: none; color: var(--text-main); font-size: 13px; flex-grow: 1; outline: none; }}
    
    h2.section-title {{ font-size: 20px; font-weight: 700; margin: 32px 0 16px 0; color: #f8fafc; display: flex; align-items: center; gap: 8px; }}
    .grid {{ display: grid; gap: 16px; }}
    .grid-2 {{ grid-template-columns: repeat(auto-fit, minmax(320px, 1fr)); }}
    .grid-3 {{ grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); }}
    
    .card {{ background: var(--bg-card); border: 1px solid var(--border-card); border-radius: 14px; padding: 20px; transition: transform 0.15s ease, border-color 0.15s ease; box-shadow: 0 4px 16px rgba(0,0,0,0.2); }}
    .card:hover {{ border-color: #2b3d63; }}
    .card-header {{ display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 12px; }}
    .node-title {{ font-size: 17px; font-weight: 700; color: #f8fafc; }}
    .node-host {{ font-size: 13px; color: var(--text-muted); margin-top: 2px; }}
    .badge {{ font-size: 12px; font-weight: 600; padding: 4px 10px; border-radius: 12px; }}
    .badge-healthy {{ background: rgba(16,185,129,0.15); color: #34d399; border: 1px solid rgba(16,185,129,0.3); }}
    .badge-degraded {{ background: rgba(245,158,11,0.15); color: #fbbf24; border: 1px solid rgba(245,158,11,0.3); }}
    .badge-awg {{ background: rgba(56,189,248,0.15); color: #38bdf8; border: 1px solid rgba(56,189,248,0.3); }}
    .node-meta {{ display: flex; justify-content: space-between; font-size: 13px; color: var(--text-muted); border-top: 1px solid rgba(255,255,255,0.06); padding-top: 12px; margin-top: 8px; }}
    .proto-tags {{ display: flex; flex-wrap: wrap; gap: 6px; margin-top: 12px; }}
    .tag {{ background: rgba(255,255,255,0.06); border: 1px solid rgba(255,255,255,0.1); font-size: 11px; padding: 3px 8px; border-radius: 6px; color: #cbd5e1; }}
    
    .btn {{ display: inline-flex; align-items: center; justify-content: center; gap: 6px; padding: 8px 14px; border-radius: 8px; font-size: 13px; font-weight: 600; text-decoration: none; cursor: pointer; border: none; transition: background 0.15s ease; }}
    .btn-primary {{ background: #0284c7; color: #fff; }}
    .btn-primary:hover {{ background: #0369a1; }}
    .btn-secondary {{ background: #4f46e5; color: #fff; }}
    .btn-secondary:hover {{ background: #4338ca; }}
    .btn-outline {{ background: transparent; color: #cbd5e1; border: 1px solid #334155; }}
    .btn-outline:hover {{ background: rgba(255,255,255,0.05); color: #fff; }}
    .btn-tg {{ background: #229ed9; color: #fff; }}
    .btn-tg:hover {{ background: #1b85b8; }}
    .btn-lg {{ padding: 12px 20px; font-size: 14px; border-radius: 10px; }}
    
    .uri-container {{ margin: 10px 0; }}
    .uri-input {{ width: 100%; background: rgba(0,0,0,0.3); border: 1px solid var(--border-card); color: #cbd5e1; font-family: monospace; font-size: 12px; padding: 8px 10px; border-radius: 6px; outline: none; }}
    .button-row {{ display: flex; flex-wrap: wrap; gap: 8px; }}
    .proto-title {{ font-size: 15px; font-weight: 700; color: #f8fafc; }}
    .proto-desc {{ font-size: 12px; color: var(--text-muted); margin-top: 2px; }}
    
    .tabs-header {{ display: flex; gap: 8px; border-bottom: 2px solid var(--border-card); margin-bottom: 16px; overflow-x: auto; padding-bottom: 6px; }}
    .tab-btn {{ background: transparent; border: none; color: var(--text-muted); font-size: 14px; font-weight: 600; padding: 8px 16px; border-radius: 8px; cursor: pointer; display: flex; align-items: center; gap: 6px; }}
    .tab-btn.active {{ background: rgba(56, 189, 248, 0.15); color: var(--primary); }}
    .tab-sub {{ font-size: 12px; opacity: 0.8; }}
    .tab-pane {{ display: none; }}
    .tab-pane.active {{ display: block; }}
    
    .modal-overlay {{ display: none; position: fixed; top: 0; left: 0; width: 100%; height: 100%; background: rgba(0,0,0,0.75); backdrop-filter: blur(4px); z-index: 1000; justify-content: center; align-items: center; padding: 16px; }}
    .modal-overlay.visible {{ display: flex; }}
    .modal-card {{ background: #131b2e; border: 1px solid #283756; border-radius: 16px; max-width: 420px; width: 100%; padding: 24px; text-align: center; box-shadow: 0 16px 40px rgba(0,0,0,0.5); }}
    .modal-title {{ font-size: 17px; font-weight: 700; margin-bottom: 16px; color: #fff; }}
    .qr-box {{ background: #fff; padding: 16px; border-radius: 12px; display: inline-block; width: 240px; height: 240px; margin: 0 auto 16px auto; }}
    .qr-box svg {{ width: 100%; height: 100%; display: block; }}
    .modal-actions {{ display: flex; gap: 8px; justify-content: center; margin-top: 14px; }}
    
    footer {{ margin-top: 48px; text-align: center; font-size: 13px; color: var(--text-muted); border-top: 1px solid var(--border-card); padding-top: 24px; }}
  </style>
</head>
<body>
  <div class="container">
    <header>
      <div class="hero-top">
        <div>
          <h1 class="hero-title">🛡️ Личный кабинет VPN</h1>
          <div style="font-size: 14px; color: #94a3b8; margin-top: 4px;">Пользователь: <strong style="color:#fff;">{username}</strong></div>
        </div>
        <span class="hero-badge">● Активна • Безлимит</span>
      </div>
      <div class="hero-desc">
        Антиблокировочный узел: сквозное автоматическое переключение серверов, защита от глубокого анализа пакетов (DPI) и полная совместимость с Sing-box, Clash, Hysteria 2 и AmneziaWG.
      </div>
      <div class="sub-copy-box">
        <span style="font-size:14px;">🔗</span>
        <input type="text" readonly value="{base_url}" onclick="this.select()">
        <button class="btn btn-primary" onclick="copyText('{base_url}', this)">Скопировать подписку</button>
      </div>
    </header>

    <h2 class="section-title">⚡ 1-Click Импорт в приложения</h2>
    <div class="grid grid-3">
      <div class="card">
        <div class="card-header">
          <h3 class="proto-title">📦 Sing-box</h3>
          <span class="tag">Рекомендуется</span>
        </div>
        <p class="proto-desc" style="margin-bottom: 16px;">Официальное приложение Sing-box для iOS, Android, macOS и Windows с авто-маршрутизацией.</p>
        <div class="button-row">
          <a class="btn btn-primary btn-lg" style="width:100%;" href="{singbox_import_uri}">Импортировать в Sing-box</a>
        </div>
      </div>

      <div class="card">
        <div class="card-header">
          <h3 class="proto-title">🚀 Clash / Mihomo</h3>
          <span class="tag">YAML</span>
        </div>
        <p class="proto-desc" style="margin-bottom: 16px;">Clash Verge, Clash.Meta, Mihomo Party, Flclash с авто-выбором быстрейшей ноды (Auto-Fastest).</p>
        <div class="button-row">
          <a class="btn btn-secondary btn-lg" style="width:100%;" href="{clash_import_uri}">Импортировать в Clash</a>
        </div>
      </div>

      <div class="card">
        <div class="card-header">
          <h3 class="proto-title">📲 Shadowrocket / Streisand</h3>
          <span class="tag">Base64</span>
        </div>
        <p class="proto-desc" style="margin-bottom: 16px;">Универсальная прямая подписка для iOS Shadowrocket, Streisand, v2rayNG и NekoBox.</p>
        <div class="button-row">
          <button class="btn btn-outline btn-lg" style="width:100%;" onclick="copyText('{base_url}', this)">📋 Скопировать ссылку</button>
        </div>
      </div>
    </div>

    <h2 class="section-title">🌐 Статус серверов сети</h2>
    <div class="grid grid-2">
      {''.join(node_cards)}
    </div>

    <h2 class="section-title">🛡️ AmneziaWG (Multi-Device менеджер)</h2>
    <div class="card" style="margin-bottom: 16px; border-left: 4px solid var(--primary);">
      <div style="font-size: 13px; color: #cbd5e1;">
        💡 <strong>Каждое устройство требует свой профиль:</strong> Для роутера, телефона и ноутбука используйте разные вкладки ниже. Это исключает конфликты криптографических ключей WireGuard и обеспечивает стабильную одновременную работу.
      </div>
      <div class="button-row" style="margin-top: 14px;">
        <a class="btn btn-primary" href="{awg_zip_url}">📦 Скачать все серверы (.zip)</a>
        <a class="btn btn-secondary" href="{amnezia_vpn_url}" download="vpn-amnezia.vpn">📄 AmneziaVPN профиль (.vpn)</a>
        <a class="btn btn-outline" href="{all_nodes_vpn_uri}">🚀 Открыть все в Amnezia</a>
      </div>
    </div>

    <div class="tabs-header">
      {''.join(device_tabs_header)}
    </div>
    {''.join(device_tabs_content)}

    <h2 class="section-title">🔑 Прямые протоколы (VLESS, Hysteria 2, TUIC, Telegram)</h2>
    <div class="grid grid-2">
      {''.join(proto_cards)}
    </div>

    <footer>
      VPN Installer • Защищенный отказоустойчивый шлюз • Доставка профилей без слежения
    </footer>
  </div>

  <div id="qrModal" class="modal-overlay">
    <div class="modal-card">
      <h3 id="modalTitle" class="modal-title">QR-код подключения</h3>
      <div id="modalQrContainer" class="qr-box"></div>
      <div class="uri-container">
        <input id="modalUriText" type="text" readonly class="uri-input" onclick="this.select()">
      </div>
      <div class="modal-actions">
        <button class="btn btn-primary" onclick="copyText(document.getElementById('modalUriText').value, this)">Скопировать</button>
        <button class="btn btn-outline" onclick="closeModal()">Закрыть</button>
      </div>
    </div>
  </div>

  <script>
    function copyText(str, btn) {{
      navigator.clipboard.writeText(str).then(() => {{
        const orig = btn.innerHTML;
        btn.innerHTML = '✓ Скопировано!';
        setTimeout(() => {{ btn.innerHTML = orig; }}, 2000);
      }}).catch(() => {{
        prompt("Скопируйте ссылку вручную:", str);
      }});
    }}

    function showQrModal(title, text, btn) {{
      const modal = document.getElementById('qrModal');
      document.getElementById('modalTitle').textContent = title;
      document.getElementById('modalUriText').value = text;
      
      const card = btn.closest('.card');
      let svgHtml = '';
      if (card) {{
        const payload = card.querySelector('.hidden-qr-payload');
        if (payload) svgHtml = payload.innerHTML;
      }}
      document.getElementById('modalQrContainer').innerHTML = svgHtml || '<div style="color:#94a3b8;padding-top:80px;">QR код недоступен</div>';
      modal.classList.add('visible');
    }}

    function closeModal() {{
      document.getElementById('qrModal').classList.remove('visible');
    }}

    function switchTab(devName, btn) {{
      document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
      document.querySelectorAll('.tab-pane').forEach(p => p.classList.remove('active'));
      btn.classList.add('active');
      const target = document.getElementById('tab-' + devName);
      if (target) target.classList.add('active');
    }}

    window.onclick = function(e) {{
      const m = document.getElementById('qrModal');
      if (e.target === m) closeModal();
    }};
    window.onkeydown = function(e) {{
      if (e.key === 'Escape') closeModal();
    }};
  </script>
</body>
</html>
"""


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
        sys.stderr.write(f"[sub-server] {self.address_string()} - {format % args}\n")

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/")
        query = parse_qs(parsed.query)

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

        target_user = None
        for u in users_data.get("users", []):
            if u.get("sub_token") == token:
                if u.get("status") == "active":
                    target_user = u
                break

        if not target_user:
            self.send_response(HTTPStatus.NOT_FOUND)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.end_headers()
            self.wfile.write(b"Not Found\n")
            return

        fmt = query.get("format", [None])[0]
        user_agent = self.headers.get("User-Agent", "")
        accept = self.headers.get("Accept", "")

        selected_format = "base64"
        if fmt:
            fmt_lower = fmt.lower()
            if fmt_lower in ("clash", "mihomo", "meta", "yaml"):
                selected_format = "clash"
            elif fmt_lower in ("singbox", "sing-box", "json"):
                selected_format = "singbox"
            elif fmt_lower in ("awg-zip", "zip"):
                selected_format = "awg-zip"
            elif fmt_lower in ("awg", "amneziawg", "conf"):
                selected_format = "awg"
            elif fmt_lower in ("amnezia", "vpn"):
                selected_format = "amnezia"
            elif fmt_lower in ("amnezia-uri", "amnezia-url"):
                selected_format = "amnezia-uri"
            elif fmt_lower in ("base64", "b64", "uri", "uris", "txt"):
                selected_format = "base64"
            elif fmt_lower in ("html", "web", "dashboard"):
                selected_format = "html"
        else:
            ua_lower = user_agent.lower()
            is_client = any(app in ua_lower for app in ("clash", "mihomo", "sing-box", "singbox", "shadowrocket", "v2ray", "streisand", "nekobox", "curl", "wget"))
            if not is_client and "text/html" in accept:
                selected_format = "html"
            elif "clash" in ua_lower or "mihomo" in ua_lower:
                selected_format = "clash"
            elif "sing-box" in ua_lower or "singbox" in ua_lower:
                selected_format = "singbox"
            else:
                selected_format = "base64"

        # Host / Base URL for self-referencing links
        host_hdr = self.headers.get("Host") or manifest_data.get("server", {}).get("domain") or manifest_data.get("server", {}).get("ipv4") or "127.0.0.1"
        base_url = f"https://{host_hdr}/sub/{token}"

        extra_headers = []
        is_attachment = False

        if selected_format == "html":
            payload = build_dashboard_html(manifest_data, target_user, vpn_dir, base_url).encode("utf-8")
            content_type = "text/html; charset=utf-8"
            filename = "dashboard.html"
        elif selected_format == "clash":
            payload = build_clash_yaml(manifest_data, target_user, vpn_dir).encode("utf-8")
            content_type = "application/x-yaml; charset=utf-8"
            filename = "vpn-clash.yaml"
        elif selected_format == "singbox":
            payload = build_singbox_json(manifest_data, target_user, vpn_dir).encode("utf-8")
            content_type = "application/json; charset=utf-8"
            filename = "config.json"
        elif selected_format == "awg":
            target_node = query.get("node", [None])[0]
            target_device = query.get("device", [None])[0]
            conf_text, resolved_node, resolved_dev = build_awg_conf(manifest_data, target_user, vpn_dir, target_node, target_device, return_meta=True)
            payload = conf_text.encode("utf-8")
            content_type = "text/plain; charset=utf-8"
            filename = f"{resolved_node}_{resolved_dev}.conf"
            is_attachment = True
        elif selected_format == "awg-zip":
            payload = build_awg_zip(manifest_data, target_user, vpn_dir)
            content_type = "application/zip"
            filename = "vpn-amnezia-configs.zip"
            is_attachment = True
        elif selected_format == "amnezia":
            target_node = query.get("node", [None])[0]
            target_device = query.get("device", [None])[0]
            cfg_obj, vpn_uri = build_amnezia_config(manifest_data, target_user, vpn_dir, target_node, target_device)
            payload = json.dumps(cfg_obj, indent=2, ensure_ascii=False).encode("utf-8")
            content_type = "application/json; charset=utf-8"
            filename = "vpn-amnezia.vpn"
            is_attachment = True
            extra_headers.append(("X-Amnezia-Vpn-Uri", vpn_uri))
        elif selected_format == "amnezia-uri":
            target_node = query.get("node", [None])[0]
            target_device = query.get("device", [None])[0]
            _, vpn_uri = build_amnezia_config(manifest_data, target_user, vpn_dir, target_node, target_device)
            payload = (vpn_uri + "\n").encode("utf-8")
            content_type = "text/plain; charset=utf-8"
            filename = "amnezia.uri"
        else:
            payload = build_base64_uris(manifest_data, target_user, vpn_dir).encode("utf-8")
            content_type = "text/plain; charset=utf-8"
            filename = "subscription.txt"

        disposition = "attachment" if is_attachment else "inline"

        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Content-Disposition", f'{disposition}; filename="{filename}"')
        self.send_header("Profile-Update-Interval", "24")
        self.send_header("Subscription-Userinfo", "upload=0; download=0; total=1073741824000; expire=0")
        for h_k, h_v in extra_headers:
            self.send_header(h_k, h_v)
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
