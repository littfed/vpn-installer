#!/usr/bin/env python3
"""
scripts/generate-warp-keys.py
Zero-external-dependency script to register a Cloudflare WARP account,
generate WireGuard X25519 keypair, and obtain assigned IP addresses and 3-byte client reserved ID.
"""

import argparse
import base64
import datetime
import json
import os
import sys
import urllib.request

# Curve25519 (X25519) pure Python Montgomery ladder implementation (RFC 7748)
P = 2**255 - 19
A24 = 121665


def x25519_scalar_mult(scalar_bytes: bytes, point_bytes: bytes) -> bytes:
    """Computes X25519 scalar multiplication in pure Python with zero dependencies."""
    s = bytearray(scalar_bytes)
    s[0] &= 248
    s[31] &= 127
    s[31] |= 64
    k = int.from_bytes(s, "little")
    x1 = int.from_bytes(point_bytes, "little") % P
    x2, z2, x3, z3 = 1, 0, x1, 1
    swap = 0
    for t in reversed(range(255)):
        kt = (k >> t) & 1
        swap ^= kt
        if swap:
            x2, x3 = x3, x2
            z2, z3 = z3, z2
        swap = kt
        A = (x2 + z2) % P
        AA = (A * A) % P
        B = (x2 - z2) % P
        BB = (B * B) % P
        E = (AA - BB) % P
        C = (x3 + z3) % P
        D = (x3 - z3) % P
        DA = (D * A) % P
        CB = (C * B) % P
        x3 = pow(DA + CB, 2, P)
        z3 = (x1 * pow(DA - CB, 2, P)) % P
        x2 = (AA * BB) % P
        z2 = (E * (AA + A24 * E)) % P
    if swap:
        x2, x3 = x3, x2
        z2, z3 = z3, z2
    return (x2 * pow(z2, P - 2, P) % P).to_bytes(32, "little")


def generate_wireguard_keypair():
    """Generates a WireGuard private/public keypair. Uses cryptography module if present, else pure Python."""
    try:
        from cryptography.hazmat.primitives.asymmetric import x25519
        from cryptography.hazmat.primitives import serialization

        priv = x25519.X25519PrivateKey.generate()
        pub = priv.public_key()
        priv_bytes = priv.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption(),
        )
        pub_bytes = pub.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        return (
            base64.b64encode(priv_bytes).decode("utf-8"),
            base64.b64encode(pub_bytes).decode("utf-8"),
        )
    except Exception:
        raw_priv = os.urandom(32)
        clamped_priv = bytearray(raw_priv)
        clamped_priv[0] &= 248
        clamped_priv[31] &= 127
        clamped_priv[31] |= 64
        base_point = (9).to_bytes(32, "little")
        pub_bytes = x25519_scalar_mult(bytes(clamped_priv), base_point)
        return (
            base64.b64encode(bytes(clamped_priv)).decode("utf-8"),
            base64.b64encode(pub_bytes).decode("utf-8"),
        )


def register_warp(public_key: str, api_url: str = None, timeout: int = 15) -> dict:
    """Registers the public key with the Cloudflare WARP REST API."""
    url = api_url or os.environ.get(
        "WARP_API_URL", "https://api.cloudflareclient.com/v0a2158/reg"
    )
    headers = {
        "User-Agent": "okhttp/3.12.1",
        "Content-Type": "application/json; charset=UTF-8",
    }
    payload = {
        "install_id": "",
        "tos": (
            datetime.datetime.now(datetime.timezone.utc)
            .isoformat()
            .replace("+00:00", "Z")
        ),
        "key": public_key,
        "fcm_token": "",
        "type": "Android",
        "locale": "en_US",
    }
    req = urllib.request.Request(
        url,
        data=json.dumps(payload).encode("utf-8"),
        headers=headers,
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8"))


def parse_warp_response(resp_data: dict, priv_key: str, pub_key: str) -> dict:
    """Extracts WireGuard configuration parameters and 3-byte reserved ID."""
    config = resp_data.get("result", resp_data).get("config", {})
    client_id = config.get("client_id", "")

    reserved = [0, 0, 0]
    if isinstance(client_id, str) and client_id:
        try:
            decoded = base64.b64decode(client_id)
            reserved = list(decoded)[:3]
        except Exception:
            reserved = [0, 0, 0]
    elif isinstance(client_id, list):
        reserved = client_id[:3]
    elif isinstance(client_id, dict) and "reserved" in client_id:
        reserved = client_id["reserved"][:3]

    while len(reserved) < 3:
        reserved.append(0)

    addresses = config.get("interface", {}).get("addresses", {})
    v4 = addresses.get("v4", "172.16.0.2")
    v6 = addresses.get("v6", "2606:4700:110:8fbb:bdf2:a2f6:a188:94d6")

    if not v4.endswith("/32"):
        v4 = f"{v4}/32"
    if not v6.endswith("/128"):
        v6 = f"{v6}/128"

    peers = config.get("peers", [])
    peer_pub = "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo="
    server = "162.159.192.1"
    server_port = 2408

    if peers:
        p0 = peers[0]
        peer_pub = p0.get("public_key", peer_pub)
        endpoint = p0.get("endpoint", {})
        host_str = endpoint.get("host", "")
        if ":" in host_str:
            parts = host_str.split(":")
            # If IPv6 [::]:port
            if host_str.startswith("["):
                server = host_str.split("]")[0].strip("[")
                server_port = int(parts[-1])
            else:
                server = parts[0]
                server_port = int(parts[1])
        elif endpoint.get("v4"):
            parts = endpoint["v4"].split(":")
            server = parts[0]
            if len(parts) > 1 and int(parts[1]) > 0:
                server_port = int(parts[1])

    # If domain engage.cloudflareclient.com, prefer Anycast IP
    if server == "engage.cloudflareclient.com":
        server = "162.159.192.1"

    outbound_block = {
        "type": "wireguard",
        "tag": "warp-out",
        "server": server,
        "server_port": server_port,
        "local_address": [v4, v6],
        "private_key": priv_key,
        "peer_public_key": peer_pub,
        "reserved": reserved,
        "mtu": 1280,
        "workers": 2,
    }

    endpoint_block = {
        "type": "wireguard",
        "tag": "warp-out",
        "address": [v4, v6],
        "private_key": priv_key,
        "peers": [
            {
                "address": server,
                "port": server_port,
                "public_key": peer_pub,
                "allowed_ips": ["0.0.0.0/0", "::/0"],
                "reserved": reserved,
            }
        ],
        "mtu": 1280,
    }

    return {
        "private_key": priv_key,
        "public_key": pub_key,
        "peer_public_key": peer_pub,
        "address": [v4, v6],
        "local_address": [v4, v6],
        "v4": v4,
        "v6": v6,
        "reserved": reserved,
        "server": server,
        "server_port": server_port,
        "outbound": outbound_block,
        "endpoint": endpoint_block,
    }


def main():
    parser = argparse.ArgumentParser(
        description="Generate Cloudflare WARP WireGuard keys and registration credentials."
    )
    parser.add_argument(
        "--api-url",
        default=None,
        help="Custom WARP registration API URL (useful for mocking/testing)",
    )
    parser.add_argument(
        "--output", "-o", default=None, help="Path to write JSON output to file"
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=15,
        help="HTTP request timeout in seconds (default: 15)",
    )
    args = parser.parse_args()

    priv_key, pub_key = generate_wireguard_keypair()
    try:
        resp = register_warp(
            pub_key, api_url=args.api_url, timeout=args.timeout
        )
        data = parse_warp_response(resp, priv_key, pub_key)
    except Exception as e:
        sys.stderr.write(f"Error registering Cloudflare WARP account: {e}\n")
        # In fallback mode, provide clean default values so config can still be prepared
        data = parse_warp_response({}, priv_key, pub_key)

    out_json = json.dumps(data, indent=2)
    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(out_json)
    print(out_json)


if __name__ == "__main__":
    main()
