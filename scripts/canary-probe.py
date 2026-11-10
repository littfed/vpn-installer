#!/usr/bin/env python3
"""
scripts/canary-probe.py
Synthetic canary probe for testing foreign VPN nodes from inside Russia.

Tests VLESS-Reality, Hysteria 2, and MTProto for every node in nodes.json
using an ephemeral sing-box micro-client and direct TCP probes.
Maintains Circuit Breaker state in node-health.json (2 failures -> degraded, 2 successes -> healthy).
"""

import argparse
import datetime
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time


def find_singbox(override_bin=None):
    if override_bin and os.path.isfile(override_bin) and os.access(override_bin, os.X_OK):
        return override_bin
    sb = shutil.which("sing-box")
    if sb:
        return sb
    common_paths = [
        "/usr/local/bin/sing-box",
        "/usr/bin/sing-box",
        "/opt/vpn-installer/bin/sing-box",
    ]
    for p in common_paths:
        if os.path.isfile(p) and os.access(p, os.X_OK):
            return p
    return None


def get_free_port():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def wait_port_open(port, timeout=2.0):
    start = time.time()
    while time.time() - start < timeout:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                return True
        except (OSError, ConnectionRefusedError):
            time.sleep(0.05)
    return False


def test_http_through_proxy(proxy_port, target_url, timeout=5.0):
    """
    Executes an HTTP request through 127.0.0.1:<proxy_port> using curl.
    Returns (success: bool, status_code: int, latency_ms: float, error: str)
    """
    curl_bin = shutil.which("curl") or "curl"
    cmd = [
        curl_bin,
        "-s",
        "-o", os.devnull,
        "-w", "%{http_code}:%{time_total}",
        "--max-time", str(timeout),
        "--proxy", f"http://127.0.0.1:{proxy_port}",
        target_url
    ]
    try:
        t0 = time.time()
        res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=timeout + 2)
        elapsed = (time.time() - t0) * 1000.0
        if res.returncode == 0 and res.stdout:
            parts = res.stdout.strip().split(":")
            if len(parts) >= 2:
                code = int(parts[0])
                time_total_s = float(parts[1])
                latency_ms = round(time_total_s * 1000.0, 1)
                # Successful if we got a valid HTTP response (even 4xx means network works)
                return (code > 0, code, latency_ms, "")
        return (False, 0, elapsed, f"curl exited with {res.returncode}: {res.stderr.strip()}")
    except subprocess.TimeoutExpired:
        return (False, 0, timeout * 1000.0, "Request timed out")
    except Exception as e:
        return (False, 0, 0.0, str(e))


def get_probe_user(users_file):
    if users_file and os.path.isfile(users_file):
        try:
            with open(users_file, "r", encoding="utf-8") as uf:
                data = json.load(uf)
                for u in data.get("users", []):
                    if u.get("status") == "active":
                        return u
        except Exception:
            pass
    return {
        "name": "canary",
        "uuid": "00000000-0000-0000-0000-000000000000",
        "password": "canary_password"
    }


def probe_vless_reality(node, singbox_bin, user=None, timeout=5.0):
    vless = node.get("protocols", {}).get("vless_reality", {})
    if not vless or not vless.get("enabled", True):
        return {"skipped": True, "reason": "Protocol disabled"}

    user = user or {}
    host = node.get("server") or node.get("ipv4") or "127.0.0.1"
    port = vless.get("port", 443)
    pbk = vless.get("public_key", "")
    sid = vless.get("short_id", "")
    sni = vless.get("sni", "gateway.icloud.com")
    uuid = user.get("uuid") or "00000000-0000-0000-0000-000000000000"

    inbound_port = get_free_port()
    config = {
        "log": {"level": "warn"},
        "inbounds": [
            {
                "type": "mixed",
                "tag": "mixed-in",
                "listen": "127.0.0.1",
                "listen_port": inbound_port
            }
        ],
        "outbounds": [
            {
                "type": "vless",
                "tag": "proxy",
                "server": host,
                "server_port": port,
                "uuid": uuid,
                "flow": "xtls-rprx-vision",
                "tls": {
                    "enabled": True,
                    "server_name": sni,
                    "utls": {"enabled": True, "fingerprint": "chrome"},
                    "reality": {
                        "enabled": True,
                        "public_key": pbk,
                        "short_id": sid
                    }
                }
            }
        ]
    }

    return _run_singbox_probes(singbox_bin, config, inbound_port, timeout)


def probe_hysteria2(node, singbox_bin, user=None, timeout=5.0):
    hy2 = node.get("protocols", {}).get("hysteria2", {})
    if not hy2 or not hy2.get("enabled", True):
        return {"skipped": True, "reason": "Protocol disabled"}

    user = user or {}
    host = node.get("server") or node.get("ipv4") or "127.0.0.1"
    port = hy2.get("port", 443)
    password = user.get("password") or hy2.get("password") or "test_hy2_pass"
    obfs = hy2.get("obfs_password", "")
    sni = hy2.get("sni", "gateway.icloud.com")

    inbound_port = get_free_port()
    config = {
        "log": {"level": "warn"},
        "inbounds": [
            {
                "type": "mixed",
                "tag": "mixed-in",
                "listen": "127.0.0.1",
                "listen_port": inbound_port
            }
        ],
        "outbounds": [
            {
                "type": "hysteria2",
                "tag": "proxy",
                "server": host,
                "server_port": port,
                "password": password,
                "tls": {
                    "enabled": True,
                    "server_name": sni,
                    "insecure": True
                },
                "obfs": {
                    "type": "salamander",
                    "password": obfs
                }
            }
        ]
    }

    return _run_singbox_probes(singbox_bin, config, inbound_port, timeout)


def _run_singbox_probes(singbox_bin, config, inbound_port, timeout):
    if not singbox_bin:
        return {"success": False, "error": "sing-box binary not found on system"}

    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as tf:
        json.dump(config, tf, indent=2)
        cfg_path = tf.name

    proc = None
    try:
        proc = subprocess.Popen(
            [singbox_bin, "run", "-c", cfg_path],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            text=True
        )

        if not wait_port_open(inbound_port, timeout=2.0):
            # Check if process crashed
            err = ""
            if proc.poll() is not None:
                err = proc.stderr.read()
            return {"success": False, "error": f"sing-box inbound port failed to open: {err.strip()}"}

        # 1. RTT Latency Check (Cloudflare 204)
        ok_rtt, code_rtt, latency_ms, err_rtt = test_http_through_proxy(
            inbound_port, "https://cp.cloudflare.com/generate_204", timeout=timeout
        )

        # 2. TSPU / Censorship Bypass Check (YouTube / Instagram)
        ok_tspu, code_tspu, _, err_tspu = test_http_through_proxy(
            inbound_port, "https://www.youtube.com", timeout=timeout
        )

        # 3. WARP Egress Check (OpenAI)
        ok_warp, code_warp, _, err_warp = test_http_through_proxy(
            inbound_port, "https://api.openai.com/v1/models", timeout=timeout
        )

        overall_success = ok_rtt or ok_tspu

        return {
            "success": overall_success,
            "latency_ms": latency_ms if ok_rtt else None,
            "rtt_ok": ok_rtt,
            "tspu_bypass_ok": ok_tspu,
            "warp_ok": ok_warp,
            "status_code_rtt": code_rtt,
            "status_code_tspu": code_tspu,
            "status_code_warp": code_warp,
            "error": err_rtt if not ok_rtt else ""
        }

    finally:
        if proc:
            try:
                proc.terminate()
                proc.wait(timeout=1.0)
            except Exception:
                try:
                    proc.kill()
                except Exception:
                    pass
        if os.path.exists(cfg_path):
            try:
                os.unlink(cfg_path)
            except Exception:
                pass


def probe_mtproto(node, timeout=3.0):
    mtp = node.get("protocols", {}).get("mtproto", {})
    if not mtp or not mtp.get("enabled", True):
        return {"skipped": True, "reason": "Protocol disabled"}

    host = node.get("server") or node.get("ipv4") or "127.0.0.1"
    port = mtp.get("port", 8443)

    t0 = time.time()
    try:
        with socket.create_connection((host, port), timeout=timeout):
            latency_ms = round((time.time() - t0) * 1000.0, 1)
            return {
                "success": True,
                "latency_ms": latency_ms,
                "tspu_bypass_ok": True,
                "error": ""
            }
    except Exception as e:
        return {
            "success": False,
            "latency_ms": None,
            "tspu_bypass_ok": False,
            "error": str(e)
        }


def update_circuit_breaker(current_state, probe_result):
    """
    Updates the Circuit Breaker state for a single protocol:
    - 2 consecutive failures -> degraded
    - 2 consecutive successes -> healthy
    """
    if probe_result.get("skipped"):
        return current_state

    failures = current_state.get("consecutive_failures", 0)
    successes = current_state.get("consecutive_successes", 0)
    status = current_state.get("status", "healthy")
    history = current_state.get("history", [])

    is_success = probe_result.get("success", False)
    latency_ms = probe_result.get("latency_ms")

    if is_success:
        successes += 1
        failures = 0
        if status == "degraded" and successes >= 2:
            status = "healthy"
        elif status == "offline" and successes >= 2:
            status = "healthy"
        elif status not in ("degraded", "offline"):
            status = "healthy"
    else:
        failures += 1
        successes = 0
        if failures >= 2:
            status = "degraded"

    # Append to rolling history (keep last 5)
    now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
    history_entry = {
        "timestamp": now_iso,
        "success": is_success,
        "latency_ms": latency_ms,
        "error": probe_result.get("error", "")
    }
    history = (history + [history_entry])[-5:]

    return {
        "status": status,
        "consecutive_failures": failures,
        "consecutive_successes": successes,
        "last_latency_ms": latency_ms,
        "last_checked": now_iso,
        "history": history
    }


def run_all_probes(nodes_data, health_data, singbox_bin, user=None, timeout=5.0, target_node=None, target_proto=None):
    results = {}
    new_health = dict(health_data)
    nodes_health = new_health.setdefault("nodes", {})

    for idx, node in enumerate(nodes_data.get("nodes", [])):
        node_name = node.get("name", f"Node-{idx+1}")
        if target_node and node_name.lower() != target_node.lower():
            continue

        node_results = {}
        node_state = nodes_health.setdefault(node_name, {"protocols": {}})
        proto_state = node_state.setdefault("protocols", {})

        # 1. VLESS Reality
        if not target_proto or target_proto in ("vless", "vless_reality", "reality"):
            res_vless = probe_vless_reality(node, singbox_bin, user=user, timeout=timeout)
            node_results["vless_reality"] = res_vless
            if not res_vless.get("skipped"):
                proto_state["vless_reality"] = update_circuit_breaker(
                    proto_state.get("vless_reality", {}), res_vless
                )

        # 2. Hysteria 2
        if not target_proto or target_proto in ("hy2", "hysteria2"):
            res_hy2 = probe_hysteria2(node, singbox_bin, user=user, timeout=timeout)
            node_results["hysteria2"] = res_hy2
            if not res_hy2.get("skipped"):
                proto_state["hysteria2"] = update_circuit_breaker(
                    proto_state.get("hysteria2", {}), res_hy2
                )

        # 3. MTProto
        if not target_proto or target_proto in ("mtp", "mtproto"):
            res_mtp = probe_mtproto(node, timeout=3.0)
            node_results["mtproto"] = res_mtp
            if not res_mtp.get("skipped"):
                proto_state["mtproto"] = update_circuit_breaker(
                    proto_state.get("mtproto", {}), res_mtp
                )

        # Calculate overall node status
        statuses = [p.get("status") for p in proto_state.values() if isinstance(p, dict) and "status" in p]
        if statuses and all(s in ("degraded", "offline") for s in statuses):
            node_state["status"] = "offline"
        elif statuses and any(s == "degraded" for s in statuses):
            node_state["status"] = "degraded"
        else:
            node_state["status"] = "healthy"

        node_state["last_checked"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
        results[node_name] = node_results

    new_health["last_updated"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
    return results, new_health


def save_health_file(health_file, health_data):
    parent = os.path.dirname(health_file)
    if parent:
        os.makedirs(parent, exist_ok=True)
    tmp_file = f"{health_file}.tmp.{os.getpid()}"
    with open(tmp_file, "w", encoding="utf-8") as f:
        json.dump(health_data, f, indent=2, ensure_ascii=False)
    os.replace(tmp_file, health_file)


def format_table(results, health_data):
    lines = []
    header = f"{'Node':<16} | {'Protocol':<14} | {'Latency':<10} | {'TSPU':<6} | {'WARP':<6} | {'Status':<10}"
    sep = "-" * len(header)
    lines.append(sep)
    lines.append(header)
    lines.append(sep)

    nodes_health = health_data.get("nodes", {})
    for node_name, protocols in results.items():
        node_h = nodes_health.get(node_name, {}).get("protocols", {})
        for proto, res in protocols.items():
            if res.get("skipped"):
                continue
            lat = f"{res.get('latency_ms', '-')} ms" if res.get("latency_ms") else "-"
            tspu = "OK" if res.get("tspu_bypass_ok") else "FAIL"
            warp = "OK" if res.get("warp_ok") else ("-" if proto == "mtproto" else "FAIL")
            st = node_h.get(proto, {}).get("status", "healthy").upper()

            lines.append(f"{node_name:<16} | {proto:<14} | {lat:<10} | {tspu:<6} | {warp:<6} | {st:<10}")

    lines.append(sep)
    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(description="Canary Probe for Foreign VPN Nodes from Russia")
    parser.add_argument("--nodes-file", default="/opt/vpn-installer/nodes.json", help="Path to nodes.json")
    parser.add_argument("--health-file", default="/opt/vpn-installer/node-health.json", help="Path to node-health.json")
    parser.add_argument("--users-file", default="/opt/vpn-installer/users.json", help="Path to users.json")
    parser.add_argument("--sing-box-bin", default=None, help="Path to sing-box executable")
    parser.add_argument("--node", default=None, help="Filter by specific node name")
    parser.add_argument("--protocol", default=None, help="Filter by specific protocol (vless, hy2, mtproto)")
    parser.add_argument("--timeout", type=float, default=5.0, help="Timeout in seconds for each probe")
    parser.add_argument("--dry-run", action="store_true", help="Do not save results to health-file")
    parser.add_argument("--json", action="store_true", help="Output JSON results to stdout")
    parser.add_argument("--quiet", action="store_true", help="Suppress non-error stdout")

    args = parser.parse_args()

    singbox_bin = find_singbox(args.sing_box_bin)

    if not os.path.isfile(args.nodes_file):
        # Graceful check for local fallback
        if os.path.isfile("nodes.json"):
            args.nodes_file = "nodes.json"
        else:
            sys.exit(f"Error: nodes file not found at {args.nodes_file}")

    if not os.path.isfile(args.users_file):
        if os.path.isfile("users.json"):
            args.users_file = "users.json"

    with open(args.nodes_file, "r", encoding="utf-8") as nf:
        nodes_data = json.load(nf)

    probe_user = get_probe_user(args.users_file)

    health_data = {}
    if os.path.isfile(args.health_file):
        try:
            with open(args.health_file, "r", encoding="utf-8") as hf:
                health_data = json.load(hf)
        except Exception:
            health_data = {}

    results, new_health = run_all_probes(
        nodes_data, health_data, singbox_bin,
        user=probe_user,
        timeout=args.timeout, target_node=args.node, target_proto=args.protocol
    )

    if not args.dry_run:
        save_health_file(args.health_file, new_health)

    if args.json:
        print(json.dumps({"results": results, "health": new_health}, indent=2, ensure_ascii=False))
    elif not args.quiet:
        print(format_table(results, new_health))

    # Exit code: 0 if at least one tested protocol succeeded or all were skipped; 1 only if all active probes failed
    any_success = False
    has_probed = False
    for node_res in results.values():
        for proto_res in node_res.values():
            if not proto_res.get("skipped"):
                has_probed = True
                if proto_res.get("success"):
                    any_success = True
                    break
    sys.exit(1 if has_probed and not any_success else 0)


if __name__ == "__main__":
    main()
