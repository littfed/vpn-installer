#!/usr/bin/env python3
"""
scripts/doctor.py - Deep Node Health Diagnostics Suite for vpn-installer
"""

import sys
import os
import json
import subprocess
import argparse
from pathlib import Path

GREEN = "\033[0;32m"
YELLOW = "\033[1;33m"
RED = "\033[0;31m"
BOLD = "\033[1m"
NC = "\033[0m"

def run_cmd(cmd):
    try:
        res = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=10)
        return res.returncode, res.stdout.strip(), res.stderr.strip()
    except Exception as e:
        return 1, "", str(e)

def check_doctor(vpn_dir=None):
    if not vpn_dir:
        vpn_dir = os.environ.get("VPN_DIR", "/opt/vpn-installer")
    vpath = Path(vpn_dir)

    checks = []
    remediations = []

    def add_result(category, name, status, message="", remediation=""):
        checks.append({
            "category": category,
            "name": name,
            "status": status,
            "message": message,
            "remediation": remediation
        })
        if status in ("FAIL", "WARN") and remediation:
            remediations.append(f"[{name}] {remediation}")

    # 1. OS & KERNEL CHECKS
    ip_fwd_val = "0"
    if Path("/proc/sys/net/ipv4/ip_forward").exists():
        ip_fwd_val = Path("/proc/sys/net/ipv4/ip_forward").read_text().strip()
    else:
        code, out, _ = run_cmd("sysctl -n net.ipv4.ip_forward")
        if code == 0:
            ip_fwd_val = out

    if ip_fwd_val == "1":
        add_result("System", "IPv4 Forwarding", "OK", "net.ipv4.ip_forward is enabled (1)")
    else:
        add_result("System", "IPv4 Forwarding", "FAIL", f"net.ipv4.ip_forward is {ip_fwd_val}", "Run: sysctl -w net.ipv4.ip_forward=1")

    # 2. CONFIGURATION & CERTS
    manifest_file = vpath / "manifest.json"
    if manifest_file.exists():
        try:
            with open(manifest_file, "r", encoding="utf-8") as f:
                mdata = json.load(f)
            protos = list(mdata.get("protocols", {}).keys())
            add_result("Config", "Manifest File", "OK", f"Valid manifest with protocols: {', '.join(protos)}")
        except Exception as e:
            add_result("Config", "Manifest File", "FAIL", f"Corrupted JSON: {e}", "Re-run: install.sh to regenerate manifest")
    else:
        add_result("Config", "Manifest File", "WARN", "manifest.json not found", "Run: install.sh")

    singbox_cfg = vpath / "config.json"
    if singbox_cfg.exists():
        try:
            with open(singbox_cfg, "r", encoding="utf-8") as f:
                sdata = json.load(f)
            inbounds = [i.get("type") for i in sdata.get("inbounds", [])]
            add_result("Config", "Sing-Box Config", "OK", f"Inbounds configured: {', '.join(inbounds)}")
        except Exception as e:
            add_result("Config", "Sing-Box Config", "FAIL", f"Corrupted config.json: {e}", "Re-run: install.sh")
    else:
        add_result("Config", "Sing-Box Config", "WARN", "config.json not found")

    fullchain = vpath / "certs" / "fullchain.pem"
    privkey = vpath / "certs" / "privkey.pem"
    if fullchain.exists() and privkey.exists() and fullchain.stat().st_size > 0:
        add_result("Config", "TLS Certificates", "OK", "fullchain.pem and privkey.pem present")
    else:
        add_result("Config", "TLS Certificates", "FAIL", "TLS certs missing or empty in certs/", "Run: vpn system harden or install.sh")

    # 3. DOCKER CONTAINERS
    code, ps_out, _ = run_cmd("docker ps --format '{{.Names}}|{{.Status}}'")
    running_containers = {}
    if code == 0 and ps_out:
        for line in ps_out.splitlines():
            line = line.strip().strip("'")
            if "|" in line:
                cname, cstatus = line.split("|", 1)
                running_containers[cname] = cstatus

    core_containers = ["sing-box-vpn", "amneziawg", "caddy-decoy", "mtproto-proxy"]
    for c in core_containers:
        if c in running_containers:
            stat = running_containers[c]
            if "Up" in stat:
                add_result("Containers", f"Container {c}", "OK", stat)
            else:
                add_result("Containers", f"Container {c}", "FAIL", stat, f"Run: docker compose restart {c.replace('-vpn', '')}")
        else:
            # Check if docker is mocked/running
            add_result("Containers", f"Container {c}", "WARN", "Container not detected in docker ps", f"Run: cd {vpn_dir} && docker compose up -d")

    # 4. NETWORK LISTENING SOCKETS
    code, ss_out, _ = run_cmd("ss -tulpn")
    if code == 0:
        expected_ports = [
            (80, "tcp", "Caddy HTTP-01"),
            (443, "tcp", "VLESS Reality"),
            (443, "udp", "Hysteria 2"),
            (8443, "tcp", "MTProto Proxy"),
            (8443, "udp", "TUIC v5"),
            (48291, "udp", "AmneziaWG")
        ]
        for port, proto, desc in expected_ports:
            needle = f":{port} "
            found = False
            for line in ss_out.splitlines():
                if proto.lower() in line.lower() and needle in line:
                    found = True
                    break
            if found:
                add_result("Sockets", f"Port {port}/{proto.upper()} ({desc})", "OK", "Listening")
            else:
                add_result("Sockets", f"Port {port}/{proto.upper()} ({desc})", "WARN", "Socket not found in ss -tulpn", f"Check container logs for {desc}")

    # 5. AMNEZIAWG INTERFACE
    code, ip_out, _ = run_cmd("ip addr show awg0")
    if code == 0 and "awg0" in ip_out:
        if "10.8.0.1/16" in ip_out:
            add_result("AmneziaWG", "Interface awg0", "OK", "awg0 is UP with 10.8.0.1/16")
        else:
            add_result("AmneziaWG", "Interface awg0", "WARN", f"awg0 IP mismatch: {ip_out}", "Run: /usr/local/bin/vpn user sync")
    else:
        add_result("AmneziaWG", "Interface awg0", "WARN", "awg0 not found in host ip addr (userspace or container)", "Run: docker compose restart amneziawg")

    # 6. FIREWALL & IPTABLES
    code, fw_out, _ = run_cmd("iptables -L FORWARD -n -v")
    if code == 0 and "10.8.0.0/16" in fw_out:
        add_result("Firewall", "FORWARD Rule 10.8.0.0/16", "OK", "Traffic forward ACCEPT rule active")
    else:
        add_result("Firewall", "FORWARD Rule 10.8.0.0/16", "FAIL", "Missing iptables FORWARD rule for 10.8.0.0/16", "Run: /opt/vpn-installer/scripts/firewall-setup.sh")

    code, nat_out, _ = run_cmd("iptables -t nat -L POSTROUTING -n -v")
    if code == 0 and ("10.8.0.0/16" in nat_out or "MASQUERADE" in nat_out):
        add_result("Firewall", "NAT MASQUERADE", "OK", "MASQUERADE rule active for egress")
    else:
        add_result("Firewall", "NAT MASQUERADE", "FAIL", "Missing MASQUERADE rule", "Run: /opt/vpn-installer/scripts/firewall-setup.sh")

    code, pre_out, _ = run_cmd("iptables -t nat -L PREROUTING -n -v")
    if code == 0 and "20000:30000" in pre_out:
        add_result("Firewall", "UDP Port Hopping", "OK", "Port hopping 20000:30000 active")
    else:
        add_result("Firewall", "UDP Port Hopping", "WARN", "Port hopping rule not detected", "Run: /opt/vpn-installer/scripts/firewall-setup.sh")

    # Overall Summary
    fails = sum(1 for c in checks if c["status"] == "FAIL")
    warns = sum(1 for c in checks if c["status"] == "WARN")
    oks = sum(1 for c in checks if c["status"] == "OK")

    overall = "HEALTHY"
    if fails > 0:
        overall = "DEGRADED" if oks > 0 else "FAILED"
    elif warns > 0:
        overall = "WARNING"

    return {
        "status": overall,
        "score": {
            "ok": oks,
            "warn": warns,
            "fail": fails,
            "total": len(checks)
        },
        "checks": checks,
        "remediations": remediations
    }

def print_cli_report(res):
    status = res["status"]
    if status == "HEALTHY":
        status_color = f"{GREEN}{BOLD}HEALTHY{NC}"
    elif status == "WARNING":
        status_color = f"{YELLOW}{BOLD}WARNING{NC}"
    else:
        status_color = f"{RED}{BOLD}{status}{NC}"

    print(f"\n==========================================================")
    print(f"             VPN Installer - Node Doctor                  ")
    print(f"Overall Status: {status_color}")
    score = res["score"]
    print(f"Passed: {GREEN}{score['ok']}{NC} | Warnings: {YELLOW}{score['warn']}{NC} | Failed: {RED}{score['fail']}{NC}")
    print(f"==========================================================\n")

    current_cat = None
    for c in res["checks"]:
        if c["category"] != current_cat:
            current_cat = c["category"]
            print(f"{BOLD}[{current_cat}]{NC}")

        st = c["status"]
        if st == "OK":
            st_str = f"{GREEN}[OK]{NC}"
        elif st == "WARN":
            st_str = f"{YELLOW}[WARN]{NC}"
        else:
            st_str = f"{RED}[FAIL]{NC}"

        msg = f" - {c['message']}" if c['message'] else ""
        print(f"  {st_str} {c['name']}{msg}")

    if res["remediations"]:
        print(f"\n{BOLD}Recommended Remediations:{NC}")
        for r in res["remediations"]:
            print(f"  {YELLOW}→{NC} {r}")

    print(f"\n==========================================================\n")

def main():
    parser = argparse.ArgumentParser(description="VPN Node Deep Diagnostics Doctor")
    parser.add_argument("--json", action="store_true", help="Output machine-readable JSON")
    parser.add_argument("--vpn-dir", default=None, help="Custom vpn directory")
    args = parser.parse_args()

    res = check_doctor(args.vpn_dir)

    if args.json:
        print(json.dumps(res, indent=2))
    else:
        print_cli_report(res)

    sys.exit(1 if res["score"]["fail"] > 0 else 0)

if __name__ == "__main__":
    main()
