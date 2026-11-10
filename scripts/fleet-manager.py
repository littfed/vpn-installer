#!/usr/bin/env python3
"""
scripts/fleet-manager.py - Automated fleet management and node provisioning
"""

import sys
import os
import json
import argparse
import subprocess
import tarfile
import io
import time
from pathlib import Path

GREEN = "\033[0;32m"
YELLOW = "\033[1;33m"
RED = "\033[0;31m"
BOLD = "\033[1m"
NC = "\033[0m"

def get_nodes_path(vpn_dir):
    return Path(vpn_dir) / "nodes.json"

def load_nodes(vpn_dir):
    npath = get_nodes_path(vpn_dir)
    if not npath.exists():
        return {"nodes": []}
    try:
        with open(npath, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception as e:
        print(f"[!] Warning: error reading {npath}: {e}", file=sys.stderr)
        return {"nodes": []}

def save_nodes(vpn_dir, data):
    npath = get_nodes_path(vpn_dir)
    npath.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = npath.with_suffix(".tmp")
    with open(tmp_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
    tmp_path.replace(npath)

def restart_sub_server():
    # Try systemctl first
    code, _, _ = run_local("systemctl is-active vpn-sub-server.service")
    if code == 0:
        run_local("systemctl restart vpn-sub-server.service")
        return True
    # Try docker compose
    code, _, _ = run_local("docker compose restart sub-server 2>/dev/null")
    return code == 0

def run_local(cmd):
    try:
        res = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=15)
        return res.returncode, res.stdout.strip(), res.stderr.strip()
    except Exception as e:
        return 1, "", str(e)

def node_list(vpn_dir, as_json=False):
    data = load_nodes(vpn_dir)
    nodes = data.get("nodes", [])

    if as_json:
        print(json.dumps(nodes, indent=2))
        return 0

    print("\n==========================================================")
    print("             VPN Installer - Fleet Nodes                  ")
    print(f"Total Configured Nodes: {len(nodes)}")
    print("==========================================================")

    if not nodes:
        print("No foreign nodes registered. (Standalone / Single Node)")
        print("To add a node: vpn node add <ip> [--password <pwd>]")
        print("==========================================================\n")
        return 0

    print(f"{'NAME':<12} {'SERVER IP':<18} {'PROTOCOLS':<30}")
    print("-" * 62)
    for n in nodes:
        name = n.get("name", "Unknown")
        ip = n.get("server", "Unknown")
        protos = []
        pdict = n.get("protocols", {})
        if pdict.get("vless_reality", {}).get("enabled"):
            protos.append("Reality")
        if pdict.get("hysteria2", {}).get("enabled"):
            protos.append("Hy2")
        if pdict.get("tuic", {}).get("enabled"):
            protos.append("TUIC")
        if pdict.get("amneziawg", {}).get("enabled"):
            protos.append("AWG")
        if pdict.get("mtproto", {}).get("enabled"):
            protos.append("MTG")
        pstr = ", ".join(protos) if protos else "None"
        print(f"{name:<12} {ip:<18} {pstr:<30}")

    print("==========================================================\n")
    return 0

def node_remove(name_or_ip, vpn_dir):
    data = load_nodes(vpn_dir)
    nodes = data.get("nodes", [])

    filtered = [n for n in nodes if n.get("name") != name_or_ip and n.get("server") != name_or_ip]
    if len(filtered) == len(nodes):
        print(f"[x] Error: Node '{name_or_ip}' not found in registry.", file=sys.stderr)
        return 1

    data["nodes"] = filtered
    save_nodes(vpn_dir, data)
    restart_sub_server()
    print(f"[✓] Node '{name_or_ip}' removed from fleet registry and subscription service reloaded.")
    return 0

def node_add(ip, name=None, user="root", password=None, key_path=None, port=22, vpn_dir=None):
    if not vpn_dir:
        vpn_dir = os.environ.get("VPN_DIR", "/opt/vpn-installer")

    print(f"[+] Initiating automated node provisioning for target: {user}@{ip}:{port}...")

    try:
        import paramiko
    except ImportError:
        print("[x] Error: python library 'paramiko' is required for automated SSH node provisioning.", file=sys.stderr)
        print("Install via: pip install paramiko", file=sys.stderr)
        return 1

    # 1. SSH Connect
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    connect_kwargs = {
        "hostname": ip,
        "port": port,
        "username": user,
        "timeout": 15
    }
    if password:
        connect_kwargs["password"] = password
    if key_path:
        connect_kwargs["key_filename"] = key_path

    try:
        ssh.connect(**connect_kwargs)
        print(f"[✓] SSH authentication successful to {ip}")
    except Exception as e:
        print(f"[x] SSH connection failed to {ip}: {e}", file=sys.stderr)
        return 1

    def run_ssh(cmd, check=True):
        stdin, stdout, stderr = ssh.exec_command(cmd)
        out = stdout.read().decode("utf-8", errors="ignore").strip()
        err = stderr.read().decode("utf-8", errors="ignore").strip()
        rc = stdout.channel.recv_exit_status()
        if check and rc != 0:
            raise RuntimeError(f"Remote command failed ({rc}): {cmd}\nOutput: {out}\nError: {err}")
        return rc, out, err

    try:
        # 2. Pre-flight check on remote host
        print("[+] Performing remote pre-flight checks (OS & privileges)...")
        rc, os_out, _ = run_ssh("cat /etc/os-release 2>/dev/null || true", check=False)
        if "ubuntu" not in os_out.lower() and "debian" not in os_out.lower():
            print("[!] Warning: Remote OS does not appear to be Ubuntu or Debian. Proceeding with caution...")

        # 3. Ensure remote directory structure and Docker
        print("[+] Ensuring remote directories and prerequisites at /opt/vpn-installer...")
        run_ssh("mkdir -p /opt/vpn-installer/{bin,scripts,templates,certs,awg,backup}")

        # Check docker
        rc, _, _ = run_ssh("command -v docker", check=False)
        if rc != 0:
            print("[+] Installing Docker on remote host...")
            run_ssh("curl -fsSL https://get.docker.com | sh")

        # 4. Upload files
        print("[+] Uploading installer codebase to remote host...")
        sftp = ssh.open_sftp()

        local_vpn_dir = Path(vpn_dir)
        repo_root = local_vpn_dir
        if not (repo_root / "scripts" / "install.sh").exists():
            repo_root = Path(__file__).resolve().parent.parent

        files_to_sync = [
            ("bin/vpn", "/opt/vpn-installer/bin/vpn", 0o755),
            ("scripts/install.sh", "/opt/vpn-installer/scripts/install.sh", 0o755),
            ("scripts/baseline.sh", "/opt/vpn-installer/scripts/baseline.sh", 0o755),
            ("scripts/doctor.py", "/opt/vpn-installer/scripts/doctor.py", 0o755),
            ("scripts/firewall-setup.sh", "/opt/vpn-installer/scripts/firewall-setup.sh", 0o755),
            ("scripts/user-sync.sh", "/opt/vpn-installer/scripts/user-sync.sh", 0o755),
            ("templates/docker-compose.yml", "/opt/vpn-installer/docker-compose.yml", 0o644),
            ("templates/docker-compose.yml", "/opt/vpn-installer/templates/docker-compose.yml", 0o644),
            ("templates/config.json.template", "/opt/vpn-installer/templates/config.json.template", 0o644),
        ]

        if (repo_root / "templates" / "Caddyfile").exists():
            files_to_sync.append(("templates/Caddyfile", "/opt/vpn-installer/templates/Caddyfile", 0o644))
        if (repo_root / "scripts" / "generate-warp-keys.py").exists():
            files_to_sync.append(("scripts/generate-warp-keys.py", "/opt/vpn-installer/scripts/generate-warp-keys.py", 0o755))
        if (repo_root / "scripts" / "sub-server.py").exists():
            files_to_sync.append(("scripts/sub-server.py", "/opt/vpn-installer/scripts/sub-server.py", 0o755))

        for local_rel, remote_dst, mode in files_to_sync:
            lpath = repo_root / local_rel
            if lpath.exists():
                try:
                    sftp.put(str(lpath), remote_dst)
                    sftp.chmod(remote_dst, mode)
                except Exception as ex:
                    print(f"[!] Warning uploading {local_rel}: {ex}", file=sys.stderr)

        # Sync users.json if exists locally
        local_users = local_vpn_dir / "users.json"
        if not local_users.exists():
            local_users = repo_root / "users.json"
        if local_users.exists():
            try:
                sftp.put(str(local_users), "/opt/vpn-installer/users.json")
                sftp.chmod("/opt/vpn-installer/users.json", 0o600)
            except Exception:
                pass

        # 5. Run installation on remote node
        print("[+] Executing install.sh on remote node (with baseline snapshot & post-flight assertions)...")
        rc, out, err = run_ssh("cd /opt/vpn-installer && bash scripts/install.sh", check=False)
        if rc != 0:
            print(f"[x] Remote installation failed with code {rc}!", file=sys.stderr)
            print("=== REMOTE INSTALL ERROR ===", file=sys.stderr)
            print(err if err else out, file=sys.stderr)
            ssh.close()
            return 1

        print("[✓] Remote installation and post-flight assertions passed!")

        # 6. Retrieve remote manifest.json
        print("[+] Retrieving remote node manifest.json...")
        manifest_remote = "/opt/vpn-installer/manifest.json"
        with io.BytesIO() as buf:
            sftp.get(manifest_remote, buf)
            buf.seek(0)
            manifest_data = json.loads(buf.read().decode("utf-8"))

        sftp.close()
        ssh.close()

        # 7. Register node into master nodes.json
        data = load_nodes(vpn_dir)
        nodes = data.get("nodes", [])

        if not name:
            # Auto-assign next Node-N
            existing_indices = []
            for n in nodes:
                nname = n.get("name", "")
                if nname.startswith("Node-"):
                    try:
                        existing_indices.append(int(nname.split("-")[1]))
                    except Exception:
                        pass
            next_idx = max(existing_indices, default=0) + 1
            name = f"Node-{next_idx}"

        node_entry = {
            "name": name,
            "server": ip,
            "protocols": manifest_data.get("protocols", {})
        }

        # Update or append
        existing = [n for n in nodes if n.get("name") == name or n.get("server") == ip]
        if existing:
            existing[0]["name"] = name
            existing[0]["server"] = ip
            existing[0]["protocols"] = manifest_data.get("protocols", {})
        else:
            nodes.append(node_entry)

        data["nodes"] = nodes
        save_nodes(vpn_dir, data)
        print(f"[✓] Node registered as '{name}' in {get_nodes_path(vpn_dir)}")

        # 8. Reload subscription server
        restart_sub_server()
        print(f"[✓] Subscription service restarted. Node '{name}' ({ip}) is now active in fleet and client subscriptions!")

        return 0

    except Exception as e:
        print(f"[x] Error during node provisioning: {e}", file=sys.stderr)
        try:
            ssh.close()
        except Exception:
            pass
        return 1

def main():
    parser = argparse.ArgumentParser(description="Fleet Node Manager CLI")
    parser.add_argument("--vpn-dir", default=None, help="VPN directory")
    subparsers = parser.add_subparsers(dest="subcommand")

    # list
    p_list = subparsers.add_parser("list", help="List registered nodes")
    p_list.add_argument("--json", action="store_true", help="Output JSON")

    # remove
    p_rm = subparsers.add_parser("remove", help="Remove a node from registry")
    p_rm.add_argument("name", help="Node name or IP to remove")

    # add
    p_add = subparsers.add_parser("add", help="Add and provision a new node")
    p_add.add_argument("ip", help="Remote server IP address")
    p_add.add_argument("--name", default=None, help="Node name (e.g. Node-4)")
    p_add.add_argument("--user", default="root", help="Remote SSH user")
    p_add.add_argument("--password", default=None, help="Remote SSH password")
    p_add.add_argument("--key", default=None, help="Remote SSH private key path")
    p_add.add_argument("--port", type=int, default=22, help="Remote SSH port")

    args = parser.parse_args()

    vpn_dir = args.vpn_dir or os.environ.get("VPN_DIR", "/opt/vpn-installer")

    if args.subcommand == "list":
        sys.exit(node_list(vpn_dir, args.json))
    elif args.subcommand == "remove":
        sys.exit(node_remove(args.name, vpn_dir))
    elif args.subcommand == "add":
        sys.exit(node_add(args.ip, name=args.name, user=args.user, password=args.password, key_path=args.key, port=args.port, vpn_dir=vpn_dir))
    else:
        parser.print_help()
        sys.exit(1)

if __name__ == "__main__":
    main()
