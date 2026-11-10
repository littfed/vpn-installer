import base64
import io
import json
import os
import re
import shutil
import subprocess
import sys
import threading
import time
import urllib.request
import urllib.error
import zipfile
from pathlib import Path
import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent


def find_bash():
    if sys.platform == "win32":
        git_bash = Path(r"C:\Program Files\Git\bin\bash.exe")
        if git_bash.exists():
            return str(git_bash)
    bash = shutil.which("bash")
    if bash:
        return bash
    return "bash"


BASH_EXE = find_bash()


def run_bash_cmd(cmd_args, env=None, cwd=None, input_text=None):
    base_env = os.environ.copy()
    base_env["SERVER_IP"] = "127.0.0.1"
    if env:
        base_env.update(env)
    res = subprocess.run(
        [BASH_EXE, "-c", " ".join(cmd_args)],
        cwd=cwd or str(REPO_ROOT),
        env=base_env,
        input=input_text,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    return res


@pytest.fixture
def installed_env(tmp_path):
    os_release = tmp_path / "os-release"
    os_release.write_text('ID="ubuntu"\nVERSION_ID="24.04"\n')

    vpn_dir = tmp_path / "opt" / "vpn-installer"
    bin_dir = tmp_path / "usr" / "bin"

    env = {
        "OS_RELEASE_FILE": str(os_release).replace("\\", "/"),
        "SKIP_ROOT_CHECK": "1",
        "SKIP_DOCKER_INSTALL": "1",
        "SKIP_CONTAINER_START": "1",
        "SERVER_IP": "127.0.0.1",
        "VPN_DOMAIN": "test.vpn.internal",
        "VPN_DIR": str(vpn_dir).replace("\\", "/"),
        "BIN_DIR": str(bin_dir).replace("\\", "/"),
        "REPO_ROOT": str(REPO_ROOT).replace("\\", "/"),
        "DOCKER_BIN": "true",
        "SYSTEMCTL_BIN": "true",
        "NON_INTERACTIVE": "1",
    }

    res = run_bash_cmd(["scripts/install.sh"], env=env)
    assert res.returncode == 0, f"Install failed: {res.stderr}\n{res.stdout}"

    # CLI path in vpn_dir/bin/vpn or bin_dir
    vpn_bin = str(vpn_dir / "bin" / "vpn").replace("\\", "/")
    if not Path(vpn_bin).exists():
        vpn_bin = str(bin_dir / "vpn").replace("\\", "/")

    # Also enable subscription
    res_sub = run_bash_cmd([f'"{vpn_bin}"', "system", "enable-sub"], env=env)
    assert res_sub.returncode == 0, f"enable-sub failed: {res_sub.stderr}"

    return {
        "env": env,
        "vpn_dir": vpn_dir,
        "bin_dir": bin_dir,
        "vpn_bin": vpn_bin
    }


def test_multi_device_user_add(installed_env):
    env = installed_env["env"]
    vpn_bin = installed_env["vpn_bin"]
    vpn_dir = installed_env["vpn_dir"]

    # 1. Add user alice
    res = run_bash_cmd([f'"{vpn_bin}"', "user", "add", "alice"], env=env)
    assert res.returncode == 0, f"User add failed: {res.stderr}\n{res.stdout}"

    users_file = vpn_dir / "users.json"
    assert users_file.exists()
    users_data = json.loads(users_file.read_text(encoding="utf-8"))
    users = users_data.get("users", [])
    alice = next((u for u in users if u.get("name") == "alice"), None)
    assert alice is not None

    # Check devices structure: device-1 and device-2 exist
    devices = alice.get("devices", {})
    assert "device-1" in devices
    assert "device-2" in devices

    d1 = devices["device-1"]
    d2 = devices["device-2"]

    # Keys must be non-empty and unique
    assert d1["private_key"]
    assert d1["public_key"]
    assert d2["private_key"]
    assert d2["public_key"]
    assert d1["private_key"] != d2["private_key"]
    assert d1["public_key"] != d2["public_key"]

    # IPs must be non-empty and unique in 10.8.0.0/16
    assert d1["ip"].startswith("10.8.")
    assert d2["ip"].startswith("10.8.")
    assert d1["ip"] != d2["ip"]

    # Legacy awg field should mirror device-1 for backward compatibility
    assert alice.get("awg") == d1


def test_user_device_cli_add_del_list(installed_env):
    env = installed_env["env"]
    vpn_bin = installed_env["vpn_bin"]
    vpn_dir = installed_env["vpn_dir"]

    # Add user bob
    run_bash_cmd([f'"{vpn_bin}"', "user", "add", "bob"], env=env)

    # 1. Add device 'router'
    res_add = run_bash_cmd([f'"{vpn_bin}"', "user", "device", "add", "bob", "router"], env=env)
    assert res_add.returncode == 0, f"Device add failed: {res_add.stderr}\n{res_add.stdout}"
    assert "Device 'router' successfully added" in res_add.stdout

    # 2. List devices
    res_list = run_bash_cmd([f'"{vpn_bin}"', "user", "device", "list", "bob"], env=env)
    assert res_list.returncode == 0
    assert "device-1" in res_list.stdout
    assert "device-2" in res_list.stdout
    assert "router" in res_list.stdout

    # 3. User show --device router
    res_show = run_bash_cmd([f'"{vpn_bin}"', "user", "show", "bob", "--device", "router"], env=env)
    assert res_show.returncode == 0
    assert "Active view: router" in res_show.stdout
    assert "AmneziaWG (.conf) [router]" in res_show.stdout

    # 4. Delete device 'router'
    res_del = run_bash_cmd([f'"{vpn_bin}"', "user", "device", "del", "bob", "router"], env=env)
    assert res_del.returncode == 0
    assert "Device 'router' successfully removed" in res_del.stdout

    # 5. List devices again - router should be gone
    res_list2 = run_bash_cmd([f'"{vpn_bin}"', "user", "device", "list", "bob"], env=env)
    assert res_list2.returncode == 0
    assert "router" not in res_list2.stdout


def test_awg0_conf_multi_device_rendering(installed_env):
    env = installed_env["env"]
    vpn_bin = installed_env["vpn_bin"]
    vpn_dir = installed_env["vpn_dir"]

    # Add user charlie
    run_bash_cmd([f'"{vpn_bin}"', "user", "add", "charlie"], env=env)
    # Add 3rd device
    run_bash_cmd([f'"{vpn_bin}"', "user", "device", "add", "charlie", "tablet"], env=env)

    # Trigger user sync
    res_sync = run_bash_cmd(["bash", "scripts/user-sync.sh"], env=env)
    assert res_sync.returncode == 0, f"user-sync failed: {res_sync.stderr}"

    awg_conf = vpn_dir / "awg" / "awg0.conf"
    assert awg_conf.exists()
    content = awg_conf.read_text(encoding="utf-8")

    # Interface address should be /16
    assert "Address = 10.8.0.1/16" in content

    # Should contain 3 distinct peers for charlie
    assert "User: charlie (device: device-1)" in content
    assert "User: charlie (device: device-2)" in content
    assert "User: charlie (device: tablet)" in content

    # Suspend user charlie
    run_bash_cmd([f'"{vpn_bin}"', "user", "suspend", "charlie"], env=env)
    run_bash_cmd(["bash", "scripts/user-sync.sh"], env=env)

    content_after_suspend = awg_conf.read_text(encoding="utf-8")
    assert "User: charlie" not in content_after_suspend


def start_sub_server(vpn_dir, port=18899):
    script_path = str(REPO_ROOT / "scripts" / "sub-server.py")
    cmd = [sys.executable, script_path, "--host", "127.0.0.1", "--port", str(port), "--vpn-dir", str(vpn_dir)]
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    time.sleep(0.6)
    return proc


def test_sub_server_endpoints_and_web_portal(installed_env):
    env = installed_env["env"]
    vpn_bin = installed_env["vpn_bin"]
    vpn_dir = installed_env["vpn_dir"]

    # Add user dave
    run_bash_cmd([f'"{vpn_bin}"', "user", "add", "dave"], env=env)

    users_file = vpn_dir / "users.json"
    users_data = json.loads(users_file.read_text(encoding="utf-8"))
    dave = next(u for u in users_data["users"] if u["name"] == "dave")
    token = dave["sub_token"]

    # Setup multi-node configuration in nodes.json
    nodes_file = vpn_dir / "nodes.json"
    nodes_config = {
        "nodes": [
            {
                "name": "RU-Master",
                "server": "127.0.0.1",
                "protocols": {
                    "vless_reality": {"enabled": True, "port": 443, "public_key": "dummy_pbk", "short_id": "01"},
                    "hysteria2": {"enabled": True, "port": 443, "obfs_password": "sec"},
                    "tuic": {"enabled": True, "port": 8443},
                    "amneziawg": {"enabled": True, "port": 48291, "public_key": "pub_ru"}
                }
            },
            {
                "name": "Exit-Node",
                "server": "103.54.16.241",
                "protocols": {
                    "vless_reality": {"enabled": True, "port": 443, "public_key": "dummy_pbk2", "short_id": "02"},
                    "hysteria2": {"enabled": True, "port": 443, "obfs_password": "sec"},
                    "tuic": {"enabled": True, "port": 8443},
                    "amneziawg": {"enabled": True, "port": 48291, "public_key": "pub_exit"}
                }
            }
        ]
    }
    nodes_file.write_text(json.dumps(nodes_config, indent=2), encoding="utf-8")

    server_port = 18899
    proc = start_sub_server(vpn_dir, port=server_port)
    base_sub = f"http://127.0.0.1:{server_port}/sub/{token}"

    try:
        # 1. Test ?format=awg (default healthy node & device-1)
        req = urllib.request.Request(f"{base_sub}?format=awg")
        with urllib.request.urlopen(req, timeout=3) as resp:
            assert resp.status == 200
            conf_body = resp.read().decode("utf-8")
            assert "[Interface]" in conf_body
            assert "[Peer]" in conf_body
            assert "Endpoint = " in conf_body

        # 2. Test ?format=awg with explicit node & device
        req = urllib.request.Request(f"{base_sub}?format=awg&node=Exit-Node&device=device-2")
        with urllib.request.urlopen(req, timeout=3) as resp:
            assert resp.status == 200
            conf_body = resp.read().decode("utf-8")
            disp = resp.headers.get("Content-Disposition", "")
            assert "Exit-Node_device-2.conf" in disp
            assert "Endpoint = 103.54.16.241:48291" in conf_body
            assert dave["devices"]["device-2"]["private_key"] in conf_body

        # 3. Test ?format=awg-zip
        req = urllib.request.Request(f"{base_sub}?format=awg-zip")
        with urllib.request.urlopen(req, timeout=3) as resp:
            assert resp.status == 200
            assert resp.headers.get("Content-Type") == "application/zip"
            zip_bytes = resp.read()
            with zipfile.ZipFile(io.BytesIO(zip_bytes)) as zf:
                namelist = zf.namelist()
                assert "device-1/RU-Master.conf" in namelist or "device-1/RU_Master.conf" in namelist
                assert "device-1/Exit-Node.conf" in namelist or "device-1/Exit_Node.conf" in namelist
                assert "device-2/RU-Master.conf" in namelist or "device-2/RU_Master.conf" in namelist
                assert "device-2/Exit-Node.conf" in namelist or "device-2/Exit_Node.conf" in namelist

        # 4. Test ?format=amnezia
        req = urllib.request.Request(f"{base_sub}?format=amnezia")
        with urllib.request.urlopen(req, timeout=3) as resp:
            assert resp.status == 200
            assert resp.headers.get("Content-Type") == "application/json; charset=utf-8"
            amnezia_data = json.loads(resp.read().decode("utf-8"))
            assert "containers" in amnezia_data
            assert amnezia_data["defaultContainer"] == "amnezia-awg"
            assert resp.headers.get("X-Amnezia-Vpn-Uri", "").startswith("vpn://")

        # 5. Test ?format=amnezia-uri
        req = urllib.request.Request(f"{base_sub}?format=amnezia-uri")
        with urllib.request.urlopen(req, timeout=3) as resp:
            assert resp.status == 200
            uri_str = resp.read().decode("utf-8").strip()
            assert uri_str.startswith("vpn://")

        # 6. Test Web Portal Dashboard (Browser User-Agent)
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
        }
        req = urllib.request.Request(base_sub, headers=headers)
        with urllib.request.urlopen(req, timeout=3) as resp:
            assert resp.status == 200
            assert resp.headers.get("Content-Type") == "text/html; charset=utf-8"
            html_content = resp.read().decode("utf-8")

            # Check core sections
            assert "Личный кабинет VPN" in html_content
            assert "dave" in html_content
            assert "RU-Master" in html_content
            assert "Exit-Node" in html_content
            assert "sing-box://" in html_content
            assert "clash://" in html_content
            assert "VLESS Reality" in html_content
            assert "Hysteria 2" in html_content
            assert "TUIC v5" in html_content
            assert "Telegram MTProto" in html_content
            assert "device-1" in html_content
            assert "device-2" in html_content
            assert "format=awg-zip" in html_content
            assert "format=amnezia" in html_content
            # Zero external CDN links
            assert "https://fonts.googleapis.com" not in html_content
            assert "https://cdnjs.cloudflare.com" not in html_content
            assert "https://cdn.jsdelivr.net" not in html_content

    finally:
        proc.terminate()
        proc.wait(timeout=2)
