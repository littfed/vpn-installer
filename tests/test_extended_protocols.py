import base64
import importlib.util
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent


def import_module_from_path(module_name, file_path):
    spec = importlib.util.spec_from_file_location(module_name, str(file_path))
    mod = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = mod
    spec.loader.exec_module(mod)
    return mod


canary_probe = import_module_from_path("canary_probe_ext", REPO_ROOT / "scripts" / "canary-probe.py")
sub_server = import_module_from_path("sub_server_ext", REPO_ROOT / "scripts" / "sub-server.py")


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


def run_bash_cmd(cmd_args, env=None, cwd=None):
    base_env = os.environ.copy()
    base_env["SERVER_IP"] = "127.0.0.1"
    if env:
        base_env.update(env)
    return subprocess.run(
        [BASH_EXE, "-c", " ".join(cmd_args)],
        cwd=cwd or str(REPO_ROOT),
        env=base_env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )


class TestExtendedProtocols:
    """Automated tests for TUIC v5 and AmneziaWG (tickets 01-08)."""

    def test_templates_contain_tuic_and_awg(self):
        # 1. Config template has tuic inbound
        cfg_template = REPO_ROOT / "templates" / "config.json.template"
        assert cfg_template.exists()
        content = cfg_template.read_text(encoding="utf-8")
        assert '"type": "tuic"' in content
        assert '"listen_port": 8443' in content
        assert '"congestion_control": "bbr"' in content

        # 2. Docker compose template has amneziawg service
        compose_template = REPO_ROOT / "templates" / "docker-compose.yml"
        assert compose_template.exists()
        compose_text = compose_template.read_text(encoding="utf-8")
        assert "amneziawg:" in compose_text
        assert "amneziavpn/amneziawg-go" in compose_text
        assert "NET_ADMIN" in compose_text
        assert "awg0.conf" in compose_text

    def test_awg_key_and_ip_allocation_in_user_management(self, tmp_path):
        vpn_dir = tmp_path / "opt" / "vpn-installer"
        vpn_dir.mkdir(parents=True, exist_ok=True)
        users_file = vpn_dir / "users.json"
        manifest_file = vpn_dir / "manifest.json"

        manifest_file.write_text(json.dumps({
            "node_uuid": "test-uuid-1",
            "server": {"ipv4": "127.0.0.1"},
            "protocols": {
                "amneziawg": {
                    "enabled": True,
                    "port": 48291,
                    "public_key": "SERVER_AWG_PUBKEY_TEST",
                    "h1": 111111, "h2": 222222, "h3": 333333, "h4": 444444,
                    "jc": 4, "jmin": 40, "jmax": 70, "s1": 30, "s2": 50
                }
            }
        }), encoding="utf-8")

        env = {
            "VPN_DIR": str(vpn_dir).replace("\\", "/"),
            "MANIFEST_FILE": str(manifest_file).replace("\\", "/")
        }

        # Add User 1
        res1 = run_bash_cmd(["bin/vpn", "user", "add", "alice"], env=env)
        assert res1.returncode == 0, f"user add alice failed: {res1.stderr}"

        # Add User 2
        res2 = run_bash_cmd(["bin/vpn", "user", "add", "bob"], env=env)
        assert res2.returncode == 0, f"user add bob failed: {res2.stderr}"

        users_data = json.loads(users_file.read_text(encoding="utf-8"))
        users = users_data.get("users", [])
        assert len(users) == 2

        alice = next(u for u in users if u["name"] == "alice")
        bob = next(u for u in users if u["name"] == "bob")

        assert "awg" in alice
        assert "awg" in bob
        assert alice["awg"]["ip"] == "10.8.0.2/32"
        assert bob["awg"]["ip"] == "10.8.0.3/32"
        assert len(base64.b64decode(alice["awg"]["private_key"])) == 32
        assert len(base64.b64decode(alice["awg"]["public_key"])) == 32
        assert len(base64.b64decode(bob["awg"]["public_key"])) == 32

    def test_awg_server_config_rendering(self, tmp_path):
        vpn_dir = tmp_path / "opt" / "vpn-installer"
        vpn_dir.mkdir(parents=True, exist_ok=True)
        awg_dir = vpn_dir / "awg"
        awg_dir.mkdir(parents=True, exist_ok=True)

        manifest_file = vpn_dir / "manifest.json"
        manifest_file.write_text(json.dumps({
            "protocols": {
                "amneziawg": {
                    "enabled": True,
                    "port": 48291,
                    "private_key": "SERVER_AWG_PRIV_KEY",
                    "public_key": "SERVER_AWG_PUB_KEY",
                    "jc": 5, "jmin": 40, "jmax": 70, "s1": 35, "s2": 55,
                    "h1": 12345678, "h2": 23456789, "h3": 34567890, "h4": 45678901
                }
            }
        }), encoding="utf-8")

        users_file = vpn_dir / "users.json"
        users_file.write_text(json.dumps({
            "users": [
                {
                    "name": "charlie",
                    "status": "active",
                    "uuid": "c0000000-0000-0000-0000-000000000001",
                    "password": "charlie-pass",
                    "awg": {
                        "public_key": "CHARLIE_PUBKEY_TEST",
                        "ip": "10.8.0.5/32"
                    }
                }
            ]
        }), encoding="utf-8")

        env = {
            "VPN_DIR": str(vpn_dir).replace("\\", "/"),
            "CONFIG_FILE": str(vpn_dir / "config.json").replace("\\", "/"),
            "TEMPLATE_FILE": str(REPO_ROOT / "templates" / "config.json.template").replace("\\", "/"),
            "MANIFEST_FILE": str(manifest_file).replace("\\", "/"),
            "USERS_FILE": str(users_file).replace("\\", "/")
        }

        # Run user-sync to render awg0.conf
        res = run_bash_cmd(["scripts/user-sync.sh"], env=env)
        assert res.returncode == 0, f"user-sync failed: {res.stderr}"

        awg_conf_path = awg_dir / "awg0.conf"
        assert awg_conf_path.exists()
        conf_content = awg_conf_path.read_text(encoding="utf-8")

        assert "Address = 10.8.0.1/24" in conf_content
        assert "ListenPort = 48291" in conf_content
        assert "PrivateKey = SERVER_AWG_PRIV_KEY" in conf_content
        assert "H1 = 12345678" in conf_content
        assert "H2 = 23456789" in conf_content
        assert "H3 = 34567890" in conf_content
        assert "H4 = 45678901" in conf_content
        assert "Jc = 5" in conf_content
        assert "[Peer]" in conf_content
        assert "PublicKey = CHARLIE_PUBKEY_TEST" in conf_content
        assert "AllowedIPs = 10.8.0.5/32" in conf_content

    def test_subscription_server_serves_tuic_and_awg(self, tmp_path):
        vpn_dir = tmp_path / "opt" / "vpn-installer"
        vpn_dir.mkdir(parents=True, exist_ok=True)

        token = "testtoken_awg_tuic"
        manifest = {
            "server": {"ipv4": "198.51.100.22"},
            "protocols": {
                "vless_reality": {
                    "enabled": True, "port": 443, "public_key": "PBK_1", "short_id": "SID_1", "sni": "gateway.icloud.com"
                },
                "hysteria2": {
                    "enabled": True, "port": 443, "obfs_password": "obfs_1"
                },
                "tuic": {
                    "enabled": True, "port": 8443, "congestion_control": "bbr"
                },
                "amneziawg": {
                    "enabled": True, "port": 48291,
                    "public_key": "AWG_SERVER_PUB_TEST",
                    "jc": 6, "jmin": 40, "jmax": 70, "s1": 32, "s2": 52,
                    "h1": 100001, "h2": 200002, "h3": 300003, "h4": 400004
                }
            }
        }
        user = {
            "name": "dave",
            "uuid": "00000000-2222-3333-4444-555555555555",
            "password": "dave_password_1",
            "sub_token": token,
            "status": "active",
            "awg": {
                "private_key": "CLIENT_AWG_PRIV_KEY",
                "public_key": "CLIENT_AWG_PUB_KEY",
                "ip": "10.8.0.10/32"
            }
        }

        # 1. AWG Conf output
        awg_conf = sub_server.build_awg_conf(manifest, user, str(vpn_dir))
        assert "PrivateKey = CLIENT_AWG_PRIV_KEY" in awg_conf
        assert "Address = 10.8.0.10/32" in awg_conf
        assert "H1 = 100001" in awg_conf
        assert "H2 = 200002" in awg_conf
        assert "PublicKey = AWG_SERVER_PUB_TEST" in awg_conf
        assert "Endpoint = 198.51.100.22:48291" in awg_conf

        # 2. Sing-box JSON has TUIC
        sb_json = json.loads(sub_server.build_singbox_json(manifest, user, str(vpn_dir)))
        tuic_ob = next((ob for ob in sb_json["outbounds"] if ob.get("type") == "tuic"), None)
        assert tuic_ob is not None
        assert tuic_ob["server_port"] == 8443
        assert tuic_ob["congestion_control"] == "bbr"
        assert tuic_ob["tag"] in [ob.get("outbounds", []) for ob in sb_json["outbounds"] if ob.get("tag") == "proxy-auto"][0]

        # 3. Clash YAML has TUIC
        clash_yaml = sub_server.build_clash_yaml(manifest, user, str(vpn_dir))
        assert "type: tuic" in clash_yaml
        assert "port: 8443" in clash_yaml
        assert "congestion-controller: bbr" in clash_yaml

    def test_canary_probe_tuic_and_awg_synthetic(self, monkeypatch):
        # Test synthetic UDP probe for AmneziaWG
        node = {
            "name": "Node-Test",
            "server": "127.0.0.1",
            "protocols": {
                "amneziawg": {
                    "enabled": True,
                    "port": 48291,
                    "h1": 123456,
                    "h2": 234567,
                    "jc": 3, "jmin": 40, "jmax": 70, "s1": 30
                }
            }
        }

        # Mock socket in canary_probe
        class MockSocket:
            def __init__(self, *args, **kwargs):
                self.sent = []
            def settimeout(self, t): pass
            def sendto(self, data, addr): self.sent.append((data, addr))
            def recvfrom(self, bufsize):
                # Return H2 header
                return (int(234567).to_bytes(4, "little") + b"mockresponse", ("127.0.0.1", 48291))
            def close(self): pass

        import socket
        monkeypatch.setattr(socket, "socket", lambda *args, **kwargs: MockSocket())

        res_awg = canary_probe.probe_amneziawg(node, timeout=1.0)
        assert res_awg["success"] is True
        assert res_awg["h2_validated"] is True
        assert res_awg["latency_ms"] is not None

        # Verify Circuit Breaker for AWG
        state = {"status": "healthy", "consecutive_failures": 0}
        # 1 failure
        state = canary_probe.update_circuit_breaker(state, {"success": False, "error": "Timeout"})
        assert state["status"] == "healthy"
        assert state["consecutive_failures"] == 1

        # 2nd failure -> degraded
        state = canary_probe.update_circuit_breaker(state, {"success": False, "error": "Timeout"})
        assert state["status"] == "degraded"
        assert state["consecutive_failures"] == 2

        # 1 success -> stays degraded
        state = canary_probe.update_circuit_breaker(state, {"success": True, "latency_ms": 50.0})
        assert state["status"] == "degraded"

        # 2nd success -> recovers to healthy
        state = canary_probe.update_circuit_breaker(state, {"success": True, "latency_ms": 48.0})
        assert state["status"] == "healthy"
