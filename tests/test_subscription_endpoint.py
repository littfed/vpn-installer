import base64
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
        "VPN_DIR": str(vpn_dir).replace("\\", "/"),
        "BIN_DIR": str(bin_dir).replace("\\", "/"),
        "VPN_DOMAIN": "vpn.example.com",
    }
    install_res = run_bash_cmd(["scripts/install.sh"], env=env)
    assert install_res.returncode == 0, f"Setup install failed: {install_res.stderr} {install_res.stdout}"

    vpn_bin = str(vpn_dir / "bin" / "vpn").replace("\\", "/")
    return {
        "vpn_dir": vpn_dir,
        "bin_dir": bin_dir,
        "env": env,
        "vpn_bin": vpn_bin,
    }


class TestSubscriptionEndpoint:
    """Automated tests for Ticket 07: Adaptive Subscription Endpoint (/sub/<token>)."""

    def test_caddyfile_and_compose_templates(self):
        caddyfile = REPO_ROOT / "templates" / "Caddyfile"
        assert caddyfile.exists(), "templates/Caddyfile must exist"
        content = caddyfile.read_text(encoding="utf-8")
        assert "reverse_proxy /sub/* 127.0.0.1:8088" in content, (
            "templates/Caddyfile must reverse proxy /sub/* to 127.0.0.1:8088"
        )

        compose_file = REPO_ROOT / "templates" / "docker-compose.yml"
        assert compose_file.exists(), "templates/docker-compose.yml must exist"
        compose_content = compose_file.read_text(encoding="utf-8")
        assert "sub-server" in compose_content, (
            "templates/docker-compose.yml must define a sub-server service"
        )

    def test_enable_sub_command_generates_tokens_and_updates_manifest(self, installed_env):
        vpn_bin = installed_env["vpn_bin"]
        env = installed_env["env"]
        vpn_dir = installed_env["vpn_dir"]

        # Create two users first
        res1 = run_bash_cmd([f'"{vpn_bin}"', "user", "add", "alice"], env=env)
        assert res1.returncode == 0, f"Add user alice failed: {res1.stderr}"
        res2 = run_bash_cmd([f'"{vpn_bin}"', "user", "add", "bob"], env=env)
        assert res2.returncode == 0, f"Add user bob failed: {res2.stderr}"

        # Run vpn system enable-sub
        sub_enable = run_bash_cmd([f'"{vpn_bin}"', "system", "enable-sub"], env=env)
        assert sub_enable.returncode == 0, f"vpn system enable-sub failed: {sub_enable.stderr} {sub_enable.stdout}"

        # Verify users.json tokens
        users_file = vpn_dir / "users.json"
        data = json.loads(users_file.read_text(encoding="utf-8"))
        for u in data.get("users", []):
            token = u.get("sub_token", "")
            assert len(token) == 64, f"User {u['name']} sub_token must be 32 bytes hex (64 chars), got {len(token)}"
            int(token, 16)  # must be valid hex

        # Verify manifest.json
        manifest_file = vpn_dir / "manifest.json"
        manifest = json.loads(manifest_file.read_text(encoding="utf-8"))
        assert manifest.get("subscription", {}).get("enabled") is True

        # Test vpn user show includes subscription URL
        show_res = run_bash_cmd([f'"{vpn_bin}"', "user", "show", "alice"], env=env)
        assert show_res.returncode == 0
        alice_token = next(u["sub_token"] for u in data["users"] if u["name"] == "alice")
        assert f"/sub/{alice_token}" in show_res.stdout
        assert "Subscription:" in show_res.stdout or "Subscription URL" in show_res.stdout or "sub/" in show_res.stdout

        # Test vpn system disable-sub
        sub_disable = run_bash_cmd([f'"{vpn_bin}"', "system", "disable-sub"], env=env)
        assert sub_disable.returncode == 0
        manifest = json.loads(manifest_file.read_text(encoding="utf-8"))
        assert manifest.get("subscription", {}).get("enabled") is False

    def test_install_script_with_enable_sub_web_flag(self, tmp_path):
        os_release = tmp_path / "os-release"
        os_release.write_text('ID="ubuntu"\nVERSION_ID="24.04"\n')

        vpn_dir = tmp_path / "opt" / "vpn-installer"
        bin_dir = tmp_path / "usr" / "bin"

        env = {
            "OS_RELEASE_FILE": str(os_release).replace("\\", "/"),
            "SKIP_ROOT_CHECK": "1",
            "SKIP_DOCKER_INSTALL": "1",
            "SKIP_CONTAINER_START": "1",
            "VPN_DIR": str(vpn_dir).replace("\\", "/"),
            "BIN_DIR": str(bin_dir).replace("\\", "/"),
        }
        res = run_bash_cmd(["scripts/install.sh", "--enable-sub-web"], env=env)
        assert res.returncode == 0, f"Install failed: {res.stderr}"

        manifest_file = vpn_dir / "manifest.json"
        assert manifest_file.exists()
        manifest = json.loads(manifest_file.read_text(encoding="utf-8"))
        assert manifest.get("subscription", {}).get("enabled") is True
        assert (vpn_dir / "scripts" / "sub-server.py").exists()

    def test_sub_server_responder_routing(self, tmp_path):
        """Test scripts/sub-server.py HTTP responses directly for different User-Agents and query params."""
        sub_server_script = REPO_ROOT / "scripts" / "sub-server.py"
        assert sub_server_script.exists(), "scripts/sub-server.py must exist"

        vpn_dir = tmp_path / "vpn"
        vpn_dir.mkdir(parents=True)
        manifest_file = vpn_dir / "manifest.json"
        users_file = vpn_dir / "users.json"

        manifest_data = {
            "server": {
                "ipv4": "198.51.100.1",
                "domain": "vpn.example.com"
            },
            "protocols": {
                "vless_reality": {
                    "port": 443,
                    "sni": "gateway.icloud.com",
                    "public_key": "test_reality_public_key_1234567890=",
                    "short_id": "0123456789abcdef"
                },
                "hysteria2": {
                    "port": 443,
                    "obfs_password": "test_obfs_password"
                }
            },
            "subscription": {
                "enabled": True,
                "port": 8088
            }
        }
        manifest_file.write_text(json.dumps(manifest_data, indent=2), encoding="utf-8")

        active_token = "a" * 64
        inactive_token = "b" * 64
        users_data = {
            "users": [
                {
                    "name": "alice",
                    "uuid": "11111111-2222-3333-4444-555555555555",
                    "password": "alice_hy2_password",
                    "sub_token": active_token,
                    "status": "active"
                },
                {
                    "name": "bob_suspended",
                    "uuid": "66666666-7777-8888-9999-000000000000",
                    "password": "bob_hy2_password",
                    "sub_token": inactive_token,
                    "status": "suspended"
                }
            ]
        }
        users_file.write_text(json.dumps(users_data, indent=2), encoding="utf-8")

        # Pick a free port
        import socket
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind(("127.0.0.1", 0))
            port = s.getsockname()[1]

        # Launch sub-server.py in subprocess
        proc = subprocess.Popen(
            [sys.executable, str(sub_server_script), "--host", "127.0.0.1", "--port", str(port), "--vpn-dir", str(vpn_dir)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )

        try:
            # Wait for server to start
            time.sleep(1.0)
            base_url = f"http://127.0.0.1:{port}"

            def fetch(path, ua=None):
                req = urllib.request.Request(f"{base_url}{path}")
                if ua:
                    req.add_header("User-Agent", ua)
                try:
                    with urllib.request.urlopen(req, timeout=5) as resp:
                        return resp.status, resp.headers, resp.read().decode("utf-8")
                except urllib.error.HTTPError as e:
                    return e.code, e.headers, e.read().decode("utf-8")

            # 1. Unknown or invalid token -> 404
            status, _, _ = fetch("/sub/nonexistenttoken")
            assert status == 404, f"Expected 404 for unknown token, got {status}"

            # 2. Suspended user -> 404
            status, _, _ = fetch(f"/sub/{inactive_token}")
            assert status == 404, f"Expected 404 for suspended user, got {status}"

            # 3. Clash.Meta / clash-verge / ClashX UA -> Clash YAML
            for clash_ua in ["Clash.Meta/v1.18.0", "clash-verge/1.3.8", "ClashX/1.9.0"]:
                status, headers, body = fetch(f"/sub/{active_token}", ua=clash_ua)
                assert status == 200, f"Expected 200 for UA '{clash_ua}', got {status}"
                assert "proxies:" in body, f"YAML missing 'proxies:' for {clash_ua}"
                assert "proxy-groups:" in body, f"YAML missing 'proxy-groups:' for {clash_ua}"
                assert "url-test" in body, f"YAML missing 'url-test' for {clash_ua}"
                assert "fallback" in body, f"YAML missing 'fallback' for {clash_ua}"
                assert "select" in body, f"YAML missing 'select' for {clash_ua}"
                assert "11111111-2222-3333-4444-555555555555" in body
                assert "alice_hy2_password" in body

            # 4. sing-box UA -> Sing-box JSON with split DNS and split routing
            status, headers, body = fetch(f"/sub/{active_token}", ua="sing-box/1.9.0")
            assert status == 200
            singbox_cfg = json.loads(body)
            assert "inbounds" in singbox_cfg
            tun_inbounds = [ib for ib in singbox_cfg["inbounds"] if ib.get("type") == "tun"]
            assert len(tun_inbounds) > 0, "Must configure TUN inbound"
            assert tun_inbounds[0].get("address") == ["172.19.0.1/30"], "TUN inbound must configure modern address array"
            assert "dns" in singbox_cfg
            # Split DNS: Yandex DNS for RU
            dns_servers = singbox_cfg["dns"]["servers"]
            assert any(s.get("server") == "77.88.8.8" and s.get("type") in ("udp", "https") for s in dns_servers), "Split DNS must include Yandex DNS (77.88.8.8)"
            assert any(s.get("server") == "1.1.1.1" and s.get("type") == "https" for s in dns_servers), "Split DNS must include remote DoH (1.1.1.1)"
            direct_dns = [s for s in dns_servers if s.get("tag") == "dns-direct"][0]
            assert "detour" not in direct_dns, "dns-direct must not specify redundant detour to empty direct outbound"
            assert tun_inbounds[0].get("strict_route") is False, "TUN must use strict_route: false to prevent Windows WFP socket deadlocks"
            assert any(ib.get("type") == "mixed" for ib in singbox_cfg["inbounds"]), "Must provide mixed inbound for system proxy"
            assert singbox_cfg.get("route", {}).get("default_domain_resolver") == "dns-direct"
            assert singbox_cfg.get("route", {}).get("default_http_client") == "direct-client"
            assert any(hc.get("tag") == "direct-client" for hc in singbox_cfg.get("http_clients", []))
            assert not any("download_detour" in rs for rs in singbox_cfg.get("route", {}).get("rule_set", [])), (
                "download_detour is deprecated in 1.14 and removed in 1.16; must use http_clients"
            )
            geosite_ru = [rs for rs in singbox_cfg.get("route", {}).get("rule_set", []) if rs.get("tag") == "geosite-ru"][0]
            assert "category-ru.srs" in geosite_ru.get("url", ""), "geosite-ru must use valid category-ru.srs rule-set URL"
            # Split routing: geosite-ru and geoip-ru -> direct
            route = singbox_cfg.get("route", {})
            rules = route.get("rules", [])
            has_ru_direct = False
            for r in rules:
                rule_set = r.get("rule_set", [])
                if isinstance(rule_set, str):
                    rule_set = [rule_set]
                if ("geosite-ru" in rule_set or "geoip-ru" in rule_set) and r.get("outbound") == "direct":
                    has_ru_direct = True
                    break
            assert has_ru_direct, "Sing-box route must direct geosite-ru / geoip-ru to direct"

            # 5. Generic UA (curl, Streisand, v2rayNG, browser) -> Base64 URI list
            for gen_ua in ["curl/8.5.0", "Streisand/1.2", "v2rayNG/1.8.5", "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"]:
                status, headers, body = fetch(f"/sub/{active_token}", ua=gen_ua)
                assert status == 200
                decoded = base64.b64decode(body.strip()).decode("utf-8")
                assert "vless://" in decoded, f"Decoded URIs missing vless:// for {gen_ua}"
                assert "hysteria2://" in decoded, f"Decoded URIs missing hysteria2:// for {gen_ua}"
                assert "11111111-2222-3333-4444-555555555555" in decoded

            # 6. Query overrides
            # Override to clash with curl UA
            status, _, body = fetch(f"/sub/{active_token}?format=clash", ua="curl/8.5.0")
            assert status == 200
            assert "proxy-groups:" in body

            # Override to singbox with Clash UA
            status, _, body = fetch(f"/sub/{active_token}?format=singbox", ua="Clash.Meta/v1.18.0")
            assert status == 200
            parsed = json.loads(body)
            assert "dns" in parsed

            # Override to base64 with sing-box UA
            status, _, body = fetch(f"/sub/{active_token}?format=base64", ua="sing-box/1.9.0")
            assert status == 200
            decoded = base64.b64decode(body.strip()).decode("utf-8")
            assert "vless://" in decoded

        finally:
            proc.terminate()
            proc.wait(timeout=5)
