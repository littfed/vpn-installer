import json
import os
import re
import shutil
import subprocess
import sys
import uuid
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


def run_bash_cmd(cmd_args, env=None, cwd=None):
    base_env = os.environ.copy()
    base_env["SERVER_IP"] = "127.0.0.1"
    if env:
        base_env.update(env)
    res = subprocess.run(
        [BASH_EXE, "-c", " ".join(cmd_args)],
        cwd=cwd or str(REPO_ROOT),
        env=base_env,
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


class TestUserManagement:
    """Automated tests for vpn-installer user registry and CLI show (Ticket 02)."""

    def test_user_add_creates_users_json_and_renders_config(self, installed_env):
        vpn_bin = installed_env["vpn_bin"]
        env = installed_env["env"]
        vpn_dir = installed_env["vpn_dir"]

        res = run_bash_cmd([f'"{vpn_bin}"', "user", "add", "alice"], env=env)
        assert res.returncode == 0, f"vpn user add alice failed: {res.stderr} {res.stdout}"

        # 1. users.json structure
        users_file = vpn_dir / "users.json"
        assert users_file.exists(), "users.json should be created by vpn user add"

        users_data = json.loads(users_file.read_text())
        assert "users" in users_data
        users = users_data["users"]
        assert len(users) == 1

        alice = users[0]
        assert alice["name"] == "alice"
        assert alice["status"] == "active"
        # Validate UUID
        parsed_uuid = uuid.UUID(alice["uuid"])
        assert str(parsed_uuid) == alice["uuid"].lower()
        # Credentials
        assert len(alice.get("password", "")) >= 8
        assert len(alice.get("sub_key", "")) > 0
        assert len(alice.get("tg_secret", "")) > 0
        assert len(alice.get("sub_token", "")) > 0
        assert "created_at" in alice

        # 2. config.json inbounds rendering
        config_file = vpn_dir / "config.json"
        assert config_file.exists()
        config = json.loads(config_file.read_text())

        inbounds = config.get("inbounds", [])
        vless_inbound = next((ib for ib in inbounds if ib.get("type") == "vless"), None)
        assert vless_inbound is not None, "VLESS inbound missing"
        vless_users = vless_inbound.get("users", [])
        alice_vless = next((u for u in vless_users if u.get("name") == "alice"), None)
        assert alice_vless is not None, "alice must be rendered into VLESS users"
        assert alice_vless["uuid"] == alice["uuid"]
        assert alice_vless["flow"] == "xtls-rprx-vision"

        hy2_inbound = next((ib for ib in inbounds if ib.get("type") == "hysteria2"), None)
        assert hy2_inbound is not None, "Hysteria 2 inbound missing"
        hy2_users = hy2_inbound.get("users", [])
        alice_hy2 = next((u for u in hy2_users if u.get("name") == "alice"), None)
        assert alice_hy2 is not None, "alice must be rendered into Hysteria 2 users"
        assert alice_hy2["password"] == alice["password"]

    def test_user_add_idempotency_and_duplicate_error(self, installed_env):
        vpn_bin = installed_env["vpn_bin"]
        env = installed_env["env"]
        vpn_dir = installed_env["vpn_dir"]

        res1 = run_bash_cmd([f'"{vpn_bin}"', "user", "add", "alice"], env=env)
        assert res1.returncode == 0

        # Attempt to add alice again
        res2 = run_bash_cmd([f'"{vpn_bin}"', "user", "add", "alice"], env=env)
        assert res2.returncode != 0, f"Expected non-zero returncode on duplicate user add, got {res2.returncode}"
        output = (res2.stdout + res2.stderr).lower()
        assert "already exists" in output or "duplicate" in output or "exists" in output

        # Verify users.json is not corrupted or duplicated
        users_file = vpn_dir / "users.json"
        users_data = json.loads(users_file.read_text())
        alice_matches = [u for u in users_data.get("users", []) if u.get("name") == "alice"]
        assert len(alice_matches) == 1, "User 'alice' must not be duplicated in users.json"

    def test_user_list_formatting(self, installed_env):
        vpn_bin = installed_env["vpn_bin"]
        env = installed_env["env"]

        # Before adding users
        empty_res = run_bash_cmd([f'"{vpn_bin}"', "user", "list"], env=env)
        assert empty_res.returncode == 0

        # Add two users
        run_bash_cmd([f'"{vpn_bin}"', "user", "add", "alice"], env=env)
        run_bash_cmd([f'"{vpn_bin}"', "user", "add", "bob"], env=env)

        list_res = run_bash_cmd([f'"{vpn_bin}"', "user", "list"], env=env)
        assert list_res.returncode == 0
        out = list_res.stdout

        assert "alice" in out
        assert "bob" in out
        assert "active" in out
        assert "NAME" in out.upper()
        assert "STATUS" in out.upper()

    def test_user_show_uris(self, installed_env):
        vpn_bin = installed_env["vpn_bin"]
        env = installed_env["env"]
        vpn_dir = installed_env["vpn_dir"]

        # User add
        add_res = run_bash_cmd([f'"{vpn_bin}"', "user", "add", "alice"], env=env)
        assert add_res.returncode == 0

        users_file = vpn_dir / "users.json"
        users_data = json.loads(users_file.read_text())
        alice = users_data["users"][0]
        alice_uuid = alice["uuid"]
        alice_pass = alice["password"]

        manifest_file = vpn_dir / "manifest.json"
        manifest_data = json.loads(manifest_file.read_text())
        pub_key = manifest_data["protocols"]["vless_reality"]["public_key"]
        short_id = manifest_data["protocols"]["vless_reality"]["short_id"]
        sni = manifest_data["protocols"]["vless_reality"]["sni"]
        obfs_pwd = manifest_data["protocols"]["hysteria2"]["obfs_password"]

        show_res = run_bash_cmd([f'"{vpn_bin}"', "user", "show", "alice"], env=env)
        assert show_res.returncode == 0, f"vpn user show failed: {show_res.stderr} {show_res.stdout}"
        out = show_res.stdout

        # Verify VLESS Reality URI
        # vless://uuid@ip:443?security=reality&flow=xtls-rprx-vision&pbk=...&sni=...&sid=...&fp=chrome#Name-Reality
        assert "vless://" in out
        assert f"vless://{alice_uuid}@127.0.0.1:443?" in out
        assert "security=reality" in out
        assert "flow=xtls-rprx-vision" in out
        assert f"pbk={pub_key}" in out
        assert f"sni={sni}" in out
        assert f"sid={short_id}" in out
        assert "fp=chrome" in out
        assert re.search(r"#[Aa]lice-Reality", out) is not None

        # Verify Hysteria 2 URI
        # hysteria2://pass@ip:443/?sni=...&obfs=salamander&obfs-password=...#Name-Hy2
        assert "hysteria2://" in out
        assert f"hysteria2://{alice_pass}@127.0.0.1:443/?" in out or f"hysteria2://{alice_pass}@127.0.0.1:443?" in out
        assert f"sni={sni}" in out
        assert "obfs=salamander" in out
        assert f"obfs-password={obfs_pwd}" in out
        assert re.search(r"#[Aa]lice-Hy2", out) is not None

        # Non-existing user
        err_res = run_bash_cmd([f'"{vpn_bin}"', "user", "show", "nonexistent"], env=env)
        assert err_res.returncode != 0
        assert "not found" in (err_res.stdout + err_res.stderr).lower()

    def test_user_show_qr_code(self, installed_env):
        vpn_bin = installed_env["vpn_bin"]
        env = installed_env["env"]

        run_bash_cmd([f'"{vpn_bin}"', "user", "add", "alice"], env=env)

        qr_res = run_bash_cmd([f'"{vpn_bin}"', "user", "show", "alice", "--qr"], env=env)
        assert qr_res.returncode == 0, f"vpn user show --qr failed: {qr_res.stderr} {qr_res.stdout}"
        out = qr_res.stdout

        # Should contain QR code characters and URI
        assert "vless://" in out
        assert "hysteria2://" in out
        # Terminal ASCII / UTF8 QR characters typically use Unicode blocks or ANSI codes
        has_qr_blocks = any(c in out for c in ["█", "▄", "▀", "##", "\033["])
        assert has_qr_blocks, "Output must contain ASCII/ANSI QR code blocks"

    def test_atomic_config_sync_and_sighup_signal(self, installed_env, tmp_path):
        vpn_bin = installed_env["vpn_bin"]
        env = installed_env["env"]
        vpn_dir = installed_env["vpn_dir"]

        # Record mock sighup signal via MOCK_SIGHUP_FILE
        signal_file = tmp_path / "sighup.log"
        env["MOCK_SIGHUP_FILE"] = str(signal_file).replace("\\", "/")

        run_bash_cmd([f'"{vpn_bin}"', "user", "add", "alice"], env=env)

        assert signal_file.exists(), "SIGHUP reload signal must be sent upon config update"
        assert "SIGHUP" in signal_file.read_text()

        # Check atomic behavior: temp files cleaned up
        tmp_files = list(vpn_dir.glob("config.json.tmp*"))
        assert len(tmp_files) == 0, "Temporary config files must be cleaned up atomically"
