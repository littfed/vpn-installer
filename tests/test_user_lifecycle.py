import json
import os
import shutil
import subprocess
import sys
import threading
from http.server import HTTPServer, BaseHTTPRequestHandler
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


class MockClashApiHandler(BaseHTTPRequestHandler):
    connections = []
    deleted_connections = []

    def do_GET(self):
        if self.path == "/connections":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            payload = json.dumps({"connections": self.__class__.connections})
            self.wfile.write(payload.encode("utf-8"))
        else:
            self.send_response(404)
            self.end_headers()

    def do_DELETE(self):
        if self.path.startswith("/connections/"):
            conn_id = self.path.split("/")[-1]
            self.__class__.deleted_connections.append(conn_id)
            self.__class__.connections = [
                c for c in self.__class__.connections if c.get("id") != conn_id
            ]
            self.send_response(204)
            self.end_headers()
        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, format, *args):
        # Suppress logging during tests
        return


@pytest.fixture
def mock_clash_server():
    MockClashApiHandler.connections = [
        {"id": "conn-alice-1", "metadata": {"user": "alice", "sourceIP": "192.168.1.10"}},
        {"id": "conn-bob-1", "metadata": {"user": "bob", "sourceIP": "192.168.1.20"}},
        {"id": "conn-alice-2", "metadata": {"user": "alice", "sourceIP": "192.168.1.11"}},
    ]
    MockClashApiHandler.deleted_connections = []

    server = HTTPServer(("127.0.0.1", 0), MockClashApiHandler)
    port = server.server_port
    server_thread = threading.Thread(target=server.serve_forever, daemon=True)
    server_thread.start()

    yield {
        "port": port,
        "url": f"http://127.0.0.1:{port}",
        "handler": MockClashApiHandler,
    }

    server.shutdown()
    server.server_close()


class TestUserLifecycle:
    """Automated tests for user lifecycle (suspend, enable, kick, delete) - Ticket 03."""

    def test_user_suspend_updates_status_removes_from_config_and_sends_sighup(self, installed_env, tmp_path):
        vpn_bin = installed_env["vpn_bin"]
        env = installed_env["env"]
        vpn_dir = installed_env["vpn_dir"]

        signal_file = tmp_path / "sighup.log"
        env["MOCK_SIGHUP_FILE"] = str(signal_file).replace("\\", "/")

        # Add alice and bob
        res_a = run_bash_cmd([f'"{vpn_bin}"', "user", "add", "alice"], env=env)
        assert res_a.returncode == 0
        res_b = run_bash_cmd([f'"{vpn_bin}"', "user", "add", "bob"], env=env)
        assert res_b.returncode == 0

        # Snapshot alice's original keys
        users_file = vpn_dir / "users.json"
        data_before = json.loads(users_file.read_text(encoding="utf-8"))
        alice_before = next(u for u in data_before["users"] if u["name"] == "alice")

        # Clear signal file before suspend
        signal_file.unlink(missing_ok=True)

        # Suspend alice
        res_suspend = run_bash_cmd([f'"{vpn_bin}"', "user", "suspend", "alice"], env=env)
        assert res_suspend.returncode == 0, f"suspend failed: {res_suspend.stderr} {res_suspend.stdout}"

        # 1. users.json: status == suspended, all keys preserved
        data_after = json.loads(users_file.read_text(encoding="utf-8"))
        alice_after = next(u for u in data_after["users"] if u["name"] == "alice")
        assert alice_after["status"] == "suspended"
        assert alice_after["uuid"] == alice_before["uuid"]
        assert alice_after["password"] == alice_before["password"]
        assert alice_after["sub_key"] == alice_before["sub_key"]
        assert alice_after["tg_secret"] == alice_before["tg_secret"]
        assert alice_after["sub_token"] == alice_before["sub_token"]
        assert alice_after["created_at"] == alice_before["created_at"]

        # bob should still be active
        bob_after = next(u for u in data_after["users"] if u["name"] == "bob")
        assert bob_after["status"] == "active"

        # 2. config.json: alice removed, bob present
        config_file = vpn_dir / "config.json"
        config = json.loads(config_file.read_text(encoding="utf-8"))
        vless_users = next(ib for ib in config["inbounds"] if ib["type"] == "vless")["users"]
        hy2_users = next(ib for ib in config["inbounds"] if ib["type"] == "hysteria2")["users"]

        assert not any(u["name"] == "alice" for u in vless_users), "alice must be excluded from VLESS inbounds"
        assert any(u["name"] == "bob" for u in vless_users), "bob must remain in VLESS inbounds"
        assert not any(u["name"] == "alice" for u in hy2_users), "alice must be excluded from Hysteria 2 inbounds"
        assert any(u["name"] == "bob" for u in hy2_users), "bob must remain in Hysteria 2 inbounds"

        # 3. SIGHUP recorded
        assert signal_file.exists()
        assert "SIGHUP" in signal_file.read_text()

    def test_user_enable_restores_active_and_renders_in_config(self, installed_env, tmp_path):
        vpn_bin = installed_env["vpn_bin"]
        env = installed_env["env"]
        vpn_dir = installed_env["vpn_dir"]

        signal_file = tmp_path / "sighup.log"
        env["MOCK_SIGHUP_FILE"] = str(signal_file).replace("\\", "/")

        run_bash_cmd([f'"{vpn_bin}"', "user", "add", "alice"], env=env)
        run_bash_cmd([f'"{vpn_bin}"', "user", "suspend", "alice"], env=env)

        signal_file.unlink(missing_ok=True)

        # Enable alice
        res_enable = run_bash_cmd([f'"{vpn_bin}"', "user", "enable", "alice"], env=env)
        assert res_enable.returncode == 0, f"enable failed: {res_enable.stderr} {res_enable.stdout}"

        # 1. users.json: status == active
        users_file = vpn_dir / "users.json"
        data = json.loads(users_file.read_text(encoding="utf-8"))
        alice = next(u for u in data["users"] if u["name"] == "alice")
        assert alice["status"] == "active"

        # 2. config.json: alice restored to inbounds
        config_file = vpn_dir / "config.json"
        config = json.loads(config_file.read_text(encoding="utf-8"))
        vless_users = next(ib for ib in config["inbounds"] if ib["type"] == "vless")["users"]
        assert any(u["name"] == "alice" for u in vless_users), "alice must be restored into VLESS inbounds"

        # 3. SIGHUP sent
        assert signal_file.exists()
        assert "SIGHUP" in signal_file.read_text()

    def test_user_kick_via_clash_api(self, installed_env, mock_clash_server):
        vpn_bin = installed_env["vpn_bin"]
        env = installed_env["env"]
        env["CLASH_API_URL"] = mock_clash_server["url"]

        run_bash_cmd([f'"{vpn_bin}"', "user", "add", "alice"], env=env)
        run_bash_cmd([f'"{vpn_bin}"', "user", "add", "bob"], env=env)

        # Kick alice
        res_kick = run_bash_cmd([f'"{vpn_bin}"', "user", "kick", "alice"], env=env)
        assert res_kick.returncode == 0, f"kick failed: {res_kick.stderr} {res_kick.stdout}"
        out = res_kick.stdout + res_kick.stderr

        # Alice's connections deleted, Bob's intact
        deleted = mock_clash_server["handler"].deleted_connections
        assert "conn-alice-1" in deleted
        assert "conn-alice-2" in deleted
        assert "conn-bob-1" not in deleted
        assert len(deleted) == 2

        # Check remaining connections on mock server
        remaining_ids = [c["id"] for c in mock_clash_server["handler"].connections]
        assert "conn-bob-1" in remaining_ids
        assert "conn-alice-1" not in remaining_ids
        assert "conn-alice-2" not in remaining_ids

        # Kicking alice again should report 0 connections
        res_kick_again = run_bash_cmd([f'"{vpn_bin}"', "user", "kick", "alice"], env=env)
        assert res_kick_again.returncode == 0
        assert "0" in (res_kick_again.stdout + res_kick_again.stderr) or "no active" in (res_kick_again.stdout + res_kick_again.stderr).lower()

    def test_user_kick_socket_termination(self, installed_env, tmp_path):
        vpn_bin = installed_env["vpn_bin"]
        env = installed_env["env"]

        mock_ss = tmp_path / "mock_ss.log"
        env["MOCK_SS_FILE"] = str(mock_ss).replace("\\", "/")
        # Unset CLASH_API_URL or point to closed port so it falls back to socket termination
        env["CLASH_API_URL"] = "http://127.0.0.1:1"

        run_bash_cmd([f'"{vpn_bin}"', "user", "add", "alice"], env=env)

        res_kick = run_bash_cmd([f'"{vpn_bin}"', "user", "kick", "alice", "--ip", "198.51.100.42"], env=env)
        assert res_kick.returncode == 0, f"kick with socket termination failed: {res_kick.stderr} {res_kick.stdout}"

        assert mock_ss.exists()
        log_content = mock_ss.read_text()
        assert "198.51.100.42" in log_content

    def test_user_delete_with_confirmation_prompt_and_force(self, installed_env, tmp_path):
        vpn_bin = installed_env["vpn_bin"]
        env = installed_env["env"]
        vpn_dir = installed_env["vpn_dir"]
        users_file = vpn_dir / "users.json"
        config_file = vpn_dir / "config.json"

        signal_file = tmp_path / "sighup.log"
        env["MOCK_SIGHUP_FILE"] = str(signal_file).replace("\\", "/")

        run_bash_cmd([f'"{vpn_bin}"', "user", "add", "alice"], env=env)
        run_bash_cmd([f'"{vpn_bin}"', "user", "add", "bob"], env=env)

        # 1. Delete without force and answering 'n' (abort)
        res_abort = run_bash_cmd([f'"{vpn_bin}"', "user", "delete", "alice"], env=env, input_text="n\n")
        assert res_abort.returncode == 0
        out_abort = (res_abort.stdout + res_abort.stderr).lower()
        assert "cancelled" in out_abort or "aborted" in out_abort or "abort" in out_abort

        # Alice must still exist in users.json and config.json
        data = json.loads(users_file.read_text(encoding="utf-8"))
        assert any(u["name"] == "alice" for u in data["users"])

        signal_file.unlink(missing_ok=True)

        # 2. Delete with --force
        res_force = run_bash_cmd([f'"{vpn_bin}"', "user", "delete", "alice", "--force"], env=env)
        assert res_force.returncode == 0, f"delete --force failed: {res_force.stderr} {res_force.stdout}"

        # Alice removed from users.json, Bob still present
        data = json.loads(users_file.read_text(encoding="utf-8"))
        assert not any(u["name"] == "alice" for u in data["users"])
        assert any(u["name"] == "bob" for u in data["users"])

        # Alice removed from config.json
        config = json.loads(config_file.read_text(encoding="utf-8"))
        vless_users = next(ib for ib in config["inbounds"] if ib["type"] == "vless")["users"]
        assert not any(u["name"] == "alice" for u in vless_users)
        assert any(u["name"] == "bob" for u in vless_users)

        # SIGHUP sent
        assert signal_file.exists()

        # 3. Delete bob with -y flag
        res_y = run_bash_cmd([f'"{vpn_bin}"', "user", "delete", "bob", "-y"], env=env)
        assert res_y.returncode == 0
        data_empty = json.loads(users_file.read_text(encoding="utf-8"))
        assert len(data_empty["users"]) == 0

    def test_nonexistent_user_operations_return_exit_code_1(self, installed_env):
        vpn_bin = installed_env["vpn_bin"]
        env = installed_env["env"]

        subcommands = [
            ["user", "suspend", "ghost"],
            ["user", "enable", "ghost"],
            ["user", "kick", "ghost"],
            ["user", "delete", "ghost", "--force"],
        ]

        for subcmd in subcommands:
            res = run_bash_cmd([f'"{vpn_bin}"'] + subcmd, env=env)
            assert res.returncode == 1, f"{' '.join(subcmd)} should fail with exit code 1, got {res.returncode}"
            err_msg = (res.stdout + res.stderr).lower()
            assert "not found" in err_msg, f"Expected 'not found' error for {' '.join(subcmd)}, got: {res.stdout} {res.stderr}"
