import json
import os
import shutil
import subprocess
import sys
import tarfile
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
def mock_env(tmp_path):
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir(parents=True, exist_ok=True)
    vpn_dir = tmp_path / "opt" / "vpn-installer"
    vpn_dir.mkdir(parents=True, exist_ok=True)

    log_file = tmp_path / "cmd_log.txt"
    log_path = str(log_file).replace("\\", "/")

    # Create mock iptables
    mock_iptables = bin_dir / "iptables"
    mock_iptables.write_text(f"""#!/usr/bin/env bash
echo "iptables $*" >> "{log_path}"
if [[ "$*" == *"-C "* ]]; then
    exit 1
fi
exit 0
""")
    mock_iptables.chmod(0o755)

    # Create mock ip6tables
    mock_ip6tables = bin_dir / "ip6tables"
    mock_ip6tables.write_text(f"""#!/usr/bin/env bash
echo "ip6tables $*" >> "{log_path}"
if [[ "$*" == *"-C "* ]]; then
    exit 1
fi
exit 0
""")
    mock_ip6tables.chmod(0o755)

    # Create mock ufw
    mock_ufw = bin_dir / "ufw"
    mock_ufw.write_text(f"""#!/usr/bin/env bash
echo "ufw $*" >> "{log_path}"
exit 0
""")
    mock_ufw.chmod(0o755)

    # Create mock docker
    mock_docker = bin_dir / "docker"
    mock_docker.write_text(f"""#!/usr/bin/env bash
echo "docker $*" >> "{log_path}"
exit 0
""")
    mock_docker.chmod(0o755)

    # Create mock docker-compose
    mock_docker_compose = bin_dir / "docker-compose"
    mock_docker_compose.write_text(f"""#!/usr/bin/env bash
echo "docker-compose $*" >> "{log_path}"
exit 0
""")
    mock_docker_compose.chmod(0o755)

    bin_path = str(bin_dir).replace("\\", "/")
    vpn_path = str(vpn_dir).replace("\\", "/")

    env = {
        "PATH": f"{bin_path}:{os.environ.get('PATH', '')}",
        "VPN_DIR": vpn_path,
        "BIN_DIR": bin_path,
        "CMD_LOG": log_path,
        "SKIP_ROOT_CHECK": "1",
        "MOCK_DOCKER": "1",
    }
    return {
        "bin_dir": bin_dir,
        "vpn_dir": vpn_dir,
        "log_file": log_file,
        "env": env,
        "tmp_path": tmp_path,
    }


class TestFirewallAndPortHopping:
    def test_firewall_setup_allows_ports_and_port_hopping(self, mock_env):
        env = mock_env["env"].copy()
        env["SSH_PORT"] = "22"

        # Execute scripts/firewall-setup.sh
        res = run_bash_cmd(["scripts/firewall-setup.sh"], env=env)
        assert res.returncode == 0, f"firewall-setup failed: {res.stdout}\n{res.stderr}"

        log_content = mock_env["log_file"].read_text()

        # Check UFW rules: 80/tcp, 443/tcp, 443/udp, 8443/tcp, 20000:30000/udp, 22/tcp
        assert "ufw allow 80/tcp" in log_content
        assert "ufw allow 443/tcp" in log_content
        assert "ufw allow 443/udp" in log_content
        assert "ufw allow 8443/tcp" in log_content
        assert "ufw allow 20000:30000/udp" in log_content
        assert "ufw allow 22/tcp" in log_content

        # Check iptables port hopping PREROUTING redirect rule: 20000:30000/udp -> 443
        assert "PREROUTING" in log_content
        assert "20000:30000" in log_content
        assert "REDIRECT" in log_content
        assert "443" in log_content

    def test_firewall_setup_custom_ssh_port(self, mock_env):
        env = mock_env["env"].copy()
        env["SSH_PORT"] = "2222"

        res = run_bash_cmd(["scripts/firewall-setup.sh"], env=env)
        assert res.returncode == 0
        log_content = mock_env["log_file"].read_text()
        assert "ufw allow 2222/tcp" in log_content

    def test_firewall_teardown(self, mock_env):
        env = mock_env["env"].copy()
        res = run_bash_cmd(["scripts/firewall-setup.sh", "--teardown"], env=env)
        assert res.returncode == 0
        log_content = mock_env["log_file"].read_text()
        # Verify removal of rules
        assert "-D PREROUTING" in log_content or "delete" in log_content


class TestOutboundAbuseBlock:
    def test_config_template_has_smtp_and_bittorrent_blocks(self):
        template_path = REPO_ROOT / "templates" / "config.json.template"
        assert template_path.exists()
        raw_text = template_path.read_text(encoding="utf-8")
        # Replace unquoted template placeholders to parse as json
        cleaned_text = (
            raw_text.replace("__REALITY_HANDSHAKE_PORT__", "443")
            .replace("__WARP_PORT__", "2408")
            .replace("__WARP_RESERVED__", "[0, 0, 0]")
        )
        data = json.loads(cleaned_text)

        rules = data.get("route", {}).get("rules", [])
        bittorrent_blocked = False
        smtp_ports = {25, 465, 587, 2525}
        smtp_blocked_ports = set()

        for rule in rules:
            if rule.get("outbound") == "block":
                if rule.get("protocol") == "bittorrent":
                    bittorrent_blocked = True
                ports = rule.get("port", [])
                for p in ports:
                    if p in smtp_ports:
                        smtp_blocked_ports.add(p)

        assert bittorrent_blocked, "BitTorrent protocol must have outbound block rule"
        assert smtp_ports == smtp_blocked_ports, f"SMTP ports {smtp_ports} must be blocked, got {smtp_blocked_ports}"

    def test_install_script_renders_abuse_blocks_in_config(self, tmp_path):
        os_release = tmp_path / "os-release"
        os_release.write_text('ID="ubuntu"\nVERSION_ID="24.04"\n')
        vpn_dir = tmp_path / "opt" / "vpn-installer"
        bin_dir = tmp_path / "usr" / "bin"

        env = {
            "OS_RELEASE_FILE": str(os_release).replace("\\", "/"),
            "VPN_DIR": str(vpn_dir).replace("\\", "/"),
            "BIN_DIR": str(bin_dir).replace("\\", "/"),
            "SKIP_ROOT_CHECK": "1",
            "SKIP_DOCKER_INSTALL": "1",
            "SKIP_CONTAINER_START": "1",
            "SERVER_IP": "198.51.100.1",
        }
        res = run_bash_cmd(["scripts/install.sh"], env=env)
        assert res.returncode == 0, f"Installer failed: {res.stdout}\n{res.stderr}"

        cfg_file = vpn_dir / "config.json"
        assert cfg_file.exists()
        with open(cfg_file, "r", encoding="utf-8") as f:
            cfg = json.load(f)

        rules = cfg.get("route", {}).get("rules", [])
        bittorrent_blocked = False
        smtp_blocked_ports = set()
        for rule in rules:
            if rule.get("outbound") == "block":
                if rule.get("protocol") == "bittorrent":
                    bittorrent_blocked = True
                for p in rule.get("port", []):
                    if p in {25, 465, 587, 2525}:
                        smtp_blocked_ports.add(p)

        assert bittorrent_blocked, "Installed config.json must block bittorrent"
        assert {25, 465, 587, 2525} == smtp_blocked_ports, f"Installed config.json must block SMTP ports, got {smtp_blocked_ports}"


class TestBackupAndRestore:
    def setup_vpn_dir(self, vpn_dir):
        vpn_dir.mkdir(parents=True, exist_ok=True)
        (vpn_dir / "manifest.json").write_text(json.dumps({
            "node_uuid": "test-uuid-1234",
            "server": {"ipv4": "198.51.100.1", "domain": "vpn.example.com"},
            "protocols": {"vless_reality": {"port": 443}, "hysteria2": {"port": 443}}
        }))
        (vpn_dir / "users.json").write_text(json.dumps({
            "users": [{"name": "alice", "uuid": "u1", "created_at": 1700000000}]
        }))
        (vpn_dir / "docker-compose.yml").write_text("services:\n  sing-box:\n    image: test\n")
        (vpn_dir / "config.json").write_text('{"log": {"level": "warn"}}')
        caddy_dir = vpn_dir / "caddy"
        caddy_dir.mkdir(parents=True, exist_ok=True)
        (caddy_dir / "Caddyfile").write_text(":80 { respond 200 }")

    def test_vpn_backup_custom_path(self, mock_env):
        vpn_dir = mock_env["vpn_dir"]
        self.setup_vpn_dir(vpn_dir)

        backup_file = mock_env["tmp_path"] / "custom-backup.tar.gz"
        env = mock_env["env"].copy()

        res = run_bash_cmd(["bin/vpn", "backup", str(backup_file).replace("\\", "/")], env=env)
        assert res.returncode == 0, f"Backup failed: {res.stdout}\n{res.stderr}"
        assert backup_file.exists()

        # Check tar contents
        with tarfile.open(backup_file, "r:gz") as tar:
            names = tar.getnames()
            assert "manifest.json" in names
            assert "users.json" in names
            assert "docker-compose.yml" in names
            assert "config.json" in names
            assert any("Caddyfile" in n for n in names)

    def test_vpn_backup_default_path(self, mock_env):
        vpn_dir = mock_env["vpn_dir"]
        self.setup_vpn_dir(vpn_dir)

        env = mock_env["env"].copy()
        res = run_bash_cmd(["bin/vpn", "backup"], env=env)
        assert res.returncode == 0, f"Default backup failed: {res.stdout}\n{res.stderr}"

        # Should be created under $VPN_DIR/backups/
        backups_dir = vpn_dir / "backups"
        assert backups_dir.exists()
        backups = list(backups_dir.glob("vpn-backup-*.tar.gz"))
        assert len(backups) == 1
        assert backups[0].stat().st_size > 0

    def test_vpn_restore_success(self, mock_env):
        vpn_dir = mock_env["vpn_dir"]
        self.setup_vpn_dir(vpn_dir)

        # Create backup
        backup_file = mock_env["tmp_path"] / "to-restore.tar.gz"
        env = mock_env["env"].copy()
        res = run_bash_cmd(["bin/vpn", "backup", str(backup_file).replace("\\", "/")], env=env)
        assert res.returncode == 0

        # Now clean vpn_dir completely
        shutil.rmtree(vpn_dir)
        assert not vpn_dir.exists()

        # Run restore
        res = run_bash_cmd(["bin/vpn", "restore", str(backup_file).replace("\\", "/")], env=env)
        assert res.returncode == 0, f"Restore failed: {res.stdout}\n{res.stderr}"

        # Verify files restored
        assert (vpn_dir / "manifest.json").exists()
        assert (vpn_dir / "users.json").exists()
        assert (vpn_dir / "docker-compose.yml").exists()
        assert (vpn_dir / "config.json").exists()

        # Verify service restart was triggered
        log_content = mock_env["log_file"].read_text()
        assert "restart" in log_content or "up" in log_content

    def test_vpn_restore_rejects_corrupted_archive(self, mock_env):
        corrupt_file = mock_env["tmp_path"] / "fake.tar.gz"
        corrupt_file.write_text("not a valid tar file content")

        env = mock_env["env"].copy()
        res = run_bash_cmd(["bin/vpn", "restore", str(corrupt_file).replace("\\", "/")], env=env)
        assert res.returncode != 0
        assert "error" in res.stderr.lower() or "error" in res.stdout.lower() or "invalid" in res.stderr.lower() or "invalid" in res.stdout.lower()


class TestSystemHarden:
    def test_system_harden_dry_run(self, mock_env):
        env = mock_env["env"].copy()
        res = run_bash_cmd(["bin/vpn", "system", "harden", "--dry-run"], env=env)
        assert res.returncode == 0
        assert "server-setup" in res.stdout
        assert "https://github.com/littfed/server-setup" in res.stdout

    def test_system_harden_mock_flag(self, mock_env):
        env = mock_env["env"].copy()
        res = run_bash_cmd(["bin/vpn", "system", "harden", "--mock"], env=env)
        assert res.returncode == 0
        assert "harden" in res.stdout.lower() or "server-setup" in res.stdout.lower()


class TestLeakTest:
    def test_leak_test_mock_output(self, mock_env):
        env = mock_env["env"].copy()
        env["MOCK_LEAK_TEST"] = "1"
        res = run_bash_cmd(["bin/vpn", "test-leak"], env=env)
        assert res.returncode == 0, f"test-leak failed: {res.stdout}\n{res.stderr}"
        out = res.stdout
        assert "IPv4" in out or "IP" in out
        assert "DNS" in out or "dns" in out
        assert "WARP" in out or "warp=on" in out


class TestUninstall:
    def test_vpn_uninstall_keep_data(self, mock_env):
        vpn_dir = mock_env["vpn_dir"]
        bin_dir = mock_env["bin_dir"]

        (vpn_dir / "manifest.json").write_text("{}")
        (vpn_dir / "docker-compose.yml").write_text("services:\n  sing-box:\n    image: test\n")
        symlink_vpn = bin_dir / "vpn"
        symlink_vpn.write_text("#!/usr/bin/env bash\necho vpn")

        env = mock_env["env"].copy()
        res = run_bash_cmd(["bin/vpn", "uninstall", "--force", "--keep-data"], env=env)
        assert res.returncode == 0, f"Uninstall failed: {res.stdout}\n{res.stderr}"

        # Check containers stopped
        log_content = mock_env["log_file"].read_text()
        assert "down" in log_content

        # Symlink removed
        assert not symlink_vpn.exists()

        # Data directory kept
        assert vpn_dir.exists()
        assert (vpn_dir / "manifest.json").exists()

    def test_vpn_uninstall_purge(self, mock_env):
        vpn_dir = mock_env["vpn_dir"]
        bin_dir = mock_env["bin_dir"]

        (vpn_dir / "manifest.json").write_text("{}")
        (vpn_dir / "docker-compose.yml").write_text("services:\n  sing-box:\n    image: test\n")
        symlink_vpn = bin_dir / "vpn"
        symlink_vpn.write_text("#!/usr/bin/env bash\necho vpn")

        env = mock_env["env"].copy()
        res = run_bash_cmd(["bin/vpn", "uninstall", "--force", "--purge"], env=env)
        assert res.returncode == 0, f"Uninstall failed: {res.stdout}\n{res.stderr}"

        # Symlink removed
        assert not symlink_vpn.exists()

        # VPN dir removed
        assert not vpn_dir.exists()
