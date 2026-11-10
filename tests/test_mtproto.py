import json
import os
import re
import shutil
import subprocess
import sys
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


class TestMTProtoProxyTelegram:
    """Automated tests for Ticket 06: MTProto Proxy (mtg v2) for Telegram."""

    def test_docker_compose_template_has_mtg_service(self):
        compose_file = REPO_ROOT / "templates" / "docker-compose.yml"
        assert compose_file.exists(), "templates/docker-compose.yml must exist"
        content = compose_file.read_text()

        assert "mtg:" in content, "docker-compose.yml must define an 'mtg' service"
        assert "nineseconds/mtg:2" in content, "mtg service must use image nineseconds/mtg:2"
        assert 'network_mode: "host"' in content or "network_mode: host" in content or "8443:8443" in content, (
            "mtg must run in host network mode or bind port 8443:8443"
        )
        assert "restart: always" in content or "restart: unless-stopped" in content, (
            "mtg service must have a restart policy"
        )
        # Verify 8443 is configured
        assert "8443" in content, "mtg service must configure port 8443"

    def test_fake_tls_secret_format_and_properties(self):
        domain = "www.cloudflare.com"
        # Secret format: ee + 16 random bytes (32 hex chars) + hex(domain)
        domain_hex = domain.encode("utf-8").hex()
        # Simulated secret
        sample_secret = f"ee{'a' * 32}{domain_hex}"

        assert sample_secret.startswith("ee"), "Fake-TLS secret must start with 'ee'"
        assert len(sample_secret) == 2 + 32 + (len(domain) * 2), (
            f"Expected secret length {2 + 32 + len(domain)*2}, got {len(sample_secret)}"
        )
        decoded_domain = bytes.fromhex(sample_secret[34:]).decode("utf-8")
        assert decoded_domain == domain, "Extracted domain must match original domain"

    def test_install_script_generates_mtproto_in_manifest(self, tmp_path):
        os_release = tmp_path / "os-release"
        os_release.write_text("ID=ubuntu\nVERSION_ID=22.04\n")

        vpn_dir = tmp_path / "vpn"
        bin_dir = tmp_path / "bin"

        env = {
            "OS_RELEASE_FILE": str(os_release).replace("\\", "/"),
            "SKIP_ROOT_CHECK": "1",
            "SKIP_DOCKER_INSTALL": "1",
            "SKIP_CONTAINER_START": "1",
            "VPN_DIR": str(vpn_dir).replace("\\", "/"),
            "BIN_DIR": str(bin_dir).replace("\\", "/"),
            "SERVER_IP": "198.51.100.1",
        }

        res = run_bash_cmd(["scripts/install.sh"], env=env)
        assert res.returncode == 0, f"Installer failed: {res.stdout}\n{res.stderr}"

        manifest_file = vpn_dir / "manifest.json"
        assert manifest_file.exists(), "manifest.json must be created by install.sh"

        manifest = json.loads(manifest_file.read_text())
        protocols = manifest.get("protocols", {})

        assert "mtproto" in protocols, "manifest.json must have 'mtproto' under protocols"
        mtproto = protocols["mtproto"]
        assert mtproto.get("enabled") is True, "mtproto.enabled must be True"
        assert mtproto.get("port") == 8443, "mtproto.port must be 8443"

        secret = mtproto.get("secret", "")
        assert secret.startswith("ee"), f"mtproto.secret must start with 'ee', got '{secret}'"
        assert len(secret) >= 34, f"mtproto.secret length must be >= 34 hex chars, got {len(secret)}"

        # Verify decoded domain from secret
        domain_part = secret[34:]
        assert len(domain_part) > 0, "Fake-TLS secret must contain domain hex encoding"
        extracted_domain = bytes.fromhex(domain_part).decode("utf-8")
        assert len(extracted_domain) > 0, "Must successfully decode domain from secret"

    def test_vpn_user_show_outputs_telegram_link_and_qr(self, tmp_path):
        os_release = tmp_path / "os-release"
        os_release.write_text("ID=ubuntu\nVERSION_ID=22.04\n")

        vpn_dir = tmp_path / "vpn"
        bin_dir = tmp_path / "bin"

        env = {
            "OS_RELEASE_FILE": str(os_release).replace("\\", "/"),
            "SKIP_ROOT_CHECK": "1",
            "SKIP_DOCKER_INSTALL": "1",
            "SKIP_CONTAINER_START": "1",
            "VPN_DIR": str(vpn_dir).replace("\\", "/"),
            "BIN_DIR": str(bin_dir).replace("\\", "/"),
            "SERVER_IP": "198.51.100.1",
        }

        # Run installer
        res_install = run_bash_cmd(["scripts/install.sh"], env=env)
        assert res_install.returncode == 0, f"Installer failed: {res_install.stdout}\n{res_install.stderr}"

        vpn_bin = bin_dir / "vpn"
        assert vpn_bin.exists(), "bin/vpn must exist"

        # Add user
        res_add = run_bash_cmd([str(vpn_bin).replace("\\", "/"), "user", "add", "telegramuser"], env=env)
        assert res_add.returncode == 0, f"Failed to add user: {res_add.stdout}\n{res_add.stderr}"

        # Show user
        res_show = run_bash_cmd([str(vpn_bin).replace("\\", "/"), "user", "show", "telegramuser"], env=env)
        assert res_show.returncode == 0, f"Failed to show user: {res_show.stdout}\n{res_show.stderr}"

        stdout = res_show.stdout
        assert "tg://proxy?" in stdout, f"Output must contain tg://proxy? link. Got:\n{stdout}"
        assert "server=198.51.100.1" in stdout, f"Link must contain server IP. Got:\n{stdout}"
        assert "port=8443" in stdout, f"Link must contain port=8443. Got:\n{stdout}"
        assert "secret=ee" in stdout, f"Link must contain secret=ee... Got:\n{stdout}"
        assert "#telegramuser" in stdout, f"Link must contain anchor #telegramuser. Got:\n{stdout}"

        # Show user with QR code
        res_qr = run_bash_cmd([str(vpn_bin).replace("\\", "/"), "user", "show", "telegramuser", "--qr"], env=env)
        assert res_qr.returncode == 0, f"Failed to show QR: {res_qr.stdout}\n{res_qr.stderr}"
        assert "Telegram" in res_qr.stdout, "QR output must mention Telegram"
        assert "tg://proxy?" in res_qr.stdout, "QR output must include tg://proxy link"

    def test_vpn_status_shows_mtproto_service_and_port(self, tmp_path):
        os_release = tmp_path / "os-release"
        os_release.write_text("ID=ubuntu\nVERSION_ID=22.04\n")

        vpn_dir = tmp_path / "vpn"
        bin_dir = tmp_path / "bin"

        env = {
            "OS_RELEASE_FILE": str(os_release).replace("\\", "/"),
            "SKIP_ROOT_CHECK": "1",
            "SKIP_DOCKER_INSTALL": "1",
            "SKIP_CONTAINER_START": "1",
            "VPN_DIR": str(vpn_dir).replace("\\", "/"),
            "BIN_DIR": str(bin_dir).replace("\\", "/"),
            "SERVER_IP": "198.51.100.1",
        }

        # Run installer
        res_install = run_bash_cmd(["scripts/install.sh"], env=env)
        assert res_install.returncode == 0

        vpn_bin = bin_dir / "vpn"
        res_status = run_bash_cmd([str(vpn_bin).replace("\\", "/"), "status"], env=env)
        assert res_status.returncode == 0, f"Status command failed: {res_status.stdout}\n{res_status.stderr}"

        stdout = res_status.stdout
        assert "MTProto" in stdout, f"Status output must include MTProto. Got:\n{stdout}"
        assert "8443" in stdout, f"Status output must include port 8443. Got:\n{stdout}"
