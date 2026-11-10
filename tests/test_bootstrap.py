import json
import os
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


class TestBootstrapInstaller:
    """Automated tests for vpn-installer bootstrap and CLI (Ticket 01)."""

    def test_os_check_rejects_unsupported_os(self, tmp_path):
        os_release = tmp_path / "os-release"
        os_release.write_text("ID=arch\nVERSION_ID=rolling\n")

        env = {
            "OS_RELEASE_FILE": str(os_release).replace("\\", "/"),
            "SKIP_ROOT_CHECK": "1",
            "SKIP_DOCKER_INSTALL": "1",
            "SKIP_CONTAINER_START": "1",
            "VPN_DIR": str(tmp_path / "vpn").replace("\\", "/"),
            "BIN_DIR": str(tmp_path / "bin").replace("\\", "/"),
        }
        res = run_bash_cmd(["scripts/install.sh"], env=env)
        assert res.returncode != 0, f"Expected non-zero returncode on unsupported OS. Output: {res.stdout} {res.stderr}"
        assert "unsupported" in (res.stdout + res.stderr).lower()

    @pytest.mark.parametrize(
        "distro,version",
        [
            ("ubuntu", "22.04"),
            ("ubuntu", "24.04"),
            ("debian", "11"),
            ("debian", "12"),
        ],
    )
    def test_os_check_accepts_supported_os(self, tmp_path, distro, version):
        os_release = tmp_path / "os-release"
        os_release.write_text(f'ID="{distro}"\nVERSION_ID="{version}"\n')

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
        res = run_bash_cmd(["scripts/install.sh"], env=env)
        assert res.returncode == 0, f"Failed on supported OS {distro} {version}: {res.stderr} {res.stdout}"

    def test_root_check_enforced(self, tmp_path):
        os_release = tmp_path / "os-release"
        os_release.write_text('ID="ubuntu"\nVERSION_ID="24.04"\n')

        env = {
            "OS_RELEASE_FILE": str(os_release).replace("\\", "/"),
            "SKIP_ROOT_CHECK": "0",
            "FORCE_NON_ROOT": "1",
            "SKIP_DOCKER_INSTALL": "1",
            "SKIP_CONTAINER_START": "1",
            "VPN_DIR": str(tmp_path / "vpn").replace("\\", "/"),
            "BIN_DIR": str(tmp_path / "bin").replace("\\", "/"),
        }
        res = run_bash_cmd(["scripts/install.sh"], env=env)
        assert res.returncode != 0, f"Expected non-zero returncode when not root: {res.stdout} {res.stderr}"
        assert "root" in (res.stdout + res.stderr).lower()

    def test_directory_layout_and_symlink(self, tmp_path):
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
        res = run_bash_cmd(["scripts/install.sh"], env=env)
        assert res.returncode == 0, f"Install failed: {res.stderr} {res.stdout}"

        # Verify layout
        assert (vpn_dir / "bin").is_dir()
        assert (vpn_dir / "config").is_dir()
        assert (vpn_dir / "certs").is_dir()
        assert (vpn_dir / "templates").is_dir()
        assert (vpn_dir / "bin" / "vpn").exists()
        assert (bin_dir / "vpn").exists()
        assert (vpn_dir / "docker-compose.yml").is_file()

    def test_manifest_generation(self, tmp_path):
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
        res = run_bash_cmd(["scripts/install.sh"], env=env)
        assert res.returncode == 0, f"Install failed: {res.stderr}"

        manifest_file = vpn_dir / "manifest.json"
        assert manifest_file.exists()

        data = json.loads(manifest_file.read_text())
        assert "node_uuid" in data
        assert "server" in data
        assert "protocols" in data
        assert "vless_reality" in data["protocols"]
        assert "hysteria2" in data["protocols"]

        vless = data["protocols"]["vless_reality"]
        assert vless["port"] == 443
        assert len(vless["private_key"]) > 0
        assert len(vless["public_key"]) > 0
        assert len(vless["short_id"]) > 0

        hy2 = data["protocols"]["hysteria2"]
        assert hy2["port"] == 443
        assert len(hy2["obfs_password"]) > 0

    def test_config_json_structure(self, tmp_path):
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
        res = run_bash_cmd(["scripts/install.sh"], env=env)
        assert res.returncode == 0, f"Install failed: {res.stderr}"

        config_file = vpn_dir / "config.json"
        assert config_file.exists(), "config.json should exist in VPN_DIR"

        config = json.loads(config_file.read_text())
        assert "inbounds" in config
        assert "outbounds" in config

        inbounds = config["inbounds"]
        vless_inbound = next((ib for ib in inbounds if ib.get("type") == "vless"), None)
        assert vless_inbound is not None, "VLESS inbound must exist"
        assert vless_inbound["listen_port"] == 443
        assert vless_inbound["tls"]["reality"]["enabled"] is True
        assert len(vless_inbound["tls"]["reality"]["private_key"]) > 0
        assert len(vless_inbound["tls"]["reality"]["short_id"]) > 0

        hy2_inbound = next((ib for ib in inbounds if ib.get("type") == "hysteria2"), None)
        assert hy2_inbound is not None, "Hysteria 2 inbound must exist"
        assert hy2_inbound["listen_port"] == 443
        assert hy2_inbound["tls"]["enabled"] is True
        assert hy2_inbound["obfs"]["type"] == "salamander"

    def test_cli_help_and_status(self, tmp_path):
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
        res = run_bash_cmd(["scripts/install.sh"], env=env)
        assert res.returncode == 0

        vpn_bin = vpn_dir / "bin" / "vpn"
        assert vpn_bin.exists()

        # Test help
        vpn_bin_str = str(vpn_bin).replace("\\", "/")
        help_res = run_bash_cmd([f'"{vpn_bin_str}"', "help"], env=env)
        assert help_res.returncode == 0
        assert "status" in help_res.stdout.lower()
        assert "service" in help_res.stdout.lower()

        # Test status
        status_res = run_bash_cmd([f'"{vpn_bin_str}"', "status"], env=env)
        assert status_res.returncode == 0
        out = status_res.stdout.lower()
        assert "vless reality" in out or "reality" in out
        assert "443" in out
