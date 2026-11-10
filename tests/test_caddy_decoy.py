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


class TestCaddyDecoyAndRealityFallback:
    """Automated tests for Ticket 05: Decoy Caddy, Port 80 & Reality Fallback."""

    def test_docker_compose_template_has_caddy_service(self):
        compose_file = REPO_ROOT / "templates" / "docker-compose.yml"
        assert compose_file.exists(), "templates/docker-compose.yml must exist"
        content = compose_file.read_text()

        assert "caddy:" in content, "docker-compose.yml must define a 'caddy' service"
        assert "caddy:alpine" in content, "caddy service must use official caddy:alpine image"

        # Check port bindings 80:80 and 127.0.0.1:8443:8443
        assert '"80:80"' in content or "'80:80'" in content or "- 80:80" in content, (
            "caddy must bind port 80:80"
        )
        assert "127.0.0.1:8443:8443" in content, (
            "caddy must bind 127.0.0.1:8443:8443"
        )

        # Check volume mounts
        assert "./caddy/Caddyfile:/etc/caddy/Caddyfile" in content, (
            "caddy must mount ./caddy/Caddyfile to /etc/caddy/Caddyfile"
        )
        assert "./caddy/html:/usr/share/caddy:ro" in content or "./caddy/html:/usr/share/caddy" in content, (
            "caddy must mount ./caddy/html to /usr/share/caddy:ro"
        )

    def test_caddyfile_template_structure_and_security_headers(self):
        caddyfile = REPO_ROOT / "templates" / "Caddyfile"
        assert caddyfile.exists(), "templates/Caddyfile must exist"
        content = caddyfile.read_text()

        # Configures port 80 (HTTP) and 8443 (HTTPS)
        assert ":80" in content or "80" in content, "Caddyfile must configure port 80"
        assert "8443" in content, "Caddyfile must configure HTTPS on port 8443"

        # Static file root and server
        assert "/usr/share/caddy" in content, "Caddyfile must serve files from /usr/share/caddy"
        assert "file_server" in content, "Caddyfile must enable file_server"

        # Security headers
        assert "X-Content-Type-Options" in content, "Caddyfile must set X-Content-Type-Options"
        assert "nosniff" in content, "X-Content-Type-Options must be nosniff"
        assert "Strict-Transport-Security" in content, "Caddyfile must set HSTS header"
        assert "X-Frame-Options" in content, "Caddyfile must set X-Frame-Options"

        # ACME / HTTP-01 challenge support
        assert "http" in content.lower(), "Caddyfile must handle HTTP-01 / HTTP challenges"

    def test_decoy_static_html_and_robots(self):
        html_dir = REPO_ROOT / "templates" / "html"
        index_file = html_dir / "index.html"
        robots_file = html_dir / "robots.txt"

        assert index_file.exists(), "templates/html/index.html must exist"
        assert robots_file.exists(), "templates/html/robots.txt must exist"

        html_content = index_file.read_text(encoding="utf-8")
        assert len(html_content) > 200, "Decoy index.html should be a realistic HTML page"
        assert "<html" in html_content.lower()
        assert "<head" in html_content.lower()
        assert "<body" in html_content.lower()

        # Anti-fingerprint: must not be default server placeholder
        assert "welcome to nginx" not in html_content.lower()
        assert "welcome to caddy" not in html_content.lower()
        assert "default page" not in html_content.lower()
        assert "under construction" not in html_content.lower()

        # Realistic IT / tech portfolio content
        assert any(
            term in html_content.lower()
            for term in ["consulting", "cloud", "solutions", "services", "infrastructure", "engineering", "technologies", "software"]
        ), "Decoy site should look like a legitimate IT consulting or technology website"

        robots_content = robots_file.read_text(encoding="utf-8")
        assert "user-agent:" in robots_content.lower()

    def test_install_script_provisions_caddy_files_and_directories(self, tmp_path):
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

        # Verify caddy directory layout in VPN_DIR
        caddy_dir = vpn_dir / "caddy"
        assert caddy_dir.is_dir(), "caddy/ directory must be created in VPN_DIR"
        assert (caddy_dir / "html").is_dir(), "caddy/html/ directory must be created"
        assert (caddy_dir / "html" / "index.html").exists(), "index.html must be copied to caddy/html/"
        assert (caddy_dir / "html" / "robots.txt").exists(), "robots.txt must be copied to caddy/html/"
        assert (caddy_dir / "Caddyfile").exists(), "Caddyfile must be created in caddy/"

    def test_reality_handshake_fallback_sni_when_no_custom_domain(self, tmp_path):
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
            "VPN_SNI": "gateway.icloud.com",
        }
        res = run_bash_cmd(["scripts/install.sh"], env=env)
        assert res.returncode == 0, f"Install failed: {res.stderr}"

        config_file = vpn_dir / "config.json"
        assert config_file.exists()
        config = json.loads(config_file.read_text())

        vless_inbound = next(ib for ib in config["inbounds"] if ib.get("type") == "vless")
        reality = vless_inbound["tls"]["reality"]
        # When no custom decoy domain is set, fallback handshake points to external SNI
        assert reality["handshake"]["server"] == "gateway.icloud.com"
        assert reality["handshake"]["server_port"] == 443

    def test_reality_handshake_fallback_caddy_when_custom_domain_set(self, tmp_path):
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
            "VPN_DOMAIN": "decoy.example.com",
        }
        res = run_bash_cmd(["scripts/install.sh"], env=env)
        assert res.returncode == 0, f"Install failed: {res.stderr}"

        config_file = vpn_dir / "config.json"
        assert config_file.exists()
        config = json.loads(config_file.read_text())

        vless_inbound = next(ib for ib in config["inbounds"] if ib.get("type") == "vless")
        reality = vless_inbound["tls"]["reality"]
        # When custom decoy domain is configured, fallback handshake routes to local Caddy (127.0.0.1:8443)
        assert reality["handshake"]["server"] == "127.0.0.1"
        assert reality["handshake"]["server_port"] == 8443
        assert vless_inbound["tls"]["server_name"] == "decoy.example.com"

        # Check Caddyfile in vpn_dir has the domain configured
        caddyfile_installed = (vpn_dir / "caddy" / "Caddyfile").read_text()
        assert "decoy.example.com" in caddyfile_installed

    def test_user_sync_preserves_reality_handshake_fallback(self, tmp_path):
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
            "VPN_DOMAIN": "custom.decoy.org",
        }
        res = run_bash_cmd(["scripts/install.sh"], env=env)
        assert res.returncode == 0

        # Run user-sync.sh and verify reality handshake is preserved
        sync_res = run_bash_cmd(["scripts/user-sync.sh"], env=env)
        assert sync_res.returncode == 0, f"user-sync failed: {sync_res.stderr}"

        config = json.loads((vpn_dir / "config.json").read_text())
        vless_inbound = next(ib for ib in config["inbounds"] if ib.get("type") == "vless")
        reality = vless_inbound["tls"]["reality"]
        assert reality["handshake"]["server"] == "127.0.0.1"
        assert reality["handshake"]["server_port"] == 8443

    def test_cli_status_displays_caddy_and_decoy_info(self, tmp_path):
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
            "VPN_DOMAIN": "decoy.myvpn.net",
        }
        res = run_bash_cmd(["scripts/install.sh"], env=env)
        assert res.returncode == 0

        vpn_bin = str(vpn_dir / "bin" / "vpn").replace("\\", "/")
        status_res = run_bash_cmd([f'"{vpn_bin}"', "status"], env=env)
        assert status_res.returncode == 0
        out = status_res.stdout.lower()

        # Decoy site or Caddy port 80 / 8443 should be mentioned in status output
        assert "80" in out
        assert "caddy" in out or "decoy" in out

    def test_unauthenticated_probe_handling_configuration(self):
        caddyfile = (REPO_ROOT / "templates" / "Caddyfile").read_text()
        # Ensure no proxy or sing-box header leaks
        assert "sing-box" not in caddyfile.lower()
        assert "proxy_pass" not in caddyfile.lower()
        assert "x-forwarded" not in caddyfile.lower()
        # Port 80 serves static HTML without leaking internal proxy signatures
        assert ":80" in caddyfile
        assert "file_server" in caddyfile

        # Verify config template fallback handshake directives exist for unauthenticated probe forwarding
        config_tpl = (REPO_ROOT / "templates" / "config.json.template").read_text()
        assert "__REALITY_HANDSHAKE_SERVER__" in config_tpl
        assert "__REALITY_HANDSHAKE_PORT__" in config_tpl

