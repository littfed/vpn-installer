import base64
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


class MockWarpServer(BaseHTTPRequestHandler):
    def do_POST(self):
        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length)
        req_data = json.loads(body.decode("utf-8")) if body else {}

        # 3 bytes reserved: base64 'Gyrj' -> [27, 42, 99]
        resp = {
            "id": "mock-reg-id",
            "type": "Android",
            "key": req_data.get("key", "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo="),
            "account": {"id": "acc-1"},
            "config": {
                "client_id": "Gyrj",
                "interface": {
                    "addresses": {
                        "v4": "172.16.0.2",
                        "v6": "2606:4700:110:8a2b:e648:c1eb:4931:6686",
                    }
                },
                "peers": [
                    {
                        "public_key": "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=",
                        "endpoint": {
                            "host": "162.159.192.1:2408",
                            "ports": [2408, 500, 1701, 4500],
                        },
                    }
                ],
            },
            "token": "mock-token",
            "warp_enabled": True,
        }
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps(resp).encode("utf-8"))

    def log_message(self, format, *args):
        pass


@pytest.fixture
def mock_warp_api():
    server = HTTPServer(("127.0.0.1", 0), MockWarpServer)
    port = server.server_port
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    url = f"http://127.0.0.1:{port}/reg"
    yield url
    server.shutdown()
    server.server_close()


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
    return env, vpn_dir, bin_dir


def test_generate_warp_keys_script_registration(mock_warp_api):
    script_path = REPO_ROOT / "scripts" / "generate-warp-keys.py"
    assert script_path.exists(), "scripts/generate-warp-keys.py must exist"

    cmd = [sys.executable, str(script_path), "--api-url", mock_warp_api]
    res = subprocess.run(cmd, capture_output=True, text=True)
    assert res.returncode == 0, f"Script failed: {res.stderr}"

    data = json.loads(res.stdout)
    assert "private_key" in data
    assert "public_key" in data
    assert "reserved" in data
    assert isinstance(data["reserved"], list)
    assert len(data["reserved"]) == 3
    assert data["reserved"] == [27, 42, 227]

    # Verify address structure
    address = data.get("address") or data.get("local_address")
    assert address is not None
    assert any("172.16." in a for a in address)
    assert any("2606:4700:" in a for a in address)

    # Verify key formats (valid base64)
    priv_bytes = base64.b64decode(data["private_key"])
    pub_bytes = base64.b64decode(data["public_key"])
    assert len(priv_bytes) == 32
    assert len(pub_bytes) == 32


def test_generate_warp_keys_output_file(tmp_path, mock_warp_api):
    script_path = REPO_ROOT / "scripts" / "generate-warp-keys.py"
    out_file = tmp_path / "warp.json"

    cmd = [
        sys.executable,
        str(script_path),
        "--api-url",
        mock_warp_api,
        "--output",
        str(out_file),
    ]
    res = subprocess.run(cmd, capture_output=True, text=True)
    assert res.returncode == 0
    assert out_file.exists()

    with open(out_file, "r", encoding="utf-8") as f:
        data = json.load(f)
    assert data["reserved"] == [27, 42, 227]


def test_install_configures_warp_egress(installed_env, mock_warp_api):
    env, vpn_dir, _ = installed_env
    env["WARP_API_URL"] = mock_warp_api

    res = run_bash_cmd(["./scripts/install.sh"], env=env)
    assert res.returncode == 0, f"install.sh failed:\nSTDERR:{res.stderr}\nSTDOUT:{res.stdout}"

    # Verify manifest.json contains warp section
    manifest_file = vpn_dir / "manifest.json"
    assert manifest_file.exists()
    with open(manifest_file, "r", encoding="utf-8") as f:
        manifest = json.load(f)

    warp_manifest = manifest.get("protocols", {}).get("warp") or manifest.get("warp")
    assert warp_manifest is not None, "WARP section missing in manifest.json"
    assert "private_key" in warp_manifest
    assert "peer_public_key" in warp_manifest
    assert "reserved" in warp_manifest
    assert len(warp_manifest["reserved"]) == 3

    # Verify config.json
    config_file = vpn_dir / "config.json"
    assert config_file.exists()
    with open(config_file, "r", encoding="utf-8") as f:
        config = json.load(f)

    # Check for warp-out definition (endpoints or outbounds)
    warp_def = None
    for ep in config.get("endpoints", []):
        if ep.get("tag") == "warp-out":
            warp_def = ep
            break
    if not warp_def:
        for ob in config.get("outbounds", []):
            if ob.get("tag") == "warp-out":
                warp_def = ob
                break

    assert warp_def is not None, "warp-out must be configured in endpoints or outbounds"
    assert warp_def.get("type") == "wireguard"
    assert warp_def.get("tag") == "warp-out"

    # Check direct outbound exists and route.final is direct
    outbounds = config.get("outbounds", [])
    has_direct = any(o.get("tag") == "direct" and o.get("type") == "direct" for o in outbounds)
    assert has_direct, "direct outbound must exist"
    assert config.get("route", {}).get("final") == "direct"

    # Check route.rule_set includes AI domains
    rule_sets = config.get("route", {}).get("rule_set", [])
    rule_set_tags = [rs.get("tag") for rs in rule_sets]
    for expected_tag in ["geosite-openai", "geosite-anthropic", "geosite-google", "geosite-cursor"]:
        assert expected_tag in rule_set_tags, f"{expected_tag} must be in route.rule_set"

    # Check route.rules directs AI rule sets to warp-out
    rules = config.get("route", {}).get("rules", [])
    ai_rule_found = False
    for r in rules:
        if r.get("outbound") == "warp-out":
            rs_list = r.get("rule_set", [])
            if isinstance(rs_list, str):
                rs_list = [rs_list]
            if any(t in rs_list for t in ["geosite-openai", "geosite-anthropic"]):
                ai_rule_found = True
                break

    assert ai_rule_found, "route.rules must have rule directing AI rule_sets to warp-out"


def test_user_sync_preserves_warp(installed_env, mock_warp_api):
    env, vpn_dir, _ = installed_env
    env["WARP_API_URL"] = mock_warp_api

    # Run installer first
    res = run_bash_cmd(["./scripts/install.sh"], env=env)
    assert res.returncode == 0

    # Run user-sync.sh
    res_sync = run_bash_cmd(["./scripts/user-sync.sh"], env=env)
    assert res_sync.returncode == 0, f"user-sync.sh failed: {res_sync.stderr}"

    config_file = vpn_dir / "config.json"
    with open(config_file, "r", encoding="utf-8") as f:
        config = json.load(f)

    # Check warp-out is still present
    has_warp = False
    for ep in config.get("endpoints", []):
        if ep.get("tag") == "warp-out":
            has_warp = True
            break
    if not has_warp:
        for ob in config.get("outbounds", []):
            if ob.get("tag") == "warp-out":
                has_warp = True
                break
    assert has_warp, "warp-out must be preserved after user-sync"
