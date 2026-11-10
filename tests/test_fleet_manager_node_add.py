import os
import sys
import json
import subprocess
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

def test_fleet_manager_list_empty(tmp_path):
    vpn_dir = tmp_path / "vpn_inst"
    vpn_dir.mkdir()
    
    script = REPO_ROOT / "scripts" / "fleet-manager.py"
    res = subprocess.run([sys.executable, str(script), "--vpn-dir", str(vpn_dir), "list"], capture_output=True, text=True)
    assert res.returncode == 0
    assert "No foreign nodes registered" in res.stdout

def test_fleet_manager_list_and_remove(tmp_path):
    vpn_dir = tmp_path / "vpn_inst"
    vpn_dir.mkdir()
    
    nodes_file = vpn_dir / "nodes.json"
    initial_nodes = {
        "nodes": [
            {
                "name": "Node-1",
                "server": "1.2.3.4",
                "protocols": {
                    "vless_reality": {"enabled": True},
                    "amneziawg": {"enabled": True}
                }
            },
            {
                "name": "Node-2",
                "server": "5.6.7.8",
                "protocols": {
                    "hysteria2": {"enabled": True}
                }
            }
        ]
    }
    nodes_file.write_text(json.dumps(initial_nodes), encoding="utf-8")
    
    script = REPO_ROOT / "scripts" / "fleet-manager.py"
    
    # 1. Test List
    res_list = subprocess.run([sys.executable, str(script), "--vpn-dir", str(vpn_dir), "list"], capture_output=True, text=True)
    assert res_list.returncode == 0
    assert "Node-1" in res_list.stdout
    assert "Node-2" in res_list.stdout
    assert "1.2.3.4" in res_list.stdout
    assert "5.6.7.8" in res_list.stdout
    
    # 2. Test List JSON
    res_json = subprocess.run([sys.executable, str(script), "--vpn-dir", str(vpn_dir), "list", "--json"], capture_output=True, text=True)
    assert res_json.returncode == 0
    data = json.loads(res_json.stdout)
    assert len(data) == 2
    assert data[0]["name"] == "Node-1"
    
    # 3. Test Remove Node-1
    res_rm = subprocess.run([sys.executable, str(script), "--vpn-dir", str(vpn_dir), "remove", "Node-1"], capture_output=True, text=True)
    assert res_rm.returncode == 0
    assert "removed from fleet registry" in res_rm.stdout
    
    # Verify remaining in nodes.json
    with open(nodes_file, "r", encoding="utf-8") as f:
        remaining = json.load(f)["nodes"]
    assert len(remaining) == 1
    assert remaining[0]["name"] == "Node-2"
    
    # 4. Test Remove non-existent node fails
    res_rm_bad = subprocess.run([sys.executable, str(script), "--vpn-dir", str(vpn_dir), "remove", "Ghost-Node"], capture_output=True, text=True)
    assert res_rm_bad.returncode == 1

def test_cli_dispatch_node(tmp_path):
    vpn_dir = tmp_path / "vpn_inst"
    vpn_dir.mkdir()
    
    nodes_file = vpn_dir / "nodes.json"
    nodes_file.write_text(json.dumps({"nodes": [{"name": "TestNode", "server": "9.9.9.9", "protocols": {}}]}), encoding="utf-8")
    
    cli = (REPO_ROOT / "bin" / "vpn").as_posix()
    vpn_dir_posix = vpn_dir.as_posix()
    
    git_bash = Path(r"C:\Program Files\Git\bin\bash.exe")
    bash = str(git_bash) if git_bash.exists() else "bash"
    
    res = subprocess.run([bash, cli, "node", "list"], capture_output=True, text=True, env={**os.environ, "VPN_DIR": vpn_dir_posix})
    assert res.returncode == 0
    assert "TestNode" in res.stdout
    assert "9.9.9.9" in res.stdout
