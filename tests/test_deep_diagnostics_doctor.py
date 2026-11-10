import os
import sys
import json
import subprocess
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

def test_doctor_json_output(tmp_path):
    vpn_dir = tmp_path / "vpn_inst"
    vpn_dir.mkdir()
    
    # 1. Create a minimal valid setup
    certs_dir = vpn_dir / "certs"
    certs_dir.mkdir()
    (certs_dir / "fullchain.pem").write_text("CERT_DATA", encoding="utf-8")
    (certs_dir / "privkey.pem").write_text("KEY_DATA", encoding="utf-8")
    
    manifest = {
        "protocols": {
            "vless_reality": {"enabled": True},
            "hysteria2": {"enabled": True},
            "amneziawg": {"enabled": True}
        }
    }
    (vpn_dir / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    
    config = {
        "inbounds": [{"type": "vless"}, {"type": "hysteria2"}]
    }
    (vpn_dir / "config.json").write_text(json.dumps(config), encoding="utf-8")
    
    doctor_script = REPO_ROOT / "scripts" / "doctor.py"
    
    res = subprocess.run([sys.executable, str(doctor_script), "--vpn-dir", str(vpn_dir), "--json"], capture_output=True, text=True)
    assert res.returncode in (0, 1) # Depends on whether running in non-root or missing docker
    
    data = json.loads(res.stdout)
    assert "status" in data
    assert "score" in data
    assert "checks" in data
    assert "remediations" in data
    
    score = data["score"]
    assert "ok" in score
    assert "warn" in score
    assert "fail" in score
    assert score["total"] > 0
    
    # Manifest & Certs should be OK
    names = {c["name"]: c["status"] for c in data["checks"]}
    assert names.get("Manifest File") == "OK"
    assert names.get("TLS Certificates") == "OK"
    assert names.get("Sing-Box Config") == "OK"

def test_doctor_cli_text_output(tmp_path):
    vpn_dir = tmp_path / "vpn_inst"
    vpn_dir.mkdir()
    
    doctor_script = REPO_ROOT / "scripts" / "doctor.py"
    res = subprocess.run([sys.executable, str(doctor_script), "--vpn-dir", str(vpn_dir)], capture_output=True, text=True)
    
    assert "VPN Installer - Node Doctor" in res.stdout
    assert "Passed:" in res.stdout
    assert "Warnings:" in res.stdout
    assert "Failed:" in res.stdout
