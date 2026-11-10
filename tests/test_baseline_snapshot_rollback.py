import os
import sys
import json
import shutil
import subprocess
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

def find_bash():
    git_bash = Path(r"C:\Program Files\Git\bin\bash.exe")
    if git_bash.exists():
        return str(git_bash)
    bash = shutil.which("bash")
    if bash:
        return bash
    raise RuntimeError("bash not found")

def run_bash(cmd, env=None):
    bash = find_bash()
    full_env = os.environ.copy()
    if env:
        full_env.update(env)
    res = subprocess.run([bash, "-c", cmd], capture_output=True, text=True, env=full_env)
    return res

def test_baseline_snapshot_creation(tmp_path):
    vpn_dir = tmp_path / "vpn_inst"
    vpn_dir.mkdir()
    
    script = (REPO_ROOT / "scripts" / "baseline.sh").as_posix()
    vpn_dir_posix = vpn_dir.as_posix()
    
    cmd = f'"{script}" snapshot test01'
    env = {
        "VPN_DIR": vpn_dir_posix,
        "SKIP_ROOT_CHECK": "1"
    }
    
    res = run_bash(cmd, env=env)
    assert res.returncode == 0, f"Error: {res.stderr}\n{res.stdout}"
    
    target_dir = vpn_dir / "backup" / "baseline-test01"
    assert target_dir.exists(), f"Snapshot dir {target_dir} was not created"
    
    meta_file = target_dir / "baseline.json"
    assert meta_file.exists(), "baseline.json not found"
    
    with open(meta_file, encoding="utf-8") as f:
        meta = json.load(f)
    
    assert "timestamp" in meta
    assert "os" in meta
    assert "ufw_active" in meta
    assert "ip_forward" in meta

def test_baseline_list_and_show(tmp_path):
    vpn_dir = tmp_path / "vpn_inst"
    vpn_dir.mkdir()
    
    script = (REPO_ROOT / "scripts" / "baseline.sh").as_posix()
    vpn_dir_posix = vpn_dir.as_posix()
    
    env = {
        "VPN_DIR": vpn_dir_posix,
        "SKIP_ROOT_CHECK": "1"
    }
    
    # 1. Snapshot
    res_snap = run_bash(f'"{script}" snapshot mysnap', env=env)
    assert res_snap.returncode == 0
    
    # 2. List
    res_list = run_bash(f'"{script}" list', env=env)
    assert res_list.returncode == 0
    assert "baseline-mysnap" in res_list.stdout
    
    # 3. Show
    res_show = run_bash(f'"{script}" show mysnap', env=env)
    assert res_show.returncode == 0
    assert "baseline-mysnap" in res_show.stdout

def test_baseline_rollback_dry(tmp_path):
    vpn_dir = tmp_path / "vpn_inst"
    vpn_dir.mkdir()
    
    script = (REPO_ROOT / "scripts" / "baseline.sh").as_posix()
    vpn_dir_posix = vpn_dir.as_posix()
    
    env = {
        "VPN_DIR": vpn_dir_posix,
        "SKIP_ROOT_CHECK": "1"
    }
    
    # Snapshot first
    run_bash(f'"{script}" snapshot testroll', env=env)
    
    # Rollback
    res_roll = run_bash(f'"{script}" rollback testroll', env=env)
    assert res_roll.returncode == 0
    assert "Rollback complete" in res_roll.stdout

def test_cli_dispatch_baseline(tmp_path):
    vpn_dir = tmp_path / "vpn_inst"
    vpn_dir.mkdir()
    
    cli = (REPO_ROOT / "bin" / "vpn").as_posix()
    vpn_dir_posix = vpn_dir.as_posix()
    
    env = {
        "VPN_DIR": vpn_dir_posix,
        "SKIP_ROOT_CHECK": "1"
    }
    
    res = run_bash(f'"{cli}" baseline snapshot clitest', env=env)
    assert res.returncode == 0
    assert (vpn_dir / "backup" / "baseline-clitest").exists()
    
    res_roll = run_bash(f'"{cli}" rollback-baseline clitest', env=env)
    assert res_roll.returncode == 0
    assert "Rollback complete" in res_roll.stdout
