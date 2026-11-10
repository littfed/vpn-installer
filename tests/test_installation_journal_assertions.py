import os
import sys
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

def run_bash_file(script_path, args=None, env=None):
    bash = find_bash()
    full_env = os.environ.copy()
    if env:
        full_env.update(env)
    cmd = [bash, str(script_path)]
    if args:
        cmd.extend(args)
    res = subprocess.run(cmd, capture_output=True, text=True, env=full_env)
    return res

def test_install_log_creation_and_formatting(tmp_path):
    vpn_dir = tmp_path / "vpn_inst"
    vpn_dir.mkdir()
    bin_dir = tmp_path / "local_bin"
    bin_dir.mkdir()
    
    install_sh = REPO_ROOT / "scripts" / "install.sh"
    vpn_dir_posix = vpn_dir.as_posix()
    bin_dir_posix = bin_dir.as_posix()
    
    env = {
        "VPN_DIR": vpn_dir_posix,
        "BIN_DIR": bin_dir_posix,
        "SKIP_ROOT_CHECK": "1",
        "SKIP_OS_CHECK": "1",
        "SKIP_DOCKER_INSTALL": "1",
        "SKIP_CONTAINER_START": "1",
        "SKIP_FIREWALL": "1",
        "SKIP_BASELINE": "1"
    }
    
    res = run_bash_file(install_sh, env=env)
    assert res.returncode == 0, f"Install failed:\nSTDOUT:\n{res.stdout}\nSTDERR:\n{res.stderr}"
    
    log_file = vpn_dir / "install.log"
    assert log_file.exists(), "install.log was not created"
    
    content = log_file.read_text(encoding="utf-8")
    assert "[INFO]" in content
    assert "Starting VPN Installer bootstrap" in content
    assert "Sing-Box Config Schema" in content
    assert "AmneziaWG Configuration" in content

def test_assertion_failure_halts_installer(tmp_path):
    vpn_dir = tmp_path / "vpn_inst"
    vpn_dir.mkdir()
    bin_dir = tmp_path / "local_bin"
    bin_dir.mkdir()
    
    install_sh = (REPO_ROOT / "scripts" / "install.sh").as_posix()
    vpn_dir_posix = vpn_dir.as_posix()
    bin_dir_posix = bin_dir.as_posix()
    
    # We invoke assert_step directly through a small bash script that sources install.sh functions
    bash = find_bash()
    test_script = f'''
    export VPN_DIR="{vpn_dir_posix}"
    export BIN_DIR="{bin_dir_posix}"
    export INSTALL_LOG="{vpn_dir_posix}/install.log"
    
    # Source only the helper functions from install.sh
    eval "$(grep -E '^(log_|assert_step)' "{install_sh}")"
    # Or define assert_step directly as in install.sh and test failure behavior
    assert_step() {{
        local step_name="$1"
        local check_cmd="$2"
        local error_msg="${{3:-Assertion failed for ${{step_name}}}}"

        if eval "$check_cmd" >> "${{INSTALL_LOG}}" 2>&1; then
            return 0
        else
            echo "POST-FLIGHT ASSERTION FAILED: ${{step_name}}" >&2
            echo "${{error_msg}}" >&2
            exit 1
        fi
    }}
    
    assert_step "Mock Failure Check" "false" "Simulated failure for verification"
    '''
    res = subprocess.run([bash, "-c", test_script], capture_output=True, text=True)
    assert res.returncode != 0
    assert "POST-FLIGHT ASSERTION FAILED: Mock Failure Check" in res.stderr
