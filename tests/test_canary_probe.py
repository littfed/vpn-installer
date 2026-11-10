import base64
import json
import os
import subprocess
import sys
import importlib.util
from pathlib import Path
import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPTS_DIR = REPO_ROOT / "scripts"

def _load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod

canary_probe = _load_module("canary_probe", str(SCRIPTS_DIR / "canary-probe.py"))
sub_server = _load_module("sub_server", str(SCRIPTS_DIR / "sub-server.py"))

update_circuit_breaker = canary_probe.update_circuit_breaker
format_table = canary_probe.format_table
save_health_file = canary_probe.save_health_file

build_clash_yaml = sub_server.build_clash_yaml
build_singbox_json = sub_server.build_singbox_json
build_base64_uris = sub_server.build_base64_uris
load_node_health = sub_server.load_node_health


class TestCanaryProbe:
    """Automated tests for Tickets 01-06: Canary Probe, Circuit Breaker, and Monitoring."""

    def test_circuit_breaker_state_transitions(self):
        """Ticket 02: 2 consecutive failures -> degraded; 2 consecutive successes -> healthy."""
        state = {}

        # 1. First failure -> still healthy
        state = update_circuit_breaker(state, {"success": False, "error": "timeout"})
        assert state["status"] == "healthy"
        assert state["consecutive_failures"] == 1
        assert state["consecutive_successes"] == 0

        # 2. Second failure -> degraded
        state = update_circuit_breaker(state, {"success": False, "error": "reset"})
        assert state["status"] == "degraded"
        assert state["consecutive_failures"] == 2
        assert state["consecutive_successes"] == 0

        # 3. Third failure -> remains degraded
        state = update_circuit_breaker(state, {"success": False, "error": "refused"})
        assert state["status"] == "degraded"
        assert state["consecutive_failures"] == 3

        # 4. First success -> still degraded (flapping protection)
        state = update_circuit_breaker(state, {"success": True, "latency_ms": 42.5})
        assert state["status"] == "degraded"
        assert state["consecutive_failures"] == 0
        assert state["consecutive_successes"] == 1
        assert state["last_latency_ms"] == 42.5

        # 5. Second success -> restored to healthy!
        state = update_circuit_breaker(state, {"success": True, "latency_ms": 39.1})
        assert state["status"] == "healthy"
        assert state["consecutive_failures"] == 0
        assert state["consecutive_successes"] == 2
        assert state["last_latency_ms"] == 39.1

        # Check rolling history capped at 5
        assert len(state["history"]) == 5

    def test_table_formatting_and_save(self, tmp_path):
        """Ticket 01, 02, 03: Table formatting and atomic save."""
        results = {
            "Node-Alpha": {
                "vless_reality": {"success": True, "latency_ms": 35.2, "tspu_bypass_ok": True, "warp_ok": True},
                "hysteria2": {"success": False, "latency_ms": None, "tspu_bypass_ok": False, "warp_ok": False},
                "mtproto": {"success": True, "latency_ms": 40.0, "tspu_bypass_ok": True, "warp_ok": False}
            }
        }
        health_data = {
            "nodes": {
                "Node-Alpha": {
                    "protocols": {
                        "vless_reality": {"status": "healthy"},
                        "hysteria2": {"status": "degraded"},
                        "mtproto": {"status": "healthy"}
                    }
                }
            }
        }

        table_str = format_table(results, health_data)
        assert "Node-Alpha" in table_str
        assert "VLESS_REALITY" in table_str.upper()
        assert "HYSTERIA2" in table_str.upper()
        assert "HEALTHY" in table_str
        assert "DEGRADED" in table_str

        # Atomic save
        health_file = tmp_path / "node-health.json"
        save_health_file(str(health_file), health_data)
        assert health_file.exists()
        loaded = json.loads(health_file.read_text(encoding="utf-8"))
        assert loaded["nodes"]["Node-Alpha"]["protocols"]["vless_reality"]["status"] == "healthy"

    def test_canary_probe_cli_execution_with_dry_run_and_json(self, tmp_path):
        """Ticket 01 & 03: canary-probe.py --json --dry-run CLI output."""
        nodes_file = tmp_path / "nodes.json"
        nodes_file.write_text(json.dumps({
            "nodes": [
                {
                    "name": "Dummy-Node",
                    "server": "127.0.0.1",
                    "protocols": {
                        "mtproto": {
                            "enabled": False
                        }
                    }
                }
            ]
        }), encoding="utf-8")

        probe_py = SCRIPTS_DIR / "canary-probe.py"
        res = subprocess.run(
            [sys.executable, str(probe_py), "--nodes-file", str(nodes_file), "--dry-run", "--json"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        assert res.returncode == 0
        data = json.loads(res.stdout)
        assert "results" in data
        assert "health" in data

    def test_subscription_filters_degraded_nodes(self, tmp_path):
        """Ticket 04: sub-server.py automatically excludes degraded protocols from AUTO-FASTEST."""
        vpn_dir = tmp_path / "opt" / "vpn-installer"
        vpn_dir.mkdir(parents=True, exist_ok=True)

        nodes_file = vpn_dir / "nodes.json"
        nodes_file.write_text(json.dumps({
            "nodes": [
                {
                    "name": "Node-1",
                    "server": "198.51.100.1",
                    "protocols": {
                        "vless_reality": {
                            "enabled": True,
                            "port": 443,
                            "public_key": "PK1",
                            "short_id": "sid1"
                        },
                        "hysteria2": {
                            "enabled": True,
                            "port": 443,
                            "pin_sha256": "hash1"
                        }
                    }
                },
                {
                    "name": "Node-2",
                    "server": "203.0.113.2",
                    "protocols": {
                        "vless_reality": {
                            "enabled": True,
                            "port": 443,
                            "public_key": "PK2",
                            "short_id": "sid2"
                        },
                        "hysteria2": {
                            "enabled": True,
                            "port": 443,
                            "pin_sha256": "hash2"
                        }
                    }
                }
            ]
        }), encoding="utf-8")

        # Mark Node-2 Hysteria 2 as degraded
        health_file = vpn_dir / "node-health.json"
        health_file.write_text(json.dumps({
            "nodes": {
                "Node-1": {
                    "protocols": {
                        "vless_reality": {"status": "healthy"},
                        "hysteria2": {"status": "healthy"}
                    }
                },
                "Node-2": {
                    "protocols": {
                        "vless_reality": {"status": "healthy"},
                        "hysteria2": {"status": "degraded"}
                    }
                }
            }
        }), encoding="utf-8")

        mock_user = {
            "name": "alice",
            "uuid": "00000000-0000-0000-0000-000000000000",
            "password": "alice_pass"
        }

        # 1. Clash: Node-2 Hysteria 2 must NOT be in AUTO-FASTEST, but IS in FALLBACK
        clash_yaml = build_clash_yaml({}, mock_user, str(vpn_dir))
        auto_block = clash_yaml.split("- name: \"AUTO-FASTEST\"")[1].split("- name: \"FALLBACK\"")[0]
        assert "Node-1 - Reality" in auto_block
        assert "Node-1 - Hysteria2" in auto_block
        assert "Node-2 - Reality" in auto_block
        assert "Node-2 - Hysteria2" not in auto_block, (
            "Degraded Node-2 Hysteria2 must be excluded from AUTO-FASTEST"
        )
        fallback_block = clash_yaml.split("- name: \"FALLBACK\"")[1].split("- name: \"PROXY\"")[0]
        assert "Node-2 - Hysteria2" in fallback_block, (
            "Degraded Node-2 Hysteria2 must remain available in FALLBACK group"
        )

        # 2. Sing-box: Node-2-Hy2 must NOT be in proxy-auto
        singbox_json_str = build_singbox_json({}, mock_user, str(vpn_dir))
        sb_cfg = json.loads(singbox_json_str)
        auto_ob = [ob for ob in sb_cfg["outbounds"] if ob.get("tag") == "proxy-auto"][0]
        assert "Node-1-Reality" in auto_ob["outbounds"]
        assert "Node-1-Hy2" in auto_ob["outbounds"]
        assert "Node-2-Reality" in auto_ob["outbounds"]
        assert "Node-2-Hy2" not in auto_ob["outbounds"], (
            "Degraded Node-2-Hy2 must be excluded from proxy-auto outbounds"
        )

        # 3. Base64: Node-2 Hysteria 2 should be flagged with -DEGRADED
        b64_str = build_base64_uris({}, mock_user, str(vpn_dir))
        decoded_uris = base64.b64decode(b64_str.strip()).decode("utf-8")
        assert "#alice-Hy2-Node-2-DEGRADED" in decoded_uris

    def test_systemd_templates_presence_and_structure(self):
        """Ticket 05: Verify vpn-canary.service and vpn-canary.timer."""
        svc_file = REPO_ROOT / "templates" / "vpn-canary.service"
        tmr_file = REPO_ROOT / "templates" / "vpn-canary.timer"

        assert svc_file.exists(), "templates/vpn-canary.service must exist"
        assert tmr_file.exists(), "templates/vpn-canary.timer must exist"

        svc_content = svc_file.read_text(encoding="utf-8")
        assert "canary-probe.py" in svc_content
        assert "Type=oneshot" in svc_content

        tmr_content = tmr_file.read_text(encoding="utf-8")
        assert "OnUnitActiveSec=7min" in tmr_content
        assert "RandomizedDelaySec=60s" in tmr_content
