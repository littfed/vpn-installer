# 05: Automated Test Suite & Integration Verification

**What to build:** Comprehensive automated test coverage validating baseline snapshot creation and rollback, installer assertion halt behavior, `vpn doctor` diagnostic scoring, and the automated `vpn node add` registration flow.

**Blocked by:** 04: Automated Fleet Provisioning & Join (`vpn node add`)

**Status:** completed

- [x] Automated pytest tests covering:
  - Baseline snapshot creation and `vpn rollback-baseline` restoring clean state
  - Post-flight assertion detection when a service fails to start or port is blocked
  - `vpn doctor` command testing with healthy and degraded mocked system states
  - `vpn node add`, `vpn node list`, and `vpn node remove` lifecycle managing `nodes.json`
- [x] All tests pass cleanly in local and CI environments without side effects on running production services
- [x] Documentation updated with node provisioning runbook and troubleshooting instructions
