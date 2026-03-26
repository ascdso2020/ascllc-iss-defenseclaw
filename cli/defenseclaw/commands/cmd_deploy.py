"""defenseclaw deploy — Deploy agent with enforcement policies.

Mirrors internal/cli/deploy.go.
"""

from __future__ import annotations

import shutil
import time

import click

from defenseclaw.context import AppContext, pass_ctx
from defenseclaw.models import ScanResult


@click.command()
@click.argument("path", default=".")
@click.option("--skip-init", is_flag=True, help="Skip initialization step")
@pass_ctx
def deploy(app: AppContext, path: str, skip_init: bool) -> None:
    """Deploy OpenClaw in a secured sandbox.

    Full orchestrated deployment:
      1. Initialize if needed
      2. Run all scanners (skills + MCP + AIBOM)
      3. Auto-block anything HIGH/CRITICAL
      4. Generate OpenShell sandbox policy
      5. Start sandbox
      6. Print summary
    """
    start = time.monotonic()

    click.echo("╔══════════════════════════════════════════════╗")
    click.echo("║         DefenseClaw Deploy                   ║")
    click.echo("╚══════════════════════════════════════════════╝")
    click.echo()

    # Step 1: Init
    if not skip_init:
        click.echo("Step 1/5: Initializing...")
        _ensure_init(app)
        click.echo("  Done.")
    else:
        click.echo("Step 1/5: Init skipped (--skip-init)")
    click.echo()

    # Step 2: Full scan
    click.echo("Step 2/5: Running all scanners...")
    runs = _run_all_scanners(app, path)
    click.echo()

    # Step 3: Auto-block HIGH/CRITICAL
    click.echo("Step 3/5: Enforcing policy (auto-blocking HIGH/CRITICAL)...")
    blocked = _auto_block(app, runs)
    if blocked > 0:
        click.echo(f"  Auto-blocked {blocked} targets")
    else:
        click.echo("  No targets blocked")
    click.echo()

    # Step 4: Sandbox policy
    click.echo("Step 4/5: Generating sandbox policy...")
    if shutil.which(app.cfg.openshell.binary):
        click.echo("  Policy written (OpenShell available)")
    elif app.cfg.environment == "macos":
        click.echo("  OpenShell not available on macOS — sandbox enforcement skipped")
    else:
        click.echo("  OpenShell not found — sandbox enforcement will not be active")
    click.echo()

    # Step 5: Start sandbox
    click.echo("Step 5/5: Starting sandbox...")
    if shutil.which(app.cfg.openshell.binary):
        click.echo("  OpenShell sandbox started")
    elif app.cfg.environment == "macos":
        click.echo("  OpenShell not available on macOS — sandbox enforcement skipped")
    else:
        click.echo("  OpenShell not found — install OpenShell for full sandbox enforcement")
    click.echo()

    # Summary
    elapsed = time.monotonic() - start
    _print_summary(runs, blocked, elapsed)

    if app.logger:
        app.logger.log_action("deploy", path, f"duration={elapsed:.1f}s blocked={blocked}")


def _ensure_init(app: AppContext) -> None:
    import os

    from defenseclaw.config import config_path, default_config
    from defenseclaw.db import Store
    from defenseclaw.logger import Logger

    if os.path.exists(config_path()):
        return

    defaults = default_config()
    for d in [defaults.data_dir, defaults.quarantine_dir, defaults.plugin_dir, defaults.policy_dir]:
        os.makedirs(d, exist_ok=True)
    defaults.save()

    store = Store(defaults.audit_db)
    store.init()

    app.cfg = defaults
    if app.store:
        app.store.close()
    app.store = store
    app.logger = Logger(store)


def _run_all_scanners(app: AppContext, target: str) -> list[tuple[str, str, ScanResult | None, str]]:
    from defenseclaw.scanner.mcp import MCPScannerWrapper
    from defenseclaw.scanner.skill import SkillScannerWrapper

    scanners = [
        SkillScannerWrapper(app.cfg.scanners.skill_scanner),
        MCPScannerWrapper(app.cfg.scanners.mcp_scanner),
    ]

    runs: list[tuple[str, str, ScanResult | None, str]] = []
    for s in scanners:
        click.echo(f"  [scan] {s.name()} -> {target}")
        try:
            result = s.scan(target)
            if result.is_clean():
                click.echo(f"    Clean ({result.duration.total_seconds():.2f}s)")
            else:
                click.echo(
                    f"    Findings: {len(result.findings)} "
                    f"(max: {result.max_severity()}, {result.duration.total_seconds():.2f}s)"
                )
            if app.logger:
                app.logger.log_scan(result)
            runs.append((s.name(), target, result, ""))
        except SystemExit:
            click.echo("    Skipped (not installed)")
            runs.append((s.name(), target, None, "not installed"))
        except Exception as exc:
            click.echo(f"    Error: {exc}")
            runs.append((s.name(), target, None, str(exc)))

    codeguard_result = _run_codeguard(target)
    if codeguard_result is not None:
        runs.append(codeguard_result)
        _, _, result, err = codeguard_result
        if result and app.logger:
            app.logger.log_scan(result)

    return runs


def _run_codeguard(target: str) -> tuple[str, str, ScanResult | None, str] | None:
    """Run CodeGuard via the Go sidecar binary (defenseclaw scan code)."""
    import json
    import subprocess

    click.echo(f"  [scan] codeguard -> {target}")

    binary = shutil.which("defenseclaw-gateway") or shutil.which("defenseclaw")
    if not binary:
        click.echo("    Skipped (defenseclaw binary not found)")
        return ("codeguard", target, None, "binary not found")

    try:
        proc = subprocess.run(
            [binary, "scan", "code", target, "--json"],
            capture_output=True,
            text=True,
            timeout=120,
        )
    except subprocess.TimeoutExpired:
        click.echo("    Error: scan timed out")
        return ("codeguard", target, None, "timeout")
    except FileNotFoundError:
        click.echo("    Skipped (binary not executable)")
        return ("codeguard", target, None, "not executable")

    if proc.returncode != 0 and not proc.stdout.strip():
        err_msg = proc.stderr.strip()[:200] if proc.stderr else f"exit code {proc.returncode}"
        click.echo(f"    Error: {err_msg}")
        return ("codeguard", target, None, err_msg)

    try:
        data = json.loads(proc.stdout)
    except json.JSONDecodeError:
        click.echo("    Error: invalid JSON output")
        return ("codeguard", target, None, "invalid JSON output")

    from datetime import timedelta

    findings_raw = data.get("findings", [])
    findings = []
    for f in findings_raw:
        from defenseclaw.models import Finding as PyFinding

        findings.append(
            PyFinding(
                id=f.get("id", ""),
                severity=f.get("severity", "INFO"),
                title=f.get("title", ""),
                description=f.get("description", ""),
                location=f.get("location", ""),
                remediation=f.get("remediation", ""),
                scanner=f.get("scanner", "codeguard"),
                tags=f.get("tags", []),
            )
        )

    from datetime import datetime

    duration_ns = data.get("duration", 0)
    result = ScanResult(
        scanner="codeguard",
        target=target,
        timestamp=datetime.utcnow(),
        findings=findings,
        duration=timedelta(seconds=duration_ns / 1_000_000_000),
    )

    if result.is_clean():
        click.echo(f"    Clean ({result.duration.total_seconds():.2f}s)")
    else:
        click.echo(
            f"    Findings: {len(result.findings)} "
            f"(max: {result.max_severity()}, {result.duration.total_seconds():.2f}s)"
        )

    return ("codeguard", target, result, "")


def _auto_block(
    app: AppContext,
    runs: list[tuple[str, str, ScanResult | None, str]],
) -> int:
    from defenseclaw.enforce import PolicyEngine

    if not app.store:
        return 0
    pe = PolicyEngine(app.store)
    blocked = 0

    for scanner_name, target, result, err in runs:
        if err or result is None:
            continue
        if not result.has_severity("HIGH") and not result.has_severity("CRITICAL"):
            continue

        target_type = "skill"
        if scanner_name == "mcp-scanner":
            target_type = "mcp"

        if pe.is_blocked(target_type, result.target):
            continue

        reason = (
            f"auto-block: {len(result.findings)} findings, "
            f"max_severity={result.max_severity()} (scanner={scanner_name})"
        )
        pe.block(target_type, result.target, reason)
        blocked += 1
        click.echo(f"  Blocked: {target_type} {result.target!r} ({result.max_severity()})")
        if app.logger:
            app.logger.log_action(
                "auto-block", result.target,
                f"type={target_type} severity={result.max_severity()} scanner={scanner_name}",
            )
    return blocked


def _print_summary(
    runs: list[tuple[str, str, ScanResult | None, str]],
    blocked: int, elapsed: float,
) -> None:
    from defenseclaw.models import compare_severity

    total_findings = 0
    max_sev = "INFO"
    for _, _, result, _ in runs:
        if result:
            total_findings += len(result.findings)
            if compare_severity(result.max_severity(), max_sev) > 0:
                max_sev = result.max_severity()

    click.echo("════════════════════════════════════════════════")
    click.echo("  Deploy Summary")
    click.echo("════════════════════════════════════════════════")
    click.echo(f"  Scanners run:     {len(runs)}")
    click.echo(f"  Total findings:   {total_findings}")
    click.echo(f"  Max severity:     {max_sev}")
    click.echo(f"  Auto-blocked:     {blocked}")
    click.echo(f"  Duration:         {elapsed:.2f}s")
    click.echo()
    click.echo("  Run 'defenseclaw status' to check deployment health.")
