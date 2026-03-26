"""defenseclaw status — Show current enforcement status and health.

Mirrors internal/cli/status.go.
"""

from __future__ import annotations

import shutil

import click

from defenseclaw.context import AppContext, pass_ctx


@click.command()
@pass_ctx
def status(app: AppContext) -> None:
    """Show DefenseClaw status.

    Displays environment, sandbox health, scanner availability,
    enforcement counts, and activity summary.
    """
    cfg = app.cfg

    click.echo("DefenseClaw Status")
    click.echo("══════════════════")
    click.echo(f"  Environment:  {cfg.environment}")
    click.echo(f"  Data dir:     {cfg.data_dir}")
    click.echo(f"  Config:       {cfg.data_dir}/config.yaml")
    click.echo(f"  Audit DB:     {cfg.audit_db}")
    click.echo()

    # Sandbox
    if shutil.which(cfg.openshell.binary):
        click.echo("  Sandbox:      available")
    else:
        click.echo("  Sandbox:      not available (OpenShell not found)")

    # Scanners
    click.echo()
    click.echo("  Scanners:")
    scanner_bins = [
        ("skill-scanner", cfg.scanners.skill_scanner.binary),
        ("mcp-scanner", cfg.scanners.mcp_scanner.binary),
        ("codeguard", "built-in"),
    ]
    for name, binary in scanner_bins:
        if binary == "built-in":
            click.echo(f"    {name:<16s} built-in")
        elif shutil.which(binary):
            click.echo(f"    {name:<16s} installed")
        else:
            click.echo(f"    {name:<16s} not found")

    # Counts from DB
    if app.store:
        try:
            counts = app.store.get_counts()
            click.echo()
            click.echo("  Enforcement:")
            click.echo(f"    Blocked skills:  {counts.blocked_skills}")
            click.echo(f"    Allowed skills:  {counts.allowed_skills}")
            click.echo(f"    Blocked MCPs:    {counts.blocked_mcps}")
            click.echo(f"    Allowed MCPs:    {counts.allowed_mcps}")
            click.echo()
            click.echo("  Activity:")
            click.echo(f"    Total scans:     {counts.total_scans}")
            click.echo(f"    Active alerts:   {counts.alerts}")
        except Exception:
            pass

    # Sidecar status
    click.echo()
    from defenseclaw.gateway import OrchestratorClient
    client = OrchestratorClient(port=cfg.gateway.api_port)
    if client.is_running():
        click.secho("  Sidecar:      running", fg="green")
    else:
        click.echo("  Sidecar:      not running")
