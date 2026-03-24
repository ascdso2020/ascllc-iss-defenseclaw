"""defenseclaw aibom — Generate and manage AI Bill of Materials.

Shells out to cisco-aibom CLI.
"""

from __future__ import annotations

import click

from defenseclaw.context import AppContext, pass_ctx


@click.group()
def aibom() -> None:
    """Manage AI Bill of Materials — generate, inspect."""


@aibom.command()
@click.argument("path", default=".")
@click.option("--json", "as_json", is_flag=True, help="Output results as JSON")
@pass_ctx
def generate(app: AppContext, path: str, as_json: bool) -> None:
    """Generate AI Bill of Materials for a project.

    Runs cisco-aibom to inventory AI components, models, and dependencies.
    """
    from defenseclaw.scanner.aibom import AIBOMScannerWrapper

    scanner = AIBOMScannerWrapper(app.cfg.scanners.aibom)
    click.echo(f"Generating AIBOM for: {path}")

    try:
        result = scanner.scan(path)
    except SystemExit:
        raise
    except Exception as exc:
        click.echo(f"error: AIBOM generation failed: {exc}", err=True)
        raise SystemExit(1)

    if app.logger:
        app.logger.log_scan(result)

    if as_json:
        click.echo(result.to_json())
    else:
        click.echo(f"  Scanner:  {result.scanner}")
        click.echo(f"  Target:   {result.target}")
        click.echo(f"  Items:    {len(result.findings)}")
        for f in result.findings:
            click.echo(f"    [{f.severity}] {f.title}")
