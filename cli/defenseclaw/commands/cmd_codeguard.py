"""defenseclaw codeguard — CodeGuard skill management."""

from __future__ import annotations

import click

from defenseclaw.context import AppContext, pass_ctx


@click.group()
def codeguard() -> None:
    """CodeGuard static-analysis skill management."""


@codeguard.command("install-skill")
@pass_ctx
def install_skill_cmd(app: AppContext) -> None:
    """Install the CodeGuard skill into the OpenClaw workspace skills directory.

    Copies the bundled CodeGuard skill into the highest-priority OpenClaw
    skills directory (workspace skills dir when configured, otherwise the
    global skills dir) and enables it in openclaw.json.

    Equivalent to the auto-install that runs during ``defenseclaw init``.
    """
    from defenseclaw.codeguard_skill import install_codeguard_skill

    click.echo("CodeGuard skill: installing...", nl=False)
    status = install_codeguard_skill(app.cfg)
    click.echo(f" {status}")
