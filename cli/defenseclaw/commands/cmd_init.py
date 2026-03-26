"""defenseclaw init — Initialize DefenseClaw environment.

Mirrors internal/cli/init.go.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys

import click

from defenseclaw.context import AppContext, pass_ctx


@click.command("init")
@click.option("--skip-install", is_flag=True, help="Skip automatic scanner dependency installation")
@pass_ctx
def init_cmd(app: AppContext, skip_install: bool) -> None:
    """Initialize DefenseClaw environment.

    Creates ~/.defenseclaw/, default config, SQLite database,
    and installs scanner dependencies.
    """
    from defenseclaw.config import config_path, default_config, detect_environment, load
    from defenseclaw.db import Store
    from defenseclaw.logger import Logger

    env = detect_environment()
    click.echo(f"  Environment: {env}")

    cfg_file = config_path()
    if os.path.exists(cfg_file):
        cfg = load()
        click.echo("  Config: preserved existing")
    else:
        cfg = default_config()
        click.echo("  Config: created new defaults")

    cfg.environment = env
    click.echo(f"  Claw mode:   {cfg.claw.mode}")
    click.echo(f"  Claw home:   {cfg.claw_home_dir()}")

    dirs = [
        cfg.data_dir, cfg.quarantine_dir,
        cfg.plugin_dir, cfg.policy_dir,
    ]

    data_dir_real = os.path.realpath(cfg.data_dir)
    for d in dirs:
        os.makedirs(d, exist_ok=True)

    external_dirs = list(cfg.skill_dirs())
    for d in external_dirs:
        d_real = os.path.realpath(d)
        if d_real.startswith(data_dir_real + os.sep):
            os.makedirs(d, exist_ok=True)
    click.echo("  Directories: created")

    _seed_rego_policies(cfg.policy_dir)

    cfg.save()
    click.echo(f"  Config: {cfg_file}")

    store = Store(cfg.audit_db)
    store.init()
    click.echo(f"  Audit DB: {cfg.audit_db}")

    logger = Logger(store)
    logger.log_action("init", cfg.data_dir, f"environment={env}")

    click.echo()
    _install_scanners(cfg, logger, skip_install)

    click.echo()
    _install_guardrail(cfg, logger, skip_install)

    click.echo()
    _install_codeguard_skill(cfg, logger)

    click.echo()
    if shutil.which(cfg.openshell.binary):
        click.echo("  OpenShell: found")
    elif env == "macos":
        click.echo("  OpenShell: not available on macOS (sandbox enforcement will be skipped)")
    else:
        click.echo("  OpenShell: not found (sandbox enforcement will not be active)")

    click.echo("\nDefenseClaw initialized. Run 'defenseclaw scan' to start scanning.")

    store.close()


def _seed_rego_policies(policy_dir: str) -> None:
    """Copy bundled Rego policies into the user's policy_dir if not already present."""
    from pathlib import Path

    here = Path(__file__).resolve()
    bundled_rego = here.parent.parent.parent.parent / "policies" / "rego"
    if not bundled_rego.is_dir():
        return

    dest_rego = os.path.join(policy_dir, "rego")
    os.makedirs(dest_rego, exist_ok=True)

    for src in bundled_rego.iterdir():
        if src.suffix in (".rego", ".json") and not src.name.startswith("."):
            dst = os.path.join(dest_rego, src.name)
            if not os.path.exists(dst):
                shutil.copy2(str(src), dst)

    click.echo(f"  Rego policies: seeded in {dest_rego}")


def _install_scanners(cfg, logger, skip: bool) -> None:
    if skip:
        click.echo("  Scanners: skipped (--skip-install)")
        return

    _verify_scanner_sdk("skill-scanner", "skill_scanner")
    _verify_scanner_sdk("mcp-scanner", "mcpscanner", min_python=(3, 11))


def _verify_scanner_sdk(name: str, import_name: str, min_python: tuple[int, ...] | None = None) -> None:
    """Check that a scanner SDK is importable; report status."""
    import importlib
    import sys

    if min_python and sys.version_info < min_python:
        ver = ".".join(str(v) for v in min_python)
        click.echo(f"  {name}: requires Python >={ver} (skipped)")
        return

    try:
        importlib.import_module(import_name)
        click.echo(f"  {name}: available")
    except ImportError:
        click.echo(f"  {name}: not installed")
        click.echo("    install with: pip install defenseclaw")


def _install_guardrail(cfg, logger, skip: bool) -> None:
    """Install LiteLLM proxy and copy the guardrail module."""
    if skip:
        click.echo("  LiteLLM: skipped (--skip-install)")
        return

    if _litellm_proxy_ready():
        click.echo("  LiteLLM: proxy extras verified")
    elif shutil.which("litellm"):
        click.echo("  LiteLLM: binary found but proxy extras missing, installing...", nl=False)
        if _install_litellm_proxy_extras():
            click.echo(" done")
            logger.log_action("install-dep", "litellm", "package=litellm[proxy]")
        else:
            click.echo(" failed")
            click.echo("    install manually: pip install 'litellm[proxy]'")
    else:
        click.echo("  LiteLLM: installing...", nl=False)
        if _install_litellm():
            click.echo(" done")
            logger.log_action("install-dep", "litellm", "package=litellm[proxy]")
        else:
            click.echo(" failed")
            click.echo("    install manually: uv tool install 'litellm[proxy]'")

    guardrail_dir = cfg.guardrail.guardrail_dir
    os.makedirs(guardrail_dir, exist_ok=True)

    from defenseclaw.guardrail import install_guardrail_module

    repo_source = _find_guardrail_source()
    if repo_source:
        install_guardrail_module(repo_source, guardrail_dir)
        click.echo(f"  Guardrail module: installed to {guardrail_dir}")
        logger.log_action("install-dep", "guardrail", f"dir={guardrail_dir}")
    else:
        click.echo("  Guardrail module: not found in package (run setup guardrail later)")


def _find_guardrail_source() -> str | None:
    candidates = [
        os.path.join(os.path.dirname(__file__), "..", "..", "..", "guardrails", "defenseclaw_guardrail.py"),
    ]
    try:
        pkg_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        repo_root = os.path.dirname(os.path.dirname(pkg_dir))
        candidates.append(os.path.join(repo_root, "guardrails", "defenseclaw_guardrail.py"))
    except Exception:
        pass

    for c in candidates:
        resolved = os.path.realpath(c)
        if os.path.isfile(resolved):
            return resolved
    return None


def _litellm_proxy_ready() -> bool:
    """Check that litellm binary exists AND its proxy extras are importable."""
    litellm_bin = shutil.which("litellm")
    if not litellm_bin:
        return False
    try:
        result = subprocess.run(
            [sys.executable, "-c", "import backoff; import prisma"],
            capture_output=True, text=True, timeout=10,
        )
        return result.returncode == 0
    except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired):
        return False


def _install_litellm_proxy_extras() -> bool:
    """Install litellm[proxy] extras into the active Python environment."""
    pip = shutil.which("pip") or shutil.which("pip3")
    uv = shutil.which("uv")
    try:
        if uv:
            result = subprocess.run(
                [uv, "pip", "install", "litellm[proxy]"],
                capture_output=True, text=True,
            )
        elif pip:
            result = subprocess.run(
                [pip, "install", "litellm[proxy]"],
                capture_output=True, text=True,
            )
        else:
            return False
        return result.returncode == 0
    except (subprocess.CalledProcessError, FileNotFoundError):
        return False


def _install_litellm() -> bool:
    _ensure_uv()
    uv = shutil.which("uv")
    if not uv:
        return False
    try:
        result = subprocess.run(
            [uv, "tool", "install", "--python", "3.13", "litellm[proxy]"],
            capture_output=True, text=True,
        )
        return result.returncode == 0 or "already installed" in result.stderr
    except (subprocess.CalledProcessError, FileNotFoundError):
        return False


def _ensure_uv() -> None:
    if shutil.which("uv"):
        return

    click.echo("  uv: not found, installing...", nl=False)
    try:
        subprocess.run(
            ["sh", "-c", "curl -LsSf https://astral.sh/uv/install.sh | sh"],
            capture_output=True, check=True,
        )
        _add_uv_to_path()
        click.echo(" done")
    except (subprocess.CalledProcessError, FileNotFoundError):
        click.echo(" failed")
        click.echo("    install uv manually: curl -LsSf https://astral.sh/uv/install.sh | sh")
        click.echo("    then re-run: defenseclaw init")


def _add_uv_to_path() -> None:
    home = os.path.expanduser("~")
    for extra in [f"{home}/.local/bin", f"{home}/.cargo/bin"]:
        if extra not in os.environ.get("PATH", ""):
            os.environ["PATH"] = extra + ":" + os.environ.get("PATH", "")


def _install_with_uv(pkg: str) -> bool:
    uv = shutil.which("uv")
    if not uv:
        return False
    try:
        result = subprocess.run(
            [uv, "tool", "install", "--python", "3.13", pkg],
            capture_output=True, text=True,
        )
        if result.returncode == 0 or "already installed" in result.stderr:
            return True
        return False
    except (subprocess.CalledProcessError, FileNotFoundError):
        return False


def _install_codeguard_skill(cfg, logger) -> None:
    """Install the CodeGuard proactive skill into the OpenClaw skills directory."""
    from defenseclaw.codeguard_skill import install_codeguard_skill

    click.echo("  CodeGuard skill: installing...", nl=False)
    status = install_codeguard_skill(cfg)
    click.echo(f" {status}")
    logger.log_action("install-skill", "codeguard", f"status={status}")
