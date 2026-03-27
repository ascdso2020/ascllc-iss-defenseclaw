# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# SPDX-License-Identifier: Apache-2.0

"""defenseclaw alerts — View and manage security alerts."""

from __future__ import annotations

import json

import click

from defenseclaw.context import AppContext, pass_ctx

# ---------------------------------------------------------------------------
# Table view helpers
# ---------------------------------------------------------------------------

_OVERHEAD   = 19
_W_IDX      = 2
_W_SEV      = 8
_W_TIME     = 5
_W_ACTION   = 17
_W_TARGET   = 11
_W_FIXED    = _W_IDX + _W_SEV + _W_TIME + _W_ACTION + _W_TARGET  # = 43

_SEV_ORDER  = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]


def _trunc(s: str, width: int) -> str:
    s = s.strip()
    if len(s) <= width:
        return s
    return s[: width - 1] + "…"


def _trunc_path(s: str, width: int) -> str:
    s = s.strip()
    if len(s) <= width:
        return s
    parts = s.rstrip("/").split("/")
    for n in range(1, len(parts) + 1):
        candidate = "/".join(parts[-n:])
        if len(candidate) + 2 <= width:
            return "…/" + candidate
    tail = parts[-1]
    if len(tail) + 2 <= width:
        return "…/" + tail
    return "…" + s[-(width - 1):]


def _humanize_details(raw: str) -> str:
    if not raw:
        return ""
    tokens = raw.split()
    if not any("=" in t for t in tokens):
        return raw
    kv: dict[str, str] = {}
    plain: list[str] = []
    for tok in tokens:
        if "=" in tok:
            k, v = tok.split("=", 1)
            kv[k] = v
        else:
            plain.append(tok)
    parts: list[str] = []
    if "host" in kv and "port" in kv:
        parts.append(f"{kv.pop('host')}:{kv.pop('port')}")
    elif "port" in kv:
        parts.append(f":{kv.pop('port')}")
    for key in ("mode", "environment", "status", "protocol", "scanner_mode"):
        if key in kv:
            parts.append(kv.pop(key))
    if "model" in kv:
        parts.append(kv.pop("model").split("/")[-1])
    for key in ("max_severity", "scanner", "findings"):
        kv.pop(key, None)
    for k, v in kv.items():
        parts.append(f"{k}={v}")
    parts.extend(plain)
    return " ".join(parts)


def _findings_json(findings: list[dict], width: int) -> str:
    suffix = "…"
    close = "]"
    parts: list[str] = []
    for f in findings:
        entry = json.dumps({"severity": f["severity"], "title": f["title"]}, separators=(",", ":"))
        candidate = "[" + ",".join(parts + [entry]) + close
        if len(candidate) > width:
            if parts:
                trunc = "[" + ",".join(parts) + "," + suffix
                if len(trunc) <= width:
                    return trunc
            full = json.dumps(
                [{"severity": f["severity"], "title": f["title"]} for f in findings],
                separators=(",", ":"),
            )
            return _trunc(full, width)
        parts.append(entry)
    return "[" + ",".join(parts) + close


def _kv(details: str) -> dict[str, str]:
    return dict(tok.split("=", 1) for tok in (details or "").split() if "=" in tok)


# ---------------------------------------------------------------------------
# TUI
# ---------------------------------------------------------------------------

_SEV_COLOR = {
    "CRITICAL": "bold red",
    "HIGH":     "red",
    "MEDIUM":   "yellow",
    "LOW":      "cyan",
    "INFO":     "dim",
    "ERROR":    "red",
}

_FILTER_CYCLE = ["ALL", "CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]


def _build_tui_app(store, limit: int):
    """Construct and return the Textual AlertsApp bound to *store*."""
    from textual.app import App, ComposeResult
    from textual.binding import Binding
    from textual.containers import ScrollableContainer
    from textual.widget import Widget
    from textual.widgets import Footer, Header, Static

    # ------------------------------------------------------------------ #
    # AlertRow — focusable accordion row                                   #
    # ------------------------------------------------------------------ #
    class AlertRow(Widget):
        """Single alert row.  Collapsed = 1 line header.  Focused = full detail."""

        can_focus = True

        DEFAULT_CSS = """
        AlertRow {
            height: auto;
            border-left: tall transparent;
            padding: 0 1;
        }
        AlertRow:focus {
            border-left: tall $accent;
            background: $boost;
        }
        AlertRow .detail {
            display: none;
            padding: 0 2;
            color: $text;
        }
        AlertRow:focus .detail {
            display: block;
        }
        """

        def __init__(self, event, idx: int) -> None:
            super().__init__(classes="alert-row")
            self.event = event
            self.idx = idx
            self._detail_cache: str | None = None

        def _header(self) -> str:
            e = self.event
            sev = e.severity or "INFO"
            color = _SEV_COLOR.get(sev, "")
            action = (e.action or "")[:17]
            target = _trunc_path(e.target or "", 40)
            ts = e.timestamp.strftime("%H:%M") if e.timestamp else ""
            return (
                f"[{color}]{sev:<8}[/{color}]  "
                f"{action:<17}  {target:<40}  [dim]{ts}[/dim]"
            )

        def _detail(self) -> str:
            if self._detail_cache is not None:
                return self._detail_cache
            e = self.event
            ts = e.timestamp.strftime("%Y-%m-%d %H:%M:%S") if e.timestamp else ""
            lines = [
                "",
                f"  [dim]Time   :[/dim]  {ts}",
                f"  [dim]Target :[/dim]  {e.target or '—'}",
            ]
            human = _humanize_details(e.details or "")
            if human:
                lines.append(f"  [dim]Details:[/dim]  {human}")
            kv_map = _kv(e.details or "")
            scanner_name = kv_map.get("scanner", "")
            if e.action == "scan" and scanner_name and e.target:
                try:
                    findings = store.get_findings_for_target(e.target, scanner_name)
                except Exception:
                    findings = []
                if findings:
                    lines += ["", f"  [bold]Findings ({len(findings)}):[/bold]"]
                    for f in findings:
                        fc = _SEV_COLOR.get(f["severity"], "")
                        loc = f"  [dim]{f['location']}[/dim]" if f.get("location") else ""
                        lines.append(f"    [{fc}][{f['severity']}][/{fc}] {f['title']}{loc}")
                else:
                    lines += ["", "  [green]✓ clean — no findings[/green]"]
            lines.append("")
            self._detail_cache = "\n".join(lines)
            return self._detail_cache

        def compose(self) -> ComposeResult:
            yield Static(self._header(), markup=True, classes="header")
            yield Static(self._detail(), markup=True, classes="detail")

        def on_focus(self) -> None:
            self.scroll_visible(animate=False)

        def on_key(self, event) -> None:
            if event.key in ("j", "down"):
                event.stop()
                self.screen.focus_next("AlertRow")
            elif event.key in ("k", "up"):
                event.stop()
                self.screen.focus_previous("AlertRow")

    # ------------------------------------------------------------------ #
    # AlertsApp                                                            #
    # ------------------------------------------------------------------ #
    class AlertsApp(App):
        CSS = """
        Screen { layout: vertical; }

        #filter-bar {
            height: 1;
            background: $surface;
            padding: 0 1;
        }

        #scroll {
            height: 1fr;
            border: solid $primary;
            padding: 0;
        }

        AlertRow {
            margin-bottom: 1;
        }
        """

        BINDINGS = [
            Binding("q,escape", "quit", "Quit"),
            Binding("r", "refresh", "Refresh"),
            Binding("f", "cycle_filter", "Filter severity"),
        ]

        def __init__(self, events: list, **kwargs):
            super().__init__(**kwargs)
            self._all_events = events
            self._filter_idx = 0

        def compose(self) -> ComposeResult:
            yield Header(show_clock=True)
            yield Static(self._filter_label(), id="filter-bar", markup=True)
            with ScrollableContainer(id="scroll"):
                yield from self._make_rows()
            yield Footer()

        def on_mount(self) -> None:
            self.title = f"DefenseClaw — Security Alerts (last {limit})"
            rows = list(self.query("AlertRow"))
            if rows:
                rows[0].focus()

        def _filter_label(self) -> str:
            sev = _FILTER_CYCLE[self._filter_idx]
            options = "  ".join(
                f"[bold underline]{f}[/]" if f == sev else f"[dim]{f}[/dim]"
                for f in _FILTER_CYCLE
            )
            return f" Filter: {options}   [dim]j/k ↑↓ navigate · f filter · r refresh · q quit[/dim]"

        def _filtered_events(self) -> list:
            sev = _FILTER_CYCLE[self._filter_idx]
            return self._all_events if sev == "ALL" else [
                e for e in self._all_events if e.severity == sev
            ]

        def _make_rows(self):
            for idx, e in enumerate(self._filtered_events(), 1):
                yield AlertRow(e, idx)

        def action_refresh(self) -> None:
            try:
                self._all_events = store.list_alerts(limit)
            except Exception:
                pass
            self._rebuild()
            self.query_one("#filter-bar").update(self._filter_label())
            self.notify("Alerts refreshed", timeout=2)

        def action_cycle_filter(self) -> None:
            self._filter_idx = (self._filter_idx + 1) % len(_FILTER_CYCLE)
            self._rebuild()
            self.query_one("#filter-bar").update(self._filter_label())

        def _rebuild(self) -> None:
            scroll = self.query_one("#scroll")
            scroll.remove_children()
            for row in self._make_rows():
                scroll.mount(row)
            rows = list(self.query("AlertRow"))
            if rows:
                rows[0].focus()

    return AlertsApp


# ---------------------------------------------------------------------------
# CLI command
# ---------------------------------------------------------------------------

@click.command()
@click.option("-n", "--limit", default=25, help="Number of alerts to load")
@click.option("--show", "show_idx", default=None, type=int,
              help="Print full details for alert # and exit (non-interactive)")
@click.option("--tui/--no-tui", default=True,
              help="Launch interactive TUI (default). Use --no-tui for plain table.")
@pass_ctx
def alerts(app: AppContext, limit: int, show_idx: int | None, tui: bool) -> None:
    """View security alerts (interactive TUI by default).

    Navigate with ↑↓ / j k, filter severity with f, refresh with r, quit with q.
    Use --no-tui for the plain table, --show N for a single alert detail.
    """
    if not app.store:
        click.echo("No audit store available. Run 'defenseclaw init' first.")
        return

    alert_list = app.store.list_alerts(limit)

    if not alert_list:
        click.echo("No alerts. All clear.")
        return

    # ---- --show <n>: non-interactive single-alert detail ----
    if show_idx is not None:
        if show_idx < 1 or show_idx > len(alert_list):
            click.echo(f"error: alert #{show_idx} not found (1–{len(alert_list)})", err=True)
            raise SystemExit(1)
        e = alert_list[show_idx - 1]
        sev_color = {"CRITICAL": "red", "HIGH": "red", "MEDIUM": "yellow", "LOW": "cyan"}.get(e.severity, "white")
        click.echo(f"Alert #{show_idx}")
        click.echo("  Severity:  ", nl=False)
        click.secho(e.severity, fg=sev_color)
        click.echo(f"  Timestamp: {e.timestamp.strftime('%Y-%m-%d %H:%M:%S') if e.timestamp else ''}")
        click.echo(f"  Action:    {e.action}")
        if e.target:
            click.echo(f"  Target:    {e.target}")
        if e.details:
            human = _humanize_details(e.details)
            if human:
                click.echo(f"  Details:   {human}")
        kv_map = _kv(e.details or "")
        scanner_name = kv_map.get("scanner", "")
        if e.action == "scan" and scanner_name and e.target:
            findings = app.store.get_findings_for_target(e.target, scanner_name)
            if findings:
                click.echo("  Findings:")
                sev_colors = {"CRITICAL": "red", "HIGH": "red", "MEDIUM": "yellow", "LOW": "cyan"}
                for f in findings:
                    color = sev_colors.get(f["severity"], "white")
                    click.secho(f"    [{f['severity']}]", fg=color, nl=False)
                    loc = f"  {f['location']}" if f["location"] else ""
                    click.echo(f" {f['title']}{loc}")
        return

    # ---- TUI (default) ----
    if tui:
        alerts_app = _build_tui_app(app.store, limit)
        alerts_app(alert_list).run()
        return

    # ---- plain table (--no-tui) ----
    from rich.console import Console
    from rich.markup import escape
    from rich.table import Table

    console = Console()
    term_width = console.size.width
    w_details = max(11, term_width - _OVERHEAD - _W_FIXED)

    table = Table(
        title=f"Security Alerts (last {limit})",
        caption="Run [bold]defenseclaw alerts --show #[/bold] for full details on any row.",
        show_lines=False,
    )
    table.add_column("#",         no_wrap=True)
    table.add_column("Severity",  style="bold", no_wrap=True)
    table.add_column("Time",      no_wrap=True)
    table.add_column("Action",    no_wrap=True)
    table.add_column("Target",    no_wrap=True)
    table.add_column("Details [--show #]", no_wrap=True)

    sev_styles = {
        "CRITICAL": "bold red",
        "HIGH":     "red",
        "MEDIUM":   "yellow",
        "LOW":      "cyan",
    }

    for idx, e in enumerate(alert_list, 1):
        sev_style = sev_styles.get(e.severity, "")
        sev_cell = f"[{sev_style}]{e.severity}[/{sev_style}]" if sev_style else e.severity
        ts     = e.timestamp.strftime("%H:%M") if e.timestamp else ""
        action = _trunc(e.action or "", _W_ACTION)
        target = _trunc_path(e.target or "", _W_TARGET)
        kv_map = _kv(e.details or "")
        scanner_name = kv_map.get("scanner", "")
        if e.action == "scan" and scanner_name and e.target:
            findings = app.store.get_findings_for_target(e.target, scanner_name)
            raw_details = _findings_json(findings, w_details) if findings else _humanize_details(e.details or "")
        else:
            raw_details = _humanize_details(e.details or "")
        details = _trunc(raw_details, w_details)
        table.add_row(
            escape(str(idx)), sev_cell, ts,
            escape(action), escape(target), escape(details),
        )

    console.print(table)
