"""Configuration loader — reads/writes ~/.defenseclaw/config.yaml.

Mirrors internal/config/config.go + defaults.go + claw.go + actions.go
so that the Go orchestrator and Python CLI share the same config file.
"""

from __future__ import annotations

import json
import os
import platform
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

DATA_DIR_NAME = ".defenseclaw"
AUDIT_DB_NAME = "audit.db"
CONFIG_FILE_NAME = "config.yaml"


def _home() -> Path:
    return Path.home()


def default_data_path() -> Path:
    return _home() / DATA_DIR_NAME


def config_path() -> Path:
    return default_data_path() / CONFIG_FILE_NAME


def _expand(p: str) -> str:
    if p.startswith("~/"):
        return str(_home() / p[2:])
    return p


# ---------------------------------------------------------------------------
# Environment detection (mirrors config.DetectEnvironment)
# ---------------------------------------------------------------------------

def detect_environment() -> str:
    if platform.system() == "Darwin":
        return "macos"
    if Path("/etc/dgx-release").exists():
        return "dgx-spark"
    try:
        out = subprocess.check_output(
            ["nvidia-smi", "-L"], stderr=subprocess.DEVNULL, text=True,
        )
        if "DGX" in out:
            return "dgx-spark"
    except (FileNotFoundError, subprocess.CalledProcessError):
        pass
    return "linux"


# ---------------------------------------------------------------------------
# Dataclasses — same YAML keys as Go structs
# ---------------------------------------------------------------------------

@dataclass
class MCPServerEntry:
    name: str = ""
    command: str = ""
    args: list[str] = field(default_factory=list)
    env: dict[str, str] = field(default_factory=dict)
    url: str = ""
    transport: str = ""


@dataclass
class ClawConfig:
    mode: str = "openclaw"
    home_dir: str = "~/.openclaw"
    config_file: str = "~/.openclaw/openclaw.json"


@dataclass
class SkillScannerConfig:
    binary: str = "skill-scanner"
    use_llm: bool = False
    use_behavioral: bool = False
    enable_meta: bool = False
    use_trigger: bool = False
    use_virustotal: bool = False
    use_aidefense: bool = False
    llm_provider: str = ""
    llm_model: str = ""
    llm_consensus_runs: int = 0
    policy: str = ""
    lenient: bool = False
    llm_api_key: str = ""
    virustotal_api_key: str = ""
    aidefense_api_key: str = ""


@dataclass
class MCPScannerConfig:
    binary: str = "mcp-scanner"
    analyzers: str = ""
    api_key: str = ""
    endpoint_url: str = ""
    llm_provider: str = ""
    llm_api_key: str = ""
    llm_model: str = ""
    llm_base_url: str = ""
    llm_timeout: int = 30
    llm_max_retries: int = 3
    scan_prompts: bool = False
    scan_resources: bool = False
    scan_instructions: bool = False


@dataclass
class ScannersConfig:
    skill_scanner: SkillScannerConfig = field(default_factory=SkillScannerConfig)
    mcp_scanner: MCPScannerConfig = field(default_factory=MCPScannerConfig)
    codeguard: str = ""


@dataclass
class OpenShellConfig:
    binary: str = "openshell"
    policy_dir: str = "/etc/openshell/policies"


@dataclass
class WatchConfig:
    debounce_ms: int = 500
    auto_block: bool = True


@dataclass
class SplunkConfig:
    hec_endpoint: str = "https://localhost:8088/services/collector/event"
    hec_token: str = ""
    index: str = "defenseclaw"
    source: str = "defenseclaw"
    sourcetype: str = "_json"
    verify_tls: bool = False
    enabled: bool = False
    batch_size: int = 50
    flush_interval_s: int = 5


@dataclass
class GatewayWatcherSkillConfig:
    enabled: bool = True
    take_action: bool = True
    dirs: list[str] = field(default_factory=list)


@dataclass
class GatewayWatcherConfig:
    enabled: bool = False
    skill: GatewayWatcherSkillConfig = field(default_factory=GatewayWatcherSkillConfig)


@dataclass
class GatewayConfig:
    host: str = "127.0.0.1"
    port: int = 18789
    token: str = ""
    device_key_file: str = ""
    auto_approve_safe: bool = False
    reconnect_ms: int = 800
    max_reconnect_ms: int = 15000
    approval_timeout_s: int = 30
    api_port: int = 18790
    watcher: GatewayWatcherConfig = field(default_factory=GatewayWatcherConfig)


@dataclass
class SeverityAction:
    file: str = "none"
    runtime: str = "enable"
    install: str = "none"


@dataclass
class SkillActionsConfig:
    critical: SeverityAction = field(
        default_factory=lambda: SeverityAction(file="quarantine", runtime="disable", install="block"),
    )
    high: SeverityAction = field(
        default_factory=lambda: SeverityAction(file="quarantine", runtime="disable", install="block"),
    )
    medium: SeverityAction = field(default_factory=SeverityAction)
    low: SeverityAction = field(default_factory=SeverityAction)
    info: SeverityAction = field(default_factory=SeverityAction)

    def for_severity(self, severity: str) -> SeverityAction:
        return {
            "CRITICAL": self.critical,
            "HIGH": self.high,
            "MEDIUM": self.medium,
            "LOW": self.low,
        }.get(severity.upper(), self.info)

    def should_disable(self, severity: str) -> bool:
        return self.for_severity(severity).runtime == "disable"

    def should_quarantine(self, severity: str) -> bool:
        return self.for_severity(severity).file == "quarantine"

    def should_install_block(self, severity: str) -> bool:
        return self.for_severity(severity).install == "block"


@dataclass
class MCPActionsConfig:
    critical: SeverityAction = field(
        default_factory=lambda: SeverityAction(file="none", runtime="enable", install="block"),
    )
    high: SeverityAction = field(
        default_factory=lambda: SeverityAction(file="none", runtime="enable", install="block"),
    )
    medium: SeverityAction = field(default_factory=SeverityAction)
    low: SeverityAction = field(default_factory=SeverityAction)
    info: SeverityAction = field(default_factory=SeverityAction)

    def for_severity(self, severity: str) -> SeverityAction:
        return {
            "CRITICAL": self.critical,
            "HIGH": self.high,
            "MEDIUM": self.medium,
            "LOW": self.low,
        }.get(severity.upper(), self.info)

    def should_install_block(self, severity: str) -> bool:
        return self.for_severity(severity).install == "block"


@dataclass
class FirewallConfig:
    config_file: str = ""
    rules_file: str = ""
    anchor_name: str = "com.defenseclaw"


@dataclass
class CiscoAIDefenseConfig:
    endpoint: str = "https://us.api.inspect.aidefense.security.cisco.com"
    api_key_env: str = "CISCO_AI_DEFENSE_API_KEY"
    timeout_ms: int = 3000
    enabled_rules: list[str] = field(default_factory=list)


@dataclass
class GuardrailConfig:
    enabled: bool = False
    mode: str = "observe"           # observe | action
    scanner_mode: str = "local"     # local | remote | both
    port: int = 4000
    model: str = ""                 # upstream model, e.g. "anthropic/claude-opus-4-5"
    model_name: str = ""            # alias exposed to OpenClaw, e.g. "claude-opus"
    api_key_env: str = ""           # env var holding the API key, e.g. "ANTHROPIC_API_KEY"
    guardrail_dir: str = ""         # directory containing guardrail module (must match litellm_config dir)
    litellm_config: str = ""        # path to generated litellm_config.yaml
    original_model: str = ""        # original OpenClaw model (for revert)
    block_message: str = ""          # custom message shown when a request is blocked (empty = default)
    cisco_ai_defense: CiscoAIDefenseConfig = field(default_factory=CiscoAIDefenseConfig)


@dataclass
class Config:
    data_dir: str = ""
    audit_db: str = ""
    quarantine_dir: str = ""
    plugin_dir: str = ""
    policy_dir: str = ""
    environment: str = ""
    claw: ClawConfig = field(default_factory=ClawConfig)
    scanners: ScannersConfig = field(default_factory=ScannersConfig)
    openshell: OpenShellConfig = field(default_factory=OpenShellConfig)
    watch: WatchConfig = field(default_factory=WatchConfig)
    firewall: FirewallConfig = field(default_factory=FirewallConfig)
    guardrail: GuardrailConfig = field(default_factory=GuardrailConfig)
    splunk: SplunkConfig = field(default_factory=SplunkConfig)
    gateway: GatewayConfig = field(default_factory=GatewayConfig)
    skill_actions: SkillActionsConfig = field(default_factory=SkillActionsConfig)
    mcp_actions: MCPActionsConfig = field(default_factory=MCPActionsConfig)

    # -- Claw-mode path resolution (mirrors claw.go) --

    def claw_home_dir(self) -> str:
        return _expand(self.claw.home_dir)

    def skill_dirs(self) -> list[str]:
        home = self.claw_home_dir()
        dirs: list[str] = []
        oc = _read_openclaw_config(self.claw.config_file)
        if oc:
            ws = oc.get("agents", {}).get("defaults", {}).get("workspace", "")
            if ws:
                dirs.append(os.path.join(_expand(ws), "skills"))
            for d in oc.get("skills", {}).get("load", {}).get("extraDirs", []):
                dirs.append(_expand(d))
        dirs.append(os.path.join(home, "skills"))
        return _dedup(dirs)

    def mcp_servers(self) -> list[MCPServerEntry]:
        """Return MCP servers from openclaw.json mcp.servers.

        Tries ``openclaw config get mcp.servers`` first (safe, schema-
        validated).  Falls back to reading the file directly when the CLI
        is unavailable or returns an error (OpenClaw < 2026.3.24).
        """
        servers = _read_mcp_servers_via_cli()
        if servers is not None:
            return servers
        return _read_mcp_servers_from_file(self.claw.config_file)

    def installed_skill_candidates(self, skill_name: str) -> list[str]:
        name = skill_name
        if "/" in name:
            name = name.rsplit("/", 1)[-1]
        name = name.lstrip("@")
        return [os.path.join(d, name) for d in self.skill_dirs()]

    def save(self) -> None:
        path = os.path.join(self.data_dir, CONFIG_FILE_NAME)
        data = _config_to_dict(self)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w") as f:
            yaml.dump(data, f, default_flow_style=False, sort_keys=False)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _read_openclaw_config(config_file: str) -> dict[str, Any] | None:
    path = _expand(config_file)
    try:
        with open(path) as f:
            return json.load(f)
    except (OSError, json.JSONDecodeError):
        return None


def _read_mcp_servers_via_cli() -> list[MCPServerEntry] | None:
    """Read mcp.servers via ``openclaw config get``.  Returns None on failure."""
    try:
        result = subprocess.run(
            ["openclaw", "config", "get", "mcp.servers"],
            capture_output=True, text=True, timeout=10,
        )
        if result.returncode != 0:
            return None
        return _parse_mcp_servers_json(result.stdout)
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return None


def _read_mcp_servers_from_file(config_file: str) -> list[MCPServerEntry]:
    """Fallback: parse mcp.servers directly from openclaw.json."""
    path = _expand(config_file)
    try:
        with open(path) as f:
            raw = f.read()
    except OSError:
        return []

    data: dict[str, Any] | None = None
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        try:
            import json5  # type: ignore[import-untyped]
            data = json5.loads(raw)
        except Exception:
            return []

    if not isinstance(data, dict):
        return []

    servers = data.get("mcp", {}).get("servers")
    if not isinstance(servers, dict):
        return []

    return _parse_mcp_servers_dict(servers)


def _parse_mcp_servers_json(text: str) -> list[MCPServerEntry]:
    text = text.strip()
    if not text:
        return []
    try:
        servers = json.loads(text)
    except json.JSONDecodeError:
        return []
    if not isinstance(servers, dict):
        return []
    return _parse_mcp_servers_dict(servers)


def _parse_mcp_servers_dict(servers: dict[str, Any]) -> list[MCPServerEntry]:
    entries: list[MCPServerEntry] = []
    for name, cfg in servers.items():
        if not isinstance(cfg, dict):
            continue
        entries.append(MCPServerEntry(
            name=name,
            command=cfg.get("command", ""),
            args=cfg.get("args", []),
            env=cfg.get("env", {}),
            url=cfg.get("url", ""),
            transport=cfg.get("transport", ""),
        ))
    return entries


def _dedup(paths: list[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for p in paths:
        if p not in seen:
            seen.add(p)
            out.append(p)
    return out


def _config_to_dict(cfg: Config) -> dict[str, Any]:
    """Serialize Config to a dict suitable for YAML."""
    from dataclasses import asdict
    return asdict(cfg)


def _merge_severity_action(raw: dict[str, Any] | None) -> SeverityAction:
    if not raw:
        return SeverityAction()
    return SeverityAction(
        file=raw.get("file", "none"),
        runtime=raw.get("runtime", "enable"),
        install=raw.get("install", "none"),
    )


def _merge_skill_actions(raw: dict[str, Any] | None) -> SkillActionsConfig:
    defaults = SkillActionsConfig()
    if not raw:
        return defaults
    return SkillActionsConfig(
        critical=_merge_severity_action(raw.get("critical")) if "critical" in raw else defaults.critical,
        high=_merge_severity_action(raw.get("high")) if "high" in raw else defaults.high,
        medium=_merge_severity_action(raw.get("medium")) if "medium" in raw else defaults.medium,
        low=_merge_severity_action(raw.get("low")) if "low" in raw else defaults.low,
        info=_merge_severity_action(raw.get("info")) if "info" in raw else defaults.info,
    )


def _merge_mcp_actions(raw: dict[str, Any] | None) -> MCPActionsConfig:
    defaults = MCPActionsConfig()
    if not raw:
        return defaults
    return MCPActionsConfig(
        critical=_merge_severity_action(raw.get("critical")) if "critical" in raw else defaults.critical,
        high=_merge_severity_action(raw.get("high")) if "high" in raw else defaults.high,
        medium=_merge_severity_action(raw.get("medium")) if "medium" in raw else defaults.medium,
        low=_merge_severity_action(raw.get("low")) if "low" in raw else defaults.low,
        info=_merge_severity_action(raw.get("info")) if "info" in raw else defaults.info,
    )


def _merge_cisco_ai_defense(raw: dict[str, Any] | None) -> CiscoAIDefenseConfig:
    if not raw:
        return CiscoAIDefenseConfig()
    return CiscoAIDefenseConfig(
        endpoint=raw.get("endpoint", "https://us.api.inspect.aidefense.security.cisco.com"),
        api_key_env=raw.get("api_key_env", "CISCO_AI_DEFENSE_API_KEY"),
        timeout_ms=raw.get("timeout_ms", 3000),
        enabled_rules=raw.get("enabled_rules", []),
    )


def _merge_guardrail(raw: dict[str, Any] | None, data_dir: str) -> GuardrailConfig:
    if not raw:
        return GuardrailConfig(
            guardrail_dir=data_dir,
            litellm_config=os.path.join(data_dir, "litellm_config.yaml"),
        )
    return GuardrailConfig(
        enabled=raw.get("enabled", False),
        mode=raw.get("mode", "observe"),
        scanner_mode=raw.get("scanner_mode", "local"),
        port=raw.get("port", 4000),
        model=raw.get("model", ""),
        model_name=raw.get("model_name", ""),
        api_key_env=raw.get("api_key_env", ""),
        guardrail_dir=raw.get("guardrail_dir", data_dir),
        litellm_config=raw.get("litellm_config", os.path.join(data_dir, "litellm_config.yaml")),
        original_model=raw.get("original_model", ""),
        block_message=raw.get("block_message", ""),
        cisco_ai_defense=_merge_cisco_ai_defense(raw.get("cisco_ai_defense")),
    )


def _merge_mcp_scanner(raw: Any) -> MCPScannerConfig:
    """Parse mcp_scanner config with backward compat for bare-string values."""
    if raw is None:
        return MCPScannerConfig()
    if isinstance(raw, str):
        return MCPScannerConfig(binary=raw)
    if isinstance(raw, dict):
        return MCPScannerConfig(
            binary=raw.get("binary", "mcp-scanner"),
            analyzers=raw.get("analyzers", ""),
            api_key=raw.get("api_key", ""),
            endpoint_url=raw.get("endpoint_url", ""),
            llm_provider=raw.get("llm_provider", ""),
            llm_api_key=raw.get("llm_api_key", ""),
            llm_model=raw.get("llm_model", ""),
            llm_base_url=raw.get("llm_base_url", ""),
            llm_timeout=raw.get("llm_timeout", 30),
            llm_max_retries=raw.get("llm_max_retries", 3),
            scan_prompts=raw.get("scan_prompts", False),
            scan_resources=raw.get("scan_resources", False),
            scan_instructions=raw.get("scan_instructions", False),
        )
    return MCPScannerConfig()


def _merge_gateway_watcher(raw: dict[str, Any] | None) -> GatewayWatcherConfig:
    if not raw:
        return GatewayWatcherConfig()
    skill_raw = raw.get("skill", {})
    return GatewayWatcherConfig(
        enabled=raw.get("enabled", False),
        skill=GatewayWatcherSkillConfig(
            enabled=skill_raw.get("enabled", True),
            take_action=skill_raw.get("take_action", True),
            dirs=skill_raw.get("dirs", []),
        ),
    )


def load() -> Config:
    """Load config from ~/.defenseclaw/config.yaml, applying defaults."""
    data_dir = str(default_data_path())
    cfg_file = os.path.join(data_dir, CONFIG_FILE_NAME)

    raw: dict[str, Any] = {}
    try:
        with open(cfg_file) as f:
            raw = yaml.safe_load(f) or {}
    except OSError:
        pass

    scanners_raw = raw.get("scanners", {})
    ss_raw = scanners_raw.get("skill_scanner", {})
    gw_raw = raw.get("gateway", {})
    splunk_raw = raw.get("splunk", {})

    return Config(
        data_dir=raw.get("data_dir", data_dir),
        audit_db=raw.get("audit_db", os.path.join(data_dir, AUDIT_DB_NAME)),
        quarantine_dir=raw.get("quarantine_dir", os.path.join(data_dir, "quarantine")),
        plugin_dir=raw.get("plugin_dir", os.path.join(data_dir, "plugins")),
        policy_dir=raw.get("policy_dir", os.path.join(data_dir, "policies")),
        environment=raw.get("environment", detect_environment()),
        claw=ClawConfig(
            mode=raw.get("claw", {}).get("mode", "openclaw"),
            home_dir=raw.get("claw", {}).get("home_dir", "~/.openclaw"),
            config_file=raw.get("claw", {}).get("config_file", "~/.openclaw/openclaw.json"),
        ),
        scanners=ScannersConfig(
            skill_scanner=SkillScannerConfig(
                binary=ss_raw.get("binary", "skill-scanner"),
                use_llm=ss_raw.get("use_llm", False),
                use_behavioral=ss_raw.get("use_behavioral", False),
                enable_meta=ss_raw.get("enable_meta", False),
                use_trigger=ss_raw.get("use_trigger", False),
                use_virustotal=ss_raw.get("use_virustotal", False),
                use_aidefense=ss_raw.get("use_aidefense", False),
                llm_provider=ss_raw.get("llm_provider", ""),
                llm_model=ss_raw.get("llm_model", ""),
                llm_consensus_runs=ss_raw.get("llm_consensus_runs", 0),
                policy=ss_raw.get("policy", ""),
                lenient=ss_raw.get("lenient", False),
                llm_api_key=ss_raw.get("llm_api_key", ""),
                virustotal_api_key=ss_raw.get("virustotal_api_key", ""),
                aidefense_api_key=ss_raw.get("aidefense_api_key", ""),
            ),
            mcp_scanner=_merge_mcp_scanner(scanners_raw.get("mcp_scanner")),
            codeguard=scanners_raw.get("codeguard", os.path.join(data_dir, "codeguard-rules")),
        ),
        openshell=OpenShellConfig(
            binary=raw.get("openshell", {}).get("binary", "openshell"),
            policy_dir=raw.get("openshell", {}).get("policy_dir", "/etc/openshell/policies"),
        ),
        watch=WatchConfig(
            debounce_ms=raw.get("watch", {}).get("debounce_ms", 500),
            auto_block=raw.get("watch", {}).get("auto_block", True),
        ),
        firewall=FirewallConfig(
            config_file=raw.get("firewall", {}).get("config_file", os.path.join(data_dir, "firewall.yaml")),
            rules_file=raw.get("firewall", {}).get("rules_file", os.path.join(data_dir, "firewall.pf.conf")),
            anchor_name=raw.get("firewall", {}).get("anchor_name", "com.defenseclaw"),
        ),
        guardrail=_merge_guardrail(raw.get("guardrail"), data_dir),
        splunk=SplunkConfig(
            hec_endpoint=splunk_raw.get("hec_endpoint", "https://localhost:8088/services/collector/event"),
            hec_token=splunk_raw.get("hec_token", ""),
            index=splunk_raw.get("index", "defenseclaw"),
            source=splunk_raw.get("source", "defenseclaw"),
            sourcetype=splunk_raw.get("sourcetype", "_json"),
            verify_tls=splunk_raw.get("verify_tls", False),
            enabled=splunk_raw.get("enabled", False),
            batch_size=splunk_raw.get("batch_size", 50),
            flush_interval_s=splunk_raw.get("flush_interval_s", 5),
        ),
        gateway=GatewayConfig(
            host=gw_raw.get("host", "127.0.0.1"),
            port=gw_raw.get("port", 18789),
            token=gw_raw.get("token", ""),
            device_key_file=gw_raw.get("device_key_file", os.path.join(data_dir, "device.key")),
            auto_approve_safe=gw_raw.get("auto_approve_safe", False),
            reconnect_ms=gw_raw.get("reconnect_ms", 800),
            max_reconnect_ms=gw_raw.get("max_reconnect_ms", 15000),
            approval_timeout_s=gw_raw.get("approval_timeout_s", 30),
            api_port=gw_raw.get("api_port", 18790),
            watcher=_merge_gateway_watcher(gw_raw.get("watcher")),
        ),
        skill_actions=_merge_skill_actions(raw.get("skill_actions")),
        mcp_actions=_merge_mcp_actions(raw.get("mcp_actions")),
    )


def default_config() -> Config:
    """Return a Config with all defaults applied (mirrors DefaultConfig in Go)."""
    data_dir = str(default_data_path())
    return Config(
        data_dir=data_dir,
        audit_db=os.path.join(data_dir, AUDIT_DB_NAME),
        quarantine_dir=os.path.join(data_dir, "quarantine"),
        plugin_dir=os.path.join(data_dir, "plugins"),
        policy_dir=os.path.join(data_dir, "policies"),
        environment=detect_environment(),
        scanners=ScannersConfig(
            codeguard=os.path.join(data_dir, "codeguard-rules"),
        ),
        firewall=FirewallConfig(
            config_file=os.path.join(data_dir, "firewall.yaml"),
            rules_file=os.path.join(data_dir, "firewall.pf.conf"),
        ),
        guardrail=GuardrailConfig(
            guardrail_dir=data_dir,
            litellm_config=os.path.join(data_dir, "litellm_config.yaml"),
        ),
        gateway=GatewayConfig(
            device_key_file=os.path.join(data_dir, "device.key"),
        ),
    )
