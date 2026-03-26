"""
CENTINELA – Configuration loader.

Reads centinela.yml (global) and per-project YAML files from
config/projects/*.yml, returns a fully populated GlobalConfig.
"""
import os
import logging
from pathlib import Path
from typing import Any, Dict, Optional, List, Tuple

import yaml

from .models import (
    GlobalConfig,
    ProjectConfig,
    SmtpConfig,
    AlertChannels,
    DeploymentWindow,
    NetworkThresholds,
)

logger = logging.getLogger("centinela.config")

# Where the panel persists runtime-safe overrides.
# This lives under /app/data (writable volume).
_DEFAULT_OVERRIDES_PATH = "/app/data/config_overrides.yml"


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _get(d: dict, *keys, default=None):
    """Safe nested dict access."""
    for k in keys:
        if not isinstance(d, dict):
            return default
        d = d.get(k, default)
    return d


def _load_smtp(raw: Dict) -> SmtpConfig:
    smtp_raw = raw.get("smtp", {})
    return SmtpConfig(
        host=smtp_raw.get("host", "localhost"),
        port=int(smtp_raw.get("port", 587)),
        user=smtp_raw.get("user", ""),
        password=smtp_raw.get("password", ""),
        from_addr=smtp_raw.get("from", "centinela@localhost"),
        use_tls=smtp_raw.get("tls", True),
        use_ssl=smtp_raw.get("ssl", False),
    )


def _load_alert_channels(raw: Dict) -> AlertChannels:
    alerts_raw = raw.get("alerts", {})
    return AlertChannels(
        emails=alerts_raw.get("emails", []),
        webhook_url=alerts_raw.get("webhook_url"),
        whatsapp_webhook=alerts_raw.get("whatsapp_webhook"),
        min_severity=alerts_raw.get("min_severity", "medium"),
    )


def _load_deployment_windows(raw: Dict) -> list:
    windows = []
    for w in raw.get("deployment_windows", []):
        windows.append(DeploymentWindow(
            start=w.get("start", "02:00"),
            end=w.get("end", "06:00"),
            days=w.get("days", [
                "monday", "tuesday", "wednesday",
                "thursday", "friday", "saturday", "sunday"
            ]),
        ))
    return windows


def _load_network_thresholds(raw: Dict) -> NetworkThresholds:
    net = raw.get("network", {})
    return NetworkThresholds(
        bytes_per_minute_warning=net.get("bytes_per_minute_warning", 52_428_800),
        bytes_per_minute_critical=net.get("bytes_per_minute_critical", 209_715_200),
        spike_multiplier=float(net.get("spike_multiplier", 5.0)),
        baseline_window_hours=int(net.get("baseline_window_hours", 168)),
        new_destination_alert=net.get("new_destination_alert", True),
        learning_period_hours=int(net.get("learning_period_hours", 72)),
    )


def _load_alert_channels_from_alert_obj(alerts_raw: Dict) -> AlertChannels:
    """Load AlertChannels from an `alerts:` dict."""
    return AlertChannels(
        emails=alerts_raw.get("emails", []),
        webhook_url=alerts_raw.get("webhook_url"),
        whatsapp_webhook=alerts_raw.get("whatsapp_webhook"),
        min_severity=alerts_raw.get("min_severity", "medium"),
    )


def _load_project(raw: Dict, source_file: str) -> Optional[ProjectConfig]:
    name = raw.get("name")
    if not name:
        logger.warning("Project in %s has no 'name', skipping.", source_file)
        return None

    project_type = raw.get("type", "generic").lower()
    if project_type not in ("wordpress", "laravel", "generic"):
        logger.warning("Unknown project type '%s' in %s, defaulting to generic.",
                       project_type, source_file)
        project_type = "generic"

    return ProjectConfig(
        name=name,
        project_type=project_type,
        container_name=raw.get("container_name"),
        container_label=raw.get("container_label"),
        container_name_prefix=raw.get("container_name_prefix"),
        app_root_in_container=raw.get("app_root", "/var/www/html"),
        custom_critical_paths=raw.get("critical_paths", []),
        exclude_paths=raw.get("exclude_paths", []),
        alerts=_load_alert_channels(raw),
        deployment_windows=_load_deployment_windows(raw),
        network=_load_network_thresholds(raw),
        extra_suspicious_processes=raw.get("extra_suspicious_processes", []),
        monitor_filesystem=raw.get("monitor_filesystem", True),
        monitor_processes=raw.get("monitor_processes", True),
        monitor_network=raw.get("monitor_network", True),
        monitor_docker_events=raw.get("monitor_docker_events", True),
        enabled=raw.get("enabled", True),
    )


def _apply_overrides(cfg: GlobalConfig, overrides_raw: Dict[str, Any]) -> None:
    """
    Apply persisted overrides to the already-loaded GlobalConfig.

    Supported override schema (best-effort, defensive):
    - global: { storage?, smtp?, monitoring?, alert_cooldown?, default_alerts? }
    - projects: either a list of {name: "...", ...fields...} or a dict
                 { "<name>": { ...fields... }, ... }
    """
    # --- Global overrides ---
    global_raw = overrides_raw.get("global", {}) if isinstance(overrides_raw, dict) else {}
    if not isinstance(global_raw, dict):
        global_raw = {}

    storage_raw = global_raw.get("storage", {})
    if isinstance(storage_raw, dict):
        if storage_raw.get("db_url"):
            cfg.db_url = storage_raw["db_url"]
        if storage_raw.get("log_dir"):
            cfg.log_dir = storage_raw["log_dir"]

    if isinstance(global_raw.get("smtp"), dict):
        cfg.smtp = _load_smtp(global_raw["smtp"])

    monitoring_raw = global_raw.get("monitoring", {})
    if isinstance(monitoring_raw, dict):
        if "network_sample_interval" in monitoring_raw:
            cfg.network_sample_interval = int(monitoring_raw["network_sample_interval"])
        if "process_check_interval" in monitoring_raw:
            cfg.process_check_interval = int(monitoring_raw["process_check_interval"])
        if "security_audit_interval" in monitoring_raw:
            cfg.security_audit_interval = int(monitoring_raw["security_audit_interval"])
        if "fs_permission_check_interval" in monitoring_raw:
            cfg.fs_permission_check_interval = int(monitoring_raw["fs_permission_check_interval"])

    alert_cooldown_raw = global_raw.get("alert_cooldown", {})
    if isinstance(alert_cooldown_raw, dict):
        for k, v in alert_cooldown_raw.items():
            try:
                cfg.alert_cooldown[str(k)] = int(v)
            except Exception:
                continue

    default_alerts_raw = global_raw.get("default_alerts", {})
    if isinstance(default_alerts_raw, dict):
        # Preserve existing defaults if override omits fields.
        if "emails" in default_alerts_raw and isinstance(default_alerts_raw["emails"], list):
            cfg.default_emails = list(default_alerts_raw["emails"])
        if "webhook_url" in default_alerts_raw:
            cfg.default_webhook_url = default_alerts_raw.get("webhook_url")
        if "whatsapp_webhook" in default_alerts_raw:
            cfg.default_whatsapp_webhook = default_alerts_raw.get("whatsapp_webhook")

    # --- Per-project overrides ---
    projects_raw = overrides_raw.get("projects", []) if isinstance(overrides_raw, dict) else []
    project_items: List[Tuple[str, Dict[str, Any]]] = []

    if isinstance(projects_raw, dict):
        for name, pdata in projects_raw.items():
            if not isinstance(pdata, dict):
                continue
            project_items.append((str(name), pdata))
    elif isinstance(projects_raw, list):
        for item in projects_raw:
            if not isinstance(item, dict):
                continue
            name = item.get("name")
            if not name:
                continue
            pdata = dict(item)
            pdata.pop("name", None)
            project_items.append((str(name), pdata))

    if not project_items:
        return

    # Index projects by name for fast lookup
    by_name: Dict[str, ProjectConfig] = {p.name: p for p in cfg.projects}

    for name, pdata in project_items:
        project = by_name.get(name)
        if project is None:
            continue

        # Simple fields
        for field_name in (
            "container_name",
            "container_label",
            "container_name_prefix",
            "app_root_in_container",
            "enabled",
            "monitor_filesystem",
            "monitor_processes",
            "monitor_network",
            "monitor_docker_events",
        ):
            if field_name in pdata:
                setattr(project, field_name, pdata[field_name])

        # Synonyms
        if "app_root" in pdata:
            project.app_root_in_container = str(pdata["app_root"])

        if "critical_paths" in pdata:
            project.custom_critical_paths = list(pdata.get("critical_paths") or [])

        if "custom_critical_paths" in pdata:
            project.custom_critical_paths = list(pdata.get("custom_critical_paths") or [])

        if "exclude_paths" in pdata:
            project.exclude_paths = list(pdata.get("exclude_paths") or [])

        if "extra_suspicious_processes" in pdata:
            project.extra_suspicious_processes = list(pdata.get("extra_suspicious_processes") or [])

        # Nested dataclasses: alerts / network / deployment_windows
        if isinstance(pdata.get("alerts"), dict):
            project.alerts = _load_alert_channels_from_alert_obj(pdata["alerts"])

        if isinstance(pdata.get("network"), dict):
            project.network = _load_network_thresholds({"network": pdata["network"]})

        if isinstance(pdata.get("deployment_windows"), list):
            project.deployment_windows = _load_deployment_windows({"deployment_windows": pdata["deployment_windows"]})


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def load_config(config_path: str = "/app/config/centinela.yml") -> GlobalConfig:
    """
    Load global configuration from centinela.yml and all project files
    found in the same directory's projects/ subdirectory.
    """
    config_file = Path(config_path)
    if not config_file.exists():
        logger.warning("Config file %s not found, using defaults.", config_path)
        raw_global: Dict[str, Any] = {}
    else:
        with config_file.open("r") as f:
            raw_global = yaml.safe_load(f) or {}

    storage = raw_global.get("storage", {})
    monitoring = raw_global.get("monitoring", {})
    cooldown_raw = raw_global.get("alert_cooldown", {})

    default_cooldown = {
        "DOCKER_EVENT_EXEC":    120,
        "DOCKER_EVENT_RESTART": 300,
        "DOCKER_EVENT_STOP":    60,
        "PROCESS_SUSPICIOUS":   120,
        "NETWORK_SPIKE":        300,
        "NETWORK_NEW_DEST":     3600,
        "FILESYSTEM_CHANGE":    600,
        "FILESYSTEM_PHP_UPLOAD": 60,
        "SECURITY_AUDIT":       86400,
        "default":              300,
    }
    default_cooldown.update(cooldown_raw)

    cfg = GlobalConfig(
        smtp=_load_smtp(raw_global),
        db_url=storage.get("db_url", "sqlite:////app/data/centinela.db"),
        log_dir=storage.get("log_dir", "/app/logs"),
        host_root=raw_global.get("host_root", "/host"),
        network_sample_interval=monitoring.get("network_sample_interval", 300),
        process_check_interval=monitoring.get("process_check_interval", 60),
        security_audit_interval=monitoring.get("security_audit_interval", 3600),
        fs_permission_check_interval=monitoring.get("fs_permission_check_interval", 1800),
        alert_cooldown=default_cooldown,
        default_emails=_get(raw_global, "default_alerts", "emails", default=[]),
        default_webhook_url=_get(raw_global, "default_alerts", "webhook_url"),
        default_whatsapp_webhook=_get(raw_global, "default_alerts", "whatsapp_webhook"),
    )

    # Load per-project files
    projects_dir = config_file.parent / "projects"
    inline_projects = raw_global.get("projects", [])

    # Inline projects from centinela.yml
    for p_raw in inline_projects:
        project = _load_project(p_raw, str(config_file))
        if project:
            cfg.projects.append(project)

    # External project files
    if projects_dir.exists():
        for yml_file in sorted(projects_dir.glob("*.yml")):
            try:
                with yml_file.open("r") as f:
                    p_raw = yaml.safe_load(f) or {}
                project = _load_project(p_raw, str(yml_file))
                if project:
                    cfg.projects.append(project)
            except Exception as exc:
                logger.error("Failed to load project file %s: %s", yml_file, exc)

    # Apply persisted overrides (panel config). This is applied at startup.
    overrides_path = os.environ.get("CENTINELA_OVERRIDES_PATH", _DEFAULT_OVERRIDES_PATH)
    overrides_file = Path(overrides_path)
    if overrides_file.exists():
        try:
            with overrides_file.open("r", encoding="utf-8") as f:
                raw_overrides = yaml.safe_load(f) or {}
            if isinstance(raw_overrides, dict):
                _apply_overrides(cfg, raw_overrides)
                logger.info("Config overrides applied from %s.", overrides_path)
            else:
                logger.warning("Overrides file %s is not a YAML dict, ignoring.", overrides_path)
        except Exception as exc:
            logger.error("Failed to load config overrides from %s: %s", overrides_path, exc)

    enabled = [p for p in cfg.projects if p.enabled]
    logger.info("Configuration loaded: %d projects (%d enabled).",
                len(cfg.projects), len(enabled))
    return cfg


class ProjectRegistry:
    """
    Maps running containers to their ProjectConfig at O(1) lookup.
    Called on every Docker event so must be fast.
    """

    def __init__(self, projects: list):
        self._by_name: Dict[str, ProjectConfig] = {}
        self._by_label_kv: Dict[str, ProjectConfig] = {}   # "key=value" -> project
        self._by_prefix: list = []                          # (prefix, project)

        for project in projects:
            if not project.enabled:
                continue
            if project.container_name:
                self._by_name[project.container_name] = project
            if project.container_label:
                self._by_label_kv[project.container_label] = project
            if project.container_name_prefix:
                self._by_prefix.append((project.container_name_prefix, project))

    def get(self, container_name: str,
            labels: Optional[Dict[str, str]] = None) -> Optional[ProjectConfig]:
        """
        Return the ProjectConfig matching this container, or None if unmonitored.
        """
        # 1. Exact name match
        if container_name in self._by_name:
            return self._by_name[container_name]

        # 2. Label match ("key=value")
        if labels:
            for key, value in labels.items():
                kv = f"{key}={value}"
                if kv in self._by_label_kv:
                    return self._by_label_kv[kv]

        # 3. Prefix match
        for prefix, project in self._by_prefix:
            if container_name.startswith(prefix):
                return project

        return None

    def all_projects(self) -> list:
        seen = set()
        result = []
        for p in self._by_name.values():
            if id(p) not in seen:
                seen.add(id(p))
                result.append(p)
        for p in self._by_label_kv.values():
            if id(p) not in seen:
                seen.add(id(p))
                result.append(p)
        for _, p in self._by_prefix:
            if id(p) not in seen:
                seen.add(id(p))
                result.append(p)
        return result
