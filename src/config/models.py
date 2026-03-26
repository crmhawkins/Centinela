"""
Configuration data models for CENTINELA.
Uses dataclasses to avoid Pydantic dependency.
"""
from dataclasses import dataclass, field
from typing import List, Optional, Dict


# ---------------------------------------------------------------------------
# Profiles: built-in path/rule sets per application type
# ---------------------------------------------------------------------------

WORDPRESS_CRITICAL_PATHS = [
    "wp-config.php",
    ".htaccess",
    "index.php",
    "wp-login.php",
    "wp-content/uploads",
    "wp-content/plugins",
    "wp-content/themes",
]

LARAVEL_CRITICAL_PATHS = [
    ".env",
    "bootstrap/cache",
    "storage",
    "storage/logs",
    "config",
    "public/index.php",
]

# Processes that are always suspicious inside web app containers
ALWAYS_SUSPICIOUS_PROCESSES = [
    "nmap", "masscan", "nikto", "sqlmap",
    "tcpdump", "tshark", "wireshark",
    "msfconsole", "metasploit",
    "nc", "netcat", "ncat",
    "socat",
]

# Processes suspicious only in certain contexts (exec-triggered or unexpected)
CONTEXT_SUSPICIOUS_PROCESSES = [
    "bash", "sh", "dash", "zsh", "ksh",
    "curl", "wget", "fetch",
    "python", "python2", "python3",
    "perl", "ruby",
    "gcc", "make", "cc",
    "base64",
    "xterm", "xorg",
]

# PHP execution patterns that are suspicious
SUSPICIOUS_PHP_PATTERNS = [
    "php -r",
    "php://input",
    "eval(",
    "system(",
    "exec(",
    "passthru(",
    "shell_exec(",
    "base64_decode(",
]

# PHP file extensions that should NOT appear in upload directories
FORBIDDEN_UPLOAD_EXTENSIONS = [
    ".php", ".php3", ".php4", ".php5", ".phtml", ".phar",
    ".asp", ".aspx", ".jsp", ".cgi", ".pl",
    ".sh", ".bash", ".py", ".rb",
    ".htaccess",
]


@dataclass
class DeploymentWindow:
    """Time window during which file changes are expected (deployments)."""
    start: str = "02:00"   # HH:MM 24h
    end: str = "06:00"     # HH:MM 24h
    days: List[str] = field(default_factory=lambda: [
        "monday", "tuesday", "wednesday",
        "thursday", "friday", "saturday", "sunday"
    ])


@dataclass
class NetworkThresholds:
    """Per-container network anomaly detection thresholds."""
    bytes_per_minute_warning: int = 52_428_800    # 50 MB/min
    bytes_per_minute_critical: int = 209_715_200  # 200 MB/min
    spike_multiplier: float = 5.0                 # alert if > N * rolling_avg
    baseline_window_hours: int = 168              # 7 days for baseline
    new_destination_alert: bool = True
    learning_period_hours: int = 72               # 3 days before alerting new dests


@dataclass
class AlertChannels:
    """Where to send alerts for a project."""
    emails: List[str] = field(default_factory=list)
    webhook_url: Optional[str] = None
    whatsapp_webhook: Optional[str] = None
    min_severity: str = "medium"  # low | medium | high


@dataclass
class ProjectConfig:
    """Full configuration for one monitored project."""
    name: str
    project_type: str  # wordpress | laravel | generic

    # Container identification (at least one required)
    container_name: Optional[str] = None
    container_label: Optional[str] = None   # "key=value" format
    container_name_prefix: Optional[str] = None

    # Paths
    app_root_in_container: str = "/var/www/html"
    custom_critical_paths: List[str] = field(default_factory=list)
    exclude_paths: List[str] = field(default_factory=list)

    # Alerting
    alerts: AlertChannels = field(default_factory=AlertChannels)

    # Deployment windows (changes outside these are suspicious)
    deployment_windows: List[DeploymentWindow] = field(default_factory=list)

    # Network
    network: NetworkThresholds = field(default_factory=NetworkThresholds)

    # Extra suspicious processes specific to this project
    extra_suspicious_processes: List[str] = field(default_factory=list)

    # Commands to never flag as suspicious (health checks, deploy scripts, etc.)
    trusted_exec_patterns: List[str] = field(default_factory=list)
    # Trusted curl/wget destinations (substrings matched against full URL/host)
    trusted_destinations: List[str] = field(default_factory=lambda: [
        "localhost", "127.0.0.1", "::1", "0.0.0.0"
    ])

    # Monitoring switches
    monitor_filesystem: bool = True
    monitor_processes: bool = True
    monitor_network: bool = True
    monitor_docker_events: bool = True

    enabled: bool = True


@dataclass
class SmtpConfig:
    host: str = "localhost"
    port: int = 587
    user: str = ""
    password: str = ""
    from_addr: str = "centinela@localhost"
    use_tls: bool = True
    use_ssl: bool = False


@dataclass
class GlobalConfig:
    smtp: SmtpConfig = field(default_factory=SmtpConfig)

    # Storage
    db_url: str = "sqlite:////app/data/centinela.db"
    log_dir: str = "/app/logs"
    host_root: str = "/host"   # Host filesystem mounted here inside container

    # Polling intervals (seconds)
    network_sample_interval: int = 300     # 5 min
    process_check_interval: int = 60       # 1 min
    security_audit_interval: int = 3600    # 1 hour
    fs_permission_check_interval: int = 1800  # 30 min

    # Alert deduplication cooldowns (seconds per alert type)
    alert_cooldown: Dict[str, int] = field(default_factory=lambda: {
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
    })

    # Global alert channels (fallback if project has no channels configured)
    default_emails: List[str] = field(default_factory=list)
    default_webhook_url: Optional[str] = None
    default_whatsapp_webhook: Optional[str] = None

    projects: List[ProjectConfig] = field(default_factory=list)
