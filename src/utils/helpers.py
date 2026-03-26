"""
CENTINELA – Utility helpers.
"""
import hashlib
import json
import logging
import os
import re
import socket
import struct
from datetime import datetime, time, timezone
from pathlib import Path
from typing import Optional

logger = logging.getLogger("centinela.utils")


# ---------------------------------------------------------------------------
# Time helpers
# ---------------------------------------------------------------------------

def now_utc() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


def in_deployment_window(windows: list) -> bool:
    """
    Return True if the current local time falls inside any deployment window.
    """
    if not windows:
        return False
    now = datetime.now()
    day_name = now.strftime("%A").lower()
    current_time = now.time()

    for window in windows:
        if day_name not in [d.lower() for d in window.days]:
            continue
        try:
            start = time.fromisoformat(window.start)
            end = time.fromisoformat(window.end)
        except ValueError:
            continue
        # Handle windows crossing midnight
        if start <= end:
            if start <= current_time <= end:
                return True
        else:
            if current_time >= start or current_time <= end:
                return True
    return False


# ---------------------------------------------------------------------------
# File / hash helpers
# ---------------------------------------------------------------------------

def sha256_file(path: str, max_bytes: int = 10 * 1024 * 1024) -> Optional[str]:
    """
    Compute SHA-256 of a file.
    Caps at max_bytes to avoid blocking on huge files.
    Returns None on any error.
    """
    try:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            remaining = max_bytes
            while remaining > 0:
                chunk = f.read(min(65536, remaining))
                if not chunk:
                    break
                h.update(chunk)
                remaining -= len(chunk)
        return h.hexdigest()
    except OSError:
        return None


def file_stat(path: str) -> dict:
    """Return dict with mtime, size, permissions, owner (or empty dict on error)."""
    try:
        st = os.stat(path)
        return {
            "mtime": str(st.st_mtime),
            "size": st.st_size,
            "permissions": oct(st.st_mode),
            "uid": st.st_uid,
            "gid": st.st_gid,
        }
    except OSError:
        return {}


def has_suspicious_extension(filename: str,
                              forbidden: list = None) -> bool:
    from config.models import FORBIDDEN_UPLOAD_EXTENSIONS
    check = forbidden or FORBIDDEN_UPLOAD_EXTENSIONS
    lower = filename.lower()
    return any(lower.endswith(ext) for ext in check)


# ---------------------------------------------------------------------------
# Network helpers
# ---------------------------------------------------------------------------

def hex_to_ip(hex_str: str) -> str:
    """Convert little-endian hex IP (from /proc/net/tcp) to dotted notation."""
    try:
        packed = bytes.fromhex(hex_str)
        # Linux /proc/net/tcp is little-endian
        addr = struct.unpack("<I", packed)[0]
        return socket.inet_ntoa(struct.pack(">I", addr))
    except Exception:
        return hex_str


def hex_to_port(hex_str: str) -> int:
    """Convert hex port string to integer."""
    try:
        return int(hex_str, 16)
    except ValueError:
        return 0


def parse_proc_net_tcp(content: str) -> list:
    """
    Parse /proc/net/tcp (or tcp6) content.
    Returns list of dicts: {local_ip, local_port, remote_ip, remote_port, state}
    State 0A = LISTEN, 01 = ESTABLISHED.
    Only returns ESTABLISHED connections.
    """
    connections = []
    for line in content.splitlines()[1:]:  # skip header
        parts = line.split()
        if len(parts) < 4:
            continue
        state = parts[3]
        if state != "01":  # 01 = ESTABLISHED
            continue
        local = parts[1].split(":")
        remote = parts[2].split(":")
        if len(local) != 2 or len(remote) != 2:
            continue
        remote_ip = hex_to_ip(remote[0])
        if remote_ip in ("0.0.0.0", "127.0.0.1"):
            continue  # skip loopback / unconnected
        connections.append({
            "local_ip": hex_to_ip(local[0]),
            "local_port": hex_to_port(local[1]),
            "remote_ip": remote_ip,
            "remote_port": hex_to_port(remote[1]),
        })
    return connections


# ---------------------------------------------------------------------------
# Docker helpers
# ---------------------------------------------------------------------------

def container_short_id(container_id: str) -> str:
    return container_id[:12] if container_id else "unknown"


def safe_json(obj) -> str:
    """Serialize to JSON, replacing un-serialisable objects with str()."""
    def default(o):
        return str(o)
    return json.dumps(obj, default=default, ensure_ascii=False)


def build_dedup_key(*parts) -> str:
    return ":".join(str(p) for p in parts)


# ---------------------------------------------------------------------------
# Process helpers
# ---------------------------------------------------------------------------

def parse_docker_top(output: str) -> list:
    """
    Parse output of `docker top <container> aux`.
    Returns list of dicts with process info.
    """
    lines = output.strip().splitlines()
    if not lines:
        return []
    header = lines[0].split()
    processes = []
    for line in lines[1:]:
        parts = line.split(None, len(header) - 1)
        if len(parts) < len(header):
            continue
        proc = dict(zip(header, parts))
        processes.append(proc)
    return processes


def _cmd_matches_pattern(cmd_lower: str, cmd_base: str, pattern: str) -> bool:
    """
    Return True if cmd matches the pattern using word-boundary checks.
    Avoids false positives like 'nc' matching 'launcher'.
    """
    import re
    p = pattern.lower()
    # Exact base-name match is always safe
    if cmd_base == p:
        return True
    # Substring match only when surrounded by word boundaries
    # (space, slash, start, end, or common delimiters)
    return bool(re.search(r'(?<![a-z0-9_])' + re.escape(p) + r'(?![a-z0-9_])', cmd_lower))


def is_suspicious_process(cmd: str, always_list: list,
                           context_list: list, extra: list = None) -> tuple:
    """
    Check if a command string is suspicious.
    Returns (is_suspicious, severity, matched_pattern).
    """
    cmd_lower = cmd.lower().strip()
    cmd_base = cmd_lower.split()[0].split("/")[-1] if cmd_lower else ""

    # Always suspicious regardless of context
    for pattern in (always_list + (extra or [])):
        if _cmd_matches_pattern(cmd_lower, cmd_base, pattern):
            return True, "high", pattern

    # Context-suspicious (medium severity)
    for pattern in context_list:
        if cmd_base == pattern.lower():
            return True, "medium", pattern

    return False, "", ""


def looks_like_healthcheck_command(cmd: str) -> bool:
    """
    Return True when a command appears to be a liveness/readiness/healthcheck.

    This intentionally includes common orchestrator and Coolify probe patterns
    to reduce false positives from benign periodic checks.
    """
    if not cmd:
        return False

    cmd_norm = " ".join(str(cmd).strip().lower().split())
    if not cmd_norm:
        return False

    simple_markers = (
        "healthcheck",
        "health check",
        "readiness",
        "liveness",
        "startup probe",
        "pg_isready",
        "mysqladmin ping",
        "--innodb_initialized",
        "redis-cli ping",
        "curl -f http://localhost",
        "curl -fs http://localhost",
        "wget --spider",
        "php artisan route:list",
        "php artisan about",
    )
    if any(marker in cmd_norm for marker in simple_markers):
        return True

    # Generic path probes such as /health, /healthz, /ready, /live.
    if re.search(r"(^|[\s\"'])/(health|healthz|ready|readiness|live|liveness)([\s\"'/?]|$)", cmd_norm):
        return True

    return False
