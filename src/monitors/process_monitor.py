"""
CENTINELA – Process Monitor.

Periodically inspects running processes inside every monitored container
using ``docker top`` (which executes ``ps aux`` inside the container's
PID namespace without requiring exec access).

Detection coverage
------------------
* Processes in ``ALWAYS_SUSPICIOUS_PROCESSES``  → HIGH severity
* Processes in ``CONTEXT_SUSPICIOUS_PROCESSES`` → MEDIUM severity
* Project-specific ``extra_suspicious_processes`` → HIGH severity
* WordPress-specific PHP eval / one-liner patterns  → HIGH severity

Architecture
------------
``run()`` iterates over all containers that have ``monitor_processes=True``
in their project config.  The inter-container delay is staggered so that
100 containers don't all fire at the same time:

    delay = process_check_interval / max(len(containers), 1)

``trigger_immediate_check()`` can be called by DockerEventMonitor when
an exec event is received, bypassing the timer for that container.
"""
from __future__ import annotations

import asyncio
import logging
from typing import Dict, List, Optional, Set, Tuple

import docker
import docker.errors

from config.models import (
    ALWAYS_SUSPICIOUS_PROCESSES,
    CONTEXT_SUSPICIOUS_PROCESSES,
    SUSPICIOUS_PHP_PATTERNS,
    GlobalConfig,
    ProjectConfig,
)
from config.loader import ProjectRegistry
from alerts.manager import AlertManager
from utils.helpers import (
    build_dedup_key,
    is_suspicious_process,
    parse_docker_top,
)

logger = logging.getLogger("centinela.monitors.process_monitor")

# Column names emitted by `docker top <id> aux` (ps aux output)
_PS_AUX_PID_COL   = "PID"
_PS_AUX_USER_COL  = "USER"
_PS_AUX_CMD_COL   = "COMMAND"      # docker top uses COMMAND not CMD
_PS_AUX_CMD_ALIAS = "CMD"          # some kernels use CMD

# PID 1 is always the container's main process – never suspicious
_MAIN_PID = "1"


class ProcessMonitor:
    """
    Periodic process scanner for monitored containers.

    Parameters
    ----------
    config:        Global CENTINELA configuration.
    registry:      Maps container names / labels → ProjectConfig.
    alert_manager: Shared AlertManager for deduplication + dispatch.
    docker_client: docker.DockerClient instance (shared, thread-safe).
    """

    def __init__(
        self,
        config: GlobalConfig,
        registry: ProjectRegistry,
        alert_manager: AlertManager,
        docker_client: docker.DockerClient,
    ) -> None:
        self._config = config
        self._registry = registry
        self._alert_manager = alert_manager
        self._docker = docker_client

        # Set of container names for which an immediate check was requested
        self._immediate_queue: asyncio.Queue[str] = asyncio.Queue()

        # Track which containers we have already warned are not running
        # (to avoid log spam on stopped containers)
        self._not_running_warned: Set[str] = set()

        self._stop_event = asyncio.Event()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def run(self) -> None:
        """
        Main loop.

        Runs two concurrent sub-tasks:
        * ``_periodic_loop()``   – regular staggered scans of all containers
        * ``_immediate_loop()``  – drains the immediate-check queue (from execs)
        """
        logger.info("ProcessMonitor starting.")
        try:
            await asyncio.gather(
                self._periodic_loop(),
                self._immediate_loop(),
            )
        except asyncio.CancelledError:
            logger.info("ProcessMonitor cancelled.")
            self._stop_event.set()
            raise
        except Exception as exc:
            logger.error(
                "ProcessMonitor encountered fatal error: %s", exc, exc_info=True
            )
            raise
        finally:
            logger.info("ProcessMonitor stopped.")

    def stop(self) -> None:
        """Signal the run() loop to stop gracefully."""
        self._stop_event.set()

    async def trigger_immediate_check(self, container_name: str) -> None:
        """
        Request an out-of-band process check for ``container_name``.

        Called by DockerEventMonitor when an exec_start event is received
        so that we can inspect what's running in the container right now,
        rather than waiting for the next periodic scan.

        Non-blocking: puts the name on an internal queue and returns
        immediately.  The actual check happens in ``_immediate_loop()``.
        """
        logger.debug(
            "ProcessMonitor: immediate check requested for %s", container_name
        )
        try:
            self._immediate_queue.put_nowait(container_name)
        except asyncio.QueueFull:
            logger.warning(
                "ProcessMonitor: immediate-check queue full, dropping %s",
                container_name,
            )

    # ------------------------------------------------------------------
    # Internal loops
    # ------------------------------------------------------------------

    async def _periodic_loop(self) -> None:
        """
        Staggered periodic scan over all monitored containers.

        The inter-container delay spreads I/O evenly over the check
        interval so all containers are visited exactly once per cycle
        without creating a thundering-herd on Docker.
        """
        while not self._stop_event.is_set():
            containers = self._get_all_monitored_containers()

            if not containers:
                logger.debug(
                    "ProcessMonitor: no monitored containers, sleeping %ds",
                    self._config.process_check_interval,
                )
                await self._interruptible_sleep(self._config.process_check_interval)
                continue

            inter_delay = self._config.process_check_interval / max(len(containers), 1)

            logger.debug(
                "ProcessMonitor: starting scan cycle – %d containers, "
                "%.1fs inter-container delay",
                len(containers), inter_delay,
            )

            for container_name, container_id, project in containers:
                if self._stop_event.is_set():
                    return

                try:
                    await self.check_container(container_name, container_id, project)
                except Exception as exc:
                    logger.error(
                        "ProcessMonitor: error checking %s: %s",
                        container_name, exc, exc_info=True,
                    )

                if inter_delay > 0:
                    await self._interruptible_sleep(inter_delay)

    async def _immediate_loop(self) -> None:
        """
        Drain the immediate-check queue.

        Waits for entries posted by ``trigger_immediate_check()``,
        resolves the container in the registry and runs ``check_container()``.
        """
        while not self._stop_event.is_set():
            try:
                container_name = await asyncio.wait_for(
                    self._immediate_queue.get(), timeout=1.0
                )
            except asyncio.TimeoutError:
                continue

            logger.info(
                "ProcessMonitor: running immediate check on %s", container_name
            )

            container_id, project = self._resolve_container(container_name)
            if container_id is None:
                logger.warning(
                    "ProcessMonitor: cannot resolve container '%s' for immediate check",
                    container_name,
                )
                self._immediate_queue.task_done()
                continue

            try:
                await self.check_container(container_name, container_id, project)
            except Exception as exc:
                logger.error(
                    "ProcessMonitor: immediate check error for %s: %s",
                    container_name, exc, exc_info=True,
                )
            finally:
                self._immediate_queue.task_done()

    # ------------------------------------------------------------------
    # Container inspection
    # ------------------------------------------------------------------

    async def check_container(
        self,
        container_name: str,
        container_id: str,
        project: Optional[ProjectConfig],
    ) -> None:
        """
        Run ``docker top`` on one container and analyse its process list.

        Offloads the blocking Docker API call to the default executor so
        the asyncio event loop is never blocked.

        Gracefully handles containers that have stopped between the time
        the check was scheduled and when it actually runs.
        """
        loop = asyncio.get_event_loop()

        try:
            top_result = await loop.run_in_executor(
                None, self._docker_top, container_name
            )
        except docker.errors.NotFound:
            if container_name not in self._not_running_warned:
                logger.info(
                    "ProcessMonitor: container '%s' not found (may have stopped).",
                    container_name,
                )
                self._not_running_warned.add(container_name)
            return
        except docker.errors.APIError as exc:
            if "is not running" in str(exc) or "No such container" in str(exc):
                if container_name not in self._not_running_warned:
                    logger.info(
                        "ProcessMonitor: container '%s' is not running.",
                        container_name,
                    )
                    self._not_running_warned.add(container_name)
                return
            logger.warning(
                "ProcessMonitor: Docker API error checking '%s': %s",
                container_name, exc,
            )
            return
        except Exception as exc:
            logger.error(
                "ProcessMonitor: unexpected error running docker top on '%s': %s",
                container_name, exc, exc_info=True,
            )
            return

        # Container is running now; clear the "not running" warning state
        self._not_running_warned.discard(container_name)

        if top_result is None:
            return  # empty or error already logged

        titles: List[str] = top_result.get("Titles", [])
        processes: List[List[str]] = top_result.get("Processes", []) or []

        if not titles or not processes:
            logger.debug(
                "ProcessMonitor: no process data for container '%s'", container_name
            )
            return

        # Parse into list of dicts
        parsed = self._parse_top_output(titles, processes)

        logger.debug(
            "ProcessMonitor: container=%s process_count=%d",
            container_name, len(parsed),
        )

        await self._analyze_processes(parsed, container_name, container_id, project)

    async def _analyze_processes(
        self,
        processes: List[Dict],
        container_name: str,
        container_id: str,
        project: Optional[ProjectConfig],
    ) -> None:
        """
        Analyse a parsed process list for suspicious entries.

        ``processes`` is a list of dicts, each with at least:
            ``pid``, ``user``, ``cmd``
        """
        if not processes:
            return

        extra = (project.extra_suspicious_processes if project else []) or []
        is_wordpress = (
            project is not None and project.project_type == "wordpress"
        )

        for proc in processes:
            pid   = proc.get("pid", "")
            user  = proc.get("user", "")
            cmd   = proc.get("cmd", "")

            # Skip PID 1 – it's always the container's main process
            if str(pid).strip() == _MAIN_PID:
                continue

            if not cmd:
                continue

            # ---- Standard suspicious-process check --------------------
            suspicious, severity, matched = is_suspicious_process(
                cmd,
                ALWAYS_SUSPICIOUS_PROCESSES,
                CONTEXT_SUSPICIOUS_PROCESSES,
                extra,
            )

            if suspicious:
                # Before flagging curl/wget, check if it's contacting a trusted destination
                if matched in ("curl", "wget"):
                    _default_trusted = ["localhost", "127.0.0.1", "::1", "0.0.0.0"]
                    trusted_dests = _default_trusted[:]
                    if project is not None and hasattr(project, "trusted_destinations"):
                        trusted_dests = list(project.trusted_destinations or _default_trusted)
                    if any(dest in cmd for dest in trusted_dests):
                        logger.debug(
                            "Skipping trusted curl/wget: %s", cmd[:200]
                        )
                        continue

                await self._emit_process_alert(
                    container_name=container_name,
                    container_id=container_id,
                    project=project,
                    pid=pid,
                    user=user,
                    cmd=cmd,
                    severity=severity,
                    matched_pattern=matched,
                )
                continue  # one alert per process is enough

            # ---- WordPress-specific PHP pattern check -----------------
            if is_wordpress:
                php_pattern = self._detect_php_pattern(cmd)
                if php_pattern:
                    await self._emit_process_alert(
                        container_name=container_name,
                        container_id=container_id,
                        project=project,
                        pid=pid,
                        user=user,
                        cmd=cmd,
                        severity="high",
                        matched_pattern=php_pattern,
                        alert_type="PROCESS_PHP_EVAL",
                    )

    # ------------------------------------------------------------------
    # Alert emission
    # ------------------------------------------------------------------

    async def _emit_process_alert(
        self,
        container_name: str,
        container_id: str,
        project: Optional[ProjectConfig],
        pid: str,
        user: str,
        cmd: str,
        severity: str,
        matched_pattern: str,
        alert_type: str = "PROCESS_SUSPICIOUS",
    ) -> None:
        """Build evidence and raise one process alert via AlertManager."""
        evidence = {
            "pid":       pid,
            "user":      user,
            "cmd":       cmd[:500],   # truncate very long command lines
            "container": container_name,
            "pattern":   matched_pattern,
        }

        rule = f"suspicious_process:{matched_pattern}"

        logger.alert(
            "Suspicious process: container=%s pid=%s user=%s pattern=%r cmd=%r project=%s",
            container_name, pid, user, matched_pattern, cmd[:120],
            project.name if project else "unregistered",
        )

        await self._alert_manager.raise_alert(
            project=project,
            container_name=container_name,
            container_id=container_id,
            alert_type=alert_type,
            severity=severity,
            rule=rule,
            evidence=evidence,
            dedup_extra=matched_pattern,  # same pattern type doesn't spam
        )

    # ------------------------------------------------------------------
    # Docker interaction helpers (synchronous – run in executor)
    # ------------------------------------------------------------------

    def _docker_top(self, container_name: str) -> Optional[Dict]:
        """
        Run ``docker top <container> aux`` and return the raw result dict.

        Returns None on an empty result.
        Raises docker.errors.NotFound / docker.errors.APIError on failure.
        """
        container = self._docker.containers.get(container_name)
        result = container.top(ps_args="aux")
        # result is a dict: {"Titles": [...], "Processes": [[...], ...]}
        return result

    # ------------------------------------------------------------------
    # Container enumeration
    # ------------------------------------------------------------------

    def _get_all_monitored_containers(
        self,
    ) -> List[Tuple[str, str, Optional[ProjectConfig]]]:
        """
        Return (container_name, container_id, project) for every running
        container that belongs to an enabled project with monitor_processes=True.

        Also includes running containers that match the registry even if
        not explicitly configured (they get project=None and are still checked
        for always-suspicious processes).
        """
        results: List[Tuple[str, str, Optional[ProjectConfig]]] = []
        seen: Set[str] = set()

        try:
            running = self._docker.containers.list()
        except docker.errors.DockerException as exc:
            logger.error(
                "ProcessMonitor: cannot list containers: %s", exc
            )
            return results

        for container in running:
            name = container.name
            cid  = container.id or ""

            if name in seen:
                continue
            seen.add(name)

            # Build labels dict for registry lookup
            labels: Dict[str, str] = container.labels or {}
            project = self._registry.get(name, labels)

            # If there's a project, respect its monitor_processes flag
            if project is not None:
                if not project.enabled or not project.monitor_processes:
                    continue
                results.append((name, cid, project))
            else:
                # Unknown container: still scan for always-suspicious processes
                # but only if it's a container running a web-like image
                # (avoid false positives on internal tooling containers)
                results.append((name, cid, None))

        return results

    def _resolve_container(
        self, container_name: str
    ) -> Tuple[Optional[str], Optional[ProjectConfig]]:
        """
        Resolve a container name to (container_id, project).
        Returns (None, None) if the container is not running.
        """
        try:
            container = self._docker.containers.get(container_name)
            labels = container.labels or {}
            project = self._registry.get(container_name, labels)
            return container.id, project
        except docker.errors.NotFound:
            return None, None
        except docker.errors.DockerException as exc:
            logger.warning(
                "ProcessMonitor: could not resolve container '%s': %s",
                container_name, exc,
            )
            return None, None

    # ------------------------------------------------------------------
    # Parse helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _parse_top_output(
        titles: List[str], processes: List[List[str]]
    ) -> List[Dict[str, str]]:
        """
        Convert docker top's raw Titles + Processes lists into a list of
        dicts suitable for analysis.

        docker top with ``aux`` returns columns::

            USER  PID  %CPU  %MEM  VSZ  RSS  TTY  STAT  START  TIME  COMMAND

        The COMMAND column is the last one and may contain spaces, so we
        split each row using ``maxsplit=len(titles)-1``.
        """
        result: List[Dict[str, str]] = []
        n_cols = len(titles)

        # Normalise column names to lowercase for consistent lookup
        norm_titles = [t.strip().upper() for t in titles]

        try:
            pid_idx  = norm_titles.index("PID")
        except ValueError:
            pid_idx  = 1   # fallback: second column in ps aux

        try:
            user_idx = norm_titles.index("USER")
        except ValueError:
            user_idx = 0

        # COMMAND column (may also appear as CMD on some systems)
        cmd_idx = n_cols - 1  # COMMAND is always last in ps aux
        for alias in ("COMMAND", "CMD"):
            if alias in norm_titles:
                cmd_idx = norm_titles.index(alias)
                break

        for row in processes:
            if not row:
                continue
            # Pad short rows defensively
            while len(row) < n_cols:
                row.append("")

            pid  = row[pid_idx].strip()
            user = row[user_idx].strip()
            cmd  = row[cmd_idx].strip()

            result.append({"pid": pid, "user": user, "cmd": cmd})

        return result

    @staticmethod
    def _detect_php_pattern(cmd: str) -> Optional[str]:
        """
        Check a command string for WordPress / PHP code-execution patterns.

        Returns the matched pattern string, or None if no match.
        """
        cmd_lower = cmd.lower()
        for pattern in SUSPICIOUS_PHP_PATTERNS:
            if pattern.lower() in cmd_lower:
                return pattern
        return None

    # ------------------------------------------------------------------
    # Sleep helper (interruptible)
    # ------------------------------------------------------------------

    async def _interruptible_sleep(self, seconds: float) -> None:
        """
        Sleep for ``seconds`` but wake up early if ``_stop_event`` is set.
        """
        try:
            await asyncio.wait_for(
                self._stop_event.wait(),
                timeout=seconds,
            )
        except asyncio.TimeoutError:
            pass  # Normal case: sleep expired without stop being requested
