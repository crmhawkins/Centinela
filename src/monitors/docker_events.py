"""
CENTINELA – Docker Event Monitor.

Streams Docker events in real-time using an event-driven architecture.
Docker's events() API is a blocking generator, so it runs inside a
ThreadPoolExecutor and puts decoded events onto an asyncio.Queue consumed
by the main async loop.

Handled container actions
--------------------------
exec_start  → HIGH    – someone ran `docker exec` inside a container
die         → MEDIUM  – container exited with a non-zero / non-SIGTERM code
oom         → CRITICAL – container was OOM-killed by the kernel
restart     → MEDIUM  – container restarted (tracked for burst detection)
start       → INFO    – new / unknown container started (log only unless suspicious)
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import time
from collections import defaultdict, deque
from concurrent.futures import ThreadPoolExecutor
from typing import Any, Deque, Dict, Optional

import docker
import docker.errors

from config.models import (
    ALWAYS_SUSPICIOUS_PROCESSES,
    CONTEXT_SUSPICIOUS_PROCESSES,
    GlobalConfig,
)
from config.loader import ProjectRegistry
from alerts.manager import AlertManager
from utils.helpers import looks_like_healthcheck_command

logger = logging.getLogger("centinela.monitors.docker_events")

# Maximum events buffered before the consumer catches up
_QUEUE_MAX = 2048

# Reconnect back-off parameters (seconds)
_BACKOFF_INITIAL = 2.0
_BACKOFF_MAX = 60.0
_BACKOFF_FACTOR = 2.0

# How many restart events in a sliding window count as a "burst"
_RESTART_BURST_COUNT = 3
_RESTART_BURST_WINDOW = 300  # seconds
_HEALTHCHECK_TRACE_LOG_WINDOW = 600  # seconds

# Exec commands issued by Centinela itself (filesystem permission checks).
# These must be ignored to prevent self-detection feedback loops.
_CENTINELA_OWN_EXEC_PREFIXES = (
    "stat -c ",   # filesystem_monitor permission checks
    "ps aux",     # process_monitor top fallback
    "ps -aux",
)

# Coolify / platform maintenance commands that should not generate incidents.
_BENIGN_ORCHESTRATOR_EXEC_PATTERNS = (
    # Coolify / orchestrator probes
    "php artisan optimize:clear",
    "templates/service-templates-latest.json",
    "nginx -t >/dev/null 2>&1",
    "php-fpm -t >/dev/null 2>&1",
    "fsockopen(\"127.0.0.1\",80)",
    "fsockopen('127.0.0.1',80)",
    "fsockopen(\"127.0.0.1\",9000)",
    "fsockopen('127.0.0.1',9000)",
    "test -f /var/www/html/artisan",
    # Common deployment / CI commands
    "php artisan migrate",
    "php artisan db:seed",
    "php artisan config:cache",
    "php artisan route:cache",
    "php artisan view:cache",
    "php artisan storage:link",
    "php artisan queue:restart",
    "composer install",
    "composer update",
    "composer dump-autoload",
    "npm install",
    "npm run build",
    "npm run prod",
    "npm ci",
    "yarn install",
    "yarn build",
    "pip install",
    "python manage.py migrate",
    "python manage.py collectstatic",
    "bundle install",
    "bundle exec",
    "supervisorctl",
    "update-alternatives",
    # Database maintenance
    "mysqladmin",
    "pg_dump",
    "pg_restore",
    "redis-cli",
    # Init / entrypoint patterns
    "/entrypoint.sh",
    "/docker-entrypoint",
    "docker-entrypoint",
)


class DockerEventMonitor:
    """
    Streams Docker container events and dispatches security alerts.

    Architecture
    ------------
    1. ``_stream_events()``  runs in a thread executor; it calls
       ``docker.from_env().events(filters={"type": "container"})``
       (a blocking generator) and puts each decoded event dict onto
       ``self._queue``.

    2. ``run()`` is an asyncio coroutine that:
       - starts the thread-based producer via ``loop.run_in_executor``
       - drains ``self._queue`` in a tight ``while True`` loop
       - calls ``_handle_event()`` for each event
       - automatically restarts the thread on Docker disconnections

    Parameters
    ----------
    config:        Global CENTINELA configuration.
    registry:      Maps container names/labels → ProjectConfig.
    alert_manager: Shared AlertManager for deduplication + dispatch.
    executor:      Optional ThreadPoolExecutor.  If None, a fresh
                   single-thread executor is created.
    """

    def __init__(
        self,
        config: GlobalConfig,
        registry: ProjectRegistry,
        alert_manager: AlertManager,
        executor: Optional[ThreadPoolExecutor] = None,
    ) -> None:
        self._config = config
        self._registry = registry
        self._alert_manager = alert_manager
        self._executor = executor or ThreadPoolExecutor(
            max_workers=1, thread_name_prefix="centinela-docker-events"
        )

        # asyncio.Queue used to bridge the blocking thread and the async loop
        self._queue: asyncio.Queue[Optional[Dict[str, Any]]] = asyncio.Queue(
            maxsize=_QUEUE_MAX
        )

        # Restart burst tracking: container_name → deque of timestamps
        self._restart_times: Dict[str, Deque[float]] = defaultdict(
            lambda: deque(maxlen=20)
        )

        # Internal sentinel: set to True to stop the run() loop gracefully
        self._stop_event = asyncio.Event()

        # Event loop reference captured in run() and used by _stream_events() thread
        self._loop: Optional[asyncio.AbstractEventLoop] = None

        # Cache of container_name → healthcheck command string (auto-populated at runtime)
        self._healthcheck_cache: Dict[str, str] = {}

        # Cross-monitor callbacks (async coroutine functions)
        # Registered via register_*_callback() from main.py
        self._exec_callbacks: list = []    # called with (container_name: str)
        self._start_callbacks: list = []   # called with (container_name, container_id, project)
        self._stop_callbacks: list = []    # called with (container_name: str)

        # Rate-limit noisy healthcheck trace lines:
        # key -> monotonic timestamp of last emitted log
        self._healthcheck_trace_last: Dict[str, float] = {}

        # Crash-loop suppression: container_name → monotonic time until which
        # individual DOCKER_EVENT_STOP alerts are suppressed.
        # Set when a restart burst is detected; expires after 2 hours.
        self._crash_loop_until: Dict[str, float] = {}

    # ------------------------------------------------------------------
    # Callback registration (called from main.py after instantiation)
    # ------------------------------------------------------------------

    def register_exec_callback(self, coro_func) -> None:
        """Register an async callback fired on every exec_start event."""
        self._exec_callbacks.append(coro_func)

    def register_start_callback(self, coro_func) -> None:
        """Register an async callback fired on every container start event."""
        self._start_callbacks.append(coro_func)

    def register_stop_callback(self, coro_func) -> None:
        """Register an async callback fired on every container die/stop event."""
        self._stop_callbacks.append(coro_func)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def run(self) -> None:
        """
        Main entry point.  Run this as a long-lived asyncio Task.

        The loop:
        1. Starts ``_stream_events()`` in the thread executor.
        2. Reads events from the queue and dispatches them.
        3. If the thread raises (Docker disconnect), waits with
           exponential back-off and then restarts.
        """
        backoff = _BACKOFF_INITIAL
        loop = asyncio.get_event_loop()
        self._loop = loop  # store for use in _stream_events() thread

        # Load healthcheck configs for already-running containers
        try:
            import docker as _docker
            _client = _docker.from_env()
            for _c in _client.containers.list():
                self._load_container_healthcheck(_c.id, _c.name)
            _client.close()
        except Exception as _e:
            logger.debug("Could not pre-load healthchecks: %s", _e)

        logger.info("DockerEventMonitor starting.")

        while not self._stop_event.is_set():
            # Drain any leftover sentinel from a previous cycle
            while not self._queue.empty():
                try:
                    self._queue.get_nowait()
                    self._queue.task_done()
                except asyncio.QueueEmpty:
                    break

            # Start the blocking producer in a thread
            producer_future = loop.run_in_executor(
                self._executor, self._stream_events
            )
            logger.info("DockerEventMonitor: event stream started.")

            try:
                # Drain the queue until the producer signals completion
                # by pushing None (sentinel) or until we're stopped.
                await self._drain_queue(producer_future)

                # Producer exited cleanly (Docker connection closed normally)
                logger.warning(
                    "DockerEventMonitor: event stream ended (Docker may have restarted)."
                )
                backoff = _BACKOFF_INITIAL  # reset on clean exit

            except asyncio.CancelledError:
                logger.info("DockerEventMonitor: cancelled, stopping.")
                self._stop_event.set()
                producer_future.cancel()
                break

            except Exception as exc:
                logger.error(
                    "DockerEventMonitor: unexpected error in run loop: %s", exc,
                    exc_info=True,
                )

            if self._stop_event.is_set():
                break

            # Reconnect with exponential back-off
            logger.info(
                "DockerEventMonitor: reconnecting in %.0f s...", backoff
            )
            await asyncio.sleep(backoff)
            backoff = min(backoff * _BACKOFF_FACTOR, _BACKOFF_MAX)

        logger.info("DockerEventMonitor stopped.")

    def stop(self) -> None:
        """Signal the run() loop to stop after the current event."""
        self._stop_event.set()

    # ------------------------------------------------------------------
    # Thread-side producer
    # ------------------------------------------------------------------

    def _stream_events(self) -> None:
        """
        Blocking function executed in the thread executor.

        Connects to Docker, iterates over ``client.events()`` and
        pushes each decoded event dict to the asyncio queue via
        ``asyncio.Queue.put_nowait``.

        On any error this method pushes a ``None`` sentinel to signal
        the async consumer that the stream has ended, then returns.
        """
        loop = self._loop  # captured from run() in the async thread

        def put(item: Optional[Dict[str, Any]]) -> None:
            """Thread-safe enqueue to the asyncio queue."""
            try:
                if loop is None or loop.is_closed():
                    return
                # run_coroutine_threadsafe blocks until the item is accepted
                future = asyncio.run_coroutine_threadsafe(
                    self._queue.put(item), loop
                )
                future.result(timeout=5)
            except Exception as e:
                # Happens on shutdown/reload; keep it as debug unless we're active.
                if self._stop_event.is_set():
                    logger.debug("DockerEventMonitor: enqueue skipped during stop.")
                else:
                    logger.warning("DockerEventMonitor: could not enqueue event: %r", e)

        try:
            client = docker.from_env()
            logger.debug("DockerEventMonitor: connected to Docker daemon.")
            for raw_event in client.events(
                filters={"type": "container"},
                decode=True,
            ):
                if self._stop_event.is_set():
                    break
                if raw_event:
                    put(raw_event)

        except docker.errors.DockerException as exc:
            logger.error("DockerEventMonitor: Docker error in stream: %s", exc)
        except Exception as exc:
            logger.error(
                "DockerEventMonitor: unexpected error in stream thread: %s",
                exc, exc_info=True,
            )
        finally:
            # Push sentinel to wake up the async consumer
            put(None)

    # ------------------------------------------------------------------
    # Async consumer
    # ------------------------------------------------------------------

    async def _drain_queue(
        self, producer_future: asyncio.Future
    ) -> None:
        """
        Consume events from ``self._queue`` until the producer signals
        end-of-stream (None sentinel) or the producer future raises.

        Also checks the producer future for exceptions so connection
        errors propagate back to the ``run()`` loop.
        """
        while True:
            # Get the next event with a timeout so we can poll the future
            try:
                event = await asyncio.wait_for(self._queue.get(), timeout=1.0)
            except asyncio.TimeoutError:
                # Check if the producer raised while we were waiting
                if producer_future.done():
                    exc = producer_future.exception()
                    if exc:
                        raise exc
                    # Sentinel may still be in the queue; keep draining
                continue

            self._queue.task_done()

            if event is None:
                # End-of-stream sentinel
                return

            # Dispatch asynchronously without blocking the drain loop
            asyncio.ensure_future(self._handle_event(event))

    # ------------------------------------------------------------------
    # Event dispatcher
    # ------------------------------------------------------------------

    async def _handle_event(self, event: Dict[str, Any]) -> None:
        """
        Route a decoded Docker event dict to the appropriate handler.

        Event structure::

            {
              "Type":   "container",
              "Action": "exec_start: bash",   # or "die", "oom", etc.
              "Actor":  {
                  "ID":         "<container_id>",
                  "Attributes": {
                      "name":     "<container_name>",
                      "image":    "<image>",
                      "exitCode": "1",
                      ...
                  }
              },
              "time":   1234567890,
            }
        """
        try:
            action: str = event.get("Action", "")
            actor: Dict[str, Any] = event.get("Actor", {})
            container_id: str = actor.get("ID", "")
            attrs: Dict[str, str] = actor.get("Attributes", {})
            container_name: str = attrs.get("name", container_id[:12])
            labels: Dict[str, str] = {
                k: v for k, v in attrs.items()
                if k.startswith("com.docker") or "." in k
            }

            # Resolve project from registry
            project = self._registry.get(container_name, labels)

            # Determine the canonical action (strip exec details from action string)
            base_action = action.split(":")[0].strip().lower()

            # High-frequency Docker noise actions (especially healthchecks).
            # We intentionally ignore them completely to avoid log floods.
            if base_action in {"exec_create", "exec_die", "top"}:
                return

            if base_action == "exec_start":
                if project and not project.monitor_docker_events:
                    return
                await self._handle_exec(
                    container_name, container_id, attrs, project, action
                )

            elif base_action == "die":
                if project and not project.monitor_docker_events:
                    return
                await self._handle_die(
                    container_name, container_id, attrs, project
                )

            elif base_action == "oom":
                if project and not project.monitor_docker_events:
                    return
                await self._handle_oom(
                    container_name, container_id, attrs, project
                )

            elif base_action == "restart":
                if project and not project.monitor_docker_events:
                    return
                await self._handle_restart(
                    container_name, container_id, attrs, project
                )

            elif base_action == "start":
                await self._handle_start(
                    container_name, container_id, attrs, project
                )

            else:
                logger.debug(
                    "DockerEvent: container=%s action=%s (not monitored)",
                    container_name, action,
                )

        except Exception as exc:
            logger.error(
                "DockerEventMonitor: error handling event %s: %s",
                event.get("Action"), exc, exc_info=True,
            )

    # ------------------------------------------------------------------
    # Specific event handlers
    # ------------------------------------------------------------------

    async def _handle_exec(
        self,
        container_name: str,
        container_id: str,
        attrs: Dict[str, str],
        project,
        raw_action: str,
    ) -> None:
        """
        Handle exec_start events.

        Docker fires 'exec_start: <command>' where the command is appended
        to the action string.  We also try to look it up via the exec ID.
        """
        # Try to get the command from multiple places
        exec_id = attrs.get("execID", "")

        # 1. Try extracting from the action string itself: "exec_start: bash"
        cmd = ""
        if ":" in raw_action:
            cmd = raw_action.split(":", 1)[1].strip()

        # 2. Fall back to execArgs attribute (some Docker versions set this)
        if not cmd:
            cmd = attrs.get("execArgs", "")

        # 3. Last resort: inspect via Docker API
        if not cmd and exec_id:
            cmd = self._get_exec_command(container_id, exec_id)

        if not cmd:
            cmd = "<unknown>"

        # Skip trusted exec commands (Centinela internals, healthchecks, patterns, destinations)
        trusted, reason = self._is_trusted_exec(cmd, container_name, project)
        if trusted:
            trace_key = f"{container_name}:{reason}:{cmd[:120]}"
            now = time.monotonic()
            last = self._healthcheck_trace_last.get(trace_key, 0.0)
            if now - last >= _HEALTHCHECK_TRACE_LOG_WINDOW:
                self._healthcheck_trace_last[trace_key] = now
                logger.info(
                    "TRACE_HEALTHCHECK_EXEC: container=%s exec_id=%s cmd=%r reason=%s",
                    container_name, exec_id[:12] if exec_id else "unknown", cmd, reason,
                )
            return

        # Only alert if the command matches a known-suspicious pattern.
        # Generic exec commands (deploys, migrations, etc.) are logged but do not
        # create incidents – they were the primary source of false positives.
        classification = self._classify_exec_command(cmd, project)
        if not classification:
            logger.info(
                "EXEC (unclassified, no incident): container=%s exec_id=%s cmd=%r",
                container_name, exec_id[:12] if exec_id else "?", cmd[:200],
            )
            # Still fire exec callbacks so the process monitor can run
            for cb in self._exec_callbacks:
                asyncio.ensure_future(cb(container_name))
            return

        # Map classification to severity
        if classification.startswith("always_suspicious") or classification.startswith("project_suspicious"):
            severity = "high"
        else:
            # context_suspicious: bash, sh, python, curl in a suspicious exec context
            severity = "medium"

        logger.alert(
            "DOCKER EXEC detected: container=%s exec_id=%s cmd=%r classification=%s project=%s",
            container_name, exec_id[:12] if exec_id else "?",
            cmd, classification, project.name if project else "unregistered",
        )

        # Build evidence
        evidence = {
            "container": container_name,
            "container_id": container_id[:12],
            "exec_id": exec_id[:12] if exec_id else "",
            "command": cmd,
            "image": attrs.get("image", ""),
            "classification": classification,
        }

        await self._alert_manager.raise_alert(
            project=project,
            container_name=container_name,
            container_id=container_id,
            alert_type="DOCKER_EVENT_EXEC",
            severity=severity,
            labels=attrs,
            rule=f"exec_in_container:{cmd.split()[0] if cmd else 'unknown'}",
            evidence=evidence,
            dedup_extra=self._exec_dedup_token(cmd, exec_id),
        )

        # Fire exec callbacks (e.g. trigger immediate process scan)
        for cb in self._exec_callbacks:
            asyncio.ensure_future(cb(container_name))

    async def _handle_die(
        self,
        container_name: str,
        container_id: str,
        attrs: Dict[str, str],
        project,
    ) -> None:
        """
        Handle container 'die' events.

        Only alerts on non-zero, non-SIGTERM (143) exit codes.
        Exit code 0 = normal shutdown; 143 = SIGTERM (graceful stop).
        """
        exit_code_str = attrs.get("exitCode", "0")
        try:
            exit_code = int(exit_code_str)
        except ValueError:
            exit_code = -1

        # Expected exit codes that do not indicate a problem:
        #   0   → clean shutdown
        #   137 → SIGKILL (docker stop after grace period, normal in rolling deploys)
        #   143 → SIGTERM (graceful stop by orchestrator)
        if exit_code in (0, 137, 143):
            logger.debug(
                "Container %s exited with code %d (expected) – no alert",
                container_name, exit_code,
            )
            return

        logger.warning(
            "Container %s died with exit code %d | project=%s",
            container_name, exit_code,
            project.name if project else "unregistered",
        )

        # Suppress individual STOP alerts when a crash loop has already been flagged.
        # The burst alert (HIGH) is the meaningful signal; individual STOPs are noise.
        if time.monotonic() < self._crash_loop_until.get(container_name, 0):
            logger.debug(
                "STOP suppressed (crash loop active): container=%s exit_code=%d",
                container_name, exit_code,
            )
            # Still fire stop callbacks so filesystem watchers are removed
            for cb in self._stop_callbacks:
                asyncio.ensure_future(cb(container_name))
            return

        evidence = {
            "container": container_name,
            "container_id": container_id[:12],
            "exit_code": exit_code,
            "image": attrs.get("image", ""),
        }

        await self._alert_manager.raise_alert(
            project=project,
            container_name=container_name,
            container_id=container_id,
            alert_type="DOCKER_EVENT_STOP",
            severity="medium",
            labels=attrs,
            rule=f"container_exit_code:{exit_code}",
            evidence=evidence,
            dedup_extra=str(exit_code),
        )

        # Fire stop callbacks (e.g. remove filesystem watchers)
        for cb in self._stop_callbacks:
            asyncio.ensure_future(cb(container_name))

    async def _handle_oom(
        self,
        container_name: str,
        container_id: str,
        attrs: Dict[str, str],
        project,
    ) -> None:
        """
        Handle OOM-kill events.  Always CRITICAL – the kernel terminated
        the container due to memory exhaustion, which may indicate a
        memory-consuming payload (crypto miner, fork bomb, etc.).
        """
        logger.critical(
            "OOM KILL: container=%s | project=%s",
            container_name, project.name if project else "unregistered",
        )

        evidence = {
            "container": container_name,
            "container_id": container_id[:12],
            "image": attrs.get("image", ""),
            "event": "oom_kill",
        }

        await self._alert_manager.raise_alert(
            project=project,
            container_name=container_name,
            container_id=container_id,
            alert_type="DOCKER_EVENT_OOM",
            severity="critical",
            labels=attrs,
            rule="container_oom_killed",
            evidence=evidence,
            dedup_extra="oom",
        )

    async def _handle_restart(
        self,
        container_name: str,
        container_id: str,
        attrs: Dict[str, str],
        project,
    ) -> None:
        """
        Handle 'restart' events.

        Track restart timestamps per container.  If ``_RESTART_BURST_COUNT``
        or more restarts happen within ``_RESTART_BURST_WINDOW`` seconds,
        emit a medium-severity alert.

        Individual restarts are only logged (no alert).
        """
        now = time.monotonic()
        window: Deque[float] = self._restart_times[container_name]
        window.append(now)

        # Count restarts within the burst window
        cutoff = now - _RESTART_BURST_WINDOW
        recent = [t for t in window if t >= cutoff]

        logger.info(
            "Container %s restarted (recent_count=%d in %ds window) | project=%s",
            container_name, len(recent), _RESTART_BURST_WINDOW,
            project.name if project else "unregistered",
        )

        if len(recent) >= _RESTART_BURST_COUNT:
            logger.alert(
                "Restart BURST: container=%s count=%d in %ds",
                container_name, len(recent), _RESTART_BURST_WINDOW,
            )
            # Mark this container as in crash loop for 2 hours to suppress
            # individual DOCKER_EVENT_STOP noise during the loop.
            self._crash_loop_until[container_name] = time.monotonic() + 7200

            evidence = {
                "container": container_name,
                "container_id": container_id[:12],
                "restart_count": len(recent),
                "window_seconds": _RESTART_BURST_WINDOW,
                "image": attrs.get("image", ""),
                "note": "Crash loop detectado. Alertas STOP individuales suprimidas 2h.",
            }

            await self._alert_manager.raise_alert(
                project=project,
                container_name=container_name,
                container_id=container_id,
                alert_type="DOCKER_EVENT_RESTART",
                severity="high",
                labels=attrs,
                rule=f"container_crash_loop:{len(recent)}",
                evidence=evidence,
                dedup_extra="burst",
            )

    async def _handle_start(
        self,
        container_name: str,
        container_id: str,
        attrs: Dict[str, str],
        project,
    ) -> None:
        """
        Handle 'start' events.

        If the container is in a known project → log at INFO only.
        If the container is unknown *and* its image name looks suspicious
        (e.g. a known attack tool image), raise an info-level alert.
        """
        image = attrs.get("image", "")

        if project:
            logger.info(
                "Container started: name=%s image=%s project=%s",
                container_name, image, project.name,
            )
            # Load healthcheck config for this container asynchronously
            loop = asyncio.get_event_loop()
            loop.run_in_executor(
                None, self._load_container_healthcheck, container_id, container_name
            )
            # Fire start callbacks for known projects (FS watcher + security audit)
            for cb in self._start_callbacks:
                asyncio.ensure_future(cb(container_name, container_id, project))
            return  # Known project – no alert needed

        # Unknown container: check if the image is suspicious
        suspicious_images = [
            "kalilinux", "parrotsec", "metasploit", "beef-xss",
            "nmap", "masscan", "sqlmap", "nikto",
        ]
        image_lower = image.lower()
        matched_image = next(
            (s for s in suspicious_images if s in image_lower), None
        )

        if matched_image:
            logger.alert(
                "Suspicious unknown container started: name=%s image=%s",
                container_name, image,
            )
            evidence = {
                "container": container_name,
                "container_id": container_id[:12],
                "image": image,
                "reason": f"image matches suspicious pattern: {matched_image}",
            }
            await self._alert_manager.raise_alert(
                project=None,
                container_name=container_name,
                container_id=container_id,
                alert_type="DOCKER_EVENT_SUSPICIOUS_START",
                severity="medium",
                labels=attrs,
                rule=f"suspicious_image:{matched_image}",
                evidence=evidence,
                dedup_extra=matched_image,
            )
        else:
            logger.info(
                "Unknown container started (not monitored): name=%s image=%s",
                container_name, image,
            )

    # ------------------------------------------------------------------
    # Helper: load container healthcheck command
    # ------------------------------------------------------------------

    def _load_container_healthcheck(
        self, container_id: str, container_name: str
    ) -> None:
        """
        Synchronously fetch and cache the healthcheck command for a container.

        Reads ``container.attrs["Config"]["Healthcheck"]["Test"]``, which is a
        list whose first element is "CMD" or "CMD-SHELL"; the actual command is
        formed by joining elements at index 1 and beyond.

        Results are stored in ``self._healthcheck_cache[container_name]``.
        Silently ignores all exceptions (container may not exist yet, no
        healthcheck configured, etc.).
        """
        try:
            client = docker.from_env()
            container = client.containers.get(container_id)
            test = (
                container.attrs.get("Config", {})
                .get("Healthcheck", {})
                .get("Test", [])
            )
            if isinstance(test, list) and len(test) > 1:
                # Skip the first element ("CMD" / "CMD-SHELL")
                healthcheck_cmd = " ".join(str(t) for t in test[1:])
                self._healthcheck_cache[container_name] = healthcheck_cmd
                logger.debug(
                    "Healthcheck cached: container=%s cmd=%r",
                    container_name, healthcheck_cmd,
                )
            client.close()
        except Exception as exc:
            logger.debug(
                "Could not load healthcheck for container=%s: %s",
                container_name, exc,
            )

    # ------------------------------------------------------------------
    # Helper: determine whether an exec command is trusted
    # ------------------------------------------------------------------

    def _is_trusted_exec(
        self, cmd: str, container_name: str, project
    ) -> tuple:
        """
        Return ``(True, reason)`` if the exec command should be ignored,
        ``(False, "")`` otherwise.

        Checks in order:
        1. Centinela own execs (``_CENTINELA_OWN_EXEC_PREFIXES``)
        2. Container healthcheck command cached in ``_healthcheck_cache``
        3. Project ``trusted_exec_patterns`` (substring match)
        4. curl/wget to a trusted destination
        """
        # 1. Centinela internal execs
        for own_prefix in _CENTINELA_OWN_EXEC_PREFIXES:
            if cmd.startswith(own_prefix):
                return (True, "centinela-internal")

        # 1b. Generic healthcheck/readiness commands (including Coolify patterns)
        if looks_like_healthcheck_command(cmd):
            return (True, "healthcheck-pattern")

        # 2. Container healthcheck
        if container_name in self._healthcheck_cache:
            cached_hc = self._healthcheck_cache[container_name]
            if cached_hc and cached_hc in cmd:
                return (True, "healthcheck")

        # 3. Project trusted exec patterns
        if project is not None:
            for pattern in (project.trusted_exec_patterns or []):
                if pattern in cmd:
                    return (True, "trusted-pattern")

        # 3b. Known benign orchestrator probes/maintenance (Coolify, health checks)
        cmd_lower = cmd.lower()
        for pattern in _BENIGN_ORCHESTRATOR_EXEC_PATTERNS:
            if pattern in cmd_lower:
                return (True, "orchestrator-maintenance")

        # 4. Trusted curl/wget destination
        cmd_stripped = cmd.strip()
        cmd_lower = cmd_stripped.lower()
        if cmd_lower.startswith("curl") or cmd_lower.startswith("wget"):
            # Collect trusted destinations from the project (or use the defaults)
            _default_destinations = ["localhost", "127.0.0.1", "::1", "0.0.0.0"]
            if project is not None:
                destinations = list(project.trusted_destinations or _default_destinations)
            else:
                destinations = _default_destinations
            # Extract all space-separated tokens that look like URL/host arguments
            # (skip flag tokens that start with -)
            tokens = cmd_stripped.split()
            for token in tokens[1:]:
                if token.startswith("-"):
                    continue
                for dest in destinations:
                    if dest in token:
                        return (True, "trusted-destination")

        return (False, "")

    @staticmethod
    def _exec_dedup_token(cmd: str, exec_id: str) -> str:
        """
        Build stable dedup token for exec incidents.
        Using exec_id causes alert storms because each execution is unique.
        """
        cmd_norm = " ".join((cmd or "").strip().lower().split())
        if cmd_norm:
            return hashlib.sha1(cmd_norm.encode("utf-8")).hexdigest()[:12]
        return exec_id[:12] if exec_id else "unknown"

    # ------------------------------------------------------------------
    # Helper: get exec command from Docker inspect
    # ------------------------------------------------------------------

    def _get_exec_command(self, container_id: str, exec_id: str) -> str:
        """
        Try to retrieve the command of an exec session via Docker API.

        Returns the command string on success, empty string on failure.
        This is a synchronous call – safe to call from the async loop
        because it's fast and lightweight (single API call with no I/O
        inside the container).
        """
        if not exec_id:
            return ""
        try:
            client = docker.from_env()
            info = client.api.exec_inspect(exec_id)
            cmd_list = info.get("ProcessConfig", {}).get("entrypoint", "")
            args = info.get("ProcessConfig", {}).get("arguments", [])
            if isinstance(args, list):
                parts = [cmd_list] + args if cmd_list else args
                return " ".join(str(p) for p in parts if p)
            return str(cmd_list)
        except docker.errors.APIError as exc:
            logger.debug(
                "Could not inspect exec %s on container %s: %s",
                exec_id[:12], container_id[:12], exc,
            )
            return ""
        except Exception as exc:
            logger.debug(
                "Unexpected error inspecting exec %s: %s", exec_id[:12], exc
            )
            return ""

    # ------------------------------------------------------------------
    # Helper: classify exec command
    # ------------------------------------------------------------------

    def _classify_exec_command(
        self, cmd: str, project
    ) -> Optional[str]:
        """
        Check whether the exec'd command is in any suspicious list.

        Returns a short classification string (e.g. "always_suspicious:nmap")
        or None if the command looks benign.

        Special handling for shell wrappers (bash/sh -c "..."):
        When a shell is invoked with -c, the shell itself is not the threat –
        the inner script is.  We analyse the inner command instead, which avoids
        false positives on deployment scripts like ``bash -c "npm run build"``.
        An interactive shell (bare ``bash`` / ``sh -i``) is still flagged.
        """
        if not cmd:
            return None

        cmd_lower = cmd.lower().strip()
        cmd_base = cmd_lower.split()[0].rstrip(";").split("/")[-1]

        # Always suspicious – check the full command string
        for pattern in ALWAYS_SUSPICIOUS_PROCESSES:
            if pattern.lower() in cmd_lower or cmd_base == pattern.lower():
                return f"always_suspicious:{pattern}"

        # Project-specific extra patterns
        if project and project.extra_suspicious_processes:
            for pattern in project.extra_suspicious_processes:
                if pattern.lower() in cmd_lower:
                    return f"project_suspicious:{pattern}"

        # Shell wrapper check: bash/sh/dash/zsh/ksh used with -c flag.
        # In this case the shell is just a runner – analyse the inner command.
        _shell_wrappers = {"bash", "sh", "dash", "zsh", "ksh"}
        if cmd_base in _shell_wrappers:
            tokens = cmd_lower.split()
            if "-c" in tokens:
                # Extract everything after -c as the "real" command to analyse
                idx = tokens.index("-c")
                inner = " ".join(tokens[idx + 1:]).strip().strip("\"'")
                if inner:
                    # Recursively classify the inner command (one level only)
                    return self._classify_exec_command(inner, project)
                # -c with no argument → treat as interactive shell
            elif any(t in ("-i", "-l", "--login", "--interactive") for t in tokens[1:]):
                # Explicitly interactive/login shell → suspicious
                return f"context_suspicious:{cmd_base}"
            else:
                # Bare shell with no -c and no script → interactive session
                if len(tokens) == 1:
                    return f"context_suspicious:{cmd_base}"
                # Shell + positional script argument (e.g. bash /opt/deploy.sh) → not suspicious
                return None

        # Context suspicious (non-shell tools)
        for pattern in CONTEXT_SUSPICIOUS_PROCESSES:
            if cmd_base == pattern.lower() and pattern not in _shell_wrappers:
                return f"context_suspicious:{pattern}"

        return None
