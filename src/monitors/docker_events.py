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
import json
import logging
import time
from collections import defaultdict, deque
from concurrent.futures import ThreadPoolExecutor
from typing import Any, Coroutine, Deque, Dict, Optional

import docker
import docker.errors

from config.models import (
    ALWAYS_SUSPICIOUS_PROCESSES,
    CONTEXT_SUSPICIOUS_PROCESSES,
    GlobalConfig,
)
from config.loader import ProjectRegistry
from alerts.manager import AlertManager

logger = logging.getLogger("centinela.monitors.docker_events")

# Maximum events buffered before the consumer catches up
_QUEUE_MAX = 2048

# Hard cap for concurrent per-event handlers.
_MAX_IN_FLIGHT_EVENT_TASKS = 64

# Hard cap for concurrent callback tasks spawned by handlers.
_MAX_IN_FLIGHT_CALLBACK_TASKS = 128

# Reconnect back-off parameters (seconds)
_BACKOFF_INITIAL = 2.0
_BACKOFF_MAX = 60.0
_BACKOFF_FACTOR = 2.0

# How many restart events in a sliding window count as a "burst"
_RESTART_BURST_COUNT = 3
_RESTART_BURST_WINDOW = 300  # seconds

# Exec commands issued by Centinela itself (filesystem permission checks).
# These must be ignored to prevent self-detection feedback loops.
_CENTINELA_OWN_EXEC_PREFIXES = (
    "stat -c ",   # filesystem_monitor permission checks
    "ps aux",     # process_monitor top fallback
    "ps -aux",
)

# Common benign healthcheck keywords/patterns seen in orchestration stacks.
_BENIGN_HEALTHCHECK_TOKENS = (
    "healthcheck",
    "healthcheck.sh",
    "docker-healthcheck",
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
        docker_client: docker.DockerClient,
        executor: Optional[ThreadPoolExecutor] = None,
    ) -> None:
        self._config = config
        self._registry = registry
        self._alert_manager = alert_manager
        self._docker = docker_client
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

        # Cross-monitor callbacks (async coroutine functions)
        # Registered via register_*_callback() from main.py
        self._exec_callbacks: list = []    # called with (container_name: str)
        self._start_callbacks: list = []   # called with (container_name, container_id, project)
        self._stop_callbacks: list = []    # called with (container_name: str)

        # Bounded concurrency for event and callback execution.
        self._event_sem = asyncio.Semaphore(_MAX_IN_FLIGHT_EVENT_TASKS)
        self._callback_sem = asyncio.Semaphore(_MAX_IN_FLIGHT_CALLBACK_TASKS)
        self._active_tasks: set[asyncio.Task] = set()

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

        await self._drain_active_tasks(timeout_seconds=5.0)
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
                # run_coroutine_threadsafe blocks until the item is accepted
                future = asyncio.run_coroutine_threadsafe(
                    self._queue.put(item), loop
                )
                future.result(timeout=5)
            except Exception as e:
                logger.warning("DockerEventMonitor: could not enqueue event: %s", e)

        stream = None
        try:
            logger.debug("DockerEventMonitor: connected to Docker daemon.")
            stream = self._docker.events(
                filters={"type": "container"},
                decode=True,
            )
            for raw_event in stream:
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
            try:
                if stream is not None:
                    stream.close()
            except Exception:
                pass
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

            # Dispatch asynchronously without blocking the drain loop.
            self._schedule_task(self._bounded_handle_event(event))

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

    async def _bounded_handle_event(self, event: Dict[str, Any]) -> None:
        """Run one event handler under the monitor's concurrency cap."""
        async with self._event_sem:
            await self._handle_event(event)

    async def _run_callback(self, callback_coro) -> None:
        """Run one callback under a dedicated callback semaphore."""
        async with self._callback_sem:
            await callback_coro

    def _schedule_task(self, coro: Coroutine[Any, Any, Any]) -> None:
        """
        Schedule a coroutine and track it so we can await graceful shutdown.
        """
        task = asyncio.create_task(coro)
        self._active_tasks.add(task)
        task.add_done_callback(self._active_tasks.discard)

    async def _drain_active_tasks(self, timeout_seconds: float = 5.0) -> None:
        """Wait briefly for in-flight event/callback tasks to finish."""
        if not self._active_tasks:
            return
        pending = list(self._active_tasks)
        done, not_done = await asyncio.wait(pending, timeout=timeout_seconds)
        if not_done:
            logger.warning(
                "DockerEventMonitor shutdown with %d in-flight task(s) still pending.",
                len(not_done),
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

        cmd_base = cmd.split()[0] if cmd else "unknown"
        cmd_lower = cmd.lower()
        cmd_base_lower = cmd_base.lower().split("/")[-1]

        # Skip exec commands issued by Centinela itself (e.g. stat for FS checks)
        for own_prefix in _CENTINELA_OWN_EXEC_PREFIXES:
            if cmd.startswith(own_prefix):
                logger.debug(
                    "Ignoring Centinela own exec: container=%s cmd=%r",
                    container_name, cmd,
                )
                return

        # Heuristic de "ruido": muchos stacks hacen curl hacia localhost para
        # healthchecks / readiness. Esto suele ser repetitivo y genera ruido
        # (incidencias masivas) si se deduplica por exec_id.
        if self._is_benign_exec_command(container_name, cmd_lower, cmd_base_lower):
            logger.debug(
                "Ignoring benign healthcheck exec: container=%s cmd=%r",
                container_name,
                cmd,
            )
            return

        logger.warning(
            "DOCKER EXEC detected: container=%s exec_id=%s cmd=%r project=%s",
            container_name, exec_id[:12] if exec_id else "?",
            cmd, project.name if project else "unregistered",
        )

        # Build evidence
        evidence = {
            "container": container_name,
            "container_id": container_id[:12],
            "exec_id": exec_id[:12] if exec_id else "",
            "command": cmd,
            "image": attrs.get("image", ""),
        }

        # Analyze the command for known-suspicious patterns
        extra_severity_info = self._classify_exec_command(cmd, project)
        if extra_severity_info:
            evidence["classification"] = extra_severity_info

        # Context suspicious (p.ej. curl) suele ser más frecuente/ruidoso que
        # las detecciones "always" o "project". Ajustamos severidad para
        # reducir impactos sin perder señal.
        severity = "high"
        # Context suspicious (e.g. curl) tends to be much noisier in real-world
        # stacks; we downgrade it so it doesn't flood the incident workflow.
        if extra_severity_info and extra_severity_info.startswith("context_suspicious"):
            severity = "medium"

        await self._alert_manager.raise_alert(
            project=project,
            container_name=container_name,
            container_id=container_id,
            alert_type="DOCKER_EVENT_EXEC",
            severity=severity,
            rule=f"exec_in_container:{cmd_base if cmd_base else 'unknown'}",
            evidence=evidence,
            # Deduplicación estable: evita spam cuando cada exec tiene exec_id distinto.
            dedup_extra=extra_severity_info or cmd_base,
        )

        # Fire exec callbacks (e.g. trigger immediate process scan)
        for cb in self._exec_callbacks:
            self._schedule_task(self._run_callback(cb(container_name)))

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

        if exit_code in (0, 143):
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
            rule=f"container_exit_code:{exit_code}",
            evidence=evidence,
            dedup_extra=str(exit_code),
        )

        # Fire stop callbacks (e.g. remove filesystem watchers)
        for cb in self._stop_callbacks:
            self._schedule_task(self._run_callback(cb(container_name)))

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
            logger.warning(
                "Restart BURST: container=%s count=%d in %ds",
                container_name, len(recent), _RESTART_BURST_WINDOW,
            )
            evidence = {
                "container": container_name,
                "container_id": container_id[:12],
                "restart_count": len(recent),
                "window_seconds": _RESTART_BURST_WINDOW,
                "image": attrs.get("image", ""),
            }

            await self._alert_manager.raise_alert(
                project=project,
                container_name=container_name,
                container_id=container_id,
                alert_type="DOCKER_EVENT_RESTART",
                severity="medium",
                rule=f"container_restart_burst:{len(recent)}",
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
            # Fire start callbacks for known projects (FS watcher + security audit)
            for cb in self._start_callbacks:
                self._schedule_task(
                    self._run_callback(cb(container_name, container_id, project))
                )
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
            logger.warning(
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
            info = self._docker.api.exec_inspect(exec_id)
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
        """
        if not cmd:
            return None

        cmd_lower = cmd.lower().strip()
        cmd_base = cmd_lower.split()[0].rstrip(";").split("/")[-1]

        # Always suspicious
        for pattern in ALWAYS_SUSPICIOUS_PROCESSES:
            if pattern.lower() in cmd_lower or cmd_base == pattern.lower():
                return f"always_suspicious:{pattern}"

        # Project-specific extra patterns
        if project and project.extra_suspicious_processes:
            for pattern in project.extra_suspicious_processes:
                if pattern.lower() in cmd_lower:
                    return f"project_suspicious:{pattern}"

        # Context suspicious
        for pattern in CONTEXT_SUSPICIOUS_PROCESSES:
            if cmd_base == pattern.lower():
                return f"context_suspicious:{pattern}"

        return None

    @staticmethod
    def _is_benign_exec_command(
        container_name: str,
        cmd_lower: str,
        cmd_base_lower: str,
    ) -> bool:
        """
        Best-effort suppression of high-frequency healthcheck noise.
        """
        # Direct healthcheck markers
        if any(token in cmd_lower for token in _BENIGN_HEALTHCHECK_TOKENS):
            return True

        # Localhost checks are extremely common and usually benign.
        if cmd_base_lower in ("curl", "wget") and (
            "http://127.0.0.1" in cmd_lower
            or "https://127.0.0.1" in cmd_lower
            or "http://localhost" in cmd_lower
            or "https://localhost" in cmd_lower
        ):
            return True

        # Shell wrappers used by healthchecks.
        if cmd_base_lower in ("sh", "bash") and (
            "127.0.0.1" in cmd_lower
            or "localhost" in cmd_lower
            or "healthcheck" in cmd_lower
        ):
            return True

        # Coolify infra often uses shell exec probes.
        if container_name.startswith("coolify-") and cmd_base_lower in ("sh", "bash"):
            return True

        return False
