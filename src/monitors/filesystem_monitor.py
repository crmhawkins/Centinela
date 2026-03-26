"""
CENTINELA – Filesystem Monitor.

Watches for suspicious filesystem changes in monitored containers using two
complementary strategies:

  A) inotify-based real-time watching (via watchdog):
       - Monitors host paths that correspond to critical container paths via
         bind-mount mappings discovered through Docker inspect.
       - PHP files created in upload directories → HIGH alert immediately.
       - Critical core files modified outside a deployment window → MEDIUM alert.

  B) Periodic hash/permission checks (via docker exec):
       - Fallback for containers whose volumes are not accessible as host bind
         mounts (e.g. named volumes without a bind path).
       - Uses `docker exec stat` to fetch mtime, size, permissions, and owner.
       - Compares against a stored snapshot in the database.
       - Raises a FILESYSTEM_CHANGE alert when anything changes outside a
         deployment window.
       - Raises a low-severity alert when a sensitive file (e.g. wp-config.php)
         has world-readable permissions.

Architecture note:
  watchdog runs its Observer on a background thread.  Events are placed into a
  thread-safe queue.Queue().  The asyncio run() loop polls that queue every
  100 ms and dispatches event processing in the async context.
"""

import asyncio
import logging
import os
import queue
import subprocess
import threading
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

import docker
import docker.errors
from watchdog.events import FileSystemEvent, FileSystemEventHandler
from watchdog.observers import Observer

from alerts.manager import AlertManager
from config.loader import ProjectRegistry
from config.models import (
    FORBIDDEN_UPLOAD_EXTENSIONS,
    LARAVEL_CRITICAL_PATHS,
    WORDPRESS_CRITICAL_PATHS,
    GlobalConfig,
    ProjectConfig,
)
from database.repository import IncidentRepository
from utils.helpers import (
    build_dedup_key,
    file_stat,
    has_suspicious_extension,
    in_deployment_window,
    sha256_file,
)

logger = logging.getLogger("centinela.monitors.filesystem")

# Watch-type constants used to tag watchdog handlers so that event processing
# can apply the correct logic.
WATCH_TYPE_UPLOADS = "uploads"        # upload directories — watch for PHP/script files
WATCH_TYPE_CRITICAL = "critical"      # critical application files (core, config, etc.)
WATCH_TYPE_GENERIC = "generic"        # everything else worth watching

# Permissions that are considered "too open" for sensitive config files.
# These are stored as octal strings, e.g. "0o644" → world-readable.
_WORLD_READABLE_MASK = 0o004  # "other read" bit

# docker exec timeout (seconds) for permission / stat checks.
_EXEC_TIMEOUT = 10


class _FSEventHandler(FileSystemEventHandler):
    """
    Watchdog event handler that bridges the watchdog thread to the asyncio
    event loop by putting event dicts onto a thread-safe queue.

    Parameters
    ----------
    event_queue:     Shared queue.Queue instance polled by the async run loop.
    container_name:  Name of the container being watched (for evidence).
    project:         The matched ProjectConfig.
    watch_type:      WATCH_TYPE_* constant for event classification.
    """

    def __init__(
        self,
        event_queue: queue.Queue,
        container_name: str,
        project: ProjectConfig,
        watch_type: str,
    ) -> None:
        super().__init__()
        self.queue = event_queue
        self.container_name = container_name
        self.project = project
        self.watch_type = watch_type

    def _enqueue(self, event: FileSystemEvent, action: str) -> None:
        try:
            self.queue.put_nowait(
                {
                    "action": action,               # "created" | "modified"
                    "src_path": event.src_path,
                    "is_directory": event.is_directory,
                    "container_name": self.container_name,
                    "project": self.project,
                    "watch_type": self.watch_type,
                }
            )
        except queue.Full:
            logger.warning(
                "Filesystem event queue is full; dropping event for %s %s",
                action, event.src_path,
            )

    def on_created(self, event: FileSystemEvent) -> None:
        if not event.is_directory:
            self._enqueue(event, "created")

    def on_modified(self, event: FileSystemEvent) -> None:
        if not event.is_directory:
            self._enqueue(event, "modified")


class FilesystemMonitor:
    """
    Monitors filesystem changes for all registered containers.

    Parameters
    ----------
    config:         Global CENTINELA configuration.
    registry:       ProjectRegistry mapping container names → ProjectConfig.
    alert_manager:  Central alert dispatcher.
    repo:           Database repository (synchronous, called via executor).
    docker_client:  docker.DockerClient (synchronous SDK).
    """

    def __init__(
        self,
        config: GlobalConfig,
        registry: ProjectRegistry,
        alert_manager: AlertManager,
        repo: IncidentRepository,
        docker_client: docker.DockerClient,
    ) -> None:
        self._config = config
        self._registry = registry
        self._alert_manager = alert_manager
        self._repo = repo
        self._docker = docker_client

        # Thread-safe queue bridging watchdog thread → asyncio loop.
        # maxsize=0 means unbounded; set a sensible cap to avoid memory issues
        # in pathological cases (e.g. a container doing millions of writes).
        self._event_queue: queue.Queue = queue.Queue(maxsize=10_000)

        # watchdog Observer instance (started in run()).
        self._observer: Optional[Observer] = None

        # Tracks active watchdog watches: container_name → list of Watch objects.
        self._watches: Dict[str, list] = {}

        # Tracks which containers are watched to avoid duplicate setup.
        self._watched_containers: Set[str] = set()

        # Lock protecting _watches and _watched_containers from concurrent
        # modification (Docker event callbacks run in a different thread).
        self._watches_lock = threading.Lock()

    # ------------------------------------------------------------------
    # Early observer start (called from main.py before startup audit)
    # ------------------------------------------------------------------

    def start_observer(self) -> None:
        """
        Start the watchdog Observer early so that add_container_watcher()
        calls during the startup audit succeed.
        Safe to call multiple times — idempotent.
        """
        if self._observer is None:
            self._observer = Observer()
            self._observer.start()
            logger.info("Filesystem watchdog Observer started (early).")

    # ------------------------------------------------------------------
    # Main entry point
    # ------------------------------------------------------------------

    async def run(self) -> None:
        """
        Starts the watchdog Observer (if not already started), sets up
        initial watchers, and runs the async event-dispatch +
        periodic-hash-check loops concurrently.
        """
        if self._observer is None:
            self._observer = Observer()
            self._observer.start()
            logger.info("Filesystem watchdog Observer started.")
        else:
            logger.info("Filesystem watchdog Observer already running.")

        # Initial watcher setup for already-running containers.
        await asyncio.get_event_loop().run_in_executor(None, self._setup_watchers)

        try:
            await asyncio.gather(
                self._event_dispatch_loop(),
                self._periodic_hash_check(),
            )
        except asyncio.CancelledError:
            raise
        finally:
            if self._observer and self._observer.is_alive():
                self._observer.stop()
                self._observer.join(timeout=5)
            logger.info("FilesystemMonitor stopped.")

    # ------------------------------------------------------------------
    # Watcher setup
    # ------------------------------------------------------------------

    def _setup_watchers(self) -> None:
        """
        Synchronous (runs in executor).  Discovers all running monitored
        containers and adds watchdog watchers for their critical paths.
        """
        try:
            containers = self._docker.containers.list()
        except docker.errors.DockerException as exc:
            logger.error("Failed to list containers for FS watcher setup: %s", exc)
            return

        for container in containers:
            container_name = container.name
            labels = container.labels or {}
            project = self._registry.get(container_name, labels)
            if project is None or not project.monitor_filesystem:
                continue
            self._add_watchers_for_container(container_name, container.id, project)

    def _add_watchers_for_container(
        self,
        container_name: str,
        container_id: str,
        project: ProjectConfig,
    ) -> None:
        """
        Synchronous helper.  Resolves watch paths and registers watchdog
        handlers.  Safe to call from any thread.
        """
        with self._watches_lock:
            if container_name in self._watched_containers:
                return

            watch_paths = self._get_watch_paths(container_id, project)
            if not watch_paths:
                logger.debug(
                    "No accessible bind-mount watch paths for %s; "
                    "will rely on periodic hash checks.",
                    container_name,
                )
                self._watched_containers.add(container_name)
                self._watches[container_name] = []
                return

            container_watches = []
            for host_path, watch_type in watch_paths:
                if not os.path.isdir(host_path):
                    logger.debug(
                        "Watch path does not exist on host: %s (container %s)",
                        host_path, container_name,
                    )
                    continue
                handler = _FSEventHandler(
                    event_queue=self._event_queue,
                    container_name=container_name,
                    project=project,
                    watch_type=watch_type,
                )
                try:
                    watch = self._observer.schedule(handler, host_path, recursive=True)
                    container_watches.append(watch)
                    logger.info(
                        "Watching %s for container %s (type=%s).",
                        host_path, container_name, watch_type,
                    )
                except Exception as exc:
                    logger.error(
                        "Failed to schedule watchdog watch on %s: %s", host_path, exc
                    )

            self._watches[container_name] = container_watches
            self._watched_containers.add(container_name)

    def _get_watch_paths(
        self,
        container_id: str,
        project: ProjectConfig,
    ) -> List[Tuple[str, str]]:
        """
        Inspect container mounts and build a list of (host_path, watch_type)
        tuples for all critical paths that have an accessible host bind mount.

        Returns an empty list if the container has no relevant bind mounts or
        if they cannot be mapped to host paths.
        """
        try:
            container = self._docker.containers.get(container_id)
            mounts: list = container.attrs.get("Mounts", [])
        except docker.errors.NotFound:
            return []
        except docker.errors.DockerException as exc:
            logger.warning("Docker error inspecting mounts for %s: %s", container_id, exc)
            return []

        # Build a mapping: container_path → host_source
        # Only bind mounts (type="bind") have a reliable host path.
        bind_mounts: Dict[str, str] = {}
        for mount in mounts:
            if mount.get("Type") == "bind":
                container_dest = mount.get("Destination", "").rstrip("/")
                host_source = mount.get("Source", "").rstrip("/")
                if container_dest and host_source:
                    bind_mounts[container_dest] = host_source

        if not bind_mounts:
            return []

        # Determine which critical paths apply to this project type.
        critical_paths: List[str] = list(project.custom_critical_paths)
        if project.project_type == "wordpress":
            critical_paths = WORDPRESS_CRITICAL_PATHS + critical_paths
        elif project.project_type == "laravel":
            critical_paths = LARAVEL_CRITICAL_PATHS + critical_paths

        app_root = project.app_root_in_container.rstrip("/")
        host_root = self._config.host_root.rstrip("/")

        result: List[Tuple[str, str]] = []
        seen_paths: Set[str] = set()

        for critical_path in critical_paths:
            container_full = f"{app_root}/{critical_path}"

            # Try to find a bind mount that covers this path.
            host_path = _resolve_host_path(container_full, bind_mounts, host_root)
            if host_path is None:
                continue

            if host_path in seen_paths:
                continue
            seen_paths.add(host_path)

            # Classify the watch type.
            if "upload" in critical_path.lower():
                watch_type = WATCH_TYPE_UPLOADS
            elif critical_path.endswith(
                (".php", ".env", ".htaccess", "wp-config.php", ".env", "config")
            ):
                watch_type = WATCH_TYPE_CRITICAL
            else:
                watch_type = WATCH_TYPE_CRITICAL

            result.append((host_path, watch_type))

        return result

    # ------------------------------------------------------------------
    # Real-time event handling (inotify via watchdog)
    # ------------------------------------------------------------------

    async def _event_dispatch_loop(self) -> None:
        """
        Polls the thread-safe event queue and dispatches events to the async
        handler.  Uses a 100 ms sleep to yield control to the event loop.
        """
        while True:
            try:
                # Drain the queue in batches to reduce overhead.
                batch: List[dict] = []
                try:
                    while len(batch) < 100:
                        batch.append(self._event_queue.get_nowait())
                except queue.Empty:
                    pass

                for event_dict in batch:
                    try:
                        await self._on_fs_event(event_dict)
                    except asyncio.CancelledError:
                        raise
                    except Exception as exc:
                        logger.error(
                            "Error processing FS event for %s: %s",
                            event_dict.get("src_path"), exc, exc_info=True,
                        )

            except asyncio.CancelledError:
                raise
            except Exception as exc:
                logger.error("Unexpected error in event dispatch loop: %s", exc, exc_info=True)

            await asyncio.sleep(0.1)

    async def _on_fs_event(self, event_dict: dict) -> None:
        """
        Process a single filesystem event dict produced by _FSEventHandler.

        Raises alerts for:
          - PHP/script files created in upload directories.
          - Critical files modified outside a deployment window.
        """
        action: str = event_dict.get("action", "")
        src_path: str = event_dict.get("src_path", "")
        container_name: str = event_dict.get("container_name", "")
        project: Optional[ProjectConfig] = event_dict.get("project")
        watch_type: str = event_dict.get("watch_type", WATCH_TYPE_GENERIC)

        if not src_path or not container_name or project is None:
            return

        filename = os.path.basename(src_path)

        # Skip paths the project explicitly excludes.
        for exclude in (project.exclude_paths or []):
            if exclude in src_path:
                logger.debug("Skipping excluded path: %s", src_path)
                return

        # --- Upload directory: new PHP / script file ---
        if watch_type == WATCH_TYPE_UPLOADS and action == "created":
            if has_suspicious_extension(filename, FORBIDDEN_UPLOAD_EXTENSIONS):
                logger.alert(
                    "PHP/script file created in uploads: %s (container %s)",
                    src_path, container_name,
                )
                evidence = {
                    "container": container_name,
                    "path": src_path,
                    "filename": filename,
                    "action": action,
                    "watch_type": watch_type,
                    "reason": "Executable/script file created in upload directory",
                }
                await self._alert_manager.raise_alert(
                    project=project,
                    container_name=container_name,
                    container_id="",
                    alert_type="FILESYSTEM_PHP_UPLOAD",
                    severity="high",
                    rule="Dangerous file type in upload directory",
                    evidence=evidence,
                    dedup_extra=src_path,
                )
                return

        # --- Critical file modified ---
        if watch_type in (WATCH_TYPE_CRITICAL, WATCH_TYPE_GENERIC):
            in_window = in_deployment_window(project.deployment_windows)
            if in_window:
                logger.debug(
                    "File change in deployment window, not alerting: %s", src_path
                )
                return

            logger.alert(
                "Critical file %s outside deployment window: %s (container %s)",
                action, src_path, container_name,
            )
            evidence = {
                "container": container_name,
                "path": src_path,
                "filename": filename,
                "action": action,
                "watch_type": watch_type,
                "in_deployment_window": False,
                "reason": f"Critical file {action} outside deployment window",
            }
            await self._alert_manager.raise_alert(
                project=project,
                container_name=container_name,
                container_id="",
                alert_type="FILESYSTEM_CHANGE",
                severity="medium",
                rule="Critical file modified outside deployment window",
                evidence=evidence,
                dedup_extra=src_path,
            )

    # ------------------------------------------------------------------
    # Periodic hash / permission checks (docker exec fallback)
    # ------------------------------------------------------------------

    async def _periodic_hash_check(self) -> None:
        """
        Periodic loop that checks critical files via docker exec for containers
        that do not have accessible bind-mount paths.
        """
        interval = self._config.fs_permission_check_interval
        logger.info("Periodic FS hash check loop started (interval=%ds).", interval)

        while True:
            await asyncio.sleep(interval)
            try:
                await self._run_hash_checks()
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                logger.error("Error in periodic hash check: %s", exc, exc_info=True)

    async def _run_hash_checks(self) -> None:
        """Iterate all monitored containers and check permissions/hashes."""
        loop = asyncio.get_event_loop()
        try:
            containers = await loop.run_in_executor(
                None, lambda: self._docker.containers.list()
            )
        except docker.errors.DockerException as exc:
            logger.error("Could not list containers for hash check: %s", exc)
            return

        for container in containers:
            container_name = container.name
            labels = container.labels or {}
            project = self._registry.get(container_name, labels)
            if project is None or not project.monitor_filesystem:
                continue

            try:
                await self._check_container_permissions(
                    container_name, container.id, project
                )
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                logger.error(
                    "Error in hash check for container %s: %s",
                    container_name, exc, exc_info=True,
                )

    async def _check_container_permissions(
        self,
        container_name: str,
        container_id: str,
        project: ProjectConfig,
    ) -> None:
        """
        Check file metadata (mtime, size, permissions, owner) for critical
        paths inside a container using docker exec.

        For each critical path:
          1. Run `stat -c "%Y %s %a %U" <file>` inside the container.
          2. Compare to the stored FilesystemSnapshot.
          3. If changed outside deployment window → FILESYSTEM_CHANGE alert.
          4. If permissions are too open → FILESYSTEM_CHANGE (permission) alert.
        """
        loop = asyncio.get_event_loop()

        critical_paths: List[str] = list(project.custom_critical_paths)
        if project.project_type == "wordpress":
            critical_paths = WORDPRESS_CRITICAL_PATHS + critical_paths
        elif project.project_type == "laravel":
            critical_paths = LARAVEL_CRITICAL_PATHS + critical_paths

        if not critical_paths:
            return

        app_root = project.app_root_in_container.rstrip("/")

        for rel_path in critical_paths:
            # Skip upload directories for this check (watchdog handles those)
            if "upload" in rel_path.lower():
                continue

            full_path = f"{app_root}/{rel_path}"

            stat_output = await loop.run_in_executor(
                None,
                lambda p=full_path, cid=container_id: _docker_exec_stat(
                    self._docker, cid, p
                ),
            )
            if stat_output is None:
                continue

            # stat -c "%Y %s %a %U" outputs: mtime_epoch size_bytes octal_perms owner
            parts = stat_output.strip().split()
            if len(parts) < 4:
                logger.debug(
                    "Unexpected stat output for %s in %s: %r",
                    full_path, container_name, stat_output,
                )
                continue

            mtime_str = parts[0]
            size_str = parts[1]
            perm_octal = parts[2]   # e.g. "640" or "644"
            owner = parts[3]

            try:
                size_bytes = int(size_str)
            except ValueError:
                size_bytes = None

            # Check permissions on sensitive files
            perm_alert = False
            if rel_path in ("wp-config.php", ".env", "config/database.php"):
                try:
                    # perm_octal is in human octal notation like "644"; check
                    # the "other" read bit.
                    perm_int = int(perm_octal, 8)
                    if perm_int & _WORLD_READABLE_MASK:
                        perm_alert = True
                except ValueError:
                    pass

            # Upsert the snapshot and check for changes.
            changed: bool = await loop.run_in_executor(
                None,
                lambda: self._repo.upsert_snapshot(
                    container_name=container_name,
                    file_path=full_path,
                    sha256=None,        # docker exec stat does not give us a hash cheaply
                    mtime=mtime_str,
                    size_bytes=size_bytes,
                    permissions=perm_octal,
                    owner=owner,
                ),
            )

            if changed and not in_deployment_window(project.deployment_windows):
                evidence = {
                    "container": container_name,
                    "path": full_path,
                    "mtime": mtime_str,
                    "size_bytes": size_bytes,
                    "permissions": perm_octal,
                    "owner": owner,
                    "reason": "File metadata changed outside deployment window",
                }
                logger.alert(
                    "Critical file changed: %s in %s (mtime=%s, perm=%s)",
                    full_path, container_name, mtime_str, perm_octal,
                )
                await self._alert_manager.raise_alert(
                    project=project,
                    container_name=container_name,
                    container_id=container_id,
                    alert_type="FILESYSTEM_CHANGE",
                    severity="medium",
                    rule="Critical file changed (periodic check)",
                    evidence=evidence,
                    dedup_extra=full_path,
                )

            if perm_alert:
                evidence = {
                    "container": container_name,
                    "path": full_path,
                    "permissions": perm_octal,
                    "owner": owner,
                    "reason": (
                        f"Sensitive file {rel_path!r} is world-readable "
                        f"(permissions={perm_octal})"
                    ),
                }
                logger.alert(
                    "World-readable sensitive file: %s in %s (perm=%s)",
                    full_path, container_name, perm_octal,
                )
                await self._alert_manager.raise_alert(
                    project=project,
                    container_name=container_name,
                    container_id=container_id,
                    alert_type="FILESYSTEM_CHANGE",
                    severity="medium",
                    rule="Sensitive file has insecure permissions",
                    evidence=evidence,
                    dedup_extra=f"perm:{full_path}",
                )

    # ------------------------------------------------------------------
    # Dynamic watcher management (called from docker_events module)
    # ------------------------------------------------------------------

    def add_container_watcher(
        self,
        container_name: str,
        container_id: str,
        project: ProjectConfig,
    ) -> None:
        """
        Add watchdog watchers for a newly started container.
        Called from the Docker events monitor on container start events.
        This method is thread-safe and synchronous (safe to call from any
        thread or coroutine via run_in_executor).
        """
        if self._observer is None or not self._observer.is_alive():
            logger.warning(
                "Observer not running; cannot add watcher for %s.", container_name
            )
            return
        logger.info("Adding FS watcher for new container: %s", container_name)
        self._add_watchers_for_container(container_name, container_id, project)

    def remove_container_watcher(self, container_name: str) -> None:
        """
        Remove all watchdog watchers for a stopped/removed container.
        Called from the Docker events monitor on container stop/die events.
        This method is thread-safe and synchronous.
        """
        with self._watches_lock:
            watches = self._watches.pop(container_name, [])
            self._watched_containers.discard(container_name)

        if self._observer is None:
            return

        for watch in watches:
            try:
                self._observer.unschedule(watch)
                logger.info("Removed FS watcher for container: %s", container_name)
            except Exception as exc:
                logger.warning(
                    "Could not unschedule watcher for %s: %s", container_name, exc
                )


# ---------------------------------------------------------------------------
# Module-level helpers
# ---------------------------------------------------------------------------

def _resolve_host_path(
    container_path: str,
    bind_mounts: Dict[str, str],
    host_root: str,
) -> Optional[str]:
    """
    Given a full container path and the dict of bind mount mappings, return
    the corresponding host filesystem path (prefixed with host_root), or None
    if no bind mount covers this path.

    Example:
        container_path = "/var/www/html/wp-content/uploads"
        bind_mounts    = {"/var/www/html": "/data/docker/volumes/mysite_www"}
        host_root      = "/host"
        → "/host/data/docker/volumes/mysite_www/wp-content/uploads"
    """
    # Sort by mount depth (longest prefix first) for most-specific match.
    sorted_mounts = sorted(bind_mounts.items(), key=lambda kv: len(kv[0]), reverse=True)

    for container_mount, host_source in sorted_mounts:
        if container_path == container_mount or container_path.startswith(
            container_mount + "/"
        ):
            relative = container_path[len(container_mount):]
            host_path = host_root.rstrip("/") + host_source + relative
            return host_path

    return None


def _docker_exec_stat(
    docker_client: docker.DockerClient,
    container_id: str,
    file_path: str,
) -> Optional[str]:
    """
    Run `stat -c "%Y %s %a %U" <file_path>` inside the container and return
    the raw stdout string, or None on any failure.

    This is a synchronous blocking call; it must be run in an executor.
    """
    try:
        container = docker_client.containers.get(container_id)
        exit_code, output = container.exec_run(
            cmd=["stat", "-c", "%Y %s %a %U", file_path],
            stdout=True,
            stderr=False,
            demux=False,
        )
        if exit_code != 0:
            # File may not exist inside the container; not an error.
            return None
        if isinstance(output, bytes):
            return output.decode("utf-8", errors="replace").strip()
        return str(output).strip() if output else None
    except docker.errors.NotFound:
        logger.debug("Container %s not found during exec_stat.", container_id)
        return None
    except docker.errors.DockerException as exc:
        logger.warning(
            "docker exec_stat failed for %s in %s: %s", file_path, container_id, exc
        )
        return None
    except Exception as exc:
        logger.warning(
            "Unexpected error in _docker_exec_stat for %s: %s", file_path, exc
        )
        return None
