#!/usr/bin/env python3
"""
CENTINELA – Docker Security Monitor
Entry point: starts all monitors and keeps them running.
"""
import asyncio
import logging
import os
import signal
import sys
from concurrent.futures import ThreadPoolExecutor

import docker

# Add src to path
sys.path.insert(0, os.path.dirname(__file__))

from config.loader import load_config, ProjectRegistry
from database.repository import IncidentRepository
from alerts.manager import AlertManager
from monitors.docker_events import DockerEventMonitor
from monitors.process_monitor import ProcessMonitor
from monitors.network_monitor import NetworkMonitor
from monitors.filesystem_monitor import FilesystemMonitor
from monitors.security_audit import SecurityAuditMonitor
from logging_manager.logger import setup_logging
from web.panel_app import create_panel_app, run_panel_server

logger = logging.getLogger("centinela.main")


async def startup_audit(
    security_monitor: SecurityAuditMonitor,
    fs_monitor: FilesystemMonitor,
    docker_client,
    registry: ProjectRegistry,
) -> None:
    """
    Run a security audit and set up filesystem watchers for all containers
    that are already running at Centinela startup time.
    """
    logger.info("Running startup audit on all currently running containers...")
    try:
        running_containers = docker_client.containers.list()
    except Exception as exc:
        logger.error("Failed to list running containers during startup audit: %s", exc)
        return

    loop = asyncio.get_event_loop()

    for container in running_containers:
        container_name = container.name
        # BUG FIX: was registry.find_project(container) – correct method is get()
        project = registry.get(container_name, container.labels or {})

        if project is None:
            logger.debug(
                "Container %s is not tracked by any project – skipping startup audit.",
                container_name,
            )
            continue

        # Security audit
        try:
            logger.info(
                "Startup: running security audit for container %s (project: %s)",
                container_name,
                project.name,
            )
            # BUG FIX: was audit_container(container, project) – correct signature is (name, id, project)
            await security_monitor.audit_container(container.name, container.id, project)
        except Exception as exc:
            logger.error(
                "Startup audit failed for container %s: %s", container_name, exc
            )

        # Filesystem watcher registration
        try:
            logger.info(
                "Startup: registering filesystem watchers for container %s (project: %s)",
                container_name,
                project.name,
            )
            # BUG FIX: was await fs_monitor.add_watcher(container, project)
            # Correct method is add_container_watcher(name, id, project) – synchronous, run in executor
            await loop.run_in_executor(
                None,
                fs_monitor.add_container_watcher,
                container.name,
                container.id,
                project,
            )
        except Exception as exc:
            logger.error(
                "Failed to register filesystem watcher for container %s: %s",
                container_name,
                exc,
            )

    logger.info("Startup audit complete (%d containers inspected).", len(running_containers))


async def main() -> None:
    # ------------------------------------------------------------------ #
    # 1. Load configuration
    # ------------------------------------------------------------------ #
    config_path = os.environ.get("CENTINELA_CONFIG", "/app/config/centinela.yml")
    logger.info("Loading configuration from: %s", config_path)
    config = load_config(config_path)

    # ------------------------------------------------------------------ #
    # 2. Setup logging
    # ------------------------------------------------------------------ #
    # BUG FIX: was setup_logging(config) – setup_logging expects a str (log_dir), not GlobalConfig
    setup_logging(config.log_dir)
    logger.info("CENTINELA starting up – logging initialised.")

    # ------------------------------------------------------------------ #
    # 3. Create Docker client
    # ------------------------------------------------------------------ #
    try:
        docker_client = docker.from_env()
        docker_client.ping()
        logger.info("Docker client connected successfully.")
    except Exception as exc:
        logger.critical("Cannot connect to Docker daemon: %s", exc)
        sys.exit(1)

    # ------------------------------------------------------------------ #
    # 4. Core infrastructure
    # ------------------------------------------------------------------ #
    # BUG FIX: was IncidentRepository(config) – expects db_url:str, not GlobalConfig
    repository = IncidentRepository(config.db_url)
    # BUG FIX: await repository.initialise() removed – DB is created in __init__, no async init needed
    logger.info("Incident repository initialised.")

    # BUG FIX: was AlertManager(config) – constructor requires (config, repo)
    alert_manager = AlertManager(config, repository)
    logger.info("Alert manager initialised.")

    # BUG FIX: was ProjectRegistry(config) – constructor expects projects:list, not GlobalConfig
    # BUG FIX: await registry.load() removed – ProjectRegistry has no load() method; sync build
    registry = ProjectRegistry(config.projects)
    logger.info(
        "Project registry loaded – %d project(s) tracked.",
        # BUG FIX: was registry.project_count() – no such method; use len(all_projects())
        len(registry.all_projects()),
    )

    # ------------------------------------------------------------------ #
    # 5. Instantiate all monitors
    # ------------------------------------------------------------------ #
    # BUG FIX: DockerEventMonitor.__init__ signature is (config, registry, alert_manager, executor=None)
    # It does NOT accept docker_client or repository – removed those kwargs
    docker_event_monitor = DockerEventMonitor(
        config=config,
        registry=registry,
        alert_manager=alert_manager,
        docker_client=docker_client,
    )

    # BUG FIX: ProcessMonitor.__init__ signature is (config, registry, alert_manager, docker_client)
    # It does NOT accept repository – removed that kwarg
    process_monitor = ProcessMonitor(
        config=config,
        registry=registry,
        alert_manager=alert_manager,
        docker_client=docker_client,
    )

    network_monitor = NetworkMonitor(
        config=config,
        registry=registry,
        alert_manager=alert_manager,
        repo=repository,
        docker_client=docker_client,
    )

    fs_monitor = FilesystemMonitor(
        config=config,
        registry=registry,
        alert_manager=alert_manager,
        repo=repository,
        docker_client=docker_client,
    )

    # BUG FIX: SecurityAuditMonitor.__init__ signature is (config, registry, alert_manager, docker_client)
    # It does NOT accept repository – removed that kwarg
    security_monitor = SecurityAuditMonitor(
        config=config,
        registry=registry,
        alert_manager=alert_manager,
        docker_client=docker_client,
    )

    # ------------------------------------------------------------------ #
    # 6. Wire monitors together via DockerEventMonitor callbacks
    # ------------------------------------------------------------------ #
    # BUG FIX: register_exec_callback / register_start_callback / register_stop_callback
    # did not exist in DockerEventMonitor – they have been added to docker_events.py.
    # Callback names and signatures have also been corrected:
    #   - process_monitor.on_exec_event  → process_monitor.trigger_immediate_check(name)
    #   - fs_monitor.add_watcher         → fs_monitor.add_container_watcher(name, id, project)  [sync]
    #   - fs_monitor.remove_watcher      → fs_monitor.remove_container_watcher(name)              [sync]
    #   - security_monitor.on_container_start → security_monitor.audit_container(name, id, project)

    # exec_start → trigger immediate process scan (ProcessMonitor has trigger_immediate_check)
    docker_event_monitor.register_exec_callback(
        process_monitor.trigger_immediate_check   # async (container_name: str)
    )

    # container start → add FS watcher + run security audit
    async def _on_container_start(container_name: str, container_id: str, project) -> None:
        if project is None:
            return
        loop = asyncio.get_event_loop()
        # add_container_watcher is synchronous (thread-safe) → run in executor
        await loop.run_in_executor(
            None,
            fs_monitor.add_container_watcher,
            container_name,
            container_id,
            project,
        )
        await security_monitor.audit_container(container_name, container_id, project)

    docker_event_monitor.register_start_callback(_on_container_start)

    # container stop/die → remove FS watcher
    async def _on_container_stop(container_name: str) -> None:
        loop = asyncio.get_event_loop()
        await loop.run_in_executor(
            None,
            fs_monitor.remove_container_watcher,
            container_name,
        )

    docker_event_monitor.register_stop_callback(_on_container_stop)

    logger.info("Monitor cross-wiring complete.")

    # ------------------------------------------------------------------ #
    # 7. Start filesystem observer early so startup audit can register watchers
    # ------------------------------------------------------------------ #
    fs_monitor.start_observer()

    # ------------------------------------------------------------------ #
    # 8. Startup audit on already-running containers
    # ------------------------------------------------------------------ #
    await startup_audit(
        security_monitor=security_monitor,
        fs_monitor=fs_monitor,
        docker_client=docker_client,
        registry=registry,
    )

    # ------------------------------------------------------------------ #
    # 9. Build async tasks and run concurrently
    # ------------------------------------------------------------------ #
    loop = asyncio.get_running_loop()
    executor = ThreadPoolExecutor(max_workers=8, thread_name_prefix="centinela")
    loop.set_default_executor(executor)

    monitor_tasks = [
        asyncio.create_task(docker_event_monitor.run(), name="docker-events"),
        asyncio.create_task(process_monitor.run(), name="process-monitor"),
        asyncio.create_task(network_monitor.run(), name="network-monitor"),
        asyncio.create_task(fs_monitor.run(), name="filesystem-monitor"),
        asyncio.create_task(security_monitor.run(), name="security-audit"),
    ]

    # ------------------------------------------------------------------ #
    # 11. Web panel (FastAPI) for logs/incidents/config overrides
    # ------------------------------------------------------------------ #
    overrides_path = os.environ.get("CENTINELA_OVERRIDES_PATH", "/app/data/config_overrides.yml")
    panel_app = create_panel_app(
        repository=repository,
        config_path=config_path,
        log_dir=config.log_dir,
        overrides_path=overrides_path,
    )
    monitor_tasks.append(
        asyncio.create_task(run_panel_server(panel_app), name="web-panel")
    )

    # ------------------------------------------------------------------ #
    # 9. Graceful shutdown via SIGTERM / SIGINT
    # ------------------------------------------------------------------ #
    def _graceful_shutdown(signum, frame):
        sig_name = signal.Signals(signum).name
        logger.info("Received %s – cancelling monitor tasks...", sig_name)
        for task in monitor_tasks:
            task.cancel()

    signal.signal(signal.SIGTERM, _graceful_shutdown)
    signal.signal(signal.SIGINT, _graceful_shutdown)

    logger.info(
        "All monitors started. CENTINELA is watching %d project(s).",
        len(registry.all_projects()),
    )

    # ------------------------------------------------------------------ #
    # 10. Wait for all tasks; handle cancellation cleanly
    # ------------------------------------------------------------------ #
    try:
        results = await asyncio.gather(*monitor_tasks, return_exceptions=True)
        for task, result in zip(monitor_tasks, results):
            if isinstance(result, asyncio.CancelledError):
                logger.info("Task '%s' cancelled cleanly.", task.get_name())
            elif isinstance(result, Exception):
                logger.error(
                    "Task '%s' raised an exception: %s", task.get_name(), result
                )
    except asyncio.CancelledError:
        logger.info("Main gather cancelled – shutting down.")
    finally:
        logger.info("Cleaning up resources...")
        # BUG FIX: await repository.close() removed – IncidentRepository has no close() method
        try:
            docker_client.close()
        except Exception as exc:
            logger.warning("Docker client close error: %s", exc)
        executor.shutdown(wait=True)
        logger.info("CENTINELA shutdown complete. Goodbye.")


if __name__ == "__main__":
    # Bootstrap logging before config is loaded so we can log startup errors
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s – %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S",
    )
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
    except Exception as exc:
        logging.critical("Fatal error in CENTINELA main: %s", exc, exc_info=True)
        sys.exit(1)
