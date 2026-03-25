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

logger = logging.getLogger("centinela.main")


async def startup_audit(
    security_monitor: SecurityAuditMonitor,
    fs_monitor: FilesystemMonitor,
    docker_client,
    registry: ProjectRegistry,
    alert_manager: AlertManager,
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

    for container in running_containers:
        container_name = container.name
        project = registry.find_project(container)

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
            await security_monitor.audit_container(container, project)
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
            await fs_monitor.add_watcher(container, project)
        except Exception as exc:
            logger.error(
                "Failed to register filesystem watcher for container %s: %s",
                container_name,
                exc,
            )

    logger.info("Startup audit complete (%d containers inspected).", len(running_containers))


def _build_shutdown_handler(tasks, executor, loop):
    """Return a signal handler that cancels all running tasks gracefully."""

    def _handler(signum, frame):
        sig_name = signal.Signals(signum).name
        logger.info("Received %s – initiating graceful shutdown...", sig_name)

        for task in tasks:
            task.cancel()

        # Ask the executor to stop accepting new work
        executor.shutdown(wait=False)

        # Stop the loop after tasks are cancelled
        loop.call_soon_threadsafe(loop.stop)

    return _handler


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
    setup_logging(config)
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
    repository = IncidentRepository(config)
    await repository.initialise()
    logger.info("Incident repository initialised.")

    alert_manager = AlertManager(config)
    logger.info("Alert manager initialised.")

    registry = ProjectRegistry(config)
    await registry.load()
    logger.info(
        "Project registry loaded – %d project(s) tracked.", registry.project_count()
    )

    # ------------------------------------------------------------------ #
    # 5. Instantiate all monitors
    # ------------------------------------------------------------------ #
    docker_event_monitor = DockerEventMonitor(
        docker_client=docker_client,
        config=config,
        registry=registry,
        repository=repository,
        alert_manager=alert_manager,
    )

    process_monitor = ProcessMonitor(
        docker_client=docker_client,
        config=config,
        registry=registry,
        repository=repository,
        alert_manager=alert_manager,
    )

    network_monitor = NetworkMonitor(
        docker_client=docker_client,
        config=config,
        registry=registry,
        repository=repository,
        alert_manager=alert_manager,
    )

    fs_monitor = FilesystemMonitor(
        docker_client=docker_client,
        config=config,
        registry=registry,
        repository=repository,
        alert_manager=alert_manager,
    )

    security_monitor = SecurityAuditMonitor(
        docker_client=docker_client,
        config=config,
        registry=registry,
        repository=repository,
        alert_manager=alert_manager,
    )

    # ------------------------------------------------------------------ #
    # 6. Wire monitors together via DockerEventMonitor callbacks
    # ------------------------------------------------------------------ #

    # exec events  → immediate process check
    docker_event_monitor.register_exec_callback(process_monitor.on_exec_event)

    # container start/stop/die → add/remove filesystem watchers dynamically
    docker_event_monitor.register_start_callback(fs_monitor.add_watcher)
    docker_event_monitor.register_stop_callback(fs_monitor.remove_watcher)

    # container start → run security audit on the newly started container
    docker_event_monitor.register_start_callback(security_monitor.on_container_start)

    logger.info("Monitor cross-wiring complete.")

    # ------------------------------------------------------------------ #
    # 7. Startup audit on already-running containers
    # ------------------------------------------------------------------ #
    await startup_audit(
        security_monitor=security_monitor,
        fs_monitor=fs_monitor,
        docker_client=docker_client,
        registry=registry,
        alert_manager=alert_manager,
    )

    # ------------------------------------------------------------------ #
    # 8. Build async tasks and run concurrently
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
        registry.project_count(),
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
        try:
            await repository.close()
        except Exception as exc:
            logger.warning("Repository close error: %s", exc)
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
