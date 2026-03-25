"""
CENTINELA – Network Monitor.

Monitors per-container network traffic volume and outbound connection
destinations, raising alerts on bandwidth spikes and new destinations.

Two main loops (both run on the same configurable interval):
  1. Traffic volume: samples container stats, calculates deltas, compares to
     rolling average, and raises NETWORK_SPIKE alerts.
  2. Connection destinations: reads /proc/net/tcp from the container's network
     namespace, upserts known destinations, and raises NETWORK_NEW_DEST alerts
     for newly-seen IPs (once the baseline learning period has elapsed).
"""

import asyncio
import logging
import os
from datetime import datetime, timedelta, timezone

def _utcnow() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)
from typing import Dict, List, Optional, Tuple

import docker
import docker.errors

from alerts.manager import AlertManager
from config.loader import ProjectRegistry
from config.models import GlobalConfig, ProjectConfig
from database.models import NetworkSample
from database.repository import IncidentRepository
from utils.helpers import build_dedup_key, parse_proc_net_tcp

logger = logging.getLogger("centinela.monitors.network")

# Minimum number of historical samples required before spike detection
# is meaningful.  Below this threshold we skip spike checks to avoid
# false positives during the very first sampling window.
_MIN_SAMPLES_FOR_SPIKE = 5

# How many days of samples to keep (in hours).
_PRUNE_OLDER_THAN_HOURS = 336  # 14 days

# How often (in intervals) we trigger the pruning routine.
# With a 5-minute interval this means prune every 7 days.
_PRUNE_EVERY_N_INTERVALS = int((7 * 24 * 60 * 60) / 300)  # ~2016


class NetworkMonitor:
    """
    Monitors network traffic and connection destinations for all registered
    containers.

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

        # In-memory store of the last raw cumulative stats snapshot per
        # container.  Key: container_name, value: dict with keys
        # "bytes_rx", "bytes_tx", "packets_rx", "packets_tx", "ts".
        self._last_stats: Dict[str, dict] = {}

        # Counter used to schedule periodic pruning without adding a separate
        # loop.
        self._interval_counter: int = 0

    # ------------------------------------------------------------------
    # Main loop
    # ------------------------------------------------------------------

    async def run(self) -> None:
        """
        Periodic sampling loop.  Runs until the task is cancelled.
        """
        interval = self._config.network_sample_interval
        logger.info(
            "NetworkMonitor started (interval=%ds, host_root=%s).",
            interval,
            self._config.host_root,
        )

        while True:
            try:
                await self._sample_all_containers()
            except asyncio.CancelledError:
                raise
            except Exception as exc:  # pragma: no cover
                logger.error("Unexpected error in NetworkMonitor.run(): %s", exc, exc_info=True)

            await asyncio.sleep(interval)

    # ------------------------------------------------------------------
    # Container discovery and per-container dispatch
    # ------------------------------------------------------------------

    async def _sample_all_containers(self) -> None:
        """
        Discover all running containers, match against the registry, and
        sample each monitored container.
        """
        self._interval_counter += 1

        loop = asyncio.get_event_loop()
        try:
            containers = await loop.run_in_executor(
                None, lambda: self._docker.containers.list()
            )
        except docker.errors.DockerException as exc:
            logger.error("Failed to list Docker containers: %s", exc)
            return

        for container in containers:
            container_name = container.name
            labels = container.labels or {}
            project = self._registry.get(container_name, labels)

            if project is None or not project.monitor_network:
                continue

            try:
                await self._sample_container(container_name, container.id, project)
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                logger.error(
                    "Error sampling container %s: %s", container_name, exc, exc_info=True
                )

        # Periodic pruning (every _PRUNE_EVERY_N_INTERVALS intervals)
        if self._interval_counter % _PRUNE_EVERY_N_INTERVALS == 0:
            await self._prune_old_samples()

    async def _sample_container(
        self,
        container_name: str,
        container_id: str,
        project: ProjectConfig,
    ) -> None:
        """
        Run both traffic and connection checks for a single container.
        """
        loop = asyncio.get_event_loop()

        # Fetch raw Docker stats (non-streaming, single snapshot)
        try:
            container_obj = await loop.run_in_executor(
                None, lambda: self._docker.containers.get(container_id)
            )
            stats = await loop.run_in_executor(
                None, lambda: container_obj.stats(stream=False)
            )
        except docker.errors.NotFound:
            logger.debug("Container %s no longer exists, skipping.", container_name)
            return
        except docker.errors.DockerException as exc:
            logger.warning("Could not get stats for %s: %s", container_name, exc)
            return

        await self._check_traffic(container_name, stats, project)
        await self._check_connections(container_name, container_id, project)

    # ------------------------------------------------------------------
    # Traffic volume monitoring
    # ------------------------------------------------------------------

    async def _check_traffic(
        self,
        container_name: str,
        stats: dict,
        project: ProjectConfig,
    ) -> None:
        """
        Calculate per-interval traffic deltas, persist a sample, and raise
        a NETWORK_SPIKE alert if the delta exceeds configured thresholds.

        Docker stats provides cumulative counters; we compute deltas by
        subtracting the previous sample stored in self._last_stats.
        """
        loop = asyncio.get_event_loop()

        # Extract cumulative counters from Docker stats payload.
        # The path in the stats JSON is networks.<iface>.rx_bytes etc.
        # If the container has multiple interfaces, sum them all.
        networks: dict = stats.get("networks", {})
        if not networks:
            # Older Docker versions use a flat "network" key
            net_single = stats.get("network", {})
            if net_single:
                networks = {"eth0": net_single}

        total_bytes_rx: int = 0
        total_bytes_tx: int = 0
        total_packets_rx: int = 0
        total_packets_tx: int = 0

        for iface_stats in networks.values():
            total_bytes_rx += int(iface_stats.get("rx_bytes", 0))
            total_bytes_tx += int(iface_stats.get("tx_bytes", 0))
            total_packets_rx += int(iface_stats.get("rx_packets", 0))
            total_packets_tx += int(iface_stats.get("tx_packets", 0))

        now = _utcnow()

        # If we have a previous sample, compute deltas; otherwise bootstrap.
        prev = self._last_stats.get(container_name)
        if prev is None:
            logger.debug(
                "Bootstrap network baseline for %s (rx=%d tx=%d).",
                container_name, total_bytes_rx, total_bytes_tx,
            )
            self._last_stats[container_name] = {
                "bytes_rx": total_bytes_rx,
                "bytes_tx": total_bytes_tx,
                "packets_rx": total_packets_rx,
                "packets_tx": total_packets_tx,
                "ts": now,
            }
            return

        delta_rx = max(0, total_bytes_rx - prev["bytes_rx"])
        delta_tx = max(0, total_bytes_tx - prev["bytes_tx"])
        delta_pkt_rx = max(0, total_packets_rx - prev["packets_rx"])
        delta_pkt_tx = max(0, total_packets_tx - prev["packets_tx"])

        # Update the in-memory snapshot for the next iteration.
        self._last_stats[container_name] = {
            "bytes_rx": total_bytes_rx,
            "bytes_tx": total_bytes_tx,
            "packets_rx": total_packets_rx,
            "packets_tx": total_packets_tx,
            "ts": now,
        }

        # Persist the delta sample to the database.
        sample = NetworkSample(
            container_name=container_name,
            timestamp=now,
            bytes_rx=delta_rx,
            bytes_tx=delta_tx,
            packets_rx=delta_pkt_rx,
            packets_tx=delta_pkt_tx,
        )
        await loop.run_in_executor(None, self._repo.save_network_sample, sample)

        logger.debug(
            "Network sample saved: %s rx=%d tx=%d pkt_rx=%d pkt_tx=%d",
            container_name, delta_rx, delta_tx, delta_pkt_rx, delta_pkt_tx,
        )

        # Spike detection
        rolling = await loop.run_in_executor(
            None,
            lambda: self._repo.get_rolling_average(
                container_name,
                window_hours=project.network.baseline_window_hours,
            ),
        )
        sample_count: int = rolling.get("sample_count", 0)

        if sample_count < _MIN_SAMPLES_FOR_SPIKE:
            logger.debug(
                "Skipping spike check for %s (only %d samples so far).",
                container_name, sample_count,
            )
            return

        avg_rx: float = rolling.get("avg_rx", 0.0)
        avg_tx: float = rolling.get("avg_tx", 0.0)

        thresholds = project.network
        spike_multiplier = thresholds.spike_multiplier
        abs_warning = thresholds.bytes_per_minute_warning
        abs_critical = thresholds.bytes_per_minute_critical

        triggered_rx = self._evaluate_spike(delta_rx, avg_rx, spike_multiplier, abs_warning)
        triggered_tx = self._evaluate_spike(delta_tx, avg_tx, spike_multiplier, abs_warning)
        triggered_critical = (delta_rx > abs_critical or delta_tx > abs_critical)

        if not (triggered_rx or triggered_tx or triggered_critical):
            return

        severity = "critical" if triggered_critical else "high"
        reason_parts: List[str] = []

        if triggered_rx:
            reason_parts.append(
                f"RX spike: {delta_rx} bytes (avg={avg_rx:.0f}, mult={spike_multiplier}x)"
            )
        if triggered_tx:
            reason_parts.append(
                f"TX spike: {delta_tx} bytes (avg={avg_tx:.0f}, mult={spike_multiplier}x)"
            )
        if triggered_critical:
            reason_parts.append(
                f"Absolute threshold exceeded (abs_critical={abs_critical}): "
                f"rx={delta_rx} tx={delta_tx}"
            )

        evidence = {
            "container": container_name,
            "delta_bytes_rx": delta_rx,
            "delta_bytes_tx": delta_tx,
            "rolling_avg_rx": round(avg_rx, 2),
            "rolling_avg_tx": round(avg_tx, 2),
            "spike_multiplier": spike_multiplier,
            "abs_warning_threshold": abs_warning,
            "abs_critical_threshold": abs_critical,
            "reasons": reason_parts,
            "sample_count_used": sample_count,
        }

        dedup_key = build_dedup_key(container_name, "NETWORK_SPIKE")
        logger.warning(
            "NETWORK_SPIKE detected on %s: %s", container_name, "; ".join(reason_parts)
        )

        await self._alert_manager.raise_alert(
            project=project,
            container_name=container_name,
            container_id="",
            alert_type="NETWORK_SPIKE",
            severity=severity,
            rule="Network traffic spike detected",
            evidence=evidence,
            dedup_extra="spike",
        )

    @staticmethod
    def _evaluate_spike(
        delta: int,
        average: float,
        multiplier: float,
        absolute_threshold: int,
    ) -> bool:
        """
        Return True if the delta exceeds either the rolling-average spike
        threshold or the absolute per-interval threshold.
        """
        if average > 0 and delta > average * multiplier:
            return True
        if delta > absolute_threshold:
            return True
        return False

    # ------------------------------------------------------------------
    # Connection destination monitoring
    # ------------------------------------------------------------------

    async def _check_connections(
        self,
        container_name: str,
        container_id: str,
        project: ProjectConfig,
    ) -> None:
        """
        Read /proc/net/tcp from the container's network namespace (exposed via
        the host root mount), parse established connections, and alert on new
        remote IP destinations.
        """
        if not project.network.new_destination_alert:
            return

        loop = asyncio.get_event_loop()

        # Resolve the main PID of the container so we can read its /proc/net.
        main_pid: Optional[int] = await loop.run_in_executor(
            None, self._get_container_pid, container_id
        )
        if main_pid is None:
            logger.debug(
                "Could not resolve PID for container %s; skipping connection check.",
                container_name,
            )
            return

        host_root = self._config.host_root
        proc_net_tcp_path = os.path.join(
            host_root, "proc", str(main_pid), "net", "tcp"
        )
        proc_net_tcp6_path = os.path.join(
            host_root, "proc", str(main_pid), "net", "tcp6"
        )

        connections: list = []

        for path in (proc_net_tcp_path, proc_net_tcp6_path):
            if not os.path.exists(path):
                logger.debug("proc net path not found (container may be restarting): %s", path)
                continue
            try:
                content = await loop.run_in_executor(None, _read_file, path)
                connections.extend(parse_proc_net_tcp(content))
            except OSError as exc:
                logger.warning("Could not read %s: %s", path, exc)

        if not connections:
            return

        # Check baseline age to decide whether we are still in the learning
        # period (during which new destinations are just recorded, not alerted).
        baseline_age_hours: float = await loop.run_in_executor(
            None,
            lambda: self._repo.get_baseline_age_hours(container_name),
        )
        learning_period = project.network.learning_period_hours
        past_learning = baseline_age_hours > learning_period

        # Deduplicate IPs seen in this sample to avoid multiple DB round-trips
        # for the same destination when a container has many sockets open.
        seen_ips_this_sample: set = set()

        for conn in connections:
            remote_ip: str = conn.get("remote_ip", "")
            if not remote_ip or remote_ip in seen_ips_this_sample:
                continue
            seen_ips_this_sample.add(remote_ip)

            is_new: bool = await loop.run_in_executor(
                None,
                lambda ip=remote_ip: self._repo.upsert_destination(container_name, ip),
            )

            if is_new:
                logger.info(
                    "New network destination for %s: %s (baseline_age=%.1fh, learning=%s).",
                    container_name, remote_ip, baseline_age_hours,
                    "active" if not past_learning else "done",
                )

            if is_new and past_learning:
                evidence = {
                    "container": container_name,
                    "remote_ip": remote_ip,
                    "remote_port": conn.get("remote_port"),
                    "local_ip": conn.get("local_ip"),
                    "local_port": conn.get("local_port"),
                    "baseline_age_hours": round(baseline_age_hours, 2),
                    "learning_period_hours": learning_period,
                }
                await self._alert_manager.raise_alert(
                    project=project,
                    container_name=container_name,
                    container_id=container_id,
                    alert_type="NETWORK_NEW_DEST",
                    severity="medium",
                    rule="New outbound network destination detected",
                    evidence=evidence,
                    dedup_extra=remote_ip,
                )

    # ------------------------------------------------------------------
    # Pruning
    # ------------------------------------------------------------------

    async def _prune_old_samples(self) -> None:
        """Remove network samples older than the configured retention window."""
        loop = asyncio.get_event_loop()
        deleted = await loop.run_in_executor(
            None,
            lambda: self._repo.prune_network_samples(
                older_than_hours=_PRUNE_OLDER_THAN_HOURS
            ),
        )
        if deleted:
            logger.info("Pruned %d old network samples.", deleted)

    # ------------------------------------------------------------------
    # Docker helpers
    # ------------------------------------------------------------------

    def _get_container_pid(self, container_id: str) -> Optional[int]:
        """
        Synchronous helper (runs in executor).  Inspects the container and
        returns the main process PID as reported by Docker, or None on failure.
        """
        try:
            container = self._docker.containers.get(container_id)
            attrs = container.attrs or {}
            state = attrs.get("State", {})
            pid = state.get("Pid")
            if pid and int(pid) > 0:
                return int(pid)
            return None
        except docker.errors.NotFound:
            logger.debug("Container %s not found when fetching PID.", container_id)
            return None
        except docker.errors.DockerException as exc:
            logger.warning("Docker error fetching PID for %s: %s", container_id, exc)
            return None
        except (ValueError, TypeError) as exc:
            logger.warning("Unexpected PID value for container %s: %s", container_id, exc)
            return None


# ---------------------------------------------------------------------------
# Module-level helpers
# ---------------------------------------------------------------------------

def _read_file(path: str) -> str:
    """Read a text file and return its content as a string."""
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        return fh.read()
