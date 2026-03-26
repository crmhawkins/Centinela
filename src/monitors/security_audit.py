"""
CENTINELA – Security Audit Monitor.

Periodically inspects the Docker configuration of each monitored container
for dangerous or misconfigured settings that increase the attack surface.

Each finding produces a separate incident so that the deduplication logic
in AlertManager can suppress repeated notifications per rule independently.

Checks performed (via container.attrs / docker inspect):
  1.  Privileged mode             – HostConfig.Privileged == True           → CRITICAL
  2.  Dangerous capabilities      – HostConfig.CapAdd contains known-bad caps → HIGH
  3.  No read-only root filesystem – HostConfig.ReadonlyRootfs == False       → LOW
  4.  AppArmor disabled            – SecurityOpt empty or "apparmor=unconfined" → MEDIUM
  5.  Seccomp disabled             – SecurityOpt contains "seccomp=unconfined"  → HIGH
  6.  Host network mode            – HostConfig.NetworkMode == "host"           → HIGH
  7.  Host PID namespace           – HostConfig.PidMode == "host"               → CRITICAL
  8.  Host IPC namespace           – HostConfig.IpcMode == "host" or "shareable" → HIGH
  9.  Dangerous sysctl values      – HostConfig.Sysctls contains risky settings → MEDIUM
  10. Sensitive port exposure       – port 22 or privileged ports (<1024) bound
                                     on host interface                           → MEDIUM
"""

import asyncio
import logging
from typing import Any, Dict, List, Optional, Set

import docker
import docker.errors

from alerts.manager import AlertManager
from config.loader import ProjectRegistry
from config.models import GlobalConfig, ProjectConfig
from utils.helpers import safe_json

logger = logging.getLogger("centinela.monitors.security_audit")

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Capabilities that are considered dangerous in a web-app container context.
_DANGEROUS_CAPS = frozenset(
    [
        "SYS_ADMIN",
        "NET_ADMIN",
        "SYS_PTRACE",
        "SYS_MODULE",
        "DAC_OVERRIDE",
        "DAC_READ_SEARCH",
    ]
)

# Sysctl keys whose presence (regardless of value) or specific dangerous values
# warrant a medium-severity finding.
_DANGEROUS_SYSCTLS: Dict[str, Optional[str]] = {
    # kernel.unprivileged_userns_clone=1 enables user namespace abuse
    "kernel.unprivileged_userns_clone": "1",
    # net.ipv4.ip_unprivileged_port_start=0 allows binding port 80/443 as any UID
    # (not necessarily dangerous by itself but flags non-standard sysctl usage)
    "net.core.somaxconn": None,         # any override worth noting
    "kernel.dmesg_restrict": "0",       # exposing kernel logs
    "kernel.kptr_restrict": "0",        # exposing kernel pointers
    "net.ipv4.ip_forward": "1",         # acting as a router
}

# Ports whose direct host binding is suspicious for a web-app container.
_SENSITIVE_PORTS = frozenset([22])      # SSH

# Host interfaces that count as "public" (empty string means all interfaces).
_PUBLIC_INTERFACES = {"", "0.0.0.0"}


class SecurityAuditMonitor:
    """
    Runs periodic security audits against container configurations.

    Parameters
    ----------
    config:         Global CENTINELA configuration.
    registry:       ProjectRegistry mapping container names → ProjectConfig.
    alert_manager:  Central alert dispatcher.
    docker_client:  docker.DockerClient (synchronous SDK).
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

        # Dedup: tracks the set of finding rules seen in the last audit cycle
        # per container, so we only log/alert when findings actually change.
        self._last_findings: Dict[str, Set[str]] = {}

    # ------------------------------------------------------------------
    # Main loop
    # ------------------------------------------------------------------

    async def run(self) -> None:
        """
        Runs a full audit of all monitored containers every
        config.security_audit_interval seconds.
        """
        interval = self._config.security_audit_interval
        logger.info("SecurityAuditMonitor started (interval=%ds).", interval)

        # Run an initial audit immediately on startup so operators get findings
        # without waiting a full interval.
        await self._audit_all_containers()

        while True:
            try:
                await asyncio.sleep(interval)
                await self._audit_all_containers()
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                logger.error(
                    "Unexpected error in SecurityAuditMonitor.run(): %s",
                    exc,
                    exc_info=True,
                )

    # ------------------------------------------------------------------
    # Container discovery
    # ------------------------------------------------------------------

    async def _audit_all_containers(self) -> None:
        """Discover running monitored containers and audit each one."""
        loop = asyncio.get_event_loop()
        try:
            containers = await loop.run_in_executor(
                None, lambda: self._docker.containers.list()
            )
        except docker.errors.DockerException as exc:
            logger.error("Failed to list containers for security audit: %s", exc)
            return

        for container in containers:
            container_name = container.name
            labels = container.labels or {}
            project = self._registry.get(container_name, labels)
            if project is None:
                continue

            try:
                await self.audit_container(container_name, container.id, project)
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                logger.error(
                    "Error auditing container %s: %s", container_name, exc, exc_info=True
                )

    # ------------------------------------------------------------------
    # Single-container audit (public – also called on container start)
    # ------------------------------------------------------------------

    async def audit_container(
        self,
        container_name: str,
        container_id: str,
        project: ProjectConfig,
    ) -> None:
        """
        Inspect a single container and raise a separate alert for each
        security finding.

        This method is intentionally public so that the Docker events module
        can call it immediately when a new container starts, without waiting
        for the next scheduled audit cycle.
        """
        loop = asyncio.get_event_loop()

        # Fetch full container attributes (equivalent to `docker inspect`).
        try:
            container_attrs = await loop.run_in_executor(
                None, lambda: self._get_container_attrs(container_id)
            )
        except docker.errors.NotFound:
            logger.debug(
                "Container %s disappeared before audit could run.", container_name
            )
            return
        except docker.errors.DockerException as exc:
            logger.warning(
                "Docker error inspecting %s for audit: %s", container_name, exc
            )
            return

        if container_attrs is None:
            return

        findings: List[dict] = self._collect_findings(container_attrs)

        if not findings:
            logger.debug("Security audit passed for container %s.", container_name)
            self._last_findings[container_name] = set()
            return

        current_rules: Set[str] = {f["rule"] for f in findings}
        previous_rules: Set[str] = self._last_findings.get(container_name, None)

        if previous_rules is not None and current_rules == previous_rules:
            logger.debug(
                "Security audit: no change in findings for container %s (%d finding(s)).",
                container_name, len(findings),
            )
            return

        self._last_findings[container_name] = current_rules

        logger.info(
            "Security audit found %d finding(s) for container %s.",
            len(findings),
            container_name,
        )

        for finding in findings:
            severity = finding["severity"]
            rule = finding["rule"]
            if severity in ("high", "critical"):
                logger.alert(
                    "Security audit finding [%s]: %s (container=%s)",
                    severity.upper(), rule, container_name,
                )
            else:
                logger.warning(
                    "Security audit finding [%s]: %s (container=%s)",
                    severity.upper(), rule, container_name,
                )
            evidence = {
                "container": container_name,
                "rule": rule,
                "severity": severity,
                "evidence": finding["evidence"],
            }
            await self._alert_manager.raise_alert(
                project=project,
                container_name=container_name,
                container_id=container_id,
                alert_type="SECURITY_AUDIT",
                severity=severity,
                rule=rule,
                evidence=evidence,
                dedup_extra=rule,
            )

    # ------------------------------------------------------------------
    # Finding collection
    # ------------------------------------------------------------------

    def _collect_findings(self, container_attrs: dict) -> List[dict]:
        """
        Inspect container_attrs (the dict from `docker inspect`) and return a
        list of finding dicts, each with keys: rule, severity, evidence (dict).

        All checks are independent; a failure in one does not prevent the
        others from running.
        """
        host_cfg: dict = container_attrs.get("HostConfig", {})
        findings: List[dict] = []

        # 1. Privileged mode
        try:
            if host_cfg.get("Privileged") is True:
                findings.append(
                    _finding(
                        rule="Container running in privileged mode",
                        severity="critical",
                        evidence={
                            "HostConfig.Privileged": True,
                            "description": (
                                "The container has full host kernel capabilities. "
                                "An attacker who escapes the container gains root on the host."
                            ),
                        },
                    )
                )
        except Exception as exc:
            logger.debug("Check 1 (privileged) failed: %s", exc)

        # 2. Dangerous capabilities
        try:
            cap_add: List[str] = host_cfg.get("CapAdd") or []
            dangerous: List[str] = [
                cap for cap in cap_add if cap.upper() in _DANGEROUS_CAPS
            ]
            if dangerous:
                findings.append(
                    _finding(
                        rule="Container has dangerous Linux capabilities",
                        severity="high",
                        evidence={
                            "HostConfig.CapAdd": cap_add,
                            "dangerous_capabilities": dangerous,
                            "description": (
                                f"Capabilities {dangerous} are granted. These can be "
                                "abused for privilege escalation or host escape."
                            ),
                        },
                    )
                )
        except Exception as exc:
            logger.debug("Check 2 (capabilities) failed: %s", exc)

        # 3. No read-only root filesystem (informational)
        try:
            if host_cfg.get("ReadonlyRootfs") is False:
                findings.append(
                    _finding(
                        rule="Container root filesystem is writable",
                        severity="low",
                        evidence={
                            "HostConfig.ReadonlyRootfs": False,
                            "description": (
                                "The container's root filesystem is not mounted read-only. "
                                "Consider using --read-only with tmpfs mounts for writable "
                                "directories to limit the blast radius of a compromise."
                            ),
                        },
                    )
                )
        except Exception as exc:
            logger.debug("Check 3 (ReadonlyRootfs) failed: %s", exc)

        # 4. AppArmor disabled
        try:
            security_opt: List[str] = host_cfg.get("SecurityOpt") or []
            security_opt_lower = [s.lower() for s in security_opt]
            apparmor_disabled = (
                not security_opt                                          # no security options at all
                or any("apparmor=unconfined" in s for s in security_opt_lower)
            )
            if apparmor_disabled:
                findings.append(
                    _finding(
                        rule="AppArmor profile not applied to container",
                        severity="medium",
                        evidence={
                            "HostConfig.SecurityOpt": security_opt,
                            "description": (
                                "The container has no AppArmor profile or is explicitly "
                                "set to 'unconfined'. AppArmor provides MAC-level "
                                "syscall filtering that limits exploitation."
                            ),
                        },
                    )
                )
        except Exception as exc:
            logger.debug("Check 4 (AppArmor) failed: %s", exc)

        # 5. Seccomp disabled
        try:
            security_opt = host_cfg.get("SecurityOpt") or []
            if any("seccomp=unconfined" in s.lower() for s in security_opt):
                findings.append(
                    _finding(
                        rule="Seccomp filtering disabled for container",
                        severity="high",
                        evidence={
                            "HostConfig.SecurityOpt": security_opt,
                            "description": (
                                "Seccomp is explicitly disabled ('seccomp=unconfined'). "
                                "The container can call any kernel syscall, widening the "
                                "kernel attack surface significantly."
                            ),
                        },
                    )
                )
        except Exception as exc:
            logger.debug("Check 5 (seccomp) failed: %s", exc)

        # 6. Host network mode
        try:
            network_mode: str = host_cfg.get("NetworkMode", "")
            if network_mode == "host":
                findings.append(
                    _finding(
                        rule="Container uses host network namespace",
                        severity="high",
                        evidence={
                            "HostConfig.NetworkMode": network_mode,
                            "description": (
                                "The container shares the host's network stack. "
                                "It can bind to any host port and reach services on "
                                "localhost directly."
                            ),
                        },
                    )
                )
        except Exception as exc:
            logger.debug("Check 6 (host network) failed: %s", exc)

        # 7. Host PID namespace
        try:
            pid_mode: str = host_cfg.get("PidMode", "")
            if pid_mode == "host":
                findings.append(
                    _finding(
                        rule="Container uses host PID namespace",
                        severity="critical",
                        evidence={
                            "HostConfig.PidMode": pid_mode,
                            "description": (
                                "The container can see and signal all host processes. "
                                "This is a near-complete privilege escalation path."
                            ),
                        },
                    )
                )
        except Exception as exc:
            logger.debug("Check 7 (host PID) failed: %s", exc)

        # 8. Host IPC namespace
        try:
            ipc_mode: str = host_cfg.get("IpcMode", "")
            if ipc_mode in ("host", "shareable"):
                findings.append(
                    _finding(
                        rule="Container shares host IPC namespace",
                        severity="high",
                        evidence={
                            "HostConfig.IpcMode": ipc_mode,
                            "description": (
                                "The container can access the host's shared memory segments "
                                f"(IpcMode={ipc_mode!r}). This may allow inter-process "
                                "attacks or data leakage between containers and the host."
                            ),
                        },
                    )
                )
        except Exception as exc:
            logger.debug("Check 8 (host IPC) failed: %s", exc)

        # 9. Dangerous sysctl values
        try:
            sysctls: Dict[str, str] = host_cfg.get("Sysctls") or {}
            dangerous_sysctls: Dict[str, str] = {}
            for key, expected_val in _DANGEROUS_SYSCTLS.items():
                if key in sysctls:
                    actual_val = sysctls[key]
                    if expected_val is None or actual_val == expected_val:
                        dangerous_sysctls[key] = actual_val
            if dangerous_sysctls:
                findings.append(
                    _finding(
                        rule="Container has dangerous sysctl settings",
                        severity="medium",
                        evidence={
                            "HostConfig.Sysctls": sysctls,
                            "dangerous_sysctls": dangerous_sysctls,
                            "description": (
                                f"Sysctls {list(dangerous_sysctls.keys())} are set to "
                                "values that can reduce isolation or enable lateral movement."
                            ),
                        },
                    )
                )
        except Exception as exc:
            logger.debug("Check 9 (sysctls) failed: %s", exc)

        # 10. Sensitive port exposure on host
        try:
            port_bindings: Dict[str, Any] = host_cfg.get("PortBindings") or {}
            exposed_findings = _check_port_bindings(port_bindings)
            findings.extend(exposed_findings)
        except Exception as exc:
            logger.debug("Check 10 (ports) failed: %s", exc)

        return findings

    # ------------------------------------------------------------------
    # Docker helpers
    # ------------------------------------------------------------------

    def _get_container_attrs(self, container_id: str) -> Optional[dict]:
        """
        Synchronous helper (runs in executor).  Returns the full container
        attrs dict or None on error.
        """
        try:
            container = self._docker.containers.get(container_id)
            return container.attrs
        except docker.errors.NotFound:
            return None
        except docker.errors.DockerException as exc:
            logger.warning("DockerException fetching attrs for %s: %s", container_id, exc)
            return None


# ---------------------------------------------------------------------------
# Module-level helpers
# ---------------------------------------------------------------------------

def _finding(rule: str, severity: str, evidence: dict) -> dict:
    """Convenience constructor for a finding dict."""
    return {"rule": rule, "severity": severity, "evidence": evidence}


def _check_port_bindings(port_bindings: Dict[str, Any]) -> List[dict]:
    """
    Inspect PortBindings and return findings for:
      - Port 22 (SSH) exposed on any host interface.
      - Any privileged port (< 1024) bound to a public host interface.

    port_bindings format:
        {"80/tcp": [{"HostIp": "0.0.0.0", "HostPort": "80"}], ...}
    """
    findings: List[dict] = []
    sensitive_exposed: List[dict] = []
    privileged_exposed: List[dict] = []

    for container_port_proto, bindings in port_bindings.items():
        if not bindings:
            continue

        # Parse "80/tcp" → container_port=80
        try:
            port_part = container_port_proto.split("/")[0]
            container_port = int(port_part)
        except (ValueError, IndexError):
            continue

        for binding in (bindings or []):
            host_ip: str = binding.get("HostIp", "")
            try:
                host_port = int(binding.get("HostPort", 0))
            except (ValueError, TypeError):
                host_port = 0

            is_public = host_ip in _PUBLIC_INTERFACES

            # SSH port check (container or host port is 22)
            if container_port in _SENSITIVE_PORTS or host_port in _SENSITIVE_PORTS:
                sensitive_exposed.append(
                    {
                        "container_port": container_port,
                        "host_ip": host_ip,
                        "host_port": host_port,
                        "reason": "SSH port (22) exposed on host",
                    }
                )

            # Privileged port check (< 1024) on a public interface
            elif is_public and 0 < host_port < 1024:
                privileged_exposed.append(
                    {
                        "container_port": container_port,
                        "host_ip": host_ip,
                        "host_port": host_port,
                        "reason": (
                            f"Privileged port {host_port} bound directly on "
                            f"public interface {host_ip!r}"
                        ),
                    }
                )

    if sensitive_exposed:
        findings.append(
            _finding(
                rule="Sensitive port (SSH/22) exposed on host interface",
                severity="medium",
                evidence={
                    "exposed_ports": sensitive_exposed,
                    "description": (
                        "Port 22 (SSH) is mapped to a host interface. An SSH daemon "
                        "inside a web-app container is highly unusual and should be "
                        "investigated."
                    ),
                },
            )
        )

    if privileged_exposed:
        findings.append(
            _finding(
                rule="Privileged port (<1024) bound directly on public host interface",
                severity="medium",
                evidence={
                    "exposed_ports": privileged_exposed,
                    "description": (
                        "One or more privileged ports are bound directly to a public "
                        "host interface. Consider using a reverse proxy or binding only "
                        "to localhost."
                    ),
                },
            )
        )

    return findings
