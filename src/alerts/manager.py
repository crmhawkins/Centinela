"""
CENTINELA – Central alert orchestration module.

Responsibilities:
  1. Deduplicate alerts (in-memory dict + DB check).
  2. Enforce per-type cooldowns.
  3. Route to email, webhook, and WhatsApp channels in parallel.
  4. Persist every incident to the database.
  5. Fully async (synchronous DB calls are offloaded to a thread executor).
"""
import asyncio
import json
import logging
from datetime import datetime, timezone

def _utcnow() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)
from typing import Dict, Optional

from config.models import AlertChannels, GlobalConfig, ProjectConfig
from database.models import Incident
from database.repository import IncidentRepository

from alerts.email_sender import format_incident_email, send_email_alert
from alerts.webhook_sender import build_webhook_payload, send_webhook
from alerts.whatsapp_sender import send_whatsapp_alert

logger = logging.getLogger("centinela.alerts.manager")

# Ordered severity levels for numeric comparison
_SEVERITY_ORDER: Dict[str, int] = {
    "low":      0,
    "medium":   1,
    "high":     2,
    "critical": 3,
}


def _severity_value(severity: str) -> int:
    """Return a numeric value for a severity label (unknown → -1)."""
    return _SEVERITY_ORDER.get(severity.lower(), -1)


class AlertManager:
    """
    Central hub for raising, deduplicating, and dispatching security alerts.

    Usage:
        manager = AlertManager(config, repo)
        raised = await manager.raise_alert(
            project, container_name, container_id,
            alert_type, severity, rule, evidence
        )
    """

    def __init__(self, config: GlobalConfig, repo: IncidentRepository) -> None:
        self._config = config
        self._repo = repo
        self._ai_analyzer = None
        # In-memory cooldown cache: dedup_key -> datetime of last alert raise
        self._last_raised: Dict[str, datetime] = {}

    def register_ai_analyzer(self, ai_analyzer) -> None:
        self._ai_analyzer = ai_analyzer

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def raise_alert(
        self,
        project: Optional[ProjectConfig],
        container_name: str,
        container_id: str,
        alert_type: str,
        severity: str,
        rule: str,
        evidence: dict,
        dedup_extra: str = "",
    ) -> bool:
        """
        Evaluate, deduplicate, persist, and dispatch a security alert.

        Parameters
        ----------
        project:        Matched ProjectConfig (can be None for unregistered containers).
        container_name: Docker container name.
        container_id:   Docker container ID (short or full SHA).
        alert_type:     Machine-readable type, e.g. "PROCESS_SUSPICIOUS".
        severity:       One of: low | medium | high | critical.
        rule:           Human-readable rule name.
        evidence:       Arbitrary dict with detection context (stored as JSON).
        dedup_extra:    Optional extra string appended to the dedup key.

        Returns
        -------
        True if a new incident was created and dispatched; False if suppressed.
        """
        project_name = project.name if project else "unregistered"

        # 1. Build dedup key
        dedup_key = f"{container_name}:{alert_type}:{rule}:{dedup_extra}"

        # 2. Resolve cooldown for this alert type
        cooldown_seconds = self._get_cooldown(alert_type)

        # 3. In-memory cooldown check (fast path — avoids DB round-trip)
        now = _utcnow()
        last_raised = self._last_raised.get(dedup_key)
        if last_raised is not None:
            elapsed = (now - last_raised).total_seconds()
            if elapsed < cooldown_seconds:
                logger.debug(
                    "SUPPRESSED (in-memory cooldown) key=%s elapsed=%.0fs cooldown=%ds",
                    dedup_key, elapsed, cooldown_seconds,
                )
                return False

        # 4. DB-level dedup check (catches cross-restart duplicates)
        loop = asyncio.get_event_loop()
        db_exists = await loop.run_in_executor(
            None,
            self._repo.recent_incident_exists,
            dedup_key,
            cooldown_seconds,
        )
        if db_exists:
            # Sync the in-memory cache so future checks hit the fast path
            self._last_raised[dedup_key] = now
            logger.debug(
                "SUPPRESSED (DB dedup) key=%s cooldown=%ds",
                dedup_key, cooldown_seconds,
            )
            return False

        # 5a. Build and persist the incident
        evidence_json = self._serialize_evidence(evidence)
        incident = Incident(
            timestamp=now,
            project=project_name,
            container_id=container_id,
            container_name=container_name,
            alert_type=alert_type,
            severity=severity.lower(),
            rule=rule,
            evidence=evidence_json,
            status="new",
            alert_sent=False,
            dedup_key=dedup_key,
        )

        incident = await loop.run_in_executor(
            None, self._repo.save_incident, incident
        )
        logger.info(
            "INCIDENT SAVED id=%s project=%s container=%s type=%s severity=%s rule=%r",
            incident.id, project_name, container_name,
            alert_type, severity, rule,
        )

        # Update in-memory cache *after* successful save
        self._last_raised[dedup_key] = now

        # 5b. Determine alert channels and send notifications
        channels = self._merge_channels(project, self._config)
        await self._send_alerts(incident, project, channels)

        # 5c. Enqueue for AI enrichment (non-blocking best effort)
        if self._ai_analyzer is not None:
            try:
                await self._ai_analyzer.enqueue(incident)
            except Exception as exc:
                logger.warning("Could not enqueue incident id=%s to AI analyzer: %s", incident.id, exc)

        return True

    # ------------------------------------------------------------------
    # Cooldown resolution
    # ------------------------------------------------------------------

    def _get_cooldown(self, alert_type: str) -> int:
        """
        Return the cooldown (seconds) for a given alert type.
        Falls back to the "default" entry, then to 300 s if absent.
        """
        cooldown_map = self._config.alert_cooldown
        if alert_type in cooldown_map:
            return cooldown_map[alert_type]
        return cooldown_map.get("default", 300)

    # ------------------------------------------------------------------
    # Alert dispatch
    # ------------------------------------------------------------------

    async def _send_alerts(
        self,
        incident: Incident,
        project: Optional[ProjectConfig],
        channels: AlertChannels,
    ) -> None:
        """
        Dispatch the incident to all configured channels in parallel.
        Each channel is guarded independently; a failure in one does not
        prevent the others from being attempted.
        """
        # Severity gate: skip sending if incident severity is below threshold
        incident_level = _severity_value(incident.severity)
        min_level = _severity_value(channels.min_severity)

        if incident_level < min_level:
            logger.info(
                "Alert send SKIPPED (severity %s < min_severity %s) for incident id=%s",
                incident.severity, channels.min_severity, incident.id,
            )
            return

        tasks = []

        # --- Email ---
        if channels.emails and self._config.smtp:
            tasks.append(self._send_email(incident, channels))

        # --- Generic webhook ---
        if channels.webhook_url:
            tasks.append(self._send_webhook(incident, channels.webhook_url))

        # --- WhatsApp bridge ---
        if channels.whatsapp_webhook:
            tasks.append(self._send_whatsapp(incident, channels.whatsapp_webhook))

        if not tasks:
            logger.warning(
                "No alert channels configured for incident id=%s project=%s",
                incident.id, incident.project,
            )
            return

        # Run all channels in parallel; gather results
        results = await asyncio.gather(*tasks, return_exceptions=True)

        any_sent = False
        for result in results:
            if isinstance(result, Exception):
                logger.error(
                    "Unexpected exception during alert dispatch for incident id=%s: %s",
                    incident.id, result,
                )
            elif result is True:
                any_sent = True

        # Mark alert_sent in DB if at least one channel succeeded
        if any_sent:
            loop = asyncio.get_event_loop()
            await loop.run_in_executor(
                None, self._repo.mark_alert_sent, incident.id
            )
            logger.info(
                "ALERT DISPATCHED incident id=%s project=%s severity=%s",
                incident.id, incident.project, incident.severity,
            )
        else:
            logger.error(
                "ALL alert channels failed for incident id=%s project=%s",
                incident.id, incident.project,
            )

    async def _send_email(self, incident: Incident, channels: AlertChannels) -> bool:
        """Send email alert; returns True on success."""
        try:
            subject, body_text, body_html = format_incident_email(incident)
            result = await send_email_alert(
                smtp_cfg=self._config.smtp,
                recipients=channels.emails,
                subject=subject,
                body_text=body_text,
                body_html=body_html,
            )
            if not result:
                logger.warning(
                    "Email alert failed for incident id=%s recipients=%s",
                    incident.id, channels.emails,
                )
            return result
        except Exception as exc:
            logger.error(
                "Exception sending email for incident id=%s: %s",
                incident.id, exc,
            )
            return False

    async def _send_webhook(self, incident: Incident, webhook_url: str) -> bool:
        """Send generic webhook; returns True on success."""
        try:
            payload = build_webhook_payload(incident)
            result = await send_webhook(url=webhook_url, payload=payload)
            if not result:
                logger.warning(
                    "Webhook delivery failed for incident id=%s url=%s",
                    incident.id, webhook_url,
                )
            return result
        except Exception as exc:
            logger.error(
                "Exception sending webhook for incident id=%s url=%s: %s",
                incident.id, webhook_url, exc,
            )
            return False

    async def _send_whatsapp(self, incident: Incident, whatsapp_webhook: str) -> bool:
        """Send WhatsApp bridge alert; returns True on success."""
        try:
            result = await send_whatsapp_alert(
                webhook_url=whatsapp_webhook,
                incident=incident,
            )
            if not result:
                logger.warning(
                    "WhatsApp alert failed for incident id=%s url=%s",
                    incident.id, whatsapp_webhook,
                )
            return result
        except Exception as exc:
            logger.error(
                "Exception sending WhatsApp alert for incident id=%s url=%s: %s",
                incident.id, whatsapp_webhook, exc,
            )
            return False

    # ------------------------------------------------------------------
    # Channel merging
    # ------------------------------------------------------------------

    def _merge_channels(
        self,
        project: Optional[ProjectConfig],
        global_cfg: GlobalConfig,
    ) -> AlertChannels:
        """
        Build the effective AlertChannels for an alert.

        Rules:
        - If the project defines at least one channel (emails, webhook, or
          whatsapp), use *only* the project channels and project min_severity.
        - If the project has no channels configured at all, fall back to the
          global defaults.
        - If there is no project (unregistered container), use global defaults.
        """
        if project is not None:
            proj_channels = project.alerts
            has_email = bool(proj_channels.emails)
            has_webhook = bool(proj_channels.webhook_url)
            has_whatsapp = bool(proj_channels.whatsapp_webhook)

            if has_email or has_webhook or has_whatsapp:
                logger.debug(
                    "Using project-level channels for project=%s", project.name
                )
                return proj_channels

        # Fall back to global defaults
        logger.debug(
            "Using global fallback channels for project=%s",
            project.name if project else "unregistered",
        )
        return AlertChannels(
            emails=list(global_cfg.default_emails),
            webhook_url=global_cfg.default_webhook_url,
            whatsapp_webhook=global_cfg.default_whatsapp_webhook,
            # Preserve the project's min_severity if it exists; otherwise default
            min_severity=(
                project.alerts.min_severity
                if project is not None
                else "medium"
            ),
        )

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _serialize_evidence(evidence: dict) -> str:
        """
        Safely serialize evidence dict to a JSON string.
        Falls back to repr() if the dict contains non-serialisable values.
        """
        try:
            return json.dumps(evidence, default=str, ensure_ascii=False)
        except Exception as exc:
            logger.warning("Could not JSON-serialize evidence (%s); using repr", exc)
            return repr(evidence)
