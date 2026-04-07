"""
CENTINELA – AI Threat Analyzer (Daily Batch Digest)

Runs once per day, fetches all recent incidents in bulk, sends a single
grouped request to the AI API, and stores one AIThreatAssessment summary.
This replaces the previous per-incident queue approach (~14 000 calls/week
→ 1 call/day).
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
import re
from collections import Counter
from datetime import datetime, timezone
from typing import Dict, List, Optional

import aiohttp

from database.models import AIThreatAssessment, Incident
from database.repository import IncidentRepository

logger = logging.getLogger("centinela.ai.analyzer")

_SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}


def _utcnow() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


class AIThreatAnalyzer:
    """
    Daily-digest AI analyzer.

    Instead of enqueueing individual incidents, this class wakes up once every
    CENTINELA_AI_INTERVAL_HOURS hours, fetches the last CENTINELA_AI_DIGEST_HOURS
    hours of incidents from the database in a single query, builds a grouped
    prompt, calls the AI API once, and persists one AIThreatAssessment row.
    """

    def __init__(self, repo: IncidentRepository) -> None:
        self._repo = repo
        self._stop_event = asyncio.Event()

        self._api_url: str = os.environ.get(
            "CENTINELA_AI_URL",
            "https://aiapi.hawkins.es/chat/text/chat",
        )
        self._api_key: str = os.environ.get(
            "CENTINELA_AI_API_KEY",
            "OllamaAPI_2024_K8mN9pQ2rS5tU7vW3xY6zA1bC4eF8hJ0lM",
        )
        self._model: str = os.environ.get(
            "CENTINELA_AI_MODEL",
            "gpt-oss:120b-cloud",
        )
        self._digest_hours: int = int(
            os.environ.get("CENTINELA_AI_DIGEST_HOURS", "24")
        )
        self._interval_hours: int = int(
            os.environ.get("CENTINELA_AI_INTERVAL_HOURS", "24")
        )

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    async def enqueue(self, incident: Incident) -> None:
        """No-op stub kept for AlertManager compatibility (digest mode)."""
        pass  # Digest mode: incidents are fetched in batch, not per-incident

    def stop(self) -> None:
        """Signal the run() loop to exit after the current sleep."""
        self._stop_event.set()

    async def run(self) -> None:
        """
        Main loop. Waits 5 minutes on startup (to let the rest of the system
        initialise), then runs a digest every self._interval_hours hours.
        Exits cleanly on CancelledError or when stop() is called.
        """
        logger.info(
            "AIThreatAnalyzer (digest mode) started. url=%s model=%s "
            "digest_hours=%s interval_hours=%s",
            self._api_url,
            self._model,
            self._digest_hours,
            self._interval_hours,
        )
        try:
            # 5-minute startup delay
            await asyncio.wait_for(self._stop_event.wait(), timeout=300)
            return  # stop() was called during startup delay
        except asyncio.TimeoutError:
            pass  # normal path – stop event was not set, proceed

        while not self._stop_event.is_set():
            try:
                await self.run_digest_now()
            except asyncio.CancelledError:
                logger.info("AIThreatAnalyzer cancelled during digest.")
                raise
            except Exception as exc:
                logger.error("Digest cycle failed unexpectedly: %s", exc, exc_info=True)

            interval_seconds = self._interval_hours * 3600
            try:
                await asyncio.wait_for(self._stop_event.wait(), timeout=interval_seconds)
                break  # stop() fired during sleep
            except asyncio.TimeoutError:
                pass  # normal path – time to run the next digest

        logger.info("AIThreatAnalyzer stopped.")

    async def run_digest_now(self) -> None:
        """
        Trigger one digest cycle immediately (also used by web endpoints).
        Fetches incidents, calls the AI, and persists the assessment.
        """
        logger.info("Starting AI digest (last %sh of incidents).", self._digest_hours)

        incidents = await self._fetch_recent_incidents(hours=self._digest_hours)
        if not incidents:
            logger.info("No incidents in the last %sh – skipping digest.", self._digest_hours)
            return

        prompt = self._build_digest_prompt(incidents)
        raw_text = await self._call_api(prompt)
        if raw_text is None:
            logger.warning("AI API returned no response – digest not saved.")
            return

        result_dict = self._parse_ai_json(raw_text)
        await self._save_digest(incidents, result_dict, raw_text)
        logger.info(
            "Digest saved. estado_general=%s incidents=%d",
            result_dict.get("estado_general", "?"),
            len(incidents),
        )

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    async def _fetch_recent_incidents(self, hours: int = 24) -> List[Incident]:
        """Fetch recent incidents from the DB via run_in_executor (sync repo)."""
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(
            None, self._repo.get_incidents_for_digest, hours
        )

    def _build_digest_prompt(self, incidents: List[Incident]) -> str:
        total = len(incidents)

        # Severity counts
        sev_counts: Counter = Counter(
            (inc.severity or "unknown").lower() for inc in incidents
        )

        # Alert type counts
        type_counts: Counter = Counter(
            (inc.alert_type or "unknown") for inc in incidents
        )

        # Container counts
        container_counts: Counter = Counter(
            (inc.container_name or "unknown") for inc in incidents
        )

        # High + critical incidents (max 20) for full detail
        priority = [
            inc for inc in incidents
            if (inc.severity or "").lower() in ("critical", "high")
        ][:20]

        lines: List[str] = [
            "Eres un analista SOC senior. Analiza el siguiente resumen de incidentes de seguridad",
            "detectados por CENTINELA en las últimas 24 horas y responde ÚNICAMENTE con JSON válido,",
            "sin texto adicional antes ni después del JSON.",
            "",
            f"TOTAL DE INCIDENTES: {total}",
            "",
            "DESGLOSE POR SEVERIDAD:",
            f"  critical : {sev_counts.get('critical', 0)}",
            f"  high     : {sev_counts.get('high', 0)}",
            f"  medium   : {sev_counts.get('medium', 0)}",
            f"  low      : {sev_counts.get('low', 0)}",
            "",
            "DESGLOSE POR TIPO DE ALERTA:",
        ]
        for alert_type, count in type_counts.most_common():
            lines.append(f"  {alert_type}: {count}")

        lines += [
            "",
            "DESGLOSE POR CONTENEDOR:",
        ]
        for container, count in container_counts.most_common():
            lines.append(f"  {container}: {count}")

        if priority:
            lines += [
                "",
                f"DETALLE DE INCIDENTES CRÍTICOS/ALTOS (mostrando {len(priority)} de "
                f"{sev_counts.get('critical', 0) + sev_counts.get('high', 0)}):",
            ]
            for inc in priority:
                evidence_short = (inc.evidence or "")[:200]
                lines += [
                    f"  ---",
                    f"  id           : {inc.id}",
                    f"  container    : {inc.container_name}",
                    f"  alert_type   : {inc.alert_type}",
                    f"  rule         : {inc.rule}",
                    f"  evidence     : {evidence_short}",
                ]

        lines += [
            "",
            "Responde SOLO con el siguiente JSON (sin markdown, sin texto extra):",
            "{",
            '  "estado_general": "verde|amarillo|rojo",',
            '  "resumen": "string máximo 500 caracteres",',
            '  "incidentes_sospechosos": [{"id": 123, "razon": "string"}],',
            '  "falsos_positivos_probables": ["SECURITY_AUDIT repetitivo", "..."],',
            '  "recomendaciones": ["string", "..."]',
            "}",
        ]

        return "\n".join(lines)

    async def _call_api(self, prompt: str) -> Optional[str]:
        """Call the AI API. Returns the response text, or None on any error."""
        payload = {"prompt": prompt, "modelo": self._model}
        headers: Dict[str, str] = {}
        if self._api_key:
            headers["x-api-key"] = self._api_key

        timeout = aiohttp.ClientTimeout(total=60)
        try:
            async with aiohttp.ClientSession(timeout=timeout) as session:
                async with session.post(
                    self._api_url,
                    json=payload,
                    headers=headers,
                    ssl=False,
                ) as resp:
                    if resp.status >= 400:
                        logger.warning(
                            "AI API returned HTTP %s for digest request.", resp.status
                        )
                        return None
                    data = await resp.json(content_type=None)

            if isinstance(data, dict):
                text = data.get("respuesta", "")
                if text:
                    return str(text)
            logger.warning("AI API response has no 'respuesta' key: %s", str(data)[:200])
            return None

        except asyncio.CancelledError:
            raise
        except Exception as exc:
            logger.error("AI API call failed: %s", exc)
            return None

    async def _save_digest(
        self,
        incidents: List[Incident],
        result_dict: dict,
        raw_text: str,
    ) -> None:
        """Persist one AIThreatAssessment row representing the daily digest."""
        estado = result_dict.get("estado_general", "amarillo").lower()

        severity_map = {"rojo": "critical", "amarillo": "high", "verde": "low"}
        severity = severity_map.get(estado, "medium")

        threat_title = "Digest diario – " + estado.upper()
        threat_description = result_dict.get("resumen", "Sin resumen disponible")[:500]
        recommendations = "\n".join(result_dict.get("recomendaciones", []))
        raw_response = json.dumps(result_dict, ensure_ascii=False)[:8000]

        # Use first incident's project/container as representative values, or
        # a generic label when the digest covers multiple containers/projects.
        projects = {inc.project for inc in incidents if inc.project}
        containers = {inc.container_name for inc in incidents if inc.container_name}
        project_label = next(iter(projects)) if len(projects) == 1 else "multiple"
        container_label = next(iter(containers)) if len(containers) == 1 else "multiple"

        assessment = AIThreatAssessment(
            timestamp=_utcnow(),
            incident_id=0,
            container_name=container_label,
            project=project_label,
            ai_model=self._model,
            threat_title=threat_title[:200],
            threat_description=threat_description,
            severity=severity,
            confidence=80,
            recommendations=recommendations,
            raw_response=raw_response,
        )

        loop = asyncio.get_event_loop()
        await loop.run_in_executor(None, self._repo.save_ai_assessment, assessment)

    def _parse_ai_json(self, text: str) -> dict:
        """Try to extract a JSON object from the AI response text."""
        try:
            return json.loads(text)
        except Exception:
            pass
        match = re.search(r"\{.*\}", text, flags=re.DOTALL)
        if match:
            try:
                return json.loads(match.group(0))
            except Exception:
                pass
        logger.warning("Could not parse AI response as JSON; using fallback.")
        return {
            "estado_general": "amarillo",
            "resumen": text[:500],
            "incidentes_sospechosos": [],
            "falsos_positivos_probables": [],
            "recomendaciones": ["Revisar manualmente los incidentes del período."],
        }
