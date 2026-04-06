"""
CENTINELA – AI Threat Analyzer

Consumes incidents from an internal queue, calls external AI API,
normalizes response to a fixed schema and stores AI assessments.
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional

import aiohttp

from database.models import AIThreatAssessment, Incident
from database.repository import IncidentRepository

logger = logging.getLogger("centinela.ai.analyzer")


def _utcnow() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


@dataclass
class AIAnalysisResult:
    title: str
    description: str
    severity: str
    confidence: int
    recommendations: str
    raw_response: str
    model: str


class AIThreatAnalyzer:
    def __init__(self, repo: IncidentRepository) -> None:
        self._repo = repo
        self._queue: asyncio.Queue[Incident] = asyncio.Queue(
            maxsize=int(os.environ.get("CENTINELA_AI_QUEUE_SIZE", "2000"))
        )
        self._stop_event = asyncio.Event()
        self._api_url = os.environ.get("CENTINELA_AI_URL", "https://192.168.1.45/chat/text/chat")
        self._api_key = os.environ.get("CENTINELA_AI_API_KEY", "OllamaAPI_2024_K8mN9pQ2rS5tU7vW3xY6zA1bC4eF8hJ0lM")
        self._model = os.environ.get("CENTINELA_AI_MODEL", "gpt-oss:120b-cloud")

    async def enqueue(self, incident: Incident) -> None:
        try:
            self._queue.put_nowait(incident)
        except asyncio.QueueFull:
            logger.warning("AI queue full. Dropping incident id=%s", incident.id)

    async def run(self) -> None:
        logger.info("AIThreatAnalyzer started. url=%s model=%s", self._api_url, self._model)
        while not self._stop_event.is_set():
            try:
                incident = await asyncio.wait_for(self._queue.get(), timeout=1.0)
            except asyncio.TimeoutError:
                continue
            try:
                result = await self._analyze_incident(incident)
                if result is not None:
                    await self._persist_assessment(incident, result)
            except Exception as exc:
                logger.error("AI analysis failed for incident id=%s: %s", incident.id, exc)
            finally:
                self._queue.task_done()

    def stop(self) -> None:
        self._stop_event.set()

    async def _analyze_incident(self, incident: Incident) -> Optional[AIAnalysisResult]:
        prompt = self._build_prompt(incident)
        payload = {"prompt": prompt, "modelo": self._model}
        headers = {}
        if self._api_key:
            headers["x-api-key"] = self._api_key

        timeout = aiohttp.ClientTimeout(total=30)
        async with aiohttp.ClientSession(timeout=timeout) as session:
            async with session.post(self._api_url, json=payload, headers=headers, ssl=False) as resp:
                if resp.status >= 400:
                    logger.warning("AI API HTTP %s for incident id=%s", resp.status, incident.id)
                    return None
                data = await resp.json(content_type=None)

        content = ""
        if isinstance(data, dict):
            content = str(data.get("respuesta") or "")
            if not content:
                metadata = data.get("metadata", {}) or {}
                message = metadata.get("message", {}) or {}
                content = str(message.get("content") or "")
        if not content:
            return None

        parsed = self._parse_ai_json(content)
        return AIAnalysisResult(
            title=parsed.get("threat_title", "Threat detected"),
            description=parsed.get("threat_description", "No description"),
            severity=parsed.get("severity", "medium"),
            confidence=max(0, min(100, int(parsed.get("confidence", 50)))),
            recommendations=parsed.get("recommendations", ""),
            raw_response=content[:5000],
            model=self._model,
        )

    def _build_prompt(self, incident: Incident) -> str:
        return (
            "Eres un analista SOC senior. Analiza el incidente y responde SOLO JSON valido, sin texto extra.\n"
            "Formato obligatorio:\n"
            "{\n"
            '  "threat_title": "string",\n'
            '  "threat_description": "string",\n'
            '  "severity": "low|medium|high|critical",\n'
            '  "confidence": 0,\n'
            '  "recommendations": "string"\n'
            "}\n\n"
            f"incident_id: {incident.id}\n"
            f"timestamp: {incident.timestamp}\n"
            f"project: {incident.project}\n"
            f"container: {incident.container_name}\n"
            f"alert_type: {incident.alert_type}\n"
            f"severity_detected: {incident.severity}\n"
            f"rule: {incident.rule}\n"
            f"evidence: {incident.evidence}\n"
        )

    def _parse_ai_json(self, text: str) -> dict:
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
        return {
            "threat_title": "Threat detected",
            "threat_description": text[:300],
            "severity": "medium",
            "confidence": 40,
            "recommendations": "Revisar manualmente el incidente.",
        }

    async def _persist_assessment(self, incident: Incident, result: AIAnalysisResult) -> None:
        assessment = AIThreatAssessment(
            timestamp=_utcnow(),
            incident_id=incident.id,
            container_name=incident.container_name,
            project=incident.project,
            ai_model=result.model,
            threat_title=result.title[:200],
            threat_description=result.description,
            severity=result.severity.lower(),
            confidence=result.confidence,
            recommendations=result.recommendations,
            raw_response=result.raw_response,
        )
        loop = asyncio.get_event_loop()
        await loop.run_in_executor(None, self._repo.save_ai_assessment, assessment)
