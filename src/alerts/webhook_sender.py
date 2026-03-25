"""
CENTINELA – Generic HTTP webhook sender.
Sends a JSON POST with the full incident payload.
"""
import logging
from typing import Optional

import aiohttp

logger = logging.getLogger("centinela.alerts.webhook")

_TIMEOUT = aiohttp.ClientTimeout(total=10)


async def send_webhook(url: str, payload: dict,
                       secret_header: Optional[str] = None,
                       secret_value: Optional[str] = None) -> bool:
    """
    POST payload as JSON to url.
    Optionally adds a custom header (e.g. X-Centinela-Secret: <token>).
    Returns True on HTTP 2xx, False otherwise.
    """
    headers = {"Content-Type": "application/json", "User-Agent": "Centinela/1.0"}
    if secret_header and secret_value:
        headers[secret_header] = secret_value

    try:
        async with aiohttp.ClientSession(timeout=_TIMEOUT) as session:
            async with session.post(url, json=payload, headers=headers) as resp:
                if resp.status < 300:
                    logger.info("Webhook delivered to %s (HTTP %s)", url, resp.status)
                    return True
                body = await resp.text()
                logger.warning("Webhook %s returned HTTP %s: %s",
                               url, resp.status, body[:200])
                return False
    except aiohttp.ClientError as exc:
        logger.error("Webhook delivery failed (%s): %s", url, exc)
        return False
    except Exception as exc:
        logger.error("Unexpected webhook error (%s): %s", url, exc)
        return False


def build_webhook_payload(incident) -> dict:
    """
    Serialise an Incident ORM object to a JSON-safe dict.
    This is the canonical format for all webhook integrations.
    """
    import json

    evidence = {}
    try:
        evidence = json.loads(incident.evidence)
    except Exception:
        evidence = {"raw": incident.evidence}

    return {
        "source": "centinela",
        "version": "1",
        "incident": {
            "id":             incident.id,
            "timestamp":      incident.timestamp.isoformat() if incident.timestamp else None,
            "project":        incident.project,
            "container_id":   incident.container_id,
            "container_name": incident.container_name,
            "alert_type":     incident.alert_type,
            "severity":       incident.severity,
            "rule":           incident.rule,
            "evidence":       evidence,
            "status":         incident.status,
        },
    }
