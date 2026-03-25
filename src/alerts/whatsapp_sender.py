"""
CENTINELA – WhatsApp bridge sender.

Design: Centinela POSTs the incident JSON to a configurable webhook URL.
That external webhook (a script or small service you control) then forwards
the message to WhatsApp via whichever API you use (Meta Cloud API, Twilio,
CallMeBot, WA-Gateway, etc.).

This module provides:
  - send_whatsapp_alert()   – POST to the configured bridge endpoint
  - format_whatsapp_text()  – compact, mobile-friendly plain-text summary

External bridge contract
------------------------
POST <whatsapp_webhook>
Content-Type: application/json

{
  "to":      "+34600000000",   // populated if configured
  "message": "...",            // plain text for WA message
  "incident": { ... }          // full incident payload
}

The bridge responds with HTTP 200 on success.
"""
import logging
from typing import Optional

import aiohttp

logger = logging.getLogger("centinela.alerts.whatsapp")

_TIMEOUT = aiohttp.ClientTimeout(total=15)


def format_whatsapp_text(incident) -> str:
    """
    Return a compact text suitable for a WhatsApp message.
    Keeps it under ~1000 chars (WA has no hard limit but shorter = better UX).
    """
    severity_tag = {
        "low": "🟡 LOW",
        "medium": "🟠 MEDIUM",
        "high": "🔴 HIGH",
        "critical": "🚨 CRITICAL",
    }.get(incident.severity, "⚠️ ALERT")

    ts = incident.timestamp.strftime("%Y-%m-%d %H:%M:%S") if incident.timestamp else "?"

    # Truncate evidence to avoid huge messages
    evidence_preview = incident.evidence[:300].replace("\n", " ")
    if len(incident.evidence) > 300:
        evidence_preview += "…"

    return (
        f"*CENTINELA ALERT*\n"
        f"{severity_tag}\n\n"
        f"📦 Project: {incident.project}\n"
        f"🐳 Container: {incident.container_name}\n"
        f"📋 Rule: {incident.rule}\n"
        f"🕐 Time: {ts}\n\n"
        f"Evidence:\n_{evidence_preview}_\n\n"
        f"ID: #{incident.id}"
    )


async def send_whatsapp_alert(
    webhook_url: str,
    incident,
    phone_number: Optional[str] = None,
) -> bool:
    """
    Send incident to the external WhatsApp bridge.
    Returns True on HTTP 2xx.
    """
    from .webhook_sender import build_webhook_payload

    full_payload = build_webhook_payload(incident)
    payload = {
        "message":  format_whatsapp_text(incident),
        "incident": full_payload["incident"],
    }
    if phone_number:
        payload["to"] = phone_number

    headers = {"Content-Type": "application/json", "User-Agent": "Centinela/1.0"}

    try:
        async with aiohttp.ClientSession(timeout=_TIMEOUT) as session:
            async with session.post(webhook_url, json=payload, headers=headers) as resp:
                if resp.status < 300:
                    logger.info("WhatsApp bridge delivered (HTTP %s) → %s",
                                resp.status, webhook_url)
                    return True
                body = await resp.text()
                logger.warning("WhatsApp bridge returned HTTP %s: %s",
                               resp.status, body[:200])
                return False
    except aiohttp.ClientError as exc:
        logger.error("WhatsApp bridge error (%s): %s", webhook_url, exc)
        return False
