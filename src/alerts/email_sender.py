"""
CENTINELA – Email alert sender (async SMTP via aiosmtplib).
"""
import asyncio
import logging
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import List

import aiosmtplib

from config.models import SmtpConfig

logger = logging.getLogger("centinela.alerts.email")


async def send_email_alert(
    smtp_cfg: SmtpConfig,
    recipients: List[str],
    subject: str,
    body_text: str,
    body_html: str = "",
) -> bool:
    """
    Send an alert email to one or more recipients.
    Returns True on success, False on failure.
    """
    if not recipients:
        return True  # nothing to do

    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"] = smtp_cfg.from_addr
    msg["To"] = ", ".join(recipients)

    msg.attach(MIMEText(body_text, "plain", "utf-8"))
    if body_html:
        msg.attach(MIMEText(body_html, "html", "utf-8"))

    try:
        await aiosmtplib.send(
            msg,
            hostname=smtp_cfg.host,
            port=smtp_cfg.port,
            username=smtp_cfg.user or None,
            password=smtp_cfg.password or None,
            use_tls=smtp_cfg.use_ssl,
            start_tls=smtp_cfg.use_tls,
        )
        logger.info("Email alert sent to %s: %s", recipients, subject)
        return True
    except Exception as exc:
        logger.error("Failed to send email to %s: %s", recipients, exc)
        return False


def format_incident_email(incident) -> tuple:
    """
    Build (subject, plain_text, html) for an incident.
    """
    severity_emoji = {
        "low": "[LOW]",
        "medium": "[MEDIUM]",
        "high": "[HIGH]",
        "critical": "[CRITICAL]",
    }
    tag = severity_emoji.get(incident.severity, "[ALERT]")

    subject = (
        f"CENTINELA {tag} | {incident.project} | "
        f"{incident.rule} | {incident.container_name}"
    )

    plain = f"""
CENTINELA SECURITY ALERT
========================
Timestamp  : {incident.timestamp}
Project    : {incident.project}
Container  : {incident.container_name}
Alert Type : {incident.alert_type}
Severity   : {incident.severity.upper()}
Rule       : {incident.rule}

Evidence:
{incident.evidence}

Status     : {incident.status}
Incident ID: {incident.id}

--
CENTINELA – Automated Security Monitor
""".strip()

    html = f"""
<html><body style="font-family:monospace;background:#0d0d0d;color:#e0e0e0;padding:20px;">
<h2 style="color:#ff4444;">&#128272; CENTINELA Security Alert</h2>
<table style="border-collapse:collapse;width:100%;">
  <tr><td style="padding:4px 12px;color:#aaa;">Timestamp</td>
      <td style="padding:4px 12px;">{incident.timestamp}</td></tr>
  <tr style="background:#1a1a1a;"><td style="padding:4px 12px;color:#aaa;">Project</td>
      <td style="padding:4px 12px;font-weight:bold;">{incident.project}</td></tr>
  <tr><td style="padding:4px 12px;color:#aaa;">Container</td>
      <td style="padding:4px 12px;">{incident.container_name}</td></tr>
  <tr style="background:#1a1a1a;"><td style="padding:4px 12px;color:#aaa;">Severity</td>
      <td style="padding:4px 12px;color:{'#ff4444' if incident.severity in ('high','critical') else '#ffaa00'};font-weight:bold;">
        {incident.severity.upper()}</td></tr>
  <tr><td style="padding:4px 12px;color:#aaa;">Rule</td>
      <td style="padding:4px 12px;">{incident.rule}</td></tr>
  <tr style="background:#1a1a1a;"><td style="padding:4px 12px;color:#aaa;">Incident ID</td>
      <td style="padding:4px 12px;">#{incident.id}</td></tr>
</table>
<h3 style="color:#ffaa00;">Evidence</h3>
<pre style="background:#1a1a1a;padding:12px;border-left:4px solid #ff4444;overflow:auto;">
{incident.evidence}
</pre>
<p style="color:#555;font-size:12px;">CENTINELA – Automated Security Monitor</p>
</body></html>
""".strip()

    return subject, plain, html
