"""
CENTINELA – Web Dashboard
FastAPI application providing a read-only dashboard and incident management UI.
"""
import base64
import hashlib
import hmac
import json
import os
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, Optional
from urllib.parse import quote

import asyncio
import docker
from fastapi import FastAPI, Form, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from fastapi.templating import Jinja2Templates
from sqlalchemy import create_engine, func, desc
from sqlalchemy.orm import sessionmaker, Session
from starlette.middleware.base import BaseHTTPMiddleware

# Ensure src/ is on the path so we can import database.models
_SRC_DIR = Path(__file__).resolve().parent.parent
if str(_SRC_DIR) not in sys.path:
    sys.path.insert(0, str(_SRC_DIR))

from database.models import AIThreatAssessment, Incident  # noqa: E402

# ---------------------------------------------------------------------------
# Module-level configuration – set via configure() before starting the server
# ---------------------------------------------------------------------------
_DB_URL: str = ""
_AI_ANALYZER = None

_TEMPLATES_DIR = Path(__file__).resolve().parent / "templates"
templates = Jinja2Templates(directory=str(_TEMPLATES_DIR))

PAGE_SIZE = 50
SESSION_COOKIE_NAME = "centinela_session"
SESSION_TTL_SECONDS = int(os.environ.get("CENTINELA_WEB_SESSION_TTL", "43200"))  # 12h


def _bytes_to_human(num_bytes: Optional[float]) -> str:
    if num_bytes is None:
        return "—"
    value = float(num_bytes)
    units = ["B", "KB", "MB", "GB", "TB"]
    idx = 0
    while value >= 1024.0 and idx < len(units) - 1:
        value /= 1024.0
        idx += 1
    if idx == 0:
        return f"{int(value)} {units[idx]}"
    return f"{value:.1f} {units[idx]}"


def _safe_cpu_percent(stats: Dict[str, Any]) -> float:
    try:
        cpu_total = stats.get("cpu_stats", {}).get("cpu_usage", {}).get("total_usage", 0)
        pre_total = stats.get("precpu_stats", {}).get("cpu_usage", {}).get("total_usage", 0)
        cpu_delta = cpu_total - pre_total

        sys_total = stats.get("cpu_stats", {}).get("system_cpu_usage", 0)
        pre_sys_total = stats.get("precpu_stats", {}).get("system_cpu_usage", 0)
        sys_delta = sys_total - pre_sys_total

        cpu_count = (
            len(stats.get("cpu_stats", {}).get("cpu_usage", {}).get("percpu_usage", []) or [])
            or stats.get("cpu_stats", {}).get("online_cpus")
            or 1
        )
        if cpu_delta > 0 and sys_delta > 0:
            return (cpu_delta / sys_delta) * cpu_count * 100.0
    except Exception:
        return 0.0
    return 0.0


def _collect_container_runtime_metrics() -> list:
    rows = []
    client = None
    try:
        client = docker.from_env()
        for container in client.containers.list():
            name = container.name
            short_id = (container.id or "")[:12]
            image = getattr(container.image, "tags", []) or []
            image_label = image[0] if image else (container.image.short_id if container.image else "unknown")
            status = container.status

            cpu_pct = 0.0
            mem_usage = None
            mem_limit = None
            mem_pct = 0.0
            net_rx = 0
            net_tx = 0
            disk_rw = None

            try:
                stats = container.stats(stream=False)
                cpu_pct = _safe_cpu_percent(stats)
                mem = stats.get("memory_stats", {}) or {}
                mem_usage = mem.get("usage")
                mem_limit = mem.get("limit")
                if mem_usage is not None and mem_limit:
                    mem_pct = (float(mem_usage) / float(mem_limit)) * 100.0
                networks = stats.get("networks", {}) or {}
                for iface in networks.values():
                    net_rx += int(iface.get("rx_bytes", 0) or 0)
                    net_tx += int(iface.get("tx_bytes", 0) or 0)
            except Exception:
                pass

            # NOTE: inspect_container(..., size=True) can be very expensive on hosts
            # with many containers/layers and may block the dashboard route.
            # We keep disk as unavailable by default to preserve responsiveness.
            disk_rw = None

            rows.append({
                "name": name,
                "id": short_id,
                "image": image_label,
                "status": status,
                "cpu_pct": round(cpu_pct, 2),
                "mem_usage_human": _bytes_to_human(mem_usage),
                "mem_limit_human": _bytes_to_human(mem_limit),
                "mem_pct": round(mem_pct, 2),
                "disk_rw_human": _bytes_to_human(disk_rw),
                "net_rx_human": _bytes_to_human(net_rx),
                "net_tx_human": _bytes_to_human(net_tx),
            })
    finally:
        if client is not None:
            try:
                client.close()
            except Exception:
                pass
    return sorted(rows, key=lambda r: r["name"])


def configure(db_url: str) -> None:
    """Called from main.py before the uvicorn server starts."""
    global _DB_URL
    _DB_URL = db_url


def configure_ai_analyzer(analyzer) -> None:
    """Called from main.py to register the AIThreatAnalyzer singleton."""
    global _AI_ANALYZER
    _AI_ANALYZER = analyzer


def _auth_credentials() -> tuple[str, str]:
    user = os.environ.get("CENTINELA_WEB_USER", "admin")
    password = os.environ.get("CENTINELA_WEB_PASS", "centinela")
    return user, password


def _session_secret() -> str:
    # Can be overridden; fallback keeps compatibility without extra env vars.
    return os.environ.get("CENTINELA_WEB_SESSION_SECRET", "centinela-session-secret")


def _build_session_token(username: str, password: str) -> str:
    payload = f"{username}:{password}:{_session_secret()}".encode("utf-8")
    return hmac.new(_session_secret().encode("utf-8"), payload, hashlib.sha256).hexdigest()


def _is_valid_session(cookie_value: Optional[str]) -> bool:
    if not cookie_value:
        return False
    user, password = _auth_credentials()
    expected = _build_session_token(user, password)
    return hmac.compare_digest(cookie_value, expected)


def _totp_secret() -> str:
    return os.environ.get("CENTINELA_WEB_2FA_SECRET", "").strip()


def _hotp(secret_b32: str, counter: int, digits: int = 6) -> Optional[str]:
    try:
        key = base64.b32decode(secret_b32.upper(), casefold=True)
    except Exception:
        return None
    msg = counter.to_bytes(8, "big")
    digest = hmac.new(key, msg, hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    code_int = (
        ((digest[offset] & 0x7F) << 24)
        | (digest[offset + 1] << 16)
        | (digest[offset + 2] << 8)
        | digest[offset + 3]
    )
    return str(code_int % (10 ** digits)).zfill(digits)


def _verify_totp(code: str, skew_steps: int = 1, step_seconds: int = 30) -> bool:
    secret = _totp_secret()
    if not secret:
        return False
    normalized = "".join(ch for ch in str(code) if ch.isdigit())
    if len(normalized) != 6:
        return False
    now_counter = int(time.time() // step_seconds)
    for delta in range(-skew_steps, skew_steps + 1):
        expected = _hotp(secret, now_counter + delta, digits=6)
        if expected and hmac.compare_digest(expected, normalized):
            return True
    return False


def _get_db_session(db_url: str) -> Session:
    """Create a read-only SQLAlchemy session from the given db_url."""
    connect_args = {}
    if db_url.startswith("sqlite"):
        connect_args["check_same_thread"] = False
    engine = create_engine(
        db_url,
        connect_args=connect_args,
        pool_pre_ping=True,
        echo=False,
    )
    SessionFactory = sessionmaker(bind=engine, autocommit=False, autoflush=False)
    return SessionFactory()


# ---------------------------------------------------------------------------
# App factory
# ---------------------------------------------------------------------------

def _auth_enabled() -> bool:
    """Return False when auth is explicitly disabled via environment variables."""
    if os.environ.get("CENTINELA_WEB_AUTH", "").lower() == "false":
        return False
    _user = os.environ.get("CENTINELA_WEB_USER", "admin")
    _pass = os.environ.get("CENTINELA_WEB_PASS", "centinela")
    if _user == "" and _pass == "":
        return False
    return True


class SessionAuthMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        if not _auth_enabled():
            return await call_next(request)
        # Exempt auth and health endpoints from authentication.
        if request.url.path in ("/health", "/login", "/logout"):
            return await call_next(request)

        session_cookie = request.cookies.get(SESSION_COOKIE_NAME)
        if not _is_valid_session(session_cookie):
            next_url = request.url.path
            if request.url.query:
                next_url = f"{next_url}?{request.url.query}"
            return RedirectResponse(
                url=f"/login?next={quote(next_url, safe='/?=&')}",
                status_code=303,
            )
        return await call_next(request)


def create_web_app() -> FastAPI:
    app = FastAPI(title="CENTINELA Dashboard", docs_url=None, redoc_url=None)

    app.add_middleware(SessionAuthMiddleware)

    # ------------------------------------------------------------------
    # GET /health — Health check (exempt from auth)
    # ------------------------------------------------------------------
    @app.get("/health")
    async def health():
        return {"status": "ok"}

    @app.get("/login", response_class=HTMLResponse)
    async def login_page(request: Request, next: str = "/"):
        if not _auth_enabled():
            return RedirectResponse(url=next or "/", status_code=303)
        if _is_valid_session(request.cookies.get(SESSION_COOKIE_NAME)):
            return RedirectResponse(url=next or "/", status_code=303)
        return templates.TemplateResponse(
            request=request,
            name="login.html",
            context={"next_url": next or "/", "error": ""},
        )

    @app.post("/login", response_class=HTMLResponse)
    async def login_submit(
        request: Request,
        username: str = Form(...),
        password: str = Form(...),
        next: str = Form("/"),
    ):
        expected_user, expected_pass = _auth_credentials()
        if username != expected_user or password != expected_pass:
            return templates.TemplateResponse(
                request=request,
                name="login.html",
                context={"next_url": next or "/", "error": "Credenciales incorrectas"},
                status_code=401,
            )

        target = next if next.startswith("/") else "/"
        response = RedirectResponse(url=target, status_code=303)
        response.set_cookie(
            key=SESSION_COOKIE_NAME,
            value=_build_session_token(expected_user, expected_pass),
            max_age=SESSION_TTL_SECONDS,
            httponly=True,
            samesite="lax",
            secure=False,
            path="/",
        )
        return response

    @app.get("/logout")
    async def logout():
        response = RedirectResponse(url="/login", status_code=303)
        response.delete_cookie(SESSION_COOKIE_NAME, path="/")
        return response

    # ------------------------------------------------------------------
    # POST /ai/run — Trigger AI analysis immediately
    # ------------------------------------------------------------------
    @app.post("/ai/run")
    async def ai_run(request: Request):
        if _AI_ANALYZER is not None:
            asyncio.create_task(_AI_ANALYZER.run_digest_now())
        return RedirectResponse(url="/?ai_triggered=1", status_code=303)

    # ------------------------------------------------------------------
    # GET / — Dashboard
    # ------------------------------------------------------------------
    @app.get("/", response_class=HTMLResponse)
    async def dashboard(request: Request, ai_triggered: int = 0):
        now = datetime.now(timezone.utc).replace(tzinfo=None)
        since_24h = now - timedelta(hours=24)
        since_7d = now - timedelta(days=7)

        severity_24h = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        severity_7d = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        top_containers: list = []
        top_alert_types: list = []
        recent_incidents: list = []
        latest_ai = None

        try:
            db = _get_db_session(_DB_URL)
            try:
                # Severity counts last 24h
                rows_24h = (
                    db.query(Incident.severity, func.count(Incident.id))
                    .filter(Incident.timestamp >= since_24h)
                    .group_by(Incident.severity)
                    .all()
                )
                for severity, count in rows_24h:
                    if severity in severity_24h:
                        severity_24h[severity] = count

                # Severity counts last 7d
                rows_7d = (
                    db.query(Incident.severity, func.count(Incident.id))
                    .filter(Incident.timestamp >= since_7d)
                    .group_by(Incident.severity)
                    .all()
                )
                for severity, count in rows_7d:
                    if severity in severity_7d:
                        severity_7d[severity] = count

                # Top 5 containers last 7d
                top_containers = (
                    db.query(Incident.container_name, func.count(Incident.id).label("cnt"))
                    .filter(Incident.timestamp >= since_7d)
                    .group_by(Incident.container_name)
                    .order_by(desc("cnt"))
                    .limit(5)
                    .all()
                )

                # Top 5 alert types last 7d
                top_alert_types = (
                    db.query(Incident.alert_type, func.count(Incident.id).label("cnt"))
                    .filter(Incident.timestamp >= since_7d)
                    .group_by(Incident.alert_type)
                    .order_by(desc("cnt"))
                    .limit(5)
                    .all()
                )

                # Last 10 incidents
                recent_incidents = (
                    db.query(Incident)
                    .order_by(desc(Incident.timestamp))
                    .limit(10)
                    .all()
                )
                latest_ai = (
                    db.query(AIThreatAssessment)
                    .order_by(desc(AIThreatAssessment.timestamp))
                    .limit(1)
                    .first()
                )
            finally:
                db.close()
        except Exception as exc:
            # Log but never crash the web server
            import logging
            logging.getLogger("centinela.web").error("Dashboard DB error: %s", exc)

        return templates.TemplateResponse(
            request=request,
            name="dashboard.html",
            context={
                "severity_24h": severity_24h,
                "severity_7d": severity_7d,
                "top_containers": top_containers,
                "top_alert_types": top_alert_types,
                "recent_incidents": recent_incidents,
                "latest_ai": latest_ai,
                "ai_triggered": ai_triggered,
            },
        )

    # ------------------------------------------------------------------
    # GET /incidents — Incident list with filters + pagination
    # ------------------------------------------------------------------
    @app.get("/incidents", response_class=HTMLResponse)
    async def incident_list(
        request: Request,
        project: Optional[str] = None,
        severity: Optional[str] = None,
        status: Optional[str] = None,
        alert_type: Optional[str] = None,
        page: int = 1,
    ):
        if page < 1:
            page = 1

        incidents: list = []
        total: int = 0

        try:
            db = _get_db_session(_DB_URL)
            try:
                query = db.query(Incident)

                if project:
                    query = query.filter(Incident.project.ilike(f"%{project}%"))
                if severity:
                    query = query.filter(Incident.severity == severity.lower())
                if status:
                    query = query.filter(Incident.status == status.lower())
                if alert_type:
                    query = query.filter(Incident.alert_type.ilike(f"%{alert_type}%"))

                total = query.count()
                offset = (page - 1) * PAGE_SIZE
                incidents = (
                    query.order_by(desc(Incident.timestamp))
                    .offset(offset)
                    .limit(PAGE_SIZE)
                    .all()
                )
            finally:
                db.close()
        except Exception as exc:
            import logging
            logging.getLogger("centinela.web").error("Incident list DB error: %s", exc)

        total_pages = max(1, (total + PAGE_SIZE - 1) // PAGE_SIZE)
        active_filters = {
            k: v
            for k, v in {"project": project, "severity": severity, "status": status, "alert_type": alert_type}.items()
            if v
        }

        return templates.TemplateResponse(
            request=request,
            name="incidents.html",
            context={
                "incidents": incidents,
                "total": total,
                "page": page,
                "total_pages": total_pages,
                "page_size": PAGE_SIZE,
                "project": project or "",
                "severity": severity or "",
                "status": status or "",
                "alert_type": alert_type or "",
                "active_filters": active_filters,
            },
        )

    # ------------------------------------------------------------------
    # GET /incidents/grouped — Aggregated incident groups
    # ------------------------------------------------------------------
    @app.get("/incidents/grouped", response_class=HTMLResponse)
    async def incident_grouped(
        request: Request,
        since_days: int = 7,
        severity: Optional[str] = None,
        status: Optional[str] = None,
    ):
        if since_days not in (1, 7, 30):
            since_days = 7

        groups: list = []
        total_incidents: int = 0

        try:
            db = _get_db_session(_DB_URL)
            try:
                now = datetime.now(timezone.utc).replace(tzinfo=None)
                cutoff = now - timedelta(days=since_days)

                q = (
                    db.query(
                        Incident.alert_type,
                        Incident.container_name,
                        Incident.rule,
                        Incident.severity,
                        func.count(Incident.id).label("count"),
                        func.min(Incident.timestamp).label("first_seen"),
                        func.max(Incident.timestamp).label("last_seen"),
                    )
                    .filter(Incident.timestamp >= cutoff)
                )
                if severity:
                    q = q.filter(Incident.severity == severity.lower())
                if status:
                    q = q.filter(Incident.status == status.lower())
                rows = (
                    q
                    .group_by(
                        Incident.alert_type,
                        Incident.container_name,
                        Incident.rule,
                        Incident.severity,
                    )
                    .order_by(desc("count"))
                    .limit(200)
                    .all()
                )
                groups = [
                    {
                        "alert_type": r.alert_type,
                        "container_name": r.container_name,
                        "rule": r.rule,
                        "severity": r.severity,
                        "count": r.count,
                        "first_seen": r.first_seen,
                        "last_seen": r.last_seen,
                    }
                    for r in rows
                ]
                total_incidents = sum(g["count"] for g in groups)
            finally:
                db.close()
        except Exception as exc:
            import logging
            logging.getLogger("centinela.web").error("Incident grouped DB error: %s", exc)

        return templates.TemplateResponse(
            request=request,
            name="grouped.html",
            context={
                "groups": groups,
                "since_days": since_days,
                "severity": severity or "",
                "status": status or "",
                "total_groups": len(groups),
                "total_incidents": total_incidents,
            },
        )

    # ------------------------------------------------------------------
    # GET/POST /incidents/purge — Delete all incidents (password + TOTP)
    # ------------------------------------------------------------------
    @app.get("/incidents/purge", response_class=HTMLResponse)
    async def purge_incidents_page(request: Request):
        return templates.TemplateResponse(
            request=request,
            name="purge_incidents.html",
            context={"error": "", "ok_message": ""},
        )

    @app.post("/incidents/purge", response_class=HTMLResponse)
    async def purge_incidents_submit(
        request: Request,
        password: str = Form(...),
    ):
        _, expected_pass = _auth_credentials()
        if password != expected_pass:
            return templates.TemplateResponse(
                request=request,
                name="purge_incidents.html",
                context={"error": "Contrasena incorrecta.", "ok_message": ""},
                status_code=401,
            )

        deleted = 0
        try:
            db = _get_db_session(_DB_URL)
            try:
                deleted = db.query(Incident).delete(synchronize_session=False)
                db.commit()
            finally:
                db.close()
        except Exception as exc:
            import logging
            logging.getLogger("centinela.web").error("Purge incidents error: %s", exc)
            return templates.TemplateResponse(
                request=request,
                name="purge_incidents.html",
                context={"error": "No se pudieron borrar incidencias. Revisa logs.", "ok_message": ""},
                status_code=500,
            )

        return templates.TemplateResponse(
            request=request,
            name="purge_incidents.html",
            context={"error": "", "ok_message": f"Incidencias eliminadas: {deleted}"},
        )

    # ------------------------------------------------------------------
    # GET /containers — Runtime container metrics + incident summary
    # ------------------------------------------------------------------
    @app.get("/containers", response_class=HTMLResponse)
    async def containers_page(request: Request):
        try:
            containers = []
            by_container = {}
            now = datetime.now(timezone.utc).replace(tzinfo=None)
            since_7d = now - timedelta(days=7)

            try:
                # Docker SDK calls are blocking; run off the event loop and cap wait time.
                containers = await asyncio.wait_for(
                    asyncio.to_thread(_collect_container_runtime_metrics),
                    timeout=8.0,
                )
            except asyncio.TimeoutError:
                import logging
                logging.getLogger("centinela.web").warning(
                    "Container metrics timeout (>8s). Returning empty metrics snapshot."
                )
                containers = []
            except Exception as exc:
                import logging
                logging.getLogger("centinela.web").error("Container metrics error: %s", exc)
                containers = []

            try:
                db = _get_db_session(_DB_URL)
                try:
                    total_rows = (
                        db.query(Incident.container_name, func.count(Incident.id))
                        .group_by(Incident.container_name)
                        .all()
                    )
                    open_rows = (
                        db.query(Incident.container_name, func.count(Incident.id))
                        .filter(Incident.status != "closed")
                        .group_by(Incident.container_name)
                        .all()
                    )
                    critical_rows = (
                        db.query(Incident.container_name, func.count(Incident.id))
                        .filter(Incident.severity == "critical")
                        .group_by(Incident.container_name)
                        .all()
                    )
                    last_7d_rows = (
                        db.query(Incident.container_name, func.count(Incident.id))
                        .filter(Incident.timestamp >= since_7d)
                        .group_by(Incident.container_name)
                        .all()
                    )

                    for name, cnt in total_rows:
                        by_container.setdefault(name, {})["total"] = cnt
                    for name, cnt in open_rows:
                        by_container.setdefault(name, {})["open"] = cnt
                    for name, cnt in critical_rows:
                        by_container.setdefault(name, {})["critical"] = cnt
                    for name, cnt in last_7d_rows:
                        by_container.setdefault(name, {})["last_7d"] = cnt
                finally:
                    db.close()
            except Exception as exc:
                import logging
                logging.getLogger("centinela.web").error("Container incident summary error: %s", exc)

            if not isinstance(containers, list):
                containers = []

            normalized_rows = []
            for row in containers:
                if not isinstance(row, dict):
                    continue
                container_name = str(row.get("name") or "unknown")
                row["name"] = container_name
                row["id"] = str(row.get("id") or "—")
                row["status"] = str(row.get("status") or "unknown")
                row["image"] = str(row.get("image") or "unknown")

                try:
                    row["cpu_pct"] = float(row.get("cpu_pct") or 0.0)
                except (TypeError, ValueError):
                    row["cpu_pct"] = 0.0
                try:
                    row["mem_pct"] = float(row.get("mem_pct") or 0.0)
                except (TypeError, ValueError):
                    row["mem_pct"] = 0.0

                row["mem_usage_human"] = row.get("mem_usage_human") or "—"
                row["mem_limit_human"] = row.get("mem_limit_human") or "—"
                row["disk_rw_human"] = row.get("disk_rw_human") or "—"
                row["net_rx_human"] = row.get("net_rx_human") or "—"
                row["net_tx_human"] = row.get("net_tx_human") or "—"

                stats = by_container.get(container_name, {})
                row["inc_total"] = int(stats.get("total", 0) or 0)
                row["inc_open"] = int(stats.get("open", 0) or 0)
                row["inc_critical"] = int(stats.get("critical", 0) or 0)
                row["inc_last_7d"] = int(stats.get("last_7d", 0) or 0)
                normalized_rows.append(row)

            return templates.TemplateResponse(
                request=request,
                name="containers.html",
                context={
                    "containers": normalized_rows,
                },
            )
        except Exception as exc:
            import logging
            logging.getLogger("centinela.web").error("Containers template error: %s", exc)
            return HTMLResponse(
                content="<h1>Containers unavailable</h1><p>Check CENTINELA logs for details.</p>",
                status_code=503,
            )

    # ------------------------------------------------------------------
    # GET /incidents/{incident_id} — Incident detail
    # ------------------------------------------------------------------
    @app.get("/incidents/{incident_id}", response_class=HTMLResponse)
    async def incident_detail(request: Request, incident_id: int):
        incident = None
        evidence_pretty = ""

        try:
            db = _get_db_session(_DB_URL)
            try:
                incident = db.query(Incident).filter(Incident.id == incident_id).first()
                if incident and incident.evidence:
                    try:
                        evidence_pretty = json.dumps(json.loads(incident.evidence), indent=2)
                    except (json.JSONDecodeError, TypeError):
                        evidence_pretty = incident.evidence
            finally:
                db.close()
        except Exception as exc:
            import logging
            logging.getLogger("centinela.web").error("Incident detail DB error: %s", exc)

        if incident is None:
            return HTMLResponse(content="<h1>Incident not found</h1>", status_code=404)

        return templates.TemplateResponse(
            request=request,
            name="incident_detail.html",
            context={
                "incident": incident,
                "evidence_pretty": evidence_pretty,
            },
        )

    # ------------------------------------------------------------------
    # POST /incidents/{incident_id}/status — Update incident status
    # ------------------------------------------------------------------
    @app.post("/incidents/{incident_id}/status")
    async def update_incident_status(
        incident_id: int,
        status: str = Form(...),
    ):
        valid_statuses = {"new", "reviewed", "closed"}
        if status not in valid_statuses:
            return RedirectResponse(url=f"/incidents/{incident_id}", status_code=303)

        try:
            db = _get_db_session(_DB_URL)
            try:
                incident = db.query(Incident).filter(Incident.id == incident_id).first()
                if incident:
                    incident.status = status
                    db.commit()
            finally:
                db.close()
        except Exception as exc:
            import logging
            logging.getLogger("centinela.web").error("Status update DB error: %s", exc)

        return RedirectResponse(url=f"/incidents/{incident_id}", status_code=303)

    return app
