"""
CENTINELA – Web Dashboard
FastAPI application providing a read-only dashboard and incident management UI.
"""
import json
import os
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy import create_engine, func, desc
from sqlalchemy.orm import sessionmaker, Session

# Ensure src/ is on the path so we can import database.models
_SRC_DIR = Path(__file__).resolve().parent.parent
if str(_SRC_DIR) not in sys.path:
    sys.path.insert(0, str(_SRC_DIR))

from database.models import Incident  # noqa: E402

# ---------------------------------------------------------------------------
# Module-level configuration – set via configure() before starting the server
# ---------------------------------------------------------------------------
_DB_URL: str = ""

_TEMPLATES_DIR = Path(__file__).resolve().parent / "templates"
templates = Jinja2Templates(directory=str(_TEMPLATES_DIR))

PAGE_SIZE = 50


def configure(db_url: str) -> None:
    """Called from main.py before the uvicorn server starts."""
    global _DB_URL
    _DB_URL = db_url


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

def create_web_app() -> FastAPI:
    app = FastAPI(title="CENTINELA Dashboard", docs_url=None, redoc_url=None)

    # ------------------------------------------------------------------
    # GET / — Dashboard
    # ------------------------------------------------------------------
    @app.get("/", response_class=HTMLResponse)
    async def dashboard(request: Request):
        now = datetime.now(timezone.utc).replace(tzinfo=None)
        since_24h = now - timedelta(hours=24)
        since_7d = now - timedelta(days=7)

        severity_24h = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        severity_7d = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        top_containers: list = []
        top_alert_types: list = []
        recent_incidents: list = []

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
