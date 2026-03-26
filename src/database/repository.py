"""
CENTINELA – Database repository.

All DB access goes through this class.
Designed to be called from asyncio using run_in_executor so every public
method is synchronous (thread-safe SQLAlchemy sessions).
"""
import json
import logging
from datetime import datetime, timedelta, timezone

def _utcnow() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)
from typing import List, Optional

from sqlalchemy import delete, func, select, update
from sqlalchemy.orm import Session, sessionmaker

from .models import (
    FilesystemSnapshot,
    Incident,
    NetworkBaseline,
    NetworkSample,
    create_db,
)

logger = logging.getLogger("centinela.db")


class IncidentRepository:
    """
    Thread-safe repository for all CENTINELA persistence.
    Create one instance and share it; each method opens/closes its own session.
    """

    def __init__(self, db_url: str):
        engine = create_db(db_url)
        self._Session = sessionmaker(engine, expire_on_commit=False)

    # ------------------------------------------------------------------
    # Incidents
    # ------------------------------------------------------------------

    def save_incident(self, incident: Incident) -> Incident:
        with self._Session() as session:
            session.add(incident)
            session.commit()
            session.refresh(incident)
            logger.debug("Incident saved: id=%s project=%s rule=%s",
                         incident.id, incident.project, incident.rule)
            return incident

    def get_incidents(
        self,
        project: Optional[str] = None,
        status: Optional[str] = None,
        severity: Optional[str] = None,
        limit: int = 100,
    ) -> List[Incident]:
        with self._Session() as session:
            stmt = select(Incident).order_by(Incident.timestamp.desc())
            if project:
                stmt = stmt.where(Incident.project == project)
            if status:
                stmt = stmt.where(Incident.status == status)
            if severity:
                stmt = stmt.where(Incident.severity == severity)
            stmt = stmt.limit(limit)
            return list(session.scalars(stmt).all())

    def get_incidents_paginated(
        self,
        project: Optional[str] = None,
        status: Optional[str] = None,
        severity: Optional[str] = None,
        limit: int = 50,
        offset: int = 0,
    ) -> List[Incident]:
        """
        Fetch a page of incidents ordered by newest first.

        Offset/limit are intended for UI pagination.
        """
        with self._Session() as session:
            stmt = select(Incident).order_by(Incident.timestamp.desc())
            if project:
                stmt = stmt.where(Incident.project == project)
            if status:
                stmt = stmt.where(Incident.status == status)
            if severity:
                stmt = stmt.where(Incident.severity == severity)
            stmt = stmt.offset(offset).limit(limit)
            return list(session.scalars(stmt).all())

    def count_incidents(
        self,
        project: Optional[str] = None,
        status: Optional[str] = None,
        severity: Optional[str] = None,
    ) -> int:
        """Count incidents for filtered pagination UI."""
        with self._Session() as session:
            stmt = select(func.count(Incident.id))
            if project:
                stmt = stmt.where(Incident.project == project)
            if status:
                stmt = stmt.where(Incident.status == status)
            if severity:
                stmt = stmt.where(Incident.severity == severity)
            return int(session.scalar(stmt) or 0)

    def get_incident_by_id(self, incident_id: int) -> Optional[Incident]:
        """Fetch a single incident (used by UI detail views)."""
        with self._Session() as session:
            return session.scalar(select(Incident).where(Incident.id == incident_id))

    def update_incident_status(self, incident_id: int, status: str) -> None:
        with self._Session() as session:
            session.execute(
                update(Incident)
                .where(Incident.id == incident_id)
                .values(status=status)
            )
            session.commit()

    def mark_alert_sent(self, incident_id: int) -> None:
        with self._Session() as session:
            session.execute(
                update(Incident)
                .where(Incident.id == incident_id)
                .values(alert_sent=True)
            )
            session.commit()

    def recent_incident_exists(self, dedup_key: str, since_seconds: int) -> bool:
        """Return True if an incident with this dedup_key was created recently."""
        cutoff = _utcnow() - timedelta(seconds=since_seconds)
        with self._Session() as session:
            count = session.scalar(
                select(func.count(Incident.id))
                .where(Incident.dedup_key == dedup_key)
                .where(Incident.timestamp >= cutoff)
            )
            return (count or 0) > 0

    # ------------------------------------------------------------------
    # Network baseline
    # ------------------------------------------------------------------

    def upsert_destination(self, container_name: str, destination: str) -> bool:
        """
        Add or refresh a known destination.
        Returns True if this is a NEW destination (not seen before).
        """
        with self._Session() as session:
            existing = session.scalar(
                select(NetworkBaseline)
                .where(NetworkBaseline.container_name == container_name)
                .where(NetworkBaseline.destination == destination)
            )
            if existing:
                existing.last_seen = _utcnow()
                existing.hit_count += 1
                session.commit()
                return False
            else:
                session.add(NetworkBaseline(
                    container_name=container_name,
                    destination=destination,
                    first_seen=_utcnow(),
                    last_seen=_utcnow(),
                    hit_count=1,
                ))
                session.commit()
                return True

    def get_baseline_age_hours(self, container_name: str) -> float:
        """Return hours since the first destination was recorded for this container."""
        with self._Session() as session:
            first = session.scalar(
                select(func.min(NetworkBaseline.first_seen))
                .where(NetworkBaseline.container_name == container_name)
            )
            if not first:
                return 0.0
            delta = _utcnow() - first
            return delta.total_seconds() / 3600

    # ------------------------------------------------------------------
    # Network samples (rolling traffic stats)
    # ------------------------------------------------------------------

    def save_network_sample(self, sample: NetworkSample) -> None:
        with self._Session() as session:
            session.add(sample)
            session.commit()

    def get_rolling_average(self, container_name: str,
                            window_hours: int = 24) -> dict:
        """
        Return avg bytes_rx and bytes_tx per sample interval
        for the last window_hours.
        """
        cutoff = _utcnow() - timedelta(hours=window_hours)
        with self._Session() as session:
            rows = session.execute(
                select(
                    func.avg(NetworkSample.bytes_rx).label("avg_rx"),
                    func.avg(NetworkSample.bytes_tx).label("avg_tx"),
                    func.count(NetworkSample.id).label("count"),
                )
                .where(NetworkSample.container_name == container_name)
                .where(NetworkSample.timestamp >= cutoff)
            ).first()
            return {
                "avg_rx": float(rows.avg_rx or 0),
                "avg_tx": float(rows.avg_tx or 0),
                "sample_count": int(rows.count or 0),
            }

    def prune_network_samples(self, older_than_hours: int = 336) -> int:
        """Delete samples older than N hours (default 14 days). Returns deleted count."""
        cutoff = _utcnow() - timedelta(hours=older_than_hours)
        with self._Session() as session:
            result = session.execute(
                delete(NetworkSample).where(NetworkSample.timestamp < cutoff)
            )
            session.commit()
            return result.rowcount

    # ------------------------------------------------------------------
    # Filesystem snapshots
    # ------------------------------------------------------------------

    def upsert_snapshot(self, container_name: str, file_path: str,
                        sha256: Optional[str], mtime: Optional[str],
                        size_bytes: Optional[int], permissions: Optional[str],
                        owner: Optional[str]) -> bool:
        """
        Insert or update a filesystem snapshot.
        Returns True if something changed (sha256 or mtime differs from stored).
        """
        with self._Session() as session:
            existing = session.scalar(
                select(FilesystemSnapshot)
                .where(FilesystemSnapshot.container_name == container_name)
                .where(FilesystemSnapshot.file_path == file_path)
            )
            if existing:
                changed = (existing.sha256 != sha256 or existing.mtime != mtime)
                existing.sha256 = sha256
                existing.mtime = mtime
                existing.size_bytes = size_bytes
                existing.permissions = permissions
                existing.owner = owner
                existing.last_checked = _utcnow()
                session.commit()
                return changed
            else:
                session.add(FilesystemSnapshot(
                    container_name=container_name,
                    file_path=file_path,
                    sha256=sha256,
                    mtime=mtime,
                    size_bytes=size_bytes,
                    permissions=permissions,
                    owner=owner,
                    last_checked=_utcnow(),
                ))
                session.commit()
                return False  # first time seen is not an alert

    def get_snapshot(self, container_name: str,
                     file_path: str) -> Optional[FilesystemSnapshot]:
        with self._Session() as session:
            return session.scalar(
                select(FilesystemSnapshot)
                .where(FilesystemSnapshot.container_name == container_name)
                .where(FilesystemSnapshot.file_path == file_path)
            )
