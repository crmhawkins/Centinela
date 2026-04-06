"""
CENTINELA – SQLAlchemy ORM models.

Default backend: SQLite.
Migration path to PostgreSQL: change db_url in config.
"""
from datetime import datetime, timezone

def _utcnow():
    return datetime.now(timezone.utc).replace(tzinfo=None)

from sqlalchemy import (
    BigInteger, Boolean, Column, DateTime, Integer,
    String, Text, Index, UniqueConstraint, create_engine
)
from sqlalchemy.orm import DeclarativeBase, Session


class Base(DeclarativeBase):
    pass


# ---------------------------------------------------------------------------
# Incident – core security event table
# ---------------------------------------------------------------------------

class Incident(Base):
    """
    Every detected security event is stored here.
    The 'status' field drives a simple workflow: new → reviewed → closed.
    """
    __tablename__ = "incidents"

    id             = Column(Integer, primary_key=True, autoincrement=True)
    timestamp      = Column(DateTime, default=_utcnow, nullable=False)
    project        = Column(String(150), nullable=False, index=True)
    container_id   = Column(String(64),  nullable=True)
    container_name = Column(String(200), nullable=False, index=True)
    alert_type     = Column(String(60),  nullable=False, index=True)
    severity       = Column(String(10),  nullable=False, index=True)  # low|medium|high|critical
    rule           = Column(String(150), nullable=False)
    evidence       = Column(Text,        nullable=False)  # JSON blob
    status         = Column(String(20),  nullable=False, default="new", index=True)
    alert_sent     = Column(Boolean,     nullable=False, default=False)
    dedup_key      = Column(String(250), nullable=True,  index=True)

    __table_args__ = (
        Index("ix_incidents_ts",  "timestamp"),
        Index("ix_incidents_dup", "dedup_key", "timestamp"),
    )

    def __repr__(self):
        return (f"<Incident id={self.id} project={self.project!r} "
                f"severity={self.severity!r} rule={self.rule!r}>")


# ---------------------------------------------------------------------------
# AIThreatAssessment – AI enrichment for incidents
# ---------------------------------------------------------------------------

class AIThreatAssessment(Base):
    """
    AI-generated security assessment associated with one incident.
    """
    __tablename__ = "ai_threat_assessments"

    id = Column(Integer, primary_key=True, autoincrement=True)
    timestamp = Column(DateTime, default=_utcnow, nullable=False, index=True)
    incident_id = Column(Integer, nullable=False, index=True)
    container_name = Column(String(200), nullable=False, index=True)
    project = Column(String(150), nullable=False, index=True)
    ai_model = Column(String(120), nullable=False, default="unknown")
    threat_title = Column(String(200), nullable=False, default="Unknown threat")
    threat_description = Column(Text, nullable=False, default="")
    severity = Column(String(10), nullable=False, default="medium", index=True)
    confidence = Column(Integer, nullable=False, default=50)  # 0..100
    recommendations = Column(Text, nullable=False, default="")
    raw_response = Column(Text, nullable=False, default="")


# ---------------------------------------------------------------------------
# NetworkBaseline – known destinations per container
# ---------------------------------------------------------------------------

class NetworkBaseline(Base):
    """
    Known remote IP/host destinations for each container.
    Used to detect new outbound connections.
    """
    __tablename__ = "network_baseline"

    id             = Column(Integer,  primary_key=True, autoincrement=True)
    container_name = Column(String(200), nullable=False, index=True)
    destination    = Column(String(100), nullable=False)
    first_seen     = Column(DateTime, nullable=False, default=_utcnow)
    last_seen      = Column(DateTime, nullable=False, default=_utcnow)
    hit_count      = Column(Integer,  nullable=False, default=1)

    __table_args__ = (
        UniqueConstraint("container_name", "destination", name="uq_baseline"),
    )


# ---------------------------------------------------------------------------
# NetworkSample – rolling traffic stats
# ---------------------------------------------------------------------------

class NetworkSample(Base):
    """
    Point-in-time network byte/packet counters per container.
    Used to calculate rolling averages and detect spikes.
    Kept for baseline_window_hours then pruned.
    """
    __tablename__ = "network_samples"

    id             = Column(Integer,    primary_key=True, autoincrement=True)
    container_name = Column(String(200), nullable=False, index=True)
    timestamp      = Column(DateTime,   nullable=False, default=_utcnow, index=True)
    bytes_rx       = Column(BigInteger, nullable=False, default=0)
    bytes_tx       = Column(BigInteger, nullable=False, default=0)
    packets_rx     = Column(BigInteger, nullable=False, default=0)
    packets_tx     = Column(BigInteger, nullable=False, default=0)

    __table_args__ = (
        Index("ix_net_samples_name_ts", "container_name", "timestamp"),
    )


# ---------------------------------------------------------------------------
# FilesystemSnapshot – hash/mtime baseline for critical files
# ---------------------------------------------------------------------------

class FilesystemSnapshot(Base):
    """
    Stores last-known state of monitored files.
    Used to detect changes when inotify is not available
    (e.g., named volumes without a host bind-mount path).
    """
    __tablename__ = "filesystem_snapshots"

    id             = Column(Integer,  primary_key=True, autoincrement=True)
    container_name = Column(String(200), nullable=False, index=True)
    file_path      = Column(String(500), nullable=False)
    sha256         = Column(String(64),  nullable=True)
    mtime          = Column(String(30),  nullable=True)
    size_bytes     = Column(BigInteger,  nullable=True)
    permissions    = Column(String(10),  nullable=True)
    owner          = Column(String(50),  nullable=True)
    last_checked   = Column(DateTime,    nullable=False, default=_utcnow)

    __table_args__ = (
        UniqueConstraint("container_name", "file_path", name="uq_fs_snapshot"),
    )


# ---------------------------------------------------------------------------
# Database factory
# ---------------------------------------------------------------------------

def create_db(db_url: str) -> Session:
    """
    Create engine and all tables if they don't exist.
    Returns a Session factory (not an open session).
    """
    connect_args = {}
    if db_url.startswith("sqlite"):
        connect_args["check_same_thread"] = False

    engine = create_engine(
        db_url,
        connect_args=connect_args,
        pool_pre_ping=True,
        echo=False,
    )
    Base.metadata.create_all(engine)
    return engine
