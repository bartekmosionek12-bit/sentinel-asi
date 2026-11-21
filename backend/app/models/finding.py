"""Findingi, ich historia i rekomendacje aktualizacji."""

from __future__ import annotations

import uuid
from datetime import date, datetime
from typing import Any

from sqlalchemy import CheckConstraint, ForeignKey, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base, CreatedAt, UuidPk, utcnow
from app.models.inventory import _in

FINDING_TYPES = ("cve", "misconfig", "compliance", "eol", "exposure", "signal")
FINDING_STATUSES = (
    "open",
    "acknowledged",
    "in_progress",
    "resolved",
    "accepted_risk",
    "false_positive",
)
RISK_LEVELS = ("krytyczny", "wysoki", "średni", "niski")


class Finding(Base):
    __tablename__ = "finding"
    __table_args__ = (
        CheckConstraint(_in("type", FINDING_TYPES), name="type_valid"),
        CheckConstraint(_in("status", FINDING_STATUSES), name="status_valid"),
        CheckConstraint("risk_score BETWEEN 0 AND 100", name="risk_score_range"),
        CheckConstraint(
            "vulnerability_id IS NOT NULL OR rule_id IS NOT NULL OR type IN ('eol', 'exposure')",
            name="has_cause",
        ),
    )

    id: Mapped[UuidPk]
    asset_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("asset.id", ondelete="CASCADE"), index=True
    )
    software_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("software.id", ondelete="SET NULL")
    )
    vulnerability_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("vulnerability.id", ondelete="CASCADE"), index=True
    )
    rule_id: Mapped[str | None] = mapped_column(String(64), index=True)
    type: Mapped[str] = mapped_column(String(20), index=True)
    # asset + typ + (cve lub reguła) + software: ponowny skan aktualizuje, nie duplikuje.
    dedup_key: Mapped[str] = mapped_column(String(512), unique=True)
    status: Mapped[str] = mapped_column(String(20), default="open", index=True)
    risk_score: Mapped[float] = mapped_column(default=0.0, index=True)
    risk_level: Mapped[str] = mapped_column(String(16), default="niski")
    risk_breakdown: Mapped[dict[str, Any]] = mapped_column(default=dict)
    evidence: Mapped[dict[str, Any]] = mapped_column(default=dict)
    assignee: Mapped[str | None] = mapped_column(String(255))
    first_seen: Mapped[datetime] = mapped_column(default=utcnow)
    last_seen: Mapped[datetime] = mapped_column(default=utcnow)


class FindingEvent(Base):
    """Zdarzenia tylko do dopisywania: każda zmiana stanu findingu."""

    __tablename__ = "finding_event"

    id: Mapped[UuidPk]
    finding_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("finding.id", ondelete="CASCADE"), index=True
    )
    kind: Mapped[str] = mapped_column(String(32))
    before: Mapped[dict[str, Any]] = mapped_column(default=dict)
    after: Mapped[dict[str, Any]] = mapped_column(default=dict)
    actor: Mapped[str] = mapped_column(String(255), default="system")
    reason: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[CreatedAt]


class UpdateRecommendation(Base):
    __tablename__ = "update_recommendation"
    __table_args__ = (UniqueConstraint("software_id", "recommended_version"),)

    id: Mapped[UuidPk]
    software_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("software.id", ondelete="CASCADE"), index=True
    )
    current_version: Mapped[str] = mapped_column(String(128))
    recommended_version: Mapped[str] = mapped_column(String(128))
    fixed_cves: Mapped[list[str]] = mapped_column(default=list)
    is_eol: Mapped[bool] = mapped_column(default=False)
    eol_date: Mapped[date | None]
    created_at: Mapped[CreatedAt]
