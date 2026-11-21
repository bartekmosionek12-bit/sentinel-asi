"""Centralny inwentarz: zasoby, relacje, oprogramowanie, historia."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import CheckConstraint, ForeignKey, Index, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base, CreatedAt, UuidPk, utcnow

ASSET_TYPES = (
    "host",
    "domain",
    "ip",
    "service",
    "application",
    # Etap 6 (§7.1): typy urządzeń z AD, MDM i CMDB.
    "workstation",
    "laptop",
    "server",
    "network",
    "printer",
    "iot",
    "cloud",
    "ai_system",
)
ASSET_EXPOSURES = ("internet", "internal")
ASSET_STATUSES = ("active", "missing", "retired", "shadow")
RELATION_TYPES = ("resolves_to", "runs", "hosts", "depends_on")
MATCH_STATUSES = ("unmatched", "auto", "needs_review", "confirmed", "rejected")


def _in(column: str, values: tuple[str, ...]) -> str:
    return f"{column} IN ({', '.join(repr(v) for v in values)})"


class Asset(Base):
    __tablename__ = "asset"
    __table_args__ = (
        CheckConstraint(_in("type", ASSET_TYPES), name="type_valid"),
        CheckConstraint(_in("exposure", ASSET_EXPOSURES), name="exposure_valid"),
        CheckConstraint(_in("status", ASSET_STATUSES), name="status_valid"),
        CheckConstraint("criticality BETWEEN 1 AND 5", name="criticality_range"),
    )

    id: Mapped[UuidPk]
    type: Mapped[str] = mapped_column(String(20))
    name: Mapped[str] = mapped_column(String(255))
    # Klucz deduplikacji: ten sam zasób z importu i ze skanu scala się w jeden wiersz.
    fingerprint: Mapped[str] = mapped_column(String(512), unique=True)
    exposure: Mapped[str] = mapped_column(String(20), default="internal")
    criticality: Mapped[int] = mapped_column(default=3)
    # Właściciel jako tekst (import CSV); w P2 przechodzi do warstwy nadpisań użytkownika.
    owner: Mapped[str | None] = mapped_column(String(255))
    segment_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("network_segment.id", ondelete="SET NULL"), index=True
    )
    tags: Mapped[list[str]] = mapped_column(default=list)
    attributes: Mapped[dict[str, Any]] = mapped_column(default=dict)
    status: Mapped[str] = mapped_column(String(20), default="active", index=True)
    first_seen: Mapped[datetime] = mapped_column(default=utcnow)
    last_seen: Mapped[datetime] = mapped_column(default=utcnow)

    software: Mapped[list[Software]] = relationship(
        back_populates="asset", cascade="all, delete-orphan"
    )


class AssetRelation(Base):
    __tablename__ = "asset_relation"
    __table_args__ = (
        UniqueConstraint("source_id", "target_id", "type"),
        CheckConstraint(_in("type", RELATION_TYPES), name="type_valid"),
    )

    id: Mapped[UuidPk]
    source_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("asset.id", ondelete="CASCADE"))
    target_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("asset.id", ondelete="CASCADE"))
    type: Mapped[str] = mapped_column(String(20))
    first_seen: Mapped[datetime] = mapped_column(default=utcnow)
    last_seen: Mapped[datetime] = mapped_column(default=utcnow)


class AssetHistory(Base):
    """Zdarzenia tylko do dopisywania: diff stanu zasobu między skanami."""

    __tablename__ = "asset_history"

    id: Mapped[UuidPk]
    asset_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("asset.id", ondelete="CASCADE"), index=True
    )
    scan_run_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("scan_run.id", ondelete="SET NULL"), index=True
    )
    change: Mapped[str] = mapped_column(String(20))
    diff: Mapped[dict[str, Any]] = mapped_column(default=dict)
    created_at: Mapped[CreatedAt]


class Software(Base):
    __tablename__ = "software"
    __table_args__ = (
        UniqueConstraint("asset_id", "product", "version", "port", "source"),
        CheckConstraint(_in("match_status", MATCH_STATUSES), name="match_status_valid"),
        CheckConstraint("match_confidence BETWEEN 0 AND 1", name="confidence_range"),
        Index("ix_software_cpe_vendor_product", "cpe_vendor", "cpe_product"),
    )

    id: Mapped[UuidPk]
    asset_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("asset.id", ondelete="CASCADE"), index=True
    )
    vendor: Mapped[str] = mapped_column(String(255), default="")
    product: Mapped[str] = mapped_column(String(255))
    version: Mapped[str] = mapped_column(String(128), default="")
    raw_banner: Mapped[str | None] = mapped_column(Text)
    cpe: Mapped[str | None] = mapped_column(String(512))
    cpe_vendor: Mapped[str | None] = mapped_column(String(255))
    cpe_product: Mapped[str | None] = mapped_column(String(255))
    source: Mapped[str] = mapped_column(String(32))
    port: Mapped[int | None]
    protocol: Mapped[str | None] = mapped_column(String(8))
    match_method: Mapped[str | None] = mapped_column(String(20))
    match_confidence: Mapped[float] = mapped_column(default=0.0)
    match_status: Mapped[str] = mapped_column(String(20), default="unmatched", index=True)
    first_seen: Mapped[datetime] = mapped_column(default=utcnow)
    last_seen: Mapped[datetime] = mapped_column(default=utcnow)

    asset: Mapped[Asset] = relationship(back_populates="software")


class MatchCandidate(Base):
    """Kolejka weryfikacji: dopasowania produktu do CPE o niskiej pewności."""

    __tablename__ = "match_candidate"
    __table_args__ = (UniqueConstraint("software_id", "cpe"),)

    id: Mapped[UuidPk]
    software_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("software.id", ondelete="CASCADE"), index=True
    )
    cpe: Mapped[str] = mapped_column(String(512))
    score: Mapped[float]
    method: Mapped[str] = mapped_column(String(20))
    reason: Mapped[str] = mapped_column(Text, default="")
    decision: Mapped[str] = mapped_column(String(20), default="pending", index=True)
    decided_by: Mapped[str | None] = mapped_column(String(255))
    decided_at: Mapped[datetime | None]
    created_at: Mapped[CreatedAt]


class CpeProduct(Base):
    """Słownik par producent i produkt z CPE, po którym szuka dopasowanie rozmyte."""

    __tablename__ = "cpe_product"
    __table_args__ = (UniqueConstraint("vendor", "product"),)

    id: Mapped[UuidPk]
    vendor: Mapped[str] = mapped_column(String(255))
    product: Mapped[str] = mapped_column(String(255))
    title: Mapped[str] = mapped_column(String(512), default="")


class SignalMatch(Base):
    """Sygnał bez CPE: podatność z KEV wskazuje producenta i produkt, ale bez zakresu wersji.

    Dopasowanie do oprogramowania z inwentarza ma tylko pewność nazwy, więc nigdy nie tworzy
    findingu samo: zawsze czeka na decyzję człowieka w kolejce weryfikacji.
    """

    __tablename__ = "signal_match"
    __table_args__ = (UniqueConstraint("vulnerability_id", "software_id"),)

    id: Mapped[UuidPk]
    vulnerability_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("vulnerability.id", ondelete="CASCADE"), index=True
    )
    software_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("software.id", ondelete="CASCADE"), index=True
    )
    source: Mapped[str] = mapped_column(String(20), default="kev")
    vendor: Mapped[str] = mapped_column(String(255), default="")
    product: Mapped[str] = mapped_column(String(255), default="")
    score: Mapped[float]
    method: Mapped[str] = mapped_column(String(20))
    reason: Mapped[str] = mapped_column(Text, default="")
    decision: Mapped[str] = mapped_column(String(20), default="pending", index=True)
    decided_by: Mapped[str | None] = mapped_column(String(255))
    decided_at: Mapped[datetime | None]
    finding_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("finding.id", ondelete="SET NULL")
    )
    created_at: Mapped[CreatedAt]
