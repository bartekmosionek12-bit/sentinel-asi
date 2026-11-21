"""Segmenty sieci i źródła inwentarza.

`NetworkSegment` grupuje adresy w widoku sieci (konsola zespołu IT). `AssetSource` mówi, które
źródło widziało zasób i kiedy (skan, import), co pokazuje karta hosta.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import CheckConstraint, ForeignKey, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base, UuidPk, utcnow
from app.models.inventory import _in

ASSET_SOURCES = ("scan", "csv", "ad", "entra", "mdm", "cmdb", "dhcp", "dns", "cloud")


class NetworkSegment(Base):
    __tablename__ = "network_segment"

    id: Mapped[UuidPk]
    name: Mapped[str] = mapped_column(String(255))
    cidr: Mapped[str] = mapped_column(String(64), unique=True)


class AssetSource(Base):
    """Które źródło widziało zasób i kiedy."""

    __tablename__ = "asset_source"
    __table_args__ = (
        UniqueConstraint("asset_id", "source"),
        CheckConstraint(_in("source", ASSET_SOURCES), name="source_valid"),
    )

    id: Mapped[UuidPk]
    asset_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("asset.id", ondelete="CASCADE"), index=True
    )
    source: Mapped[str] = mapped_column(String(16))
    external_id: Mapped[str | None] = mapped_column(String(255))
    first_seen: Mapped[datetime] = mapped_column(default=utcnow)
    last_seen: Mapped[datetime] = mapped_column(default=utcnow)
