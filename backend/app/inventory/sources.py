"""Które źródło widziało zasób (skan, import) i kiedy."""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import Asset, AssetSource
from app.models.base import utcnow
from app.models.network import ASSET_SOURCES


def touch_source(
    session: Session,
    asset: Asset,
    source: str,
    external_id: str | None = None,
    *,
    now: datetime | None = None,
) -> AssetSource:
    """Zapisuje, że `source` widziało zasób teraz. Wołane przy imporcie i skanie."""
    if source not in ASSET_SOURCES:
        raise ValueError(f"Nieznane źródło inwentarza: {source}")
    now = now or utcnow()
    row = session.scalar(
        select(AssetSource).where(AssetSource.asset_id == asset.id, AssetSource.source == source)
    )
    if row is None:
        row = AssetSource(
            asset_id=asset.id, source=source, external_id=external_id, first_seen=now, last_seen=now
        )
        session.add(row)
    else:
        row.last_seen = now
        if external_id:
            row.external_id = external_id
    return row


def sources_of(session: Session, asset: Asset) -> set[str]:
    return set(
        session.scalars(select(AssetSource.source).where(AssetSource.asset_id == asset.id)).all()
    )
