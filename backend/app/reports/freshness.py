"""Świeżość danych: kiedy był ostatni zakończony skan i synchronizacja feedów.

Dane starsze niż próg z `rules/reports.yaml` (`freshness_hours`) dostają ostrzeżenie.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.feeds.base import as_utc
from app.models import FeedSync, ScanRun
from app.models.base import utcnow
from app.reports.config import ReportsConfig


@dataclass(frozen=True)
class Freshness:
    last_scan_at: datetime | None
    last_feeds_at: datetime | None
    threshold_hours: int
    now: datetime

    @property
    def age_hours(self) -> float | None:
        if self.last_scan_at is None:
            return None
        return (self.now - as_utc(self.last_scan_at)).total_seconds() / 3600

    @property
    def stale(self) -> bool:
        age = self.age_hours
        return age is None or age > self.threshold_hours

    def label(self) -> str:
        """Zdanie do konsoli, np. „Dane ze skanu sprzed 2 godzin”."""
        age = self.age_hours
        if age is None:
            return "Nie było jeszcze skanu: dane pochodzą tylko z inwentarza i katalogów."
        if age < 1:
            minutes = max(1, int(age * 60))
            return f"Dane ze skanu sprzed {minutes} min."
        if age < 48:
            return f"Dane ze skanu sprzed {int(age)} godz."
        return f"Dane ze skanu sprzed {int(age // 24)} dni."

    def as_dict(self) -> dict[str, Any]:
        return {
            "last_scan_at": self.last_scan_at.isoformat() if self.last_scan_at else None,
            "last_feeds_at": self.last_feeds_at.isoformat() if self.last_feeds_at else None,
            "age_hours": round(self.age_hours, 2) if self.age_hours is not None else None,
            "threshold_hours": self.threshold_hours,
            "stale": self.stale,
            "label": self.label(),
        }


def freshness(session: Session, config: ReportsConfig, now: datetime | None = None) -> Freshness:
    last_scan = session.scalar(
        select(ScanRun.finished_at)
        .where(ScanRun.status == "done", ScanRun.finished_at.is_not(None))
        .order_by(ScanRun.finished_at.desc())
        .limit(1)
    )
    last_feeds = session.scalar(
        select(FeedSync.finished_at)
        .where(FeedSync.finished_at.is_not(None))
        .order_by(FeedSync.finished_at.desc())
        .limit(1)
    )
    return Freshness(last_scan, last_feeds, config.freshness_hours, now or utcnow())
