"""Scenariusz zero-day (docs/ARCHITECTURE.md, sekcja 8.3): syntetyczny wpis KEV w trybie demo.

Wpis przechodzi tą samą ścieżką co prawdziwy feed: `KevFeed.apply`, dopasowanie i ocena
ryzyka, reguły powiadomień, a na końcu raport „zero-day” w skrzynce odbiorców. Model językowy
nie bierze w tym udziału, więc całość mieści się w kilku sekundach; „W skrócie” od modelu
dochodzi później w tle.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from datetime import timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core import audit
from app.feeds.base import KevRecord
from app.feeds.kev import KevFeed
from app.models import Report, Vulnerability
from app.models.base import utcnow
from app.notifications.channels import Sender
from app.pipeline import Rulebook, analyze
from app.reports.config import ReportsConfig
from app.reports.service import create_report

ACTOR = "zero_day_demo"


class ZeroDayError(ValueError):
    pass


@dataclass
class ZeroDayResult:
    report: Report
    notifications: int
    findings_rescored: int
    timings_ms: dict[str, int] = field(default_factory=dict)

    @property
    def total_ms(self) -> int:
        return sum(self.timings_ms.values())


def inject_kev(
    session: Session,
    rulebook: Rulebook,
    config: ReportsConfig,
    cve_id: str,
    *,
    sender: Sender | None = None,
    actor: str = ACTOR,
) -> ZeroDayResult:
    """Dodaje syntetyczny wpis KEV dla podatności z bazy i przeprowadza go przez cały system.

    Wywołujący odpowiada za sprawdzenie trybu demo i za commit.
    """
    vuln = session.scalar(select(Vulnerability).where(Vulnerability.cve_id == cve_id))
    if vuln is None:
        raise ZeroDayError(f"{cve_id} nie ma w bazie; wybierz podatność z feedów demo")
    if vuln.in_kev:
        raise ZeroDayError(f"{cve_id} już jest w katalogu KEV")
    affected = vuln.affected[0] if vuln.affected else None
    today = utcnow().date()
    record = KevRecord(
        cve_id=cve_id,
        vendor_project=affected.cpe_vendor if affected else "",
        product=affected.cpe_product if affected else "",
        name=f"{cve_id} (syntetyczny wpis demo)",
        description="Syntetyczny wpis KEV utworzony w trybie demo (scenariusz zero-day).",
        required_action="Zastosować poprawkę producenta albo wyłączyć podatną usługę.",
        date_added=today,
        due_date=today + timedelta(days=3),
    )
    timings: dict[str, int] = {}
    started = time.monotonic()
    KevFeed().apply(session, [record])
    audit.record(
        session,
        audit.AuditEvent(
            actor=actor,
            action="zero_day_injected",
            reason="Syntetyczny wpis KEV (tryb demo): scenariusz zero-day",
            inputs={"cve_id": cve_id, "synthetic": True, "due_date": record.due_date},
            object_type="vulnerability",
            object_id=cve_id,
        ),
    )
    timings["kev"] = _ms(started)

    started = time.monotonic()
    analysis = analyze(session, rulebook, sender)
    timings["analysis_and_notifications"] = _ms(started)

    started = time.monotonic()
    report = create_report(
        session,
        config,
        kind="zero_day",
        actor=actor,
        today=today,
        cve_ids=[cve_id],
        extra_scope={"synthetic_kev": True},
    )
    timings["report"] = _ms(started)
    return ZeroDayResult(
        report=report,
        notifications=len(analysis.notifications),
        findings_rescored=len(analysis.findings.of_kind("rescored")),
        timings_ms=timings,
    )


def _ms(started: float) -> int:
    return int((time.monotonic() - started) * 1000)
