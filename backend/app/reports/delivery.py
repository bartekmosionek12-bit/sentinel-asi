"""Digesty i e-mail raportów (Etap 6, ARCHITECTURE §8.5 i §12.3).

Digest: powiadomienia z regułą `delivery: digest` czekają w stanie `digest_pending`; raz na
dobę (beat) albo na żądanie (`python -m app.cli digest`) kod zbiera je w jeden raport rodzaju
`digest`. Fakty, światło i „W skrócie” liczy ten sam kod co w ocenie stanu, tylko dla
findingów z tych powiadomień. Raport trafia do skrzynek, a powiadomienia przechodzą w stan
`digested` ze wskazaniem raportu.

E-mail: zawsze wersja „W skrócie” (bez danych technicznych), PDF w załączniku. E-mail opuszcza
system, więc nigdy nie zawiera adresów IP, banerów ani dowodów, a dane osobowe (nazwiska
właścicieli) są ukryte jak w każdym eksporcie (ARCHITECTURE §15), niezależnie od tego, kto
zlecił wysyłkę.
"""

from __future__ import annotations

import uuid
from collections.abc import Sequence
from datetime import datetime
from typing import Any, Protocol

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core import audit
from app.models import Notification, Report
from app.models.base import utcnow
from app.notifications.channels import Attachment, ChannelError
from app.reports.config import ReportsConfig
from app.reports.pdf import KIND_LABELS, LIGHT_LABELS, PdfError, filename, render_pdf, report_view
from app.reports.service import create_report

EMAIL_AUDIENCE = "W skrócie (bez danych technicznych)"


class Mailer(Protocol):
    def configured(self) -> set[str]: ...

    def send_email(self, title: str, body: str, attachments: Sequence[Attachment] = ()) -> None: ...


def email_body(view: dict[str, Any]) -> str:
    """Treść e-maila: światło i „W skrócie” po redakcji, szczegóły w załączonym PDF."""
    light = LIGHT_LABELS.get(view["light"], view["light"])
    lines = [
        f"{KIND_LABELS.get(view['kind'], view['kind'])}: {view['title']}",
        f"Światło: {light}. {view['light_reason']}",
        "",
        "W skrócie",
    ]
    for item in view["summary"]:
        lines += [f"{item['question']}", f"  {item['answer']}"]
    lines += [
        "",
        "Pełny raport (fakty i działania) jest w załączonym PDF oraz w skrzynce w konsoli.",
        "Wiadomość nie zawiera danych technicznych; są dostępne tylko w konsoli operacyjnej.",
    ]
    return "\n".join(lines)


def email_report(
    session: Session, report: Report, mailer: Mailer, *, actor: str, now: datetime | None = None
) -> str:
    """Wysyła raport e-mailem (wersja „W skrócie” + PDF). Zwraca `sent`, `failed` albo `skipped`."""
    if "email" not in mailer.configured():
        return "skipped"
    # Eksport poza system: dane osobowe zawsze ukryte (ARCHITECTURE §15).
    view = report_view(report, technical=True, personal=True)
    status, error = "sent", ""
    try:
        pdf = render_pdf(view, generated_at=now or utcnow(), audience=EMAIL_AUDIENCE)
        mailer.send_email(report.title, email_body(view), [Attachment(filename(view), pdf)])
    except (PdfError, ChannelError) as failure:
        status, error = "failed", str(failure)[:300]
    session.add(
        Notification(
            report_id=report.id,
            rule_name=f"raport_{report.kind}_email",
            channel="email",
            group_key=f"report:{report.id}:email",
            status=status,
            payload={"title": report.title, **({"error": error} if error else {})},
        )
    )
    audit.record(
        session,
        audit.AuditEvent(
            actor=actor,
            action="report_emailed" if status == "sent" else "report_email_failed",
            reason=f"E-mail z raportem „{report.title}” ({EMAIL_AUDIENCE})"
            + (f": {error}" if error else ""),
            inputs={
                "kind": report.kind,
                "attachment": "pdf",
                "redacted": True,
                "personal_hidden": True,
            },
            object_type="report",
            object_id=str(report.id),
        ),
    )
    session.flush()
    return status


def _pending(session: Session) -> list[Notification]:
    return list(
        session.scalars(
            select(Notification)
            .where(Notification.status == "digest_pending")
            .order_by(Notification.created_at)
        ).all()
    )


def create_digest(
    session: Session,
    config: ReportsConfig,
    *,
    actor: str,
    mailer: Mailer | None = None,
    now: datetime | None = None,
) -> Report | None:
    """Zbiera powiadomienia `digest_pending` w raport `digest`. Bez oczekujących: None."""
    pending = _pending(session)
    if not pending:
        return None
    now = now or utcnow()
    finding_ids: list[uuid.UUID] = []
    for notification in pending:
        for value in notification.payload.get("finding_ids", []):
            finding = uuid.UUID(str(value))
            if finding not in finding_ids:
                finding_ids.append(finding)
    since = min(n.created_at for n in pending).date().isoformat()
    report = create_report(
        session,
        config,
        kind="digest",
        actor=actor,
        today=now.date(),
        finding_ids=finding_ids,
        since=since,
        extra_scope={"notifications": len(pending)},
    )
    email_status = "skipped"
    wants_email = any(n.channel == "email" for n in pending)
    if mailer is not None and wants_email:
        email_status = email_report(session, report, mailer, actor=actor, now=now)
    for notification in pending:
        notification.report_id = report.id
        if notification.channel == "email":
            notification.status = "digested" if email_status == "sent" else "failed"
        else:
            notification.status = "digested"
    audit.record(
        session,
        audit.AuditEvent(
            actor=actor,
            action="digest_created",
            reason=f"Digest z {len(pending)} powiadomień, {len(finding_ids)} findingów",
            inputs={
                "notifications": len(pending),
                "findings": len(finding_ids),
                "email": email_status,
                "since": since,
            },
            object_type="report",
            object_id=str(report.id),
        ),
    )
    session.flush()
    return report
