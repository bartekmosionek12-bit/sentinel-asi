"""Etap 6: digest z powiadomień i e-mail raportu (wersja „W skrócie” z PDF)."""

from __future__ import annotations

from collections.abc import Sequence
from datetime import UTC, datetime
from email.message import EmailMessage
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from app.core.config import Settings
from app.models import AuditLog, Finding, Notification, Report, ReportDelivery
from app.notifications.channels import Attachment, ChannelError, ChannelSender
from app.pipeline import Rulebook, analyze
from app.reports.config import ReportsConfig
from app.reports.delivery import create_digest, email_report
from app.reports.service import create_report, template_is_valid
from tests.pipeline_helpers import RULES, seed_feeds, seed_inventory

CONFIG = ReportsConfig.from_dir(RULES)
RULEBOOK = Rulebook.from_dir(RULES)
NOW = datetime(2026, 11, 21, 7, 0, tzinfo=UTC)


class FakeMailer:
    def __init__(self, *, fail: bool = False) -> None:
        self.sent: list[tuple[str, str, list[Attachment]]] = []
        self._fail = fail

    def configured(self) -> set[str]:
        return {"email"}

    def send_email(self, title: str, body: str, attachments: Sequence[Attachment] = ()) -> None:
        if self._fail:
            raise ChannelError("email: SMTPServerDisconnected")
        self.sent.append((title, body, list(attachments)))


def _seed(session: Session) -> None:
    seed_feeds(session)
    seed_inventory(session)
    analyze(session, RULEBOOK)


def _pending(session: Session, findings: list[Finding], channels: Sequence[str]) -> None:
    for channel in channels:
        session.add(
            Notification(
                finding_id=findings[0].id,
                rule_name="wysokie_ryzyko",
                channel=channel,
                group_key=f"wysokie_ryzyko:{findings[0].asset_id}",
                status="digest_pending",
                payload={"finding_ids": [str(f.id) for f in findings], "delivery": "digest"},
            )
        )
    session.flush()


def test_digest_collects_pending_notifications_into_one_report(
    session_factory: sessionmaker[Session],
) -> None:
    with session_factory() as session:
        _seed(session)
        assert create_digest(session, CONFIG, actor="test", now=NOW) is None
        findings = list(session.scalars(select(Finding).order_by(Finding.risk_score)).all())[:1]
        _pending(session, findings, ["in_app"])
        mailer = FakeMailer()
        report = create_digest(session, CONFIG, actor="test", mailer=mailer, now=NOW)
        assert report is not None
        assert report.kind == "digest"
        assert report.title == "Podsumowanie zmian (2026-11-21)"
        assert report.scope["finding_ids"] == [str(findings[0].id)]
        assert len(report.technical["rows"]) == 1
        assert template_is_valid(report, CONFIG).ok
        assert report.summary["what"].startswith("Zmiany od poprzedniego podsumowania: 1 ")
        # Tylko in_app w kolejce: digest trafia do skrzynek, bez e-maila.
        assert mailer.sent == []
        statuses = session.scalars(
            select(Notification.status).where(Notification.rule_name == "wysokie_ryzyko")
        ).all()
        assert statuses == ["digested"]
        assert session.scalars(
            select(ReportDelivery).where(ReportDelivery.report_id == report.id)
        ).all()
        assert session.scalars(select(AuditLog).where(AuditLog.action == "digest_created")).one()
        # Drugi przebieg: nic nie czeka.
        assert create_digest(session, CONFIG, actor="test", now=NOW) is None


def test_digest_email_has_pdf_without_technical_details(
    session_factory: sessionmaker[Session],
) -> None:
    with session_factory() as session:
        _seed(session)
        findings = list(session.scalars(select(Finding)).all())
        _pending(session, findings, ["in_app", "email"])
        mailer = FakeMailer()
        report = create_digest(session, CONFIG, actor="test", mailer=mailer, now=NOW)
        assert report is not None
        [(title, body, attachments)] = mailer.sent
        assert title == report.title
        assert "W skrócie" in body
        assert "172.30.99" not in body
        # Eksport poza system: nazwiska i zespoły właścicieli ukryte (ARCHITECTURE §15).
        assert "Zespół WWW" not in body
        assert "[dane osobowe ukryte]" in body
        assert (
            attachments[0].filename
            == "sentinel-digest-" + report.created_at.date().isoformat() + ".pdf"
        )
        assert attachments[0].content.startswith(b"%PDF-")
        statuses = set(
            session.scalars(
                select(Notification.status).where(Notification.rule_name == "wysokie_ryzyko")
            ).all()
        )
        assert statuses == {"digested"}
        assert session.scalars(
            select(AuditLog).where(AuditLog.action == "report_emailed")
        ).one().object_id == str(report.id)


def test_failed_email_is_recorded_and_report_still_in_inbox(
    session_factory: sessionmaker[Session],
) -> None:
    with session_factory() as session:
        _seed(session)
        report = create_report(session, CONFIG, kind="assessment", actor="test")
        assert email_report(session, report, FakeMailer(fail=True), actor="test") == "failed"
        failed = session.scalars(select(Notification).where(Notification.channel == "email")).one()
        assert failed.status == "failed"
        assert "SMTPServerDisconnected" in failed.payload["error"]
        assert session.get(Report, report.id) is not None


def test_email_skipped_when_channel_not_configured(
    session_factory: sessionmaker[Session],
) -> None:
    class NoMail(FakeMailer):
        def configured(self) -> set[str]:
            return set()

    with session_factory() as session:
        _seed(session)
        report = create_report(session, CONFIG, kind="assessment", actor="test")
        assert email_report(session, report, NoMail(), actor="test") == "skipped"


def test_smtp_attachment_and_starttls_switch() -> None:
    sent: list[EmailMessage] = []
    calls: list[str] = []

    class FakeSmtp:
        def __init__(self, host: str, port: int) -> None:
            calls.append(f"{host}:{port}")

        def __enter__(self) -> Any:
            return self

        def __exit__(self, *_: object) -> None:
            return None

        def starttls(self) -> None:
            calls.append("starttls")

        def send_message(self, message: EmailMessage) -> None:
            sent.append(message)

    settings = Settings(
        _env_file=None,
        smtp_host="mailpit",
        smtp_port=1025,
        smtp_from="sentinel@demo.lab",
        notify_email_to="zarzad@demo.lab",
        smtp_starttls=False,
    )
    sender = ChannelSender(settings, smtp_factory=FakeSmtp)  # type: ignore[arg-type]
    sender.send_email("Raport", "treść", [Attachment("raport.pdf", b"%PDF-1.7 test")])
    assert calls == ["mailpit:1025"]
    [message] = sent
    [attachment] = list(message.iter_attachments())
    assert attachment.get_filename() == "raport.pdf"
    assert attachment.get_content_type() == "application/pdf"
