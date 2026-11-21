"""API raportów i skrzynki: role, redakcja, odczyt, zlecenie warstwy „W skrócie”."""

from __future__ import annotations

import uuid

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from app.models import AuditLog, CustomRole, Report
from app.pipeline import Rulebook, analyze
from app.reports.config import ReportsConfig
from app.reports.service import PERSON_HIDDEN, create_report
from app.reports.zero_day import inject_kev
from tests.conftest import RecordingDispatcher, TokenFactory
from tests.pipeline_helpers import RULES, seed_feeds, seed_inventory

CONFIG = ReportsConfig.from_dir(RULES)
RULEBOOK = Rulebook.from_dir(RULES)


@pytest.fixture
def report_id(session_factory: sessionmaker[Session]) -> uuid.UUID:
    with session_factory() as session:
        seed_feeds(session)
        seed_inventory(session)
        analyze(session, RULEBOOK)
        report = create_report(session, CONFIG, kind="assessment", actor="test")
        session.commit()
        return report.id


def _as(tokens: TokenFactory, role: str) -> dict[str, str]:
    return tokens.headers([role], username=f"{role}-1")


def test_inbox_shows_unread_report_and_marks_it_read(
    anon_client: TestClient, tokens: TokenFactory, report_id: uuid.UUID
) -> None:
    headers = _as(tokens, "viewer")
    inbox = anon_client.get("/api/inbox", headers=headers).json()
    assert inbox["unread"] == 1
    assert inbox["items"][0]["id"] == str(report_id)
    assert inbox["items"][0]["light"] == "red"
    assert anon_client.post(f"/api/reports/{report_id}/read", headers=headers).status_code == 204
    assert anon_client.post(f"/api/reports/{report_id}/read", headers=headers).status_code == 204
    after = anon_client.get("/api/inbox", headers=headers).json()
    assert after["unread"] == 0
    assert after["items"][0]["read"] is True
    # Odczyt jest per osoba: inna osoba nadal ma raport nieprzeczytany.
    other = tokens.headers(["editor"], username="editor-2")
    assert anon_client.get("/api/inbox", headers=other).json()["unread"] == 1


def test_inbox_is_for_recipient_roles_only(
    anon_client: TestClient,
    tokens: TokenFactory,
    report_id: uuid.UUID,
    session_factory: sessionmaker[Session],
) -> None:
    # Rola własna z odczytem raportów, ale spoza `recipients` w rules/reports.yaml.
    with session_factory() as session:
        session.add(CustomRole(name="raporty", permissions=["reports:read"], created_by="t"))
        session.commit()
    outsider = _as(tokens, "raporty")
    assert anon_client.get("/api/inbox", headers=outsider).json()["unread"] == 0
    reports = anon_client.get("/api/reports", headers=outsider).json()
    assert [r["id"] for r in reports] == [str(report_id)]


def test_report_detail_has_names_and_technical_layer(
    anon_client: TestClient, tokens: TokenFactory, report_id: uuid.UUID
) -> None:
    viewer = anon_client.get(f"/api/reports/{report_id}", headers=_as(tokens, "viewer")).json()
    who = next(s["answer"] for s in viewer["summary"] if s["key"] == "who")
    assert "web-01" in who
    assert "Zespół WWW" in who  # właściciel z inwentarza widoczny w konsoli
    assert viewer["summary"][0]["question"] == "Co się stało?"
    assert viewer["technical"][0]["asset"] == "web-01"


def test_only_admin_with_mfa_creates_reports_and_requests_summaries(
    client: TestClient,
    tokens: TokenFactory,
    report_id: uuid.UUID,
    dispatcher: RecordingDispatcher,
    session_factory: sessionmaker[Session],
) -> None:
    created = client.post("/api/reports")
    assert created.status_code == 201
    body = created.json()
    assert body["summary_source"] == "template"
    assert dispatcher.calls[-1][0] == "generate_report_summary"
    assert client.post(f"/api/reports/{report_id}/summary").status_code == 202
    modifier = _as(tokens, "modifier")
    assert client.post("/api/reports", headers=modifier).status_code == 403
    no_mfa = tokens.headers(["administrator"], client="sentinel-cli", username="admin-2")
    assert client.post("/api/reports", headers=no_mfa).status_code == 403
    with session_factory() as session:
        assert len(session.scalars(select(Report)).all()) == 2
        created_by = session.scalars(
            select(AuditLog.actor).where(AuditLog.action == "report_created")
        ).all()
        assert "user:admin" in created_by


def test_zero_day_report_appears_in_inbox(
    anon_client: TestClient,
    tokens: TokenFactory,
    report_id: uuid.UUID,
    session_factory: sessionmaker[Session],
) -> None:
    with session_factory() as session:
        result = inject_kev(session, RULEBOOK, CONFIG, "CVE-2021-23017")
        session.commit()
        zero_day = result.report.id
    inbox = anon_client.get("/api/inbox", headers=_as(tokens, "viewer")).json()
    assert inbox["unread"] == 2
    assert inbox["items"][0]["id"] == str(zero_day)
    assert inbox["items"][0]["kind"] == "zero_day"


def test_glossary_for_any_logged_in_user(anon_client: TestClient, tokens: TokenFactory) -> None:
    terms = anon_client.get("/api/glossary", headers=_as(tokens, "viewer")).json()
    assert {"KEV", "CVE"} <= {t["key"] for t in terms}
    assert anon_client.get("/api/glossary").status_code == 401


def test_unknown_report_is_404(anon_client: TestClient, tokens: TokenFactory) -> None:
    response = anon_client.get(f"/api/reports/{uuid.uuid4()}", headers=_as(tokens, "viewer"))
    assert response.status_code == 404


def test_pdf_export_hides_people_and_is_audited(
    anon_client: TestClient,
    tokens: TokenFactory,
    report_id: uuid.UUID,
    session_factory: sessionmaker[Session],
) -> None:
    response = anon_client.get(f"/api/reports/{report_id}/pdf", headers=_as(tokens, "viewer"))
    assert response.status_code == 200
    assert response.headers["content-type"] == "application/pdf"
    assert response.content.startswith(b"%PDF-")
    assert "attachment" in response.headers["content-disposition"]
    with session_factory() as session:
        entry = session.scalars(
            select(AuditLog).where(AuditLog.action == "report_pdf_downloaded")
        ).one()
        assert entry.object_id == str(report_id)
        assert entry.inputs == {"redacted": False, "personal_hidden": True}


def test_pdf_html_without_technical_details_and_people(
    session_factory: sessionmaker[Session], report_id: uuid.UUID
) -> None:
    from datetime import UTC, datetime

    from app.reports.pdf import render_html, report_view

    now = datetime(2026, 11, 21, tzinfo=UTC)
    with session_factory() as session:
        report = session.get(Report, report_id)
        assert report is not None
        named = render_html(
            report_view(report, technical=True, personal=False), generated_at=now, audience="m"
        )
        hidden = render_html(
            report_view(report, technical=True, personal=True), generated_at=now, audience="a"
        )
    assert "Co się stało?" in named
    assert "web-01" in named
    assert "172.30.99" not in named
    assert "Zespół WWW" in named
    assert "Zespół WWW" not in hidden
    assert PERSON_HIDDEN in hidden


def test_pdf_export_needs_export_permission(
    anon_client: TestClient, tokens: TokenFactory, report_id: uuid.UUID
) -> None:
    assert anon_client.get(f"/api/reports/{report_id}/pdf").status_code == 401
    missing = anon_client.get(f"/api/reports/{uuid.uuid4()}/pdf", headers=_as(tokens, "viewer"))
    assert missing.status_code == 404
