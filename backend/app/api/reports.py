"""Raporty dwuwarstwowe, skrzynka raportów i słownik terminów (Etap 4b)."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Query, Response, status
from pydantic import BaseModel
from sqlalchemy import func, select

from app.api.deps import DispatcherDep, SessionDep
from app.core.audit import AuditEvent, record
from app.iam.deps import authenticated, require
from app.iam.redaction import VIEW_PERMISSION, RedactingRoute
from app.iam.tokens import Principal
from app.models import Report, ReportDelivery, ReportRead, User
from app.models.base import utcnow
from app.reports.config import ReportsConfig
from app.reports.freshness import freshness
from app.reports.pdf import PdfError, filename, render_pdf, report_view
from app.reports.service import create_report, present
from app.runtime import get_reports_config

router = APIRouter(prefix="/api", tags=["raporty"], route_class=RedactingRoute)

Reader = Annotated[Principal, Depends(require("reports:read"))]
Exporter = Annotated[Principal, Depends(require("reports:export"))]
Generator = Annotated[Principal, Depends(require("reports:generate"))]
ConfigDep = Annotated[ReportsConfig, Depends(get_reports_config)]


class ReportListItem(BaseModel):
    id: uuid.UUID
    kind: str
    title: str
    light: str
    light_reason: str
    summary_source: str
    created_at: datetime
    read: bool


class InboxOut(BaseModel):
    unread: int
    items: list[ReportListItem]


class SummaryItem(BaseModel):
    key: str
    question: str
    answer: str


class ReportOut(ReportListItem):
    scope: dict[str, Any]
    summary: list[SummaryItem]
    summary_validation: str
    summary_model: str | None
    summary_problems: list[str]
    summary_updated_at: datetime | None
    facts: dict[str, list[str]]
    technical: list[dict[str, Any]]
    created_by: str


class GlossaryTermOut(BaseModel):
    key: str
    name: str
    definition: str


def _user_id(session: SessionDep, principal: Principal) -> uuid.UUID | None:
    return session.scalar(select(User.id).where(User.subject == principal.subject))


def _read_ids(session: SessionDep, principal: Principal) -> set[uuid.UUID]:
    user_id = _user_id(session, principal)
    if user_id is None:
        return set()
    return set(session.scalars(select(ReportRead.report_id).where(ReportRead.user_id == user_id)))


def _item(report: Report, read: set[uuid.UUID]) -> ReportListItem:
    return ReportListItem(
        id=report.id,
        kind=report.kind,
        title=report.title,
        light=report.light,
        light_reason=report.light_reason,
        summary_source=report.summary_source,
        created_at=report.created_at,
        read=report.id in read,
    )


def _detail(report: Report, principal: Principal, read: set[uuid.UUID]) -> ReportOut:
    shown = present(report, personal=True)
    return ReportOut(
        **_item(report, read).model_dump(),
        scope=report.scope,
        summary=[SummaryItem(**item) for item in shown["summary"]],
        summary_validation=report.summary_validation,
        summary_model=report.summary_model,
        summary_problems=list(report.summary_problems or []),
        summary_updated_at=report.summary_updated_at,
        facts=shown["facts"],
        technical=shown["technical"],
        created_by=report.created_by,
    )


def _get(session: SessionDep, report_id: uuid.UUID) -> Report:
    report = session.get(Report, report_id)
    if report is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Nie znaleziono raportu")
    return report


@router.get("/reports", response_model=list[ReportListItem])
def list_reports(
    session: SessionDep,
    principal: Reader,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
) -> list[ReportListItem]:
    read = _read_ids(session, principal)
    reports = session.scalars(select(Report).order_by(Report.created_at.desc()).limit(limit))
    return [_item(report, read) for report in reports]


@router.get("/inbox", response_model=InboxOut)
def inbox(
    session: SessionDep,
    principal: Reader,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
) -> InboxOut:
    """Raporty doręczone do ról zalogowanej osoby, od najnowszego, z liczbą nieprzeczytanych."""
    roles = sorted(principal.roles)
    delivered = (
        select(ReportDelivery.report_id)
        .where(ReportDelivery.recipient_role.in_(roles), ReportDelivery.channel == "inbox")
        .distinct()
    )
    read = _read_ids(session, principal)
    reports = session.scalars(
        select(Report)
        .where(Report.id.in_(delivered))
        .order_by(Report.created_at.desc())
        .limit(limit)
    ).all()
    total = session.scalar(select(func.count()).select_from(delivered.subquery())) or 0
    read_delivered = len(read & set(session.scalars(delivered)))
    return InboxOut(unread=total - read_delivered, items=[_item(r, read) for r in reports])


@router.get("/reports/{report_id}", response_model=ReportOut)
def get_report(report_id: uuid.UUID, session: SessionDep, principal: Reader) -> ReportOut:
    report = _get(session, report_id)
    return _detail(report, principal, _read_ids(session, principal))


@router.get("/reports/{report_id}/pdf", response_class=Response)
def report_pdf(report_id: uuid.UUID, session: SessionDep, principal: Exporter) -> Response:
    """PDF raportu z tą samą redakcją co odpowiedź JSON dla tej osoby."""
    report = _get(session, report_id)
    technical = not principal.can(VIEW_PERMISSION)
    # PDF to eksport poza system: nazwy osób (właściciele z inwentarza) ukryte.
    personal = True
    view = report_view(report, technical=technical, personal=personal)
    audience = "bez danych technicznych" if technical else "konsola zespołu IT"
    try:
        pdf = render_pdf(view, generated_at=utcnow(), audience=audience)
    except PdfError as error:
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, str(error)) from error
    record(
        session,
        AuditEvent(
            actor=principal.actor,
            action="report_pdf_downloaded",
            reason=f"PDF raportu „{report.title}” ({audience})",
            inputs={"redacted": technical, "personal_hidden": personal},
            object_type="report",
            object_id=str(report.id),
        ),
    )
    return Response(
        pdf,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{filename(view)}"'},
    )


@router.post("/reports/{report_id}/read", status_code=status.HTTP_204_NO_CONTENT)
def mark_read(report_id: uuid.UUID, session: SessionDep, principal: Reader) -> None:
    """Potwierdzenie odczytu przez zalogowaną osobę (idempotentne)."""
    _get(session, report_id)
    user_id = _user_id(session, principal)
    if user_id is None:
        return
    exists = session.scalar(
        select(ReportRead.id).where(
            ReportRead.report_id == report_id, ReportRead.user_id == user_id
        )
    )
    if exists is None:
        session.add(ReportRead(report_id=report_id, user_id=user_id))


@router.post("/reports", response_model=ReportOut, status_code=status.HTTP_201_CREATED)
def create_assessment(
    session: SessionDep,
    principal: Generator,
    config: ConfigDep,
    dispatcher: DispatcherDep,
) -> ReportOut:
    """Raport o wszystkich otwartych zagrożeniach. Od razu w skrzynkach (szablon), a model
    dopisuje warstwę „W skrócie” w tle, jeśli jest skonfigurowany."""
    report = create_report(session, config, kind="assessment", actor=principal.actor)
    session.commit()
    dispatcher.generate_report_summary(report.id, principal.actor)
    return _detail(report, principal, set())


@router.post(
    "/reports/{report_id}/summary",
    status_code=status.HTTP_202_ACCEPTED,
    response_model=dict[str, str],
)
def request_summary(
    report_id: uuid.UUID, session: SessionDep, principal: Generator, dispatcher: DispatcherDep
) -> dict[str, str]:
    """Zleca modelowi (ponownie) warstwę „W skrócie”. Światło i fakty się nie zmieniają."""
    _get(session, report_id)
    return {"task_id": dispatcher.generate_report_summary(report_id, principal.actor)}


@router.get(
    "/glossary",
    response_model=list[GlossaryTermOut],
    dependencies=[Depends(authenticated())],
)
def glossary(config: ConfigDep) -> list[GlossaryTermOut]:
    return [
        GlossaryTermOut(key=t.key, name=t.name, definition=t.definition) for t in config.glossary
    ]


# --- moduł 21: „Aktualny obraz”, świeżość danych, prośby o skanowanie (§25.1) ---


class FreshnessOut(BaseModel):
    last_scan_at: str | None
    last_feeds_at: str | None
    age_hours: float | None
    threshold_hours: int
    stale: bool
    label: str


@router.get("/freshness", response_model=FreshnessOut)
def data_freshness(session: SessionDep, config: ConfigDep, principal: Reader) -> FreshnessOut:
    """Kiedy był ostatni skan i czy dane są starsze niż próg z `rules/reports.yaml`."""
    return FreshnessOut(**freshness(session, config).as_dict())
