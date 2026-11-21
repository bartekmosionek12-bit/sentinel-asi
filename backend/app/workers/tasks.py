"""Zadania Celery. Każde zadanie otwiera własną sesję i samo ją zatwierdza."""

from __future__ import annotations

import uuid
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.db import get_sessionmaker
from app.explainer.service import Listener
from app.feeds.service import sync_all
from app.models import Report, Vulnerability
from app.pipeline import analyze
from app.reports.service import generate_summary
from app.runtime import (
    agent_gateway,
    agent_service,
    channel_sender,
    explainer_service,
    feed_source,
    get_event_bus,
    get_reports_config,
    get_rulebook,
    local_provider,
    scan_service,
)
from app.workers.celery_app import celery_app


@celery_app.task(name="app.workers.tasks.ping")
def ping() -> str:
    return "pong:default"


@celery_app.task(name="app.workers.tasks.scans.ping")
def ping_scans() -> str:
    return "pong:scans"


@celery_app.task(name="app.workers.tasks.feeds.ping")
def ping_feeds() -> str:
    return "pong:feeds"


@celery_app.task(name="app.workers.tasks.llm.ping")
def ping_llm() -> str:
    return "pong:llm"


@celery_app.task(name="app.workers.tasks.scans.run_scan")
def run_scan(trigger: str = "scheduled", actor: str = "system") -> dict[str, Any]:
    with get_sessionmaker()() as session:
        run = scan_service(session).run(trigger=trigger, actor=actor)
        return {"scan_run_id": str(run.id), "status": run.status, "summary": run.summary}


@celery_app.task(name="app.workers.tasks.scans.approve_action")
def approve_action(action_id: str, approved_by: str, reason: str) -> dict[str, Any]:
    with get_sessionmaker()() as session:
        action = scan_service(session).approve(
            uuid.UUID(action_id), approved_by=approved_by, reason=reason
        )
        return {"action_id": str(action.id), "status": action.status, "detail": action.detail}


@celery_app.task(name="app.workers.tasks.feeds.sync_feeds")
def sync_feeds(actor: str = "system") -> dict[str, Any]:
    """Synchronizuje feedy i zleca ponowną analizę (kolejka `default`)."""
    with get_sessionmaker()() as session:
        summary = sync_all(session, feed_source(session, get_settings()), actor=actor)
        session.commit()
    run_analysis.delay()
    return {"feeds": summary.results, "changed_cves": len(summary.changed_cves)}


@celery_app.task(name="app.workers.tasks.run_analysis")
def run_analysis() -> dict[str, int]:
    with get_sessionmaker()() as session:
        report = analyze(session, get_rulebook(), channel_sender())
        session.commit()
        return report.summary()


@celery_app.task(name="app.workers.tasks.llm.generate_explanation")
def generate_explanation(
    cve_id: str,
    audience: str,
    actor: str = "system",
    job_id: str | None = None,
    regenerate: bool = False,
    use_external: bool = False,
) -> dict[str, Any]:
    """Generuje wyjaśnienie (albo bierze je z cache) i publikuje postęp dla interfejsu.

    Kolejka `llm` ma concurrency=1, więc model obsługuje jedno zadanie naraz.
    """
    bus = get_event_bus() if job_id else None

    def emit(event: dict[str, Any]) -> None:
        if bus is not None and job_id is not None:
            bus.publish(job_id, event)

    try:
        with get_sessionmaker()() as session:
            vuln = session.scalar(select(Vulnerability).where(Vulnerability.cve_id == cve_id))
            if vuln is None:
                emit({"type": "error", "message": f"Nie znaleziono podatności {cve_id}"})
                return {"status": "not_found"}
            emit({"type": "start"})
            explanation = explainer_service(session).generate(
                vuln,
                audience,
                actor=actor,
                regenerate=regenerate,
                use_external=use_external,
                listener=Listener(
                    on_token=lambda token: emit({"type": "token", "text": token}),
                    on_retry=lambda: emit({"type": "retry"}),
                ),
            )
            session.commit()
    except Exception as error:
        emit({"type": "error", "message": "Generowanie nie powiodło się"})
        raise error
    emit(
        {
            "type": "done",
            "source": explanation.source,
            "validation": explanation.validation,
            "problems": list(explanation.problems),
        }
    )
    return {"status": explanation.validation, "source": explanation.source}


@celery_app.task(name="app.workers.tasks.llm.generate_report_summary")
def generate_report_summary(report_id: str, actor: str = "system") -> dict[str, Any]:
    """Warstwa „W skrócie” od modelu dla raportu, który już jest w skrzynce (z szablonem)."""
    with get_sessionmaker()() as session:
        report = session.get(Report, uuid.UUID(report_id))
        if report is None:
            return {"status": "not_found"}
        outcome = generate_summary(
            session,
            report,
            get_reports_config(),
            local_provider(get_settings()),
            actor=actor,
        )
        session.commit()
        return {"status": outcome.validation, "attempts": outcome.attempts}


@celery_app.task(name="app.workers.tasks.create_digest")
def create_digest_task(actor: str = "system:beat") -> dict[str, Any]:
    """Digest z powiadomień `digest_pending` (beat raz na dobę). Kolejka domyślna."""
    from app.reports.delivery import create_digest

    with get_sessionmaker()() as session:
        report = create_digest(session, get_reports_config(), actor=actor, mailer=channel_sender())
        session.commit()
        return {"report_id": str(report.id) if report else None}


@celery_app.task(name="app.workers.tasks.email_report")
def email_report_task(report_id: str, actor: str = "system") -> dict[str, Any]:
    from app.reports.delivery import email_report

    with get_sessionmaker()() as session:
        report = session.get(Report, uuid.UUID(report_id))
        if report is None:
            return {"status": "not_found"}
        status = email_report(session, report, channel_sender(), actor=actor)
        session.commit()
        return {"status": status}


# --- agent (moduł 5.2) ---------------------------------------------------------


@celery_app.task(name="app.workers.tasks.agent.plan_task")
def plan_agent_task(task_id: str) -> dict[str, Any]:
    with get_sessionmaker()() as session:
        task = agent_service(session).plan_task(uuid.UUID(task_id))
        return {"task_id": str(task.id), "status": task.status}


@celery_app.task(name="app.workers.tasks.agent.execute_task")
def execute_agent_task(task_id: str) -> dict[str, Any]:
    def after_tools(session: Session) -> dict[str, Any]:
        return {"analysis": analyze(session, get_rulebook(), channel_sender()).summary()}

    with get_sessionmaker()() as session:
        task = agent_service(session).execute(
            uuid.UUID(task_id), agent_gateway(get_settings()), after_tools=after_tools
        )
        return {"task_id": str(task.id), "status": task.status}


# --- moduł 19: test bezpieczeństwa agenta (osobny worker `worker-harness`) --------


@celery_app.task(name="app.workers.tasks.agent_tests.run_agent_test")
def run_agent_test(
    suite: str = "quick",
    trigger: str = "manual",
    requested_by: str = "system",
    config_version_id: str | None = None,
) -> dict[str, Any]:
    from app.agent_tests.gate import run_test
    from app.core.scope_guard import ScopeConfig

    settings = get_settings()
    with get_sessionmaker()() as session:
        run = run_test(
            session,
            suite=suite,
            trigger=trigger,
            requested_by=requested_by,
            config_version_id=uuid.UUID(config_version_id) if config_version_id else None,
            provider=local_provider(settings),
            scope=ScopeConfig.from_file(settings.scope_file),
            cases_path=settings.agent_cases_file,
            key_path=settings.harness_signing_key,
        )
        run_id, passed = str(run.id), run.passed
    # Harness nie pisze do tabel raportów: raport tworzy kolejka domyślna.
    celery_app.send_task(
        "app.workers.tasks.create_ai_test_report",
        args=[run_id],
        kwargs={"actor": requested_by},
    )
    return {"run_id": run_id, "passed": passed}


@celery_app.task(name="app.workers.tasks.create_ai_test_report")
def create_ai_test_report_task(run_id: str, actor: str = "system") -> dict[str, Any]:
    """Raport „Czy nasz agent AI jest bezpieczny?” z wyników testu (moduł 19, §23.4)."""
    from app.reports.ai_test import create_ai_test_report

    with get_sessionmaker()() as session:
        report = create_ai_test_report(
            session, get_reports_config(), uuid.UUID(run_id), actor=f"system:agent-test ({actor})"
        )
        session.commit()
        return {"report_id": str(report.id), "light": report.light}
