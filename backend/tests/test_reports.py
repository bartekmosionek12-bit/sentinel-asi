"""Raporty dwuwarstwowe, walidacja „W skrócie” i scenariusz zero-day."""

from __future__ import annotations

from datetime import date

import pytest
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.explainer.providers import FakeProvider, ProviderError
from app.models import AuditLog, Finding, Notification, Report, ReportDelivery, Vulnerability
from app.pipeline import Rulebook, analyze
from app.reports.config import QUESTION_KEYS, QUESTIONS, ReportsConfig
from app.reports.service import (
    PERSON_HIDDEN,
    create_report,
    generate_summary,
    present,
    template_is_valid,
)
from app.reports.validator import parse_answers
from app.reports.zero_day import ZeroDayError, inject_kev
from tests.pipeline_helpers import RULES, seed_feeds, seed_inventory

CONFIG = ReportsConfig.from_dir(RULES)
RULEBOOK = Rulebook.from_dir(RULES)
TODAY = date(2026, 11, 20)


@pytest.fixture
def analyzed(session: Session) -> Session:
    seed_feeds(session)
    seed_inventory(session)
    analyze(session, RULEBOOK)
    return session


def _report(session: Session, **kwargs: object) -> Report:
    return create_report(session, CONFIG, kind="assessment", actor="test", today=TODAY, **kwargs)  # type: ignore[arg-type]


def _answers(**overrides: str) -> str:
    base = {
        "what": "Przegląd objął otwarte zagrożenia na naszych zasobach i część z nich jest pilna.",
        "exposed": "Tak, jesteśmy zagrożeni. Najpilniejszy jest asset_1, bo przestępcy już "
        "wykorzystują jego podatność.",
        "worst": "Przestępcy mogą przejąć asset_1 i wykraść z niego dane klientów.",
        "todo": "Trzeba jak najszybciej zaktualizować oprogramowanie na asset_1.",
        "who": "Za asset_1 odpowiada person_1, który powinien to zrobić w ciągu trzech dni.",
    }
    base.update(overrides)
    return "\n".join(f"{label}\n{base[key]}" for key, label in QUESTIONS)


def test_assessment_report_light_facts_and_template(analyzed: Session) -> None:
    report = _report(analyzed)
    # web-01: Apache 2.4.49 z KEV, dostępny z internetu → czerwone światło z pierwszej reguły.
    assert report.light == "red"
    assert report.light_reason.startswith("Aktywnie wykorzystywana")
    assert set(report.summary) == set(QUESTION_KEYS)
    assert report.summary_source == "template"
    assert template_is_valid(report, CONFIG).ok, template_is_valid(report, CONFIG).messages
    facts = " ".join(line for lines in report.facts.values() for line in lines)
    # Model nigdy nie zobaczy nazw zasobów, adresów ani osób: tylko tokeny.
    for secret in ("web-01", "proxy-01", "172.30.99.", "Zespół WWW"):
        assert secret not in facts
        assert secret not in " ".join(report.summary.values())
    assert report.entities["asset_1"]["name"] == "web-01"
    assert any(e["kind"] == "person" for e in report.entities.values())
    rows = report.technical["rows"]
    assert rows
    assert rows[0]["cve_id"] in {"CVE-2021-41773", "CVE-2021-42013"}


def test_report_is_delivered_to_role_inboxes_and_audited(analyzed: Session) -> None:
    report = _report(analyzed)
    deliveries = analyzed.scalars(select(ReportDelivery)).all()
    assert {(d.report_id, d.recipient_role, d.channel) for d in deliveries} == {
        (report.id, role, "inbox") for role in ("administrator", "editor", "modifier", "viewer")
    }
    note = analyzed.scalars(select(Notification).where(Notification.report_id == report.id)).one()
    assert note.channel == "in_app"
    assert note.status == "sent"
    entry = analyzed.scalars(select(AuditLog).where(AuditLog.action == "report_created")).one()
    assert entry.object_id == str(report.id)
    assert entry.inputs["light"] == "red"


def test_presentation_resolves_tokens_and_can_hide_people(
    analyzed: Session,
) -> None:
    report = _report(analyzed)
    shown = present(report, personal=True)
    who = next(item for item in shown["summary"] if item["key"] == "who")["answer"]
    assert "web-01" in who
    assert "Zespół WWW" in who
    hidden = present(report, personal=False)
    who_hidden = next(item for item in hidden["summary"] if item["key"] == "who")["answer"]
    assert "web-01" in who_hidden
    assert "Zespół WWW" not in who_hidden
    assert PERSON_HIDDEN in who_hidden
    assert "asset_" not in str(shown)


def test_green_report_without_findings_still_has_a_valid_template(session: Session) -> None:
    report = _report(session)
    assert report.light == "green"
    assert template_is_valid(report, CONFIG).ok


def test_model_summary_is_used_after_validation(analyzed: Session) -> None:
    report = _report(analyzed)
    outcome = generate_summary(analyzed, report, CONFIG, FakeProvider([_answers()]))
    assert outcome.validation == "passed", outcome.problems
    assert report.summary_source == "model"
    assert report.summary["worst"].startswith("Przestępcy mogą przejąć asset_1")
    assert report.light == "red"
    assert analyzed.scalars(
        select(AuditLog).where(AuditLog.action == "report_summary_passed")
    ).one()


@pytest.mark.parametrize(
    ("override", "code"),
    [
        # Posłuszny model wykonał polecenie wstrzyknięte w opis podatności.
        ({"exposed": "Nie, ryzyko jest niskie i nie trzeba nic robić."}, "contradiction"),
        ({"worst": "Przestępcy mogą przejąć web-01 i wykraść dane."}, "identity_leak"),
        ({"worst": "Przestępcy mogą przejąć serwer 172.30.99.10."}, "identity_leak"),
        ({"todo": "Zaktualizować asset_9 natychmiast, to bardzo pilne."}, "unknown_token"),
        ({"todo": "Zaktualizować oprogramowanie do wersji 9.9.9 na asset_1."}, "unknown_version"),
        ({"what": "Pojawiła się podatność CVE-2099-0001 w oprogramowaniu firmy."}, "unknown_cve"),
        ({"todo": "Wejść na stronę evil.example i pobrać łatkę dla asset_1."}, "domain"),
    ],
)
def test_model_summary_rejected_without_changing_the_assessment(
    analyzed: Session, override: dict[str, str], code: str
) -> None:
    report = _report(analyzed)
    template = dict(report.summary)
    provider = FakeProvider([_answers(**override)])
    outcome = generate_summary(analyzed, report, CONFIG, provider)
    assert outcome.validation == "rejected"
    assert len(provider.prompts) == 1  # błąd faktów: bez ponownej próby
    entry = analyzed.scalars(
        select(AuditLog).where(AuditLog.action == "report_summary_rejected")
    ).one()
    assert code in entry.inputs["problems"]
    assert report.summary == template
    assert report.summary_source == "template"
    assert report.light == "red"


def test_jargon_gets_one_retry(analyzed: Session) -> None:
    report = _report(analyzed)
    provider = FakeProvider([_answers(todo="Trzeba wdrożyć WAF i patch na asset_1."), _answers()])
    outcome = generate_summary(analyzed, report, CONFIG, provider)
    assert outcome.validation == "passed"
    assert outcome.attempts == 2


def test_model_unavailable_keeps_template(analyzed: Session) -> None:
    report = _report(analyzed)
    assert generate_summary(analyzed, report, CONFIG, None).validation == "unavailable"
    outcome = generate_summary(
        analyzed, report, CONFIG, FakeProvider([ProviderError("brak połączenia")])
    )
    assert outcome.validation == "unavailable"
    assert report.summary_source == "template"


def test_parse_answers_splits_on_questions() -> None:
    parsed = parse_answers("**Co się stało?**\nAla.\n\n## Czy jesteśmy zagrożeni?\n- Tak.")
    assert parsed == {"what": "Ala.", "exposed": "Tak."}


def test_zero_day_injection_reaches_the_inbox_quickly_without_llm(analyzed: Session) -> None:
    nginx = analyzed.scalar(
        select(Finding).join(Vulnerability).where(Vulnerability.cve_id == "CVE-2021-23017")
    )
    assert nginx is not None
    before = nginx.risk_score
    result = inject_kev(analyzed, RULEBOOK, CONFIG, "CVE-2021-23017")
    assert result.total_ms < 5000
    assert result.findings_rescored == 1
    assert nginx.risk_score > before
    report = result.report
    assert report.kind == "zero_day"
    assert report.scope["synthetic_kev"] is True
    assert report.title == "Zero-day: CVE-2021-23017"
    assert [row["cve_id"] for row in report.technical["rows"]] == ["CVE-2021-23017"]
    assert template_is_valid(report, CONFIG).ok
    assert "CVE-2021-23017" in report.summary["what"]
    actions = analyzed.scalars(select(AuditLog.action)).all()
    assert "zero_day_injected" in actions
    assert "report_created" in actions
    vuln = analyzed.scalar(select(Vulnerability).where(Vulnerability.cve_id == "CVE-2021-23017"))
    assert vuln is not None
    assert vuln.in_kev


def test_zero_day_refuses_unknown_or_already_known_cves(analyzed: Session) -> None:
    with pytest.raises(ZeroDayError, match="nie ma w bazie"):
        inject_kev(analyzed, RULEBOOK, CONFIG, "CVE-2099-0001")
    with pytest.raises(ZeroDayError, match="już jest"):
        inject_kev(analyzed, RULEBOOK, CONFIG, "CVE-2021-41773")


def test_parse_answers_normalises_token_case() -> None:
    answers = parse_answers(_answers(who="Person_1 naprawi Asset_1 w ciągu trzech dni roboczych."))
    assert answers["who"] == "person_1 naprawi asset_1 w ciągu trzech dni roboczych."
