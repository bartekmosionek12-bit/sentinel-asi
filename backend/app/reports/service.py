"""Raporty dwuwarstwowe: tworzenie, doręczanie do skrzynek i warstwa „W skrócie” z modelu.

Raport powstaje od razu z odpowiedziami z szablonu (bez modelu, więc zero-day trafia do
skrzynki w kilka sekund). Model może potem w tle zastąpić odpowiedzi swoimi zdaniami, jeśli
przejdą walidację; światło, fakty i warstwa techniczna nigdy się przy tym nie zmieniają.
"""

from __future__ import annotations

import re
import uuid
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import date
from typing import Any

from sqlalchemy.orm import Session

from app.core import audit
from app.explainer.prompts import load_template
from app.explainer.providers import LLMProvider, LLMResult, ProviderError, generate
from app.explainer.validator import ValidationResult
from app.models import Notification, Report, ReportDelivery
from app.models.base import utcnow
from app.reports.config import QUESTIONS, ReportsConfig
from app.reports.facts import ReportData, build
from app.reports.validator import (
    TOKEN_RE,
    SummaryContext,
    parse_answers,
    validate_summary,
)

PROMPT_NAME = "report_summary"
MAX_ATTEMPTS = 2
LIGHT_LABELS = {"red": "czerwone", "yellow": "żółte", "green": "zielone"}
PERSON_HIDDEN = "[dane osobowe ukryte]"


def summary_context(report: Report, *, system_prompt: str = "") -> SummaryContext:
    products = [str(r["product"]) for r in report.technical.get("rows", []) if r.get("product")]
    return SummaryContext(report.facts, report.entities, report.light, products, system_prompt)


def facts_prompt_text(report: Report) -> str:
    lines = [f"Światło raportu (ustalone przez system): {LIGHT_LABELS[report.light]}."]
    for key, label in QUESTIONS:
        lines.append(f"{label}")
        lines.extend(f"- {fact}" for fact in report.facts.get(key, []))
    return "\n".join(lines)


def deliver(session: Session, config: ReportsConfig, report: Report) -> None:
    """Doręczenie do skrzynek ról z `rules/reports.yaml` i powiadomienie w aplikacji."""
    for role in config.recipients:
        session.add(ReportDelivery(report_id=report.id, recipient_role=role, channel="inbox"))
    session.add(
        Notification(
            report_id=report.id,
            rule_name=f"raport_{report.kind}",
            channel="in_app",
            group_key=f"report:{report.id}",
            status="sent",
            payload={
                "title": report.title,
                "light": report.light,
                "lines": [report.light_reason],
                "recipients": list(config.recipients),
            },
        )
    )
    session.flush()


def create_report(
    session: Session,
    config: ReportsConfig,
    *,
    kind: str,
    actor: str,
    today: date | None = None,
    cve_ids: Sequence[str] | None = None,
    finding_ids: Sequence[uuid.UUID] | None = None,
    since: str | None = None,
    extra_scope: Mapping[str, Any] | None = None,
) -> Report:
    """Liczy fakty i światło, zapisuje raport z szablonem i doręcza go do skrzynek."""
    data: ReportData = build(
        session,
        config,
        kind=kind,
        today=today or utcnow().date(),
        cve_ids=cve_ids,
        finding_ids=finding_ids,
        since=since,
    )
    template = data.template
    report = Report(
        kind=kind,
        title=data.title,
        scope={**data.scope, **(extra_scope or {})},
        light=data.light,
        light_reason=data.light_reason,
        facts=data.facts,
        entities=data.entities,
        summary=template,
        summary_source="template",
        summary_validation="none",
        technical=data.technical,
        created_by=actor,
    )
    session.add(report)
    session.flush()
    deliver(session, config, report)
    audit.record(
        session,
        audit.AuditEvent(
            actor=actor,
            action="report_created",
            reason=f"{report.title}: światło {LIGHT_LABELS[report.light]} ({report.light_reason})",
            inputs={
                "kind": kind,
                "light": report.light,
                "scope": report.scope,
                "recipients": list(config.recipients),
                "findings": len(data.technical["rows"]),
                "summary_source": "template",
            },
            object_type="report",
            object_id=str(report.id),
        ),
    )
    return report


@dataclass(frozen=True)
class SummaryOutcome:
    validation: str  # passed | rejected | unavailable
    problems: tuple[str, ...] = ()
    attempts: int = 0


def generate_summary(
    session: Session,
    report: Report,
    config: ReportsConfig,
    provider: LLMProvider | None,
    *,
    actor: str = "system",
) -> SummaryOutcome:
    """Prosi model o warstwę „W skrócie”. Zapis tylko po walidacji, inaczej zostaje szablon."""
    template = load_template(PROMPT_NAME)
    prompt = template.render(facts_prompt_text(report))
    inputs: dict[str, Any] = {
        "prompt_version": prompt.version,
        "provider": getattr(provider, "name", None),
        "model": getattr(provider, "model", None),
        "light": report.light,
    }
    if provider is None:
        return _finish(
            session, report, actor, "unavailable", inputs, ("model nie jest skonfigurowany",)
        )

    context = summary_context(report, system_prompt=prompt.system)
    verdict = ValidationResult()
    result: LLMResult | None = None
    answers: dict[str, str] = {}
    attempts = 0
    try:
        while attempts < MAX_ATTEMPTS:
            attempts += 1
            result = generate(
                provider, prompt, max_tokens=config.plain_language.max_tokens * len(QUESTIONS)
            )
            answers = parse_answers(result.text)
            verdict = validate_summary(answers, config=config, context=context)
            if verdict.ok or not verdict.retryable:
                break
    except ProviderError as error:
        return _finish(
            session, report, actor, "unavailable", {**inputs, "attempts": attempts}, (str(error),)
        )
    assert result is not None  # noqa: S101 - pętla wykonała się co najmniej raz
    inputs.update(
        attempts=attempts,
        tokens=result.tokens,
        duration_ms=result.duration_ms,
        problems=verdict.codes,
    )
    report.prompt_version = prompt.version
    report.summary_model = result.model
    if verdict.ok:
        report.summary = {key: answers[key] for key, _ in QUESTIONS}
        report.summary_source = "model"
        return _finish(session, report, actor, "passed", inputs, ())
    return _finish(session, report, actor, "rejected", inputs, tuple(verdict.messages))


def _finish(
    session: Session,
    report: Report,
    actor: str,
    validation: str,
    inputs: dict[str, Any],
    problems: tuple[str, ...],
) -> SummaryOutcome:
    report.summary_validation = validation
    report.summary_problems = list(problems)
    report.summary_updated_at = utcnow()
    session.flush()
    reasons = {
        "passed": "Warstwa „W skrócie” od modelu zaakceptowana przez walidator",
        "rejected": "Odpowiedź modelu odrzucona przez walidator: "
        + "; ".join(problems)
        + ". Raport zachowuje odpowiedzi z szablonu",
        "unavailable": "Model niedostępny; raport zachowuje odpowiedzi z szablonu",
    }
    audit.record(
        session,
        audit.AuditEvent(
            actor=actor,
            action=f"report_summary_{validation}",
            reason=reasons[validation],
            inputs=inputs,
            object_type="report",
            object_id=str(report.id),
        ),
    )
    return SummaryOutcome(validation, problems, int(inputs.get("attempts", 0)))


def template_is_valid(report: Report, config: ReportsConfig) -> ValidationResult:
    return validate_summary(report.summary, config=config, context=summary_context(report))


# --- prezentacja ---


def resolve_tokens(text: str, entities: Mapping[str, Mapping[str, Any]], *, personal: bool) -> str:
    def replace(match: re.Match[str]) -> str:
        entity = entities.get(match.group(0))
        if entity is None:
            return match.group(0)
        if entity.get("kind") == "person" and not personal:
            return PERSON_HIDDEN
        return str(entity.get("name", match.group(0)))

    return TOKEN_RE.sub(replace, text)


def present(report: Report, *, personal: bool) -> dict[str, Any]:
    """Raport z nazwami zamiast tokenów. `personal=False` ukrywa nazwy osób (np. w e-mailu)."""
    entities = report.entities

    def names(value: Any) -> Any:
        if isinstance(value, str):
            return resolve_tokens(value, entities, personal=personal)
        if isinstance(value, list):
            return [names(v) for v in value]
        if isinstance(value, dict):
            return {k: names(v) for k, v in value.items()}
        return value

    return {
        "summary": [
            {"key": key, "question": label, "answer": names(report.summary.get(key, ""))}
            for key, label in QUESTIONS
        ],
        "facts": {key: names(report.facts.get(key, [])) for key, _ in QUESTIONS},
        "technical": names(report.technical.get("rows", [])),
    }
