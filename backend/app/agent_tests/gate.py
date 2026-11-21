"""Bramka zmian konfiguracji agenta i zapis podpisanych wyników testu (ARCHITECTURE §23.3).

Konfiguracja agenta to: model planisty, wersja promptu, wersja zdolności i włączenie
zewnętrznego LLM. Każda zmiana tworzy `AgentConfigVersion` w stanie `pending_test`. Wersja
staje się aktywna dopiero po zaliczonym teście; admin może ją wymusić mimo porażki, ale tylko
z uzasadnieniem, które trafia do audytu i do raportu dla kierownictwa.
"""

from __future__ import annotations

import uuid
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from sqlalchemy import select, update
from sqlalchemy.orm import Session

from app.agent.capability import Capability
from app.agent.service import activate_capability
from app.agent_tests import signing
from app.agent_tests.cases import host_for, load_cases
from app.agent_tests.harness import evaluate_case, summarize
from app.core import audit
from app.core.scope_guard import ScopeConfig
from app.explainer.prompts import load_template
from app.explainer.providers import LLMProvider
from app.models import (
    AgentCapability,
    AgentConfigVersion,
    AgentTestCaseResult,
    AgentTestRun,
)
from app.models.base import utcnow

LIVE_STATES = ("active", "forced")


class GateError(Exception):
    """Operacji na wersji konfiguracji nie da się wykonać."""


@dataclass(frozen=True)
class RuntimeConfig:
    model: str
    prompt_version: str
    external_llm: bool


def runtime_config(llm_model: str, external_llm: bool) -> RuntimeConfig:
    return RuntimeConfig(
        model=llm_model.strip() or "template",
        prompt_version=load_template("agent_plan").version,
        external_llm=external_llm,
    )


def _matches(row: AgentConfigVersion, config: RuntimeConfig, capability_version: int) -> bool:
    return (
        row.model == config.model
        and row.prompt_version == config.prompt_version
        and row.external_llm == config.external_llm
        and row.capability_version == capability_version
    )


def live_capability_version(session: Session) -> int | None:
    row = session.scalar(select(AgentCapability).where(AgentCapability.active.is_(True)))
    return row.version if row else None


def request_change(
    session: Session,
    config: RuntimeConfig,
    *,
    capability_version: int,
    reason: str,
    actor: str,
) -> AgentConfigVersion:
    """Nowa wersja konfiguracji w stanie `pending_test` (albo istniejąca, jeśli już czeka)."""
    for row in session.scalars(
        select(AgentConfigVersion).where(AgentConfigVersion.state == "pending_test")
    ):
        if _matches(row, config, capability_version):
            return row
    row = AgentConfigVersion(
        model=config.model,
        prompt_version=config.prompt_version,
        capability_version=capability_version,
        external_llm=config.external_llm,
        state="pending_test",
        reason=reason[:2000],
        created_by=actor,
    )
    session.add(row)
    session.flush()
    audit.record(
        session,
        audit.AuditEvent(
            actor=actor,
            action="agent_config_pending_test",
            reason=reason,
            inputs={
                "model": row.model,
                "prompt_version": row.prompt_version,
                "capability_version": capability_version,
                "external_llm": row.external_llm,
            },
            object_type="agent_config_version",
            object_id=str(row.id),
        ),
    )
    return row


def config_ready(
    session: Session, config: RuntimeConfig, enqueue: Callable[[uuid.UUID], None] | None = None
) -> tuple[uuid.UUID | None, str | None]:
    """(id aktywnej wersji, None) albo (None, powód blokady). Zmiana = zlecenie testu."""
    capability_version = live_capability_version(session)
    if capability_version is None:
        return None, "Agent nie ma aktywnych zdolności. Nada je administrator."
    for row in session.scalars(
        select(AgentConfigVersion).where(AgentConfigVersion.state.in_(LIVE_STATES))
    ):
        if _matches(row, config, capability_version):
            return row.id, None
    pending = request_change(
        session,
        config,
        capability_version=capability_version,
        reason="Zmiana modelu, promptu albo zewnętrznego LLM wykryta przy starcie zadania",
        actor="system:agent-config",
    )
    session.commit()
    if enqueue is not None:
        enqueue(pending.id)
    return None, (
        "Konfiguracja agenta zmieniła się i czeka na test bezpieczeństwa (moduł 19). "
        "Agent ruszy po zaliczonym teście albo po świadomym wymuszeniu przez administratora."
    )


def _capability_for(session: Session, version: int | None) -> Capability | None:
    if version is None:
        return None
    row = session.scalar(select(AgentCapability).where(AgentCapability.version == version))
    return Capability.from_model(row) if row else None


def run_test(
    session: Session,
    *,
    suite: str,
    trigger: str,
    requested_by: str,
    config_version_id: uuid.UUID | None,
    provider: LLMProvider | None,
    scope: ScopeConfig,
    cases_path: Path,
    key_path: Path,
) -> AgentTestRun:
    """Uruchamia zestaw, podpisuje wynik, zapisuje go i rozstrzyga bramkę zmian."""
    config = session.get(AgentConfigVersion, config_version_id) if config_version_id else None
    run = AgentTestRun(
        config_version_id=config.id if config else None,
        suite=suite,
        trigger=trigger,
        requested_by=requested_by,
        status="running",
    )
    session.add(run)
    session.commit()
    capability = _capability_for(
        session, config.capability_version if config else live_capability_version(session)
    )
    default = load_cases(cases_path)
    if capability is None:
        capability = default.capability
    cases = load_cases(cases_path, host_for(capability)).suite(suite)
    outcomes = [evaluate_case(case, provider, capability, scope) for case in cases]
    summary = summarize(outcomes)
    payload: dict[str, Any] = {
        "run_id": str(run.id),
        "suite": suite,
        "trigger": trigger,
        "config_version_id": str(config.id) if config else None,
        "model": provider.model if provider else "template",
        "capability_version": capability.version,
        **summary,
    }
    key = signing.load_or_create_key(key_path)
    sha = signing.digest(payload)
    for outcome in outcomes:
        session.add(
            AgentTestCaseResult(
                run_id=run.id,
                case_id=outcome.case.id,
                category=outcome.case.category,
                title=outcome.case.title,
                model_resisted=outcome.model_resisted,
                code_held=outcome.code_held,
                verdicts=outcome.verdicts,
                transcript=outcome.transcript,
                attempts=outcome.attempts,
            )
        )
    run.model_passed = summary["model_passed"]
    run.model_failed = summary["model_failed"]
    run.code_passed = summary["code_passed"]
    run.code_failed = summary["code_failed"]
    run.passed = bool(summary["passed"])
    run.result_sha256 = sha
    run.signature = signing.sign(key, sha)
    run.public_key = signing.public_pem(key)
    run.status = "done"
    run.finished_at = utcnow()
    audit.record(
        session,
        audit.AuditEvent(
            actor="system:agent-test-harness",
            action="agent_test_finished",
            reason=(
                f"Test agenta ({suite}): kod {summary['code_passed']}/{summary['cases']}, "
                f"model {summary['model_passed']}/{summary['cases']}"
            ),
            inputs={
                "run": str(run.id),
                "sha256": sha,
                "passed": run.passed,
                "config_version": str(config.id) if config else None,
            },
            object_type="agent_test_run",
            object_id=str(run.id),
            actor_type="system",
            on_behalf_of=requested_by,
        ),
    )
    if config is not None and config.state == "pending_test":
        _decide(session, config, passed=bool(run.passed), run=run)
    session.commit()
    return run


def _decide(
    session: Session, config: AgentConfigVersion, *, passed: bool, run: AgentTestRun
) -> None:
    if passed:
        _activate(
            session,
            config,
            "active",
            actor="system:agent-test-harness",
            reason=f"Test {run.id} zaliczony",
        )
        return
    config.state = "rejected"
    audit.record(
        session,
        audit.AuditEvent(
            actor="system:agent-test-harness",
            action="agent_config_rejected",
            reason=f"Test {run.id} niezaliczony: zmiana nie weszła w życie",
            inputs={"run": str(run.id), "code_failed": run.code_failed},
            object_type="agent_config_version",
            object_id=str(config.id),
        ),
    )


def _activate(
    session: Session, config: AgentConfigVersion, state: str, *, actor: str, reason: str
) -> None:
    session.execute(
        update(AgentConfigVersion)
        .where(AgentConfigVersion.state.in_(LIVE_STATES), AgentConfigVersion.id != config.id)
        .values(state="superseded")
    )
    config.state = state
    config.activated_at = utcnow()
    activate_capability(session, config.capability_version, actor=actor, reason=reason)
    audit.record(
        session,
        audit.AuditEvent(
            actor=actor,
            action="agent_config_activated" if state == "active" else "agent_config_forced",
            reason=reason,
            inputs={
                "model": config.model,
                "prompt_version": config.prompt_version,
                "capability_version": config.capability_version,
                "forced": state == "forced",
            },
            object_type="agent_config_version",
            object_id=str(config.id),
        ),
    )


def force(
    session: Session, config_id: uuid.UUID, *, actor: str, justification: str
) -> AgentConfigVersion:
    """Świadome wymuszenie wersji mimo niezaliczonego (albo trwającego) testu."""
    config = session.get(AgentConfigVersion, config_id)
    if config is None:
        raise GateError("Nie ma takiej wersji konfiguracji")
    if config.state not in ("pending_test", "rejected"):
        raise GateError("Wymusić można tylko wersję czekającą na test albo odrzuconą")
    if len(justification.strip()) < 20:
        raise GateError("Wymuszenie wymaga uzasadnienia (co najmniej 20 znaków)")
    config.forced_by = actor
    config.force_justification = justification.strip()[:4000]
    _activate(session, config, "forced", actor=actor, reason=justification.strip())
    session.commit()
    return config
