"""Zależności FastAPI."""

from __future__ import annotations

import uuid
from typing import Annotated, Protocol

from fastapi import Depends
from sqlalchemy.orm import Session

from app.core.config import Settings, get_settings
from app.core.db import get_session
from app.core.scope_guard import ScopeGuard
from app.pipeline import Rulebook
from app.runtime import build_scope_guard, get_rulebook, get_scope_guard

__all__ = [
    "DispatcherDep",
    "RulebookDep",
    "ScopeGuardDep",
    "SessionDep",
    "SettingsDep",
    "build_scope_guard",
    "get_dispatcher",
    "get_rulebook",
    "get_scope_guard",
]


class Dispatcher(Protocol):
    """Zleca pracę workerom. API samo nie skanuje i nie pobiera feedów."""

    def run_scan(self, actor: str) -> str: ...

    def approve_action(self, action_id: uuid.UUID, approved_by: str, reason: str) -> str: ...

    def sync_feeds(self, actor: str) -> str: ...

    def generate_explanation(
        self,
        cve_id: str,
        audience: str,
        actor: str,
        job_id: str | None,
        *,
        regenerate: bool = False,
        use_external: bool = False,
        background: bool = False,
    ) -> str: ...

    def generate_report_summary(self, report_id: uuid.UUID, actor: str) -> str: ...

    def plan_agent_task(self, task_id: uuid.UUID) -> str: ...

    def execute_agent_task(self, task_id: uuid.UUID) -> str: ...

    def run_agent_test(
        self, suite: str, trigger: str, requested_by: str, config_version_id: uuid.UUID | None
    ) -> str: ...


class CeleryDispatcher:
    def _send(self, name: str, *args: str) -> str:
        from app.workers.celery_app import celery_app

        return str(celery_app.send_task(name, args=list(args)).id)

    def run_scan(self, actor: str) -> str:
        return self._send("app.workers.tasks.scans.run_scan", "manual", actor)

    def approve_action(self, action_id: uuid.UUID, approved_by: str, reason: str) -> str:
        return self._send(
            "app.workers.tasks.scans.approve_action", str(action_id), approved_by, reason
        )

    def sync_feeds(self, actor: str) -> str:
        return self._send("app.workers.tasks.feeds.sync_feeds", actor)

    def generate_explanation(
        self,
        cve_id: str,
        audience: str,
        actor: str,
        job_id: str | None,
        *,
        regenerate: bool = False,
        use_external: bool = False,
        background: bool = False,
    ) -> str:
        from app.workers.celery_app import celery_app

        result = celery_app.send_task(
            "app.workers.tasks.llm.generate_explanation",
            args=[cve_id, audience, actor, job_id, regenerate, use_external],
            # Żądanie użytkownika wyprzedza generowanie w tle.
            priority=5 if background else 0,
        )
        return str(result.id)

    def generate_report_summary(self, report_id: uuid.UUID, actor: str) -> str:
        from app.workers.celery_app import celery_app

        result = celery_app.send_task(
            "app.workers.tasks.llm.generate_report_summary",
            args=[str(report_id), actor],
            priority=5,
        )
        return str(result.id)

    def plan_agent_task(self, task_id: uuid.UUID) -> str:
        return self._send("app.workers.tasks.agent.plan_task", str(task_id))

    def execute_agent_task(self, task_id: uuid.UUID) -> str:
        return self._send("app.workers.tasks.agent.execute_task", str(task_id))

    def run_agent_test(
        self, suite: str, trigger: str, requested_by: str, config_version_id: uuid.UUID | None
    ) -> str:
        from app.workers.celery_app import celery_app

        result = celery_app.send_task(
            "app.workers.tasks.agent_tests.run_agent_test",
            kwargs={
                "suite": suite,
                "trigger": trigger,
                "requested_by": requested_by,
                "config_version_id": str(config_version_id) if config_version_id else None,
            },
        )
        return str(result.id)


def get_dispatcher() -> Dispatcher:
    return CeleryDispatcher()


SessionDep = Annotated[Session, Depends(get_session)]
SettingsDep = Annotated[Settings, Depends(get_settings)]
ScopeGuardDep = Annotated[ScopeGuard, Depends(get_scope_guard)]
RulebookDep = Annotated[Rulebook, Depends(get_rulebook)]
DispatcherDep = Annotated[Dispatcher, Depends(get_dispatcher)]
