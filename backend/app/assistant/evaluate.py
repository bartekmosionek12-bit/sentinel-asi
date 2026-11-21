"""Ocena klasyfikacji Sentka na przypadkach z `eval/assistant_cases.yaml`.

Wspólne dla testu w CI (same słowa kluczowe) i `eval/run_eval_assistant.py` (model lokalny).
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from datetime import date
from pathlib import Path
from typing import Any

import yaml
from sqlalchemy.orm import Session

from app.assistant.answers import build
from app.assistant.classify import ModelClassifier
from app.assistant.service import catalog
from app.iam.tokens import Principal
from app.reports.config import ReportsConfig


@dataclass(frozen=True)
class CaseResult:
    id: str
    expect: str
    got: str
    source: str
    intent_ok: bool
    params_ok: bool
    action_ok: bool
    safety: bool
    ms: int

    @property
    def ok(self) -> bool:
        return self.intent_ok and self.params_ok and self.action_ok


def load_cases(path: Path) -> list[dict[str, Any]]:
    return list(yaml.safe_load(path.read_text(encoding="utf-8"))["cases"])


def run_case(
    session: Session,
    case: dict[str, Any],
    *,
    classifier: ModelClassifier,
    config: ReportsConfig,
    principal: Principal,
    today: date,
) -> CaseResult:
    started = time.monotonic()
    intent = classifier.classify(str(case["q"]), catalog(session, config, principal))
    elapsed = int((time.monotonic() - started) * 1000)
    answer = build(session, intent, config, principal, today)
    params = intent.params()
    wanted = case.get("params") or {}
    params_ok = all(params.get(key) == value for key, value in wanted.items())
    action = (answer.action or {}).get("kind")
    action_ok = "action" not in case or action == case["action"]
    return CaseResult(
        id=str(case["id"]),
        expect=str(case["expect"]),
        got=intent.name,
        source=intent.source,
        intent_ok=intent.name == case["expect"],
        params_ok=params_ok,
        action_ok=action_ok,
        safety=bool(case.get("safety")),
        ms=elapsed,
    )
