"""Sentek: `POST /api/assistant` (moduł 21, ARCHITECTURE §25.2)."""

from __future__ import annotations

from typing import Annotated, Any

from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field

from app.api.deps import SessionDep
from app.assistant.answers import DISCLAIMER
from app.assistant.classify import ModelClassifier
from app.assistant.service import ask
from app.assistant.text import MAX_QUESTION_CHARS
from app.iam.deps import require
from app.iam.redaction import RedactingRoute
from app.iam.tokens import Principal
from app.models.base import utcnow
from app.reports.config import ReportsConfig
from app.runtime import assistant_classifier, get_reports_config

router = APIRouter(prefix="/api", tags=["asystent"], route_class=RedactingRoute)


def get_assistant_classifier() -> ModelClassifier:
    return assistant_classifier()


class Question(BaseModel):
    question: str = Field(min_length=1, max_length=MAX_QUESTION_CHARS)


class Link(BaseModel):
    label: str
    to: str


class AnswerOut(BaseModel):
    intent: str
    source: str
    text: list[str]
    links: list[Link]
    suggestions: list[str]
    action: dict[str, Any] | None
    pose: str
    freshness: str | None
    disclaimer: str


@router.post("/assistant", response_model=AnswerOut)
def assistant(
    payload: Question,
    session: SessionDep,
    principal: Annotated[Principal, Depends(require("assistant:use"))],
    config: Annotated[ReportsConfig, Depends(get_reports_config)],
    classifier: Annotated[ModelClassifier, Depends(get_assistant_classifier)],
) -> AnswerOut:
    """Odpowiedź z danych. Model (lokalny) najwyżej rozpoznaje, o co chodzi w pytaniu."""
    answer = ask(
        session,
        payload.question,
        principal=principal,
        config=config,
        classifier=classifier,
        today=utcnow().date(),
    )
    session.commit()
    return AnswerOut(
        intent=answer.intent,
        source=answer.source,
        text=answer.text,
        links=[Link(**link) for link in answer.links],
        suggestions=answer.suggestions,
        action=answer.action,
        pose=answer.pose,
        freshness=answer.freshness,
        disclaimer=DISCLAIMER,
    )
