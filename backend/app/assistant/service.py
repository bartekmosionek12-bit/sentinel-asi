"""Jedno pytanie do Sentka: katalog nazw, intencja, odpowiedź i wpis w audycie.

W audycie zostaje intencja, parametry (nazwy z bazy) i źródło klasyfikacji. Surowy tekst
pytania NIE trafia do audytu ani logów: może zawierać dane osobowe.
"""

from __future__ import annotations

from datetime import date

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.assistant.answers import NON_DEVICE_TYPES, Answer, build
from app.assistant.classify import Catalog, ModelClassifier
from app.assistant.text import MAX_QUESTION_CHARS, Named
from app.core import audit
from app.iam.tokens import Principal
from app.models import Asset, Software
from app.reports.config import ReportsConfig


def catalog(session: Session, config: ReportsConfig, principal: Principal) -> Catalog:
    """Nazwy, które Sentek rozpoznaje. Urządzenia i programy tylko z `inventory:read`."""
    terms = [Named(term.key, term.name, (term.key,)) for term in config.glossary]
    devices: list[Named] = []
    products: list[Named] = []
    if principal.can("inventory:read"):
        devices = [
            Named(str(a.id), a.name)
            for a in session.scalars(
                select(Asset).where(
                    Asset.type.not_in(NON_DEVICE_TYPES),
                    Asset.status.in_(("active", "shadow", "missing")),
                )
            )
        ]
        # „Apache httpd” rozpoznajemy też po pierwszym słowie („czy mamy Apache?”).
        products = [
            Named(p, p, (p.split()[0],) if len(p.split()[0]) >= 4 else ())
            for p in session.scalars(select(Software.product).distinct())
            if p and len(p) >= 3
        ]
    return Catalog(devices=devices, products=products, terms=terms)


def ask(
    session: Session,
    question: str,
    *,
    principal: Principal,
    config: ReportsConfig,
    classifier: ModelClassifier,
    today: date,
) -> Answer:
    text = question.strip()[:MAX_QUESTION_CHARS]
    intent = classifier.classify(text, catalog(session, config, principal))
    answer = build(session, intent, config, principal, today)
    audit.record(
        session,
        audit.AuditEvent(
            actor=principal.actor,
            action="assistant_asked",
            reason=f"Pytanie do Sentka rozpoznane jako {intent.name} ({intent.source})",
            inputs={
                "intent": intent.name,
                "params": intent.params(),
                "source": intent.source,
                "model_ms": intent.model_ms,
                "chars": len(text),
            },
            object_type="assistant",
        ),
    )
    return answer
