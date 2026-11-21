"""Raporty dwuwarstwowe i skrzynka odbiorców raportów (Etap 4b, docs/ARCHITECTURE.md 8.5 i 12.3)."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import CheckConstraint, ForeignKey, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base, CreatedAt, UuidPk
from app.models.inventory import _in

REPORT_KINDS = ("assessment", "zero_day", "digest", "ai_test")
REPORT_LIGHTS = ("red", "yellow", "green")
SUMMARY_SOURCES = ("model", "template")
# none: modelu nie pytano (jeszcze); passed: tekst modelu po walidacji; rejected: odrzucony,
# zostaje szablon; unavailable: model nie odpowiedział albo nie jest skonfigurowany.
SUMMARY_VALIDATIONS = ("none", "passed", "rejected", "unavailable")


class Report(Base):
    """Raport: fakty i światło liczy kod, warstwę „W skrócie” formułuje model albo szablon.

    Teksty i fakty zawierają tokeny `asset_<n>` i `person_<n>` zamiast nazw; `entities`
    przechowuje ich znaczenie, a nazwy podstawia dopiero API (z redakcją danych osobowych).
    """

    __tablename__ = "report"
    __table_args__ = (
        CheckConstraint(_in("kind", REPORT_KINDS), name="kind_valid"),
        CheckConstraint(_in("light", REPORT_LIGHTS), name="light_valid"),
        CheckConstraint(_in("summary_source", SUMMARY_SOURCES), name="summary_source_valid"),
        CheckConstraint(
            _in("summary_validation", SUMMARY_VALIDATIONS), name="summary_validation_valid"
        ),
    )

    id: Mapped[UuidPk]
    kind: Mapped[str] = mapped_column(String(20), index=True)
    title: Mapped[str] = mapped_column(String(255))
    scope: Mapped[dict[str, Any]] = mapped_column(default=dict)
    light: Mapped[str] = mapped_column(String(8))
    light_reason: Mapped[str] = mapped_column(Text, default="")
    # Fakty do każdego z pięciu pytań (wybrane przez kod) i słownik tokenów.
    facts: Mapped[dict[str, Any]] = mapped_column(default=dict)
    entities: Mapped[dict[str, Any]] = mapped_column(default=dict)
    # Warstwa „W skrócie”: odpowiedź na każde pytanie.
    summary: Mapped[dict[str, Any]] = mapped_column(default=dict)
    summary_source: Mapped[str] = mapped_column(String(10), default="template")
    summary_validation: Mapped[str] = mapped_column(String(12), default="none")
    summary_model: Mapped[str | None] = mapped_column(String(128))
    summary_problems: Mapped[list[str]] = mapped_column(default=list)
    prompt_version: Mapped[str | None] = mapped_column(String(64))
    # Warstwa techniczna: wiersze z bazy (redakcja bez `secrets:redacted:view` w API).
    technical: Mapped[dict[str, Any]] = mapped_column(default=dict)
    created_by: Mapped[str] = mapped_column(String(255))
    created_at: Mapped[CreatedAt]
    summary_updated_at: Mapped[datetime | None]


class ReportDelivery(Base):
    """Doręczenie raportu do skrzynek wszystkich osób z daną rolą.

    Doręczamy roli, nie kontu: konto w bazie powstaje dopiero przy pierwszym logowaniu, a
    odbiorca zalogowany później też ma widzieć raporty wysłane wcześniej.
    """

    __tablename__ = "report_delivery"
    __table_args__ = (UniqueConstraint("report_id", "recipient_role", "channel"),)

    id: Mapped[UuidPk]
    report_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("report.id", ondelete="CASCADE"), index=True
    )
    recipient_role: Mapped[str] = mapped_column(String(32), index=True)
    channel: Mapped[str] = mapped_column(String(16), default="inbox")
    created_at: Mapped[CreatedAt]


class ReportRead(Base):
    """Potwierdzenie odczytu raportu przez konkretną osobę."""

    __tablename__ = "report_read"
    __table_args__ = (UniqueConstraint("report_id", "user_id"),)

    id: Mapped[UuidPk]
    report_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("report.id", ondelete="CASCADE"), index=True
    )
    user_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("iam_user.id", ondelete="CASCADE"), index=True
    )
    read_at: Mapped[CreatedAt]
