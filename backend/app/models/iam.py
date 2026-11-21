"""Tożsamość i uprawnienia (Etap 4).

Role i uprawnienia są kopią `rules/roles.yaml` (źródło prawdy w Git), synchronizowaną przy
starcie API, żeby dało się je odpytać i powiązać. Użytkownicy powstają przy pierwszym
wywołaniu API z ważnym tokenem Keycloaka; hasła i drugi składnik trzyma wyłącznie Keycloak.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import Boolean, CheckConstraint, ForeignKey, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base, CreatedAt, UuidPk
from app.models.inventory import _in

PRINCIPAL_KINDS = ("human", "agent", "system")


class User(Base):
    __tablename__ = "iam_user"
    __table_args__ = (CheckConstraint(_in("kind", PRINCIPAL_KINDS), name="kind_valid"),)

    id: Mapped[UuidPk]
    # `sub` z tokenu Keycloaka: stały identyfikator konta.
    subject: Mapped[str] = mapped_column(String(255), unique=True)
    username: Mapped[str] = mapped_column(String(255), index=True)
    display_name: Mapped[str] = mapped_column(String(255), default="")
    email: Mapped[str] = mapped_column(String(255), default="")
    kind: Mapped[str] = mapped_column(String(16), default="human")
    # Role z ostatniego tokenu (podgląd w konsoli); o dostępie decyduje zawsze bieżący token.
    roles: Mapped[list[str]] = mapped_column(default=list)
    active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[CreatedAt]
    last_seen_at: Mapped[datetime | None]


class Role(Base):
    __tablename__ = "iam_role"
    __table_args__ = (CheckConstraint(_in("kind", PRINCIPAL_KINDS), name="kind_valid"),)

    name: Mapped[str] = mapped_column(String(64), primary_key=True)
    description: Mapped[str] = mapped_column(Text, default="")
    kind: Mapped[str] = mapped_column(String(16), default="human")


class Permission(Base):
    __tablename__ = "iam_permission"

    name: Mapped[str] = mapped_column(String(64), primary_key=True)
    description: Mapped[str] = mapped_column(Text, default="")
    mfa: Mapped[bool] = mapped_column(Boolean, default=False)


class RolePermission(Base):
    __tablename__ = "iam_role_permission"

    role_name: Mapped[str] = mapped_column(
        ForeignKey("iam_role.name", ondelete="CASCADE"), primary_key=True
    )
    permission_name: Mapped[str] = mapped_column(
        ForeignKey("iam_permission.name", ondelete="CASCADE"), primary_key=True
    )


class CustomRole(Base):
    """Rola własna z edytora ról (P1). Uprawnienia tylko z `rules/roles.yaml`, bez `iam:manage`.

    Osobna tabela, bo `iam_role` jest kopią pliku nadpisywaną przy starcie API.
    """

    __tablename__ = "iam_custom_role"

    name: Mapped[str] = mapped_column(String(64), primary_key=True)
    description: Mapped[str] = mapped_column(Text, default="")
    permissions: Mapped[list[str]] = mapped_column(default=list)
    created_by: Mapped[str] = mapped_column(String(255))
    created_at: Mapped[CreatedAt]
    updated_by: Mapped[str | None] = mapped_column(String(255))
    updated_at: Mapped[datetime | None]


class RoleGrant(Base):
    """Rola nadana w konsoli (poza Keycloakiem): rola własna albo editor, modifier, viewer.

    Działa od następnego żądania; uprawnienia i tak wylicza backend przy każdym wywołaniu.
    """

    __tablename__ = "iam_role_grant"
    __table_args__ = (UniqueConstraint("user_id", "role_name"),)

    id: Mapped[UuidPk]
    user_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("iam_user.id", ondelete="CASCADE"), index=True
    )
    role_name: Mapped[str] = mapped_column(String(64))
    granted_by: Mapped[str] = mapped_column(String(255))
    granted_at: Mapped[CreatedAt]


__all__ = [
    "PRINCIPAL_KINDS",
    "CustomRole",
    "Permission",
    "Role",
    "RoleGrant",
    "RolePermission",
    "User",
    "uuid",
]
