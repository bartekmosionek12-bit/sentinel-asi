"""Użytkownicy, role i edytor ról (P1, brief pkt 12–13). Projekt: docs/ROLES.md."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy import select

from app.api.deps import SessionDep
from app.iam import custom_roles
from app.iam.deps import get_role_catalog, require
from app.iam.rbac import GRANTABLE_BUILTIN_ROLES, RESERVED_PERMISSIONS
from app.iam.redaction import RedactingRoute
from app.iam.tokens import Principal
from app.models import CustomRole, RoleGrant, User

router = APIRouter(prefix="/api/iam", tags=["role"], route_class=RedactingRoute)

Reader = Annotated[Principal, Depends(require("iam:read"))]
Manager = Annotated[Principal, Depends(require("iam:manage"))]

# Polskie nazwy ról z briefu (pkt 13) do interfejsu.
ROLE_LABELS = {
    "administrator": "Administracja",
    "editor": "Dodawanie, usuwanie, modyfikacja",
    "modifier": "Modyfikacja i odczyt",
    "viewer": "Odczyt",
    "agent": "Agent (tożsamość techniczna)",
    "system": "System (tożsamość techniczna)",
}


class PermissionOut(BaseModel):
    name: str
    description: str
    mfa: bool
    reserved: bool


class RoleOut(BaseModel):
    name: str
    label: str
    description: str
    kind: str
    builtin: bool
    grantable: bool
    permissions: list[str]
    created_by: str | None = None
    updated_at: datetime | None = None


class RoleIn(BaseModel):
    description: str = Field(default="", max_length=500)
    permissions: list[str] = Field(default_factory=list, max_length=200)


class UserOut(BaseModel):
    id: uuid.UUID
    username: str
    display_name: str
    kind: str
    active: bool
    token_roles: list[str]
    granted_roles: list[str]
    last_seen_at: datetime | None


class GrantIn(BaseModel):
    role: str = Field(min_length=1, max_length=64)


@router.get("/permissions", response_model=list[PermissionOut])
def list_permissions(principal: Reader) -> list[PermissionOut]:
    catalog = get_role_catalog()
    return [
        PermissionOut(
            name=p.name,
            description=p.description,
            mfa=p.mfa,
            reserved=p.name in RESERVED_PERMISSIONS,
        )
        for p in sorted(catalog.permissions.values(), key=lambda p: p.name)
    ]


def _custom_out(row: CustomRole) -> RoleOut:
    return RoleOut(
        name=row.name,
        label=row.name,
        description=row.description,
        kind="human",
        builtin=False,
        grantable=True,
        permissions=sorted(row.permissions),
        created_by=row.created_by,
        updated_at=row.updated_at or row.created_at,
    )


@router.get("/roles", response_model=list[RoleOut])
def list_roles(session: SessionDep, principal: Reader) -> list[RoleOut]:
    """Role z `rules/roles.yaml` (wbudowane) i role własne z edytora."""
    catalog = get_role_catalog()
    out = [
        RoleOut(
            name=role.name,
            label=ROLE_LABELS.get(role.name, role.name),
            description=role.description,
            kind=role.kind,
            builtin=True,
            grantable=role.name in GRANTABLE_BUILTIN_ROLES,
            permissions=sorted(role.permissions),
        )
        for role in catalog.roles.values()
    ]
    out.extend(_custom_out(row) for row in custom_roles.custom_rows(session))
    return out


@router.put("/roles/{name}", response_model=RoleOut)
def save_role(name: str, payload: RoleIn, session: SessionDep, principal: Manager) -> RoleOut:
    """Tworzy albo zmienia rolę własną (tylko uprawnienia z pliku, bez `iam:manage`)."""
    try:
        row, _ = custom_roles.save_role(
            session,
            get_role_catalog(),
            name=name,
            description=payload.description,
            permissions=payload.permissions,
            actor=principal.actor,
        )
    except custom_roles.RoleEditError as error:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, str(error)) from error
    session.commit()
    return _custom_out(row)


@router.delete("/roles/{name}", status_code=status.HTTP_204_NO_CONTENT)
def delete_role(name: str, session: SessionDep, principal: Manager) -> None:
    try:
        custom_roles.delete_role(session, name, actor=principal.actor)
    except custom_roles.RoleEditError as error:
        raise HTTPException(status.HTTP_404_NOT_FOUND, str(error)) from error
    session.commit()


def _user_out(session: SessionDep, user: User) -> UserOut:
    granted = sorted(
        session.scalars(select(RoleGrant.role_name).where(RoleGrant.user_id == user.id))
    )
    return UserOut(
        id=user.id,
        username=user.username,
        display_name=user.display_name,
        kind=user.kind,
        active=user.active,
        token_roles=sorted(set(user.roles or []) - set(granted)),
        granted_roles=granted,
        last_seen_at=user.last_seen_at,
    )


@router.get("/users", response_model=list[UserOut])
def list_users(session: SessionDep, principal: Reader) -> list[UserOut]:
    """Konta, które choć raz wywołały API (tworzy je pierwsze logowanie przez Keycloak)."""
    users = session.scalars(select(User).order_by(User.username))
    return [_user_out(session, user) for user in users]


def _user(session: SessionDep, user_id: uuid.UUID) -> User:
    user = session.get(User, user_id)
    if user is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Nie ma takiego konta")
    return user


@router.post("/users/{user_id}/roles", response_model=UserOut)
def grant_role(
    user_id: uuid.UUID, payload: GrantIn, session: SessionDep, principal: Manager
) -> UserOut:
    user = _user(session, user_id)
    try:
        custom_roles.grant(session, user, payload.role, actor=principal.actor)
    except custom_roles.RoleEditError as error:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, str(error)) from error
    session.commit()
    return _user_out(session, user)


@router.delete("/users/{user_id}/roles/{role}", response_model=UserOut)
def revoke_role(user_id: uuid.UUID, role: str, session: SessionDep, principal: Manager) -> UserOut:
    user = _user(session, user_id)
    try:
        custom_roles.revoke(session, user, role, actor=principal.actor)
    except custom_roles.RoleEditError as error:
        raise HTTPException(status.HTTP_404_NOT_FOUND, str(error)) from error
    session.commit()
    return _user_out(session, user)
