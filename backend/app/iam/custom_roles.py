"""Edytor ról (P1, brief pkt 12): role własne i nadawanie ról w konsoli.

Role z `rules/roles.yaml` zostają źródłem prawdy; administrator może dołożyć role własne
złożone z istniejących uprawnień (bez `iam:manage`) i nadać użytkownikowi rolę własną albo
jedną z ról `editor`, `modifier`, `viewer`. Rolę `administrator` nadaje wyłącznie Keycloak.
Uprawnienia wylicza backend przy każdym żądaniu: token (role z Keycloaka) + nadania z bazy.
Każda zmiana trafia do dziennika audytu.
"""

from __future__ import annotations

import re
from dataclasses import replace

from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from app.core import audit
from app.iam.rbac import GRANTABLE_BUILTIN_ROLES, RESERVED_PERMISSIONS, RoleCatalog
from app.iam.tokens import Principal
from app.models import CustomRole, RoleGrant, User
from app.models.base import utcnow

NAME_RE = re.compile(r"^[a-z][a-z0-9_-]{2,39}$")


class RoleEditError(ValueError):
    """Zmiana roli odrzucona (zła nazwa, nieznane albo zastrzeżone uprawnienie, brak roli)."""


def custom_rows(session: Session) -> list[CustomRole]:
    return list(session.scalars(select(CustomRole).order_by(CustomRole.name)))


def effective_catalog(session: Session, catalog: RoleCatalog) -> RoleCatalog:
    return catalog.with_custom(
        (row.name, row.description, row.permissions) for row in custom_rows(session)
    )


def granted_roles(session: Session, subject: str) -> frozenset[str]:
    return frozenset(
        session.scalars(
            select(RoleGrant.role_name)
            .join(User, User.id == RoleGrant.user_id)
            .where(User.subject == subject, User.active.is_(True))
        )
    )


def apply_grants(session: Session, catalog: RoleCatalog, principal: Principal) -> Principal:
    """Tożsamość człowieka z rolami nadanymi w konsoli. Agent i system bez zmian."""
    if principal.kind != "human":
        return principal
    extra = granted_roles(session, principal.subject)
    has_custom = session.scalar(select(CustomRole.name).limit(1)) is not None
    if not extra and not has_custom:
        return principal
    roles = principal.roles | extra
    full = effective_catalog(session, catalog)
    # Nadanie w konsoli nie zmienia rodzaju tożsamości (rola własna jest zawsze `human`).
    return replace(principal, roles=roles, permissions=full.resolve(roles, mfa=principal.mfa))


def _check(catalog: RoleCatalog, name: str, permissions: list[str], *, new: bool) -> list[str]:
    if new and not NAME_RE.match(name):
        raise RoleEditError(
            "Nazwa roli: małe litery, cyfry, „-” i „_”, od 3 do 40 znaków, zaczyna się literą"
        )
    if name in catalog.roles:
        raise RoleEditError(f"Rola {name} jest zdefiniowana w rules/roles.yaml")
    unknown = sorted(set(permissions) - set(catalog.permissions))
    if unknown:
        raise RoleEditError(f"Nieznane uprawnienia: {', '.join(unknown)}")
    reserved = sorted(set(permissions) & RESERVED_PERMISSIONS)
    if reserved:
        raise RoleEditError(f"Tych uprawnień nie można dać roli własnej: {', '.join(reserved)}")
    return sorted(set(permissions))


def save_role(
    session: Session,
    catalog: RoleCatalog,
    *,
    name: str,
    description: str,
    permissions: list[str],
    actor: str,
) -> tuple[CustomRole, bool]:
    """Tworzy albo zmienia rolę własną. Zwraca (rola, czy nowa)."""
    row = session.get(CustomRole, name)
    clean = _check(catalog, name, permissions, new=row is None)
    before = list(row.permissions) if row is not None else None
    if row is None:
        row = CustomRole(name=name, description=description, permissions=clean, created_by=actor)
        session.add(row)
    else:
        row.description = description
        row.permissions = clean
        row.updated_by = actor
        row.updated_at = utcnow()
    session.flush()
    audit.record(
        session,
        audit.AuditEvent(
            actor=actor,
            action="role_created" if before is None else "role_updated",
            reason=f"Rola własna {name}: {len(clean)} uprawnień",
            inputs={"before": before, "after": clean, "description": description},
            object_type="role",
            object_id=name,
        ),
    )
    return row, before is None


def delete_role(session: Session, name: str, *, actor: str) -> None:
    row = session.get(CustomRole, name)
    if row is None:
        raise RoleEditError(f"Nie ma roli własnej {name}")
    holders = list(
        session.scalars(
            select(User.username)
            .join(RoleGrant, RoleGrant.user_id == User.id)
            .where(RoleGrant.role_name == name)
        )
    )
    session.execute(delete(RoleGrant).where(RoleGrant.role_name == name))
    session.delete(row)
    audit.record(
        session,
        audit.AuditEvent(
            actor=actor,
            action="role_deleted",
            reason=f"Usunięta rola własna {name} (odebrana {len(holders)} kontom)",
            inputs={"permissions": list(row.permissions), "revoked_from": holders},
            object_type="role",
            object_id=name,
        ),
    )


def grantable(session: Session) -> list[str]:
    return [*GRANTABLE_BUILTIN_ROLES, *(row.name for row in custom_rows(session))]


def grant(session: Session, user: User, role_name: str, *, actor: str) -> RoleGrant:
    if role_name not in grantable(session):
        raise RoleEditError(
            f"Roli {role_name} nie można nadać w konsoli (administrator tylko w Keycloaku)"
        )
    if user.kind != "human":
        raise RoleEditError("Role nadaje się tylko ludziom; agent ma zdolności, nie role")
    existing = session.scalar(
        select(RoleGrant).where(RoleGrant.user_id == user.id, RoleGrant.role_name == role_name)
    )
    if existing is not None:
        return existing
    row = RoleGrant(user_id=user.id, role_name=role_name, granted_by=actor)
    session.add(row)
    session.flush()
    audit.record(
        session,
        audit.AuditEvent(
            actor=actor,
            action="role_granted",
            reason=f"Nadana rola {role_name} kontu {user.username}",
            inputs={"role": role_name, "user": user.username},
            object_type="user",
            object_id=user.subject,
        ),
    )
    return row


def revoke(session: Session, user: User, role_name: str, *, actor: str) -> None:
    row = session.scalar(
        select(RoleGrant).where(RoleGrant.user_id == user.id, RoleGrant.role_name == role_name)
    )
    if row is None:
        raise RoleEditError(f"Konto {user.username} nie ma nadanej w konsoli roli {role_name}")
    session.delete(row)
    audit.record(
        session,
        audit.AuditEvent(
            actor=actor,
            action="role_revoked",
            reason=f"Odebrana rola {role_name} kontu {user.username}",
            inputs={"role": role_name, "user": user.username},
            object_type="user",
            object_id=user.subject,
        ),
    )
