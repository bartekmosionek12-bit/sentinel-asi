"""Uwierzytelnianie i autoryzacja na każdym endpoincie (deny-by-default).

Każda trasa API deklaruje dokładnie jedno: `require("uprawnienie")`, `authenticated()` (każdy
zalogowany, np. `/api/me`) albo `public_endpoint()`.
Test `test_every_route_declares_access` odrzuca trasę bez deklaracji, więc nowego endpointu
nie da się „zapomnieć” zabezpieczyć.
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from functools import lru_cache
from typing import Annotated, Any, Protocol

import redis
from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core import request_context
from app.core.audit import AuditEvent, AuditSink, DbAuditSink
from app.core.config import Settings, get_settings
from app.core.db import get_session, get_sessionmaker
from app.iam.custom_roles import apply_grants
from app.iam.rbac import RoleCatalog
from app.iam.tokens import Principal, TokenError, TokenPolicy, TokenVerifier
from app.models import Notification, User
from app.models.base import utcnow

logger = logging.getLogger("sentinel.iam")

PERMISSION_ATTR = "__sentinel_permission__"
PUBLIC = "public"
AUTHENTICATED = "authenticated"
_bearer = HTTPBearer(auto_error=False)


@lru_cache
def get_role_catalog() -> RoleCatalog:
    return RoleCatalog.from_file(get_settings().rules_dir / "roles.yaml")


@lru_cache
def get_token_verifier() -> TokenVerifier:
    from app.iam.jwks import JwksKeyProvider

    settings = get_settings()
    policy = TokenPolicy(issuer=settings.oidc_issuer, audience=settings.oidc_audience)
    return TokenVerifier(JwksKeyProvider(settings.oidc_jwks_url), policy, get_role_catalog)


class SessionRegistry(Protocol):
    """Unieważnione sesje (wylogowanie) i zdarzenia „tylko raz na sesję”."""

    def is_revoked(self, session_id: str) -> bool: ...

    def revoke(self, session_id: str, ttl_seconds: int) -> None: ...

    def first_time(self, key: str, ttl_seconds: int) -> bool: ...


class RedisSessionRegistry:
    def __init__(self, url: str) -> None:
        self._client = redis.Redis.from_url(url, socket_connect_timeout=2)

    def is_revoked(self, session_id: str) -> bool:
        try:
            return bool(self._client.exists(f"iam:revoked:{session_id}"))
        except redis.RedisError:
            # Bez Redisa nie potrafimy sprawdzić wylogowania: odmawiamy (fail closed).
            return True

    def revoke(self, session_id: str, ttl_seconds: int) -> None:
        self._client.set(f"iam:revoked:{session_id}", "1", ex=ttl_seconds)

    def first_time(self, key: str, ttl_seconds: int) -> bool:
        try:
            return bool(self._client.set(f"iam:once:{key}", "1", ex=ttl_seconds, nx=True))
        except redis.RedisError:
            return True


class MemorySessionRegistry:
    def __init__(self) -> None:
        self.revoked: set[str] = set()
        self.seen: set[str] = set()

    def is_revoked(self, session_id: str) -> bool:
        return session_id in self.revoked

    def revoke(self, session_id: str, ttl_seconds: int) -> None:
        self.revoked.add(session_id)

    def first_time(self, key: str, ttl_seconds: int) -> bool:
        if key in self.seen:
            return False
        self.seen.add(key)
        return True


@lru_cache
def _redis_registry(url: str) -> RedisSessionRegistry:
    return RedisSessionRegistry(url)


def get_session_registry() -> SessionRegistry:
    return _redis_registry(get_settings().redis_url)


def get_audit_sink() -> AuditSink:
    """Audit we własnej transakcji: odmowa dostępu zostaje w dzienniku mimo błędu żądania."""
    return DbAuditSink(get_sessionmaker())


SESSION_TTL_SECONDS = 12 * 3600
_USER_TOUCH_SECONDS = 300


def _sync_user(session: Session, principal: Principal) -> None:
    user = session.scalar(select(User).where(User.subject == principal.subject))
    now = utcnow()
    if user is None:
        session.add(
            User(
                subject=principal.subject,
                username=principal.username,
                display_name=principal.display_name,
                email=principal.email,
                kind=principal.kind,
                roles=sorted(principal.roles),
                last_seen_at=now,
            )
        )
        session.flush()
        return
    last = user.last_seen_at
    if last is not None and last.tzinfo is None:
        last = last.replace(tzinfo=now.tzinfo)
    changed = sorted(principal.roles) != list(user.roles or [])
    if changed or last is None or (now - last).total_seconds() > _USER_TOUCH_SECONDS:
        user.roles = sorted(principal.roles)
        user.username = principal.username
        user.display_name = principal.display_name
        user.email = principal.email
        user.last_seen_at = now


def _event(principal: Principal, request: Request, **kwargs: Any) -> AuditEvent:
    return AuditEvent(
        actor=principal.actor,
        actor_type=principal.kind,
        actor_id=principal.subject,
        request_id=getattr(request.state, "request_id", None),
        **kwargs,
    )


def get_principal(
    request: Request,
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(_bearer)],
    verifier: Annotated[TokenVerifier, Depends(get_token_verifier)],
    registry: Annotated[SessionRegistry, Depends(get_session_registry)],
    audit: Annotated[AuditSink, Depends(get_audit_sink)],
    session: Annotated[Session, Depends(get_session)],
    settings: Annotated[Settings, Depends(get_settings)],
) -> Principal:
    cached = getattr(request.state, "principal", None)
    if isinstance(cached, Principal):
        return cached
    if credentials is None or credentials.scheme.lower() != "bearer":
        raise HTTPException(
            status.HTTP_401_UNAUTHORIZED,
            "Wymagane logowanie",
            headers={"WWW-Authenticate": "Bearer"},
        )
    try:
        principal = verifier.principal(credentials.credentials)
    except TokenError as error:
        logger.info("token_rejected", extra={"reason": str(error)})
        raise HTTPException(
            status.HTTP_401_UNAUTHORIZED,
            "Token nieważny albo wygasły",
            headers={"WWW-Authenticate": "Bearer"},
        ) from error
    if principal.session_id and registry.is_revoked(principal.session_id):
        raise HTTPException(
            status.HTTP_401_UNAUTHORIZED,
            "Sesja została zakończona",
            headers={"WWW-Authenticate": "Bearer"},
        )
    # Role nadane w edytorze ról (P1) dokładamy do ról z tokenu przy każdym żądaniu.
    principal = apply_grants(session, get_role_catalog(), principal)
    request.state.principal = principal
    context = request_context.current()
    if context is not None:
        context.actor_type = principal.kind
        context.actor_id = principal.subject
    _sync_user(session, principal)
    if principal.username == settings.breakglass_username and registry.first_time(
        f"breakglass:{principal.session_id or principal.subject}", SESSION_TTL_SECONDS
    ):
        audit(
            _event(
                principal,
                request,
                action="breakglass_used",
                reason="Użycie konta awaryjnego (break-glass)",
                inputs={"client": principal.client_id, "session": principal.session_id},
                object_type="user",
                object_id=principal.subject,
            )
        )
        # Alert w aplikacji (lista powiadomień w konsoli operacyjnej). Wysyłka kanałami
        # zewnętrznymi (e-mail, Slack, Teams) przez worker: Etap 4b, skrzynka i raporty.
        session.add(
            Notification(
                rule_name="breakglass_login",
                channel="in_app",
                group_key=f"breakglass:{principal.subject}",
                status="sent",
                payload={
                    "title": "Logowanie kontem awaryjnym (break-glass)",
                    "lines": [
                        f"Konto {principal.username} zalogowało się do {principal.client_id}.",
                        "Sprawdź, czy to uzgodnione użycie, i nadaj nowe dane konta "
                        "(scripts/breakglass.sh).",
                    ],
                    "username": principal.username,
                    "session": principal.session_id,
                },
            )
        )
        logger.warning("breakglass_used", extra={"user": principal.username})
    return principal


PrincipalDep = Annotated[Principal, Depends(get_principal)]


def deny(principal: Principal, permission: str, request: Request, audit: AuditSink) -> None:
    """Odmowa dostępu: wpis `access_denied` w audycie (własna transakcja) i 403."""
    audit(
        _event(
            principal,
            request,
            action="access_denied",
            reason=f"Brak uprawnienia {permission}",
            inputs={
                "permission": permission,
                "method": request.method,
                "path": request.url.path,
                "roles": sorted(principal.roles),
                "mfa": principal.mfa,
            },
            object_type="endpoint",
            object_id=f"{request.method} {request.url.path}",
        )
    )
    detail = f"Brak uprawnienia: {permission}"
    catalog = get_role_catalog()
    # Podpowiedź o MFA tylko wtedy, gdy role wywołującego dałyby to uprawnienie po MFA.
    if not principal.mfa and permission in catalog.resolve(principal.roles, mfa=True):
        detail += " (wymaga logowania z MFA w konsoli operacyjnej)"
    raise HTTPException(status.HTTP_403_FORBIDDEN, detail)


def ensure(principal: Principal, permission: str, request: Request, audit: AuditSink) -> None:
    """Dodatkowe sprawdzenie w treści endpointu (np. poziom L3 zależy od zatwierdzanej akcji)."""
    if permission not in get_role_catalog().permissions:
        raise ValueError(f"Nieznane uprawnienie {permission}")
    if not principal.can(permission):
        deny(principal, permission, request, audit)


AuditSinkDep = Annotated[AuditSink, Depends(get_audit_sink)]


def require(permission: str) -> Callable[..., Principal]:
    """Zależność: wymaga uprawnienia. Odmowa = 403 i wpis `access_denied` w audycie."""
    catalog = get_role_catalog()
    if permission not in catalog.permissions:
        raise ValueError(f"Nieznane uprawnienie {permission} (brak w rules/roles.yaml)")

    def dependency(request: Request, principal: PrincipalDep, audit: AuditSinkDep) -> Principal:
        if not principal.can(permission):
            deny(principal, permission, request, audit)
        return principal

    setattr(dependency, PERMISSION_ATTR, permission)
    return dependency


def authenticated() -> Callable[..., Principal]:
    """Zależność: dowolny zalogowany (np. własny profil, wylogowanie)."""

    def dependency(principal: PrincipalDep) -> Principal:
        return principal

    setattr(dependency, PERMISSION_ATTR, AUTHENTICATED)
    return dependency


def public_endpoint() -> Callable[[], None]:
    """Jawna deklaracja, że endpoint nie wymaga logowania (tylko zdrowie i konfiguracja)."""

    def dependency() -> None:
        return None

    setattr(dependency, PERMISSION_ATTR, PUBLIC)
    return dependency
