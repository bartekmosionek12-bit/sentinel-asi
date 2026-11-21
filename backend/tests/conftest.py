"""Wspólne fixture'y: baza SQLite w pamięci, bez sieci, bez Redisa, bez modelu."""

from __future__ import annotations

import time
import uuid
from collections.abc import Iterable, Iterator
from dataclasses import dataclass, field
from ipaddress import ip_address
from typing import Any

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from app.api.deps import get_dispatcher, get_scope_guard
from app.core.audit import AuditEvent, DbAuditSink
from app.core.db import get_session
from app.core.scope_guard import IPAddress, ScopeConfig, ScopeGuard
from app.iam.deps import (
    MemorySessionRegistry,
    get_audit_sink,
    get_role_catalog,
    get_session_registry,
    get_token_verifier,
)
from app.iam.tokens import StaticKeyProvider, TokenPolicy, TokenVerifier
from app.main import create_app
from app.models import Base


class FakeResolver:
    """Resolver bez sieci: zwraca adresy z podanej mapy."""

    def __init__(self, mapping: dict[str, list[str]] | None = None) -> None:
        self.mapping = mapping or {}
        self.calls: list[str] = []

    def resolve(self, hostname: str) -> list[IPAddress]:
        self.calls.append(hostname)
        return [ip_address(a) for a in self.mapping.get(hostname, [])]


class MemoryAudit:
    def __init__(self) -> None:
        self.events: list[AuditEvent] = []

    def __call__(self, event: AuditEvent) -> None:
        self.events.append(event)

    @property
    def actions(self) -> list[str]:
        return [e.action for e in self.events]


TEST_ISSUER = "http://keycloak.test/auth/realms/sentinel"
TEST_AUDIENCE = "sentinel-api"
ADMIN_CLIENT = "sentinel-admin"
# Klient bez kroku TOTP (np. skrypt z hasłem): token bez `otp` w `amr`.
DASHBOARD_CLIENT = "sentinel-cli"
HUMAN_ROLES = frozenset({"administrator", "editor", "modifier", "viewer"})
TEST_POLICY = TokenPolicy(issuer=TEST_ISSUER, audience=TEST_AUDIENCE)


@pytest.fixture(scope="session")
def signing_key() -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


@dataclass
class TokenFactory:
    """Wystawia tokeny jak Keycloak realmu `sentinel`, podpisane kluczem testowym."""

    key: rsa.RSAPrivateKey
    issued: list[dict[str, Any]] = field(default_factory=list)

    def claims(
        self,
        roles: Iterable[str],
        *,
        client: str | None = None,
        username: str | None = None,
        sid: str | None = None,
        amr: list[str] | None = None,
        lifetime: int = 300,
        **extra: Any,
    ) -> dict[str, Any]:
        roles = list(roles)
        # Jak w realmie: ludzie logują się do konsoli zespołu IT hasłem i TOTP (amr pwd+otp);
        # inne klienty bez drugiego składnika.
        human = bool(HUMAN_ROLES & set(roles))
        client = client or (ADMIN_CLIENT if human else DASHBOARD_CLIENT)
        if amr is None:
            amr = ["pwd", "otp"] if human and client == ADMIN_CLIENT else ["pwd"]
        name = username or (roles[0] if roles else "anonim")
        now = int(time.time())
        claims: dict[str, Any] = {
            "iss": TEST_ISSUER,
            "aud": TEST_AUDIENCE,
            "sub": f"sub-{name}",
            "azp": client,
            "iat": now,
            "exp": now + lifetime,
            "preferred_username": name,
            "name": name.title(),
            "email": f"{name}@sentinel.example",
            "sid": sid or uuid.uuid4().hex,
            "realm_access": {"roles": roles},
        }
        if amr:
            claims["amr"] = amr
        claims.update(extra)
        return claims

    def encode(self, claims: dict[str, Any], key: rsa.RSAPrivateKey | None = None) -> str:
        self.issued.append(claims)
        return jwt.encode(claims, key or self.key, algorithm="RS256", headers={"kid": "test"})

    def token(self, roles: Iterable[str], **kwargs: Any) -> str:
        return self.encode(self.claims(roles, **kwargs))

    def headers(self, roles: Iterable[str], **kwargs: Any) -> dict[str, str]:
        return {"Authorization": f"Bearer {self.token(roles, **kwargs)}"}


@pytest.fixture
def tokens(signing_key: rsa.RSAPrivateKey) -> TokenFactory:
    return TokenFactory(signing_key)


@pytest.fixture
def session_registry() -> MemorySessionRegistry:
    return MemorySessionRegistry()


class RecordingDispatcher:
    """Zamiast Celery zapisuje zlecenia (testy nie mają brokera)."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, tuple[Any, ...]]] = []

    def _record(self, name: str, *args: Any) -> str:
        self.calls.append((name, args))
        return f"task-{name}"

    def run_scan(self, actor: str) -> str:
        return self._record("run_scan", actor)

    def approve_action(self, action_id: uuid.UUID, approved_by: str, reason: str) -> str:
        return self._record("approve_action", action_id, approved_by, reason)

    def sync_feeds(self, actor: str) -> str:
        return self._record("sync_feeds", actor)

    def generate_explanation(
        self, cve_id: str, audience: str, actor: str, *args: Any, **kwargs: Any
    ) -> str:
        return self._record("generate_explanation", cve_id, audience, actor)

    def generate_report_summary(self, report_id: uuid.UUID, actor: str) -> str:
        return self._record("generate_report_summary", report_id, actor)

    def plan_agent_task(self, task_id: uuid.UUID) -> str:
        return self._record("plan_agent_task", task_id)

    def execute_agent_task(self, task_id: uuid.UUID) -> str:
        return self._record("execute_agent_task", task_id)

    def run_agent_test(
        self, suite: str, trigger: str, requested_by: str, config_version_id: uuid.UUID | None
    ) -> str:
        return self._record("run_agent_test", suite, trigger, requested_by, config_version_id)


@pytest.fixture
def dispatcher() -> RecordingDispatcher:
    return RecordingDispatcher()


@pytest.fixture
def session_factory() -> Iterator[sessionmaker[Session]]:
    engine = create_engine(
        "sqlite+pysqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    yield sessionmaker(bind=engine, expire_on_commit=False)
    engine.dispose()


@pytest.fixture
def session(session_factory: sessionmaker[Session]) -> Iterator[Session]:
    with session_factory() as db:
        yield db


@pytest.fixture
def audit_sink() -> MemoryAudit:
    return MemoryAudit()


@pytest.fixture
def anon_client(
    session_factory: sessionmaker[Session],
    signing_key: rsa.RSAPrivateKey,
    session_registry: MemorySessionRegistry,
    dispatcher: RecordingDispatcher,
) -> Iterator[TestClient]:
    """Klient API bez tokenu. Weryfikacja tokenów kluczem testowym zamiast JWKS Keycloaka."""
    app = create_app()

    def _session() -> Iterator[Session]:
        with session_factory() as db:
            yield db
            db.commit()

    guard = ScopeGuard(
        ScopeConfig.from_dict({"allow": {"cidrs": ["10.10.0.0/24"]}}),
        audit=DbAuditSink(session_factory),
        resolver=FakeResolver(),
    )
    app.dependency_overrides[get_session] = _session
    app.dependency_overrides[get_scope_guard] = lambda: guard
    verifier = TokenVerifier(
        StaticKeyProvider(signing_key.public_key()), TEST_POLICY, get_role_catalog
    )
    app.dependency_overrides[get_token_verifier] = lambda: verifier
    app.dependency_overrides[get_session_registry] = lambda: session_registry
    app.dependency_overrides[get_audit_sink] = lambda: DbAuditSink(session_factory)
    app.dependency_overrides[get_dispatcher] = lambda: dispatcher
    with TestClient(app) as test_client:
        yield test_client


@pytest.fixture
def client(anon_client: TestClient, tokens: TokenFactory) -> TestClient:
    """Klient API zalogowany jako administrator z MFA (konsola zespołu IT)."""
    anon_client.headers.update(tokens.headers(["administrator"], username="admin"))
    return anon_client
