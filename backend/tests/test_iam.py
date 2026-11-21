"""Etap 4: uwierzytelnianie, uprawnienia na każdym endpoincie, MFA, audyt odmów, redakcja."""

from __future__ import annotations

import hashlib
import hmac
import json
import time
import uuid
from collections.abc import Iterator
from typing import Any

import httpx
import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi.routing import APIRoute
from fastapi.testclient import TestClient
from jwt.utils import base64url_encode
from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from app.core.audit import verify_chain
from app.iam.deps import (
    AUTHENTICATED,
    PERMISSION_ATTR,
    PUBLIC,
    MemorySessionRegistry,
    get_role_catalog,
    get_token_verifier,
    require,
)
from app.iam.jwks import JwksKeyProvider
from app.iam.rbac import RbacConfigError, RoleCatalog
from app.iam.redaction import REDACTED_ADDRESS, redact
from app.iam.sync import sync_catalog
from app.iam.tokens import StaticKeyProvider, TokenError, TokenVerifier, principal_from_claims
from app.main import create_app
from app.models import (
    Asset,
    AuditLog,
    CustomRole,
    Notification,
    Permission,
    Role,
    RolePermission,
    User,
)
from tests.conftest import (
    ADMIN_CLIENT,
    DASHBOARD_CLIENT,
    HUMAN_ROLES,
    TEST_AUDIENCE,
    TEST_ISSUER,
    TEST_POLICY,
    TokenFactory,
)

CATALOG = get_role_catalog()


def _declarations(route: Any) -> list[str]:
    found: list[str] = []

    def walk(dependant: Any) -> None:
        marker = getattr(dependant.call, PERMISSION_ATTR, None)
        if marker is not None:
            found.append(marker)
        for sub in dependant.dependencies:
            walk(sub)

    walk(route.dependant)
    return found


def _api_routes() -> list[Any]:
    """Trasy API z zależnościami w postaci, w jakiej obsługuje je aplikacja (z routerów)."""
    routes: list[Any] = []
    for route in create_app().routes:
        if isinstance(route, APIRoute):
            routes.append(route)
        elif hasattr(route, "effective_route_contexts"):  # router dołączony (FastAPI ≥ 0.160)
            routes.extend(route.effective_route_contexts())
    assert len(routes) > 25, "Test nie widzi tras API, więc niczego by nie sprawdził"
    return routes


# --- deny-by-default: każda trasa deklaruje dostęp ----------------------------------


def test_every_route_declares_access() -> None:
    """Nowy endpoint bez `require()`, `authenticated()` albo `public_endpoint()` nie przejdzie."""
    missing = [f"{sorted(r.methods)} {r.path}" for r in _api_routes() if not _declarations(r)]
    assert missing == []


def test_every_route_declares_exactly_one_access_rule() -> None:
    doubled = {r.path: d for r in _api_routes() if len(d := _declarations(r)) > 1}
    assert doubled == {}


def test_only_health_is_public() -> None:
    public = [r.path for r in _api_routes() if PUBLIC in _declarations(r)]
    assert public == ["/api/health"]


def test_unknown_permission_fails_at_import() -> None:
    with pytest.raises(ValueError, match="Nieznane uprawnienie"):
        require("scan:everything")


# --- macierz rola × endpoint ----------------------------------------------------------

# Rodzaje wywołujących: role z tokenu i klient, który go wystawił. MFA wynika z `amr`
# (ludzie w konsoli zespołu IT logują się hasłem i TOTP, patrz infra/keycloak).
CALLERS: dict[str, tuple[list[str], str]] = {
    "admin_mfa": (["administrator"], ADMIN_CLIENT),
    "admin_bez_mfa": (["administrator"], DASHBOARD_CLIENT),
    "editor": (["editor"], ADMIN_CLIENT),
    "modifier": (["modifier"], ADMIN_CLIENT),
    "viewer": (["viewer"], ADMIN_CLIENT),
    "viewer_bez_mfa": (["viewer"], DASHBOARD_CLIENT),
    "agent": (["agent"], "sentinel-agent"),
    "system": (["system"], "sentinel-pipeline"),
    "bez_roli": ([], DASHBOARD_CLIENT),
    "nieznana_rola": (["root"], ADMIN_CLIENT),
}


def _url(path: str) -> str:
    return (
        path.replace("{job_id}", "x")
        .replace("{asset_id}", str(uuid.uuid4()))
        .replace("{finding_id}", str(uuid.uuid4()))
        .replace("{candidate_id}", str(uuid.uuid4()))
        .replace("{action_id}", str(uuid.uuid4()))
        .replace("{report_id}", str(uuid.uuid4()))
    )


def _call(client: TestClient, method: str, path: str, headers: dict[str, str]) -> int:
    kwargs: dict[str, Any] = {"headers": headers}
    if method in {"POST", "PATCH", "PUT"}:
        kwargs["json"] = {}
    return int(client.request(method, _url(path), **kwargs).status_code)


def _guarded_routes() -> list[tuple[str, str, str]]:
    result = []
    for route in _api_routes():
        (marker,) = _declarations(route)
        if marker != PUBLIC:
            result.append((sorted(route.methods)[0], route.path, marker))
    return result


GUARDED = _guarded_routes()


@pytest.mark.parametrize("caller", list(CALLERS))
def test_role_endpoint_matrix(anon_client: TestClient, tokens: TokenFactory, caller: str) -> None:
    roles, client_id = CALLERS[caller]
    mfa = client_id == ADMIN_CLIENT and bool(HUMAN_ROLES & set(roles))
    granted = CATALOG.resolve(frozenset(roles), mfa=mfa)
    headers = tokens.headers(roles, client=client_id, username=f"u-{caller}")
    wrong: list[str] = []
    # Wylogowanie unieważnia sesję tokenu, więc idzie na końcu.
    ordered = sorted(GUARDED, key=lambda item: item[1] == "/api/auth/logout")
    for method, path, permission in ordered:
        allowed = permission == AUTHENTICATED or permission in granted
        status = _call(anon_client, method, path, headers)
        if allowed and status in (401, 403):
            wrong.append(f"{method} {path}: {status}, a powinien mieć dostęp ({permission})")
        if not allowed and status != 403:
            wrong.append(f"{method} {path}: {status}, a powinno być 403 ({permission})")
    assert wrong == []


def test_matrix_without_token_is_401_everywhere(anon_client: TestClient) -> None:
    statuses = {f"{m} {p}": _call(anon_client, m, p, {}) for m, p, _ in GUARDED}
    assert set(statuses.values()) == {401}, statuses


def test_public_health_needs_no_token(anon_client: TestClient) -> None:
    assert anon_client.get("/api/health").status_code == 200


def test_matrix_covers_key_expectations() -> None:
    """Jawne oczekiwania z briefu (pkt 13) i docs/ROLES.md, niezależne od roles.yaml."""
    admin = CATALOG.resolve(frozenset({"administrator"}), mfa=True)
    editor = CATALOG.resolve(frozenset({"editor"}), mfa=True)
    modifier = CATALOG.resolve(frozenset({"modifier"}), mfa=True)
    viewer = CATALOG.resolve(frozenset({"viewer"}), mfa=True)
    assert set(CATALOG.permissions) == admin
    # Odczyt: tylko czyta i eksportuje, nic nie zmienia.
    writes = {p for p in CATALOG.permissions if CATALOG.requires_mfa(p)} - {"console:admin"}
    assert not viewer & writes
    assert {"inventory:read", "findings:read", "reports:export"} <= viewer
    # Modyfikacja: zmienia istniejące dane, ale nie dodaje i niczego nie uruchamia.
    assert {"findings:update", "review:decide"} <= modifier
    assert not modifier & {"inventory:write", "scan:run", "agent:task", "reports:generate"}
    # Editor: dodaje, uruchamia skany i zatwierdza L2/L3 oraz plany agenta (decyzja 21.11).
    assert {"inventory:write", "scan:run", "scan:approve:l2", "scan:approve:l3"} <= editor
    assert "agent:task" in editor
    # Tylko administrator: tożsamość, zakres, zdolności agenta, integracje, audyt.
    admin_only = {
        "iam:manage",
        "scope:manage",
        "agent:configure",
        "agent_test:override",
        "integrations:manage",
        "llm:external:manage",
        "audit:read",
        "audit:export",
    }
    assert not (editor | modifier | viewer) & admin_only
    assert viewer < modifier < editor < admin
    # Agent i system nie mają dziś uprawnień do API (agent dostaje zdolności w Etapie 5).
    assert CATALOG.resolve(frozenset({"agent"}), mfa=False) == frozenset()
    assert CATALOG.resolve(frozenset({"system"}), mfa=False) == frozenset()


# --- tokeny ---------------------------------------------------------------------------


def _status(client: TestClient, token: str) -> int:
    return int(client.get("/api/me", headers={"Authorization": f"Bearer {token}"}).status_code)


def test_valid_token_returns_profile(anon_client: TestClient, tokens: TokenFactory) -> None:
    me = anon_client.get("/api/me", headers=tokens.headers(["viewer"], username="marta")).json()
    assert (me["username"], me["kind"], me["roles"], me["mfa"]) == (
        "marta",
        "human",
        ["viewer"],
        True,
    )
    assert "findings:read" in me["permissions"]
    assert "scan:run" not in me["permissions"]


@pytest.mark.parametrize(
    "change",
    [
        {"exp": int(time.time()) - 60},
        {"iss": "http://evil.example/realms/sentinel"},
        {"aud": "account"},
        {"sub": None},
    ],
    ids=["wygasly", "obcy_wydawca", "obcy_odbiorca", "bez_sub"],
)
def test_invalid_claims_are_rejected(
    anon_client: TestClient, tokens: TokenFactory, change: dict[str, Any]
) -> None:
    claims = tokens.claims(["administrator"])
    claims.update(change)
    claims = {k: v for k, v in claims.items() if v is not None}
    assert _status(anon_client, tokens.encode(claims)) == 401


def test_token_signed_with_other_key_is_rejected(
    anon_client: TestClient, tokens: TokenFactory
) -> None:
    other = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    assert _status(anon_client, tokens.encode(tokens.claims(["administrator"]), key=other)) == 401


def test_symmetric_and_unsigned_tokens_are_rejected(
    anon_client: TestClient, tokens: TokenFactory, signing_key: rsa.RSAPrivateKey
) -> None:
    claims = tokens.claims(["administrator"])
    unsigned = jwt.encode(claims, key=None, algorithm="none")  # type: ignore[arg-type]
    assert _status(anon_client, unsigned) == 401
    # Klasyczny atak: HS256 podpisany kluczem publicznym (znanym z JWKS) jako sekretem.
    public_pem = signing_key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    header = base64url_encode(json.dumps({"alg": "HS256", "typ": "JWT", "kid": "test"}).encode())
    payload = base64url_encode(json.dumps(claims).encode())
    signing_input = header + b"." + payload
    signature = base64url_encode(hmac.new(public_pem, signing_input, hashlib.sha256).digest())
    forged = (signing_input + b"." + signature).decode()
    assert _status(anon_client, forged) == 401


def test_missing_or_malformed_header(anon_client: TestClient) -> None:
    assert anon_client.get("/api/me").status_code == 401
    assert anon_client.get("/api/me", headers={"Authorization": "Basic YTpi"}).status_code == 401
    assert anon_client.get("/api/me", headers={"Authorization": "Bearer x.y.z"}).status_code == 401


# --- MFA ------------------------------------------------------------------------------


def test_admin_without_mfa_keeps_read_but_loses_operations(
    anon_client: TestClient, tokens: TokenFactory
) -> None:
    headers = tokens.headers(["administrator"], client=DASHBOARD_CLIENT, username="ala")
    assert anon_client.get("/api/findings", headers=headers).status_code == 200
    denied = anon_client.post("/api/scans", headers=headers)
    assert denied.status_code == 403
    assert "MFA" in denied.json()["detail"]


def test_mfa_comes_from_amr_not_from_client(anon_client: TestClient, tokens: TokenFactory) -> None:
    """O MFA decyduje `amr` w tokenie, a nie klient OIDC, przez który się zalogowano."""
    with_otp = tokens.headers(["administrator"], client=DASHBOARD_CLIENT, amr=["pwd", "otp"])
    assert anon_client.post("/api/scans", headers=with_otp).status_code == 202
    password_only = tokens.headers(["administrator"], client=ADMIN_CLIENT, amr=["pwd"])
    assert anon_client.post("/api/scans", headers=password_only).status_code == 403
    no_amr = tokens.headers(["administrator"], client=ADMIN_CLIENT, amr=[])
    assert anon_client.post("/api/scans", headers=no_amr).status_code == 403


def test_service_accounts_never_count_as_mfa() -> None:
    claims = {
        "sub": "svc",
        "azp": ADMIN_CLIENT,
        "amr": ["otp"],
        "realm_access": {"roles": ["agent", "administrator"]},
    }
    principal = principal_from_claims(claims, TEST_POLICY, CATALOG)
    assert principal.kind == "agent"
    assert principal.mfa is False
    assert not any(CATALOG.requires_mfa(p) for p in principal.permissions)


# --- audyt odmowy, aktor w audycie, identyfikator żądania -------------------------------


def _audit(factory: sessionmaker[Session], action: str) -> list[AuditLog]:
    with factory() as db:
        return list(db.scalars(select(AuditLog).where(AuditLog.action == action)))


def test_viewer_denied_on_scan_is_audited(
    anon_client: TestClient, tokens: TokenFactory, session_factory: sessionmaker[Session]
) -> None:
    """Rola „Odczyt” próbuje uruchomić skan: 403 i wpis w audycie."""
    headers = tokens.headers(["viewer"], username="marta")
    response = anon_client.post("/api/scans", headers={**headers, "X-Request-ID": "req-demo-0005"})
    assert response.status_code == 403
    assert response.headers["x-request-id"] == "req-demo-0005"
    (entry,) = _audit(session_factory, "access_denied")
    assert entry.actor == "user:marta"
    assert (entry.actor_type, entry.actor_id, entry.request_id) == (
        "human",
        "sub-marta",
        "req-demo-0005",
    )
    assert entry.inputs["permission"] == "scan:run"
    assert entry.inputs["roles"] == ["viewer"]
    assert entry.object_id == "POST /api/scans"
    with session_factory() as db:
        assert verify_chain(db).ok


def test_console_needs_role_and_mfa_and_denials_are_audited(
    anon_client: TestClient, tokens: TokenFactory, session_factory: sessionmaker[Session]
) -> None:
    """Wejście na /admin: bez roli z briefu albo bez TOTP odmowa z wpisem w audycie."""
    stranger = tokens.headers(["root"], client=ADMIN_CLIENT, username="marta")
    assert anon_client.get("/api/console/admin", headers=stranger).status_code == 403
    (entry,) = _audit(session_factory, "access_denied")
    assert entry.inputs["permission"] == "console:admin"
    assert "MFA" not in anon_client.get("/api/console/admin", headers=stranger).json()["detail"]
    for role in sorted(HUMAN_ROLES):
        ok = tokens.headers([role], username=f"u-{role}")
        assert anon_client.get("/api/console/admin", headers=ok).status_code == 204, role
    admin_without_otp = tokens.headers(["administrator"], amr=["pwd"])
    denied = anon_client.get("/api/console/admin", headers=admin_without_otp)
    assert denied.status_code == 403
    assert "MFA" in denied.json()["detail"]
    admin = tokens.headers(["administrator"])
    assert anon_client.get("/api/console/admin", headers=admin).status_code == 204


def test_audit_entries_carry_actor_and_request_id(
    client: TestClient, session_factory: sessionmaker[Session]
) -> None:
    created = client.post(
        "/api/assets",
        json={"name": "www.sentinel.example", "type": "domain"},
        headers={"X-Request-ID": "bad id with spaces"},
    )
    assert created.status_code == 201
    request_id = created.headers["x-request-id"]
    assert len(request_id) == 32  # niepoprawny nagłówek zastąpiony nowym identyfikatorem
    listed = client.get("/api/audit-log?action=asset_created").json()["items"][0]
    assert (listed["actor_type"], listed["request_id"], listed["hash_version"]) == (
        "human",
        request_id,
        2,
    )
    (entry,) = _audit(session_factory, "asset_created")
    assert (entry.actor, entry.actor_type, entry.actor_id, entry.request_id) == (
        "user:admin",
        "human",
        "sub-admin",
        request_id,
    )
    assert entry.hash_version == 2


def test_client_cannot_choose_the_actor(
    client: TestClient, session_factory: sessionmaker[Session], dispatcher: Any
) -> None:
    assert client.post("/api/scans", json={"actor": "ktos-inny"}).status_code == 202
    assert dispatcher.calls == [("run_scan", ("user:admin",))]


def test_users_are_provisioned_from_tokens(
    anon_client: TestClient, tokens: TokenFactory, session_factory: sessionmaker[Session]
) -> None:
    anon_client.get("/api/me", headers=tokens.headers(["viewer"], username="marta"))
    anon_client.get("/api/me", headers=tokens.headers(["modifier", "viewer"], username="marta"))
    with session_factory() as db:
        (user,) = db.scalars(select(User)).all()
    assert (user.subject, user.username, user.kind) == ("sub-marta", "marta", "human")
    assert user.roles == ["modifier", "viewer"]


# --- sesje i konto awaryjne -----------------------------------------------------------


def test_logout_revokes_session_immediately(
    anon_client: TestClient,
    tokens: TokenFactory,
    session_registry: MemorySessionRegistry,
    session_factory: sessionmaker[Session],
) -> None:
    headers = tokens.headers(["viewer"], sid="sesja-1")
    assert anon_client.get("/api/findings", headers=headers).status_code == 200
    assert anon_client.post("/api/auth/logout", headers=headers).status_code == 204
    assert "sesja-1" in session_registry.revoked
    after = anon_client.get("/api/findings", headers=headers)
    assert after.status_code == 401
    assert after.json()["detail"] == "Sesja została zakończona"
    assert len(_audit(session_factory, "logout")) == 1


def test_breakglass_use_alerts_once_per_session(
    anon_client: TestClient, tokens: TokenFactory, session_factory: sessionmaker[Session]
) -> None:
    headers = tokens.headers(["administrator"], username="breakglass-admin", sid="awaria-1")
    for _ in range(3):
        assert anon_client.get("/api/me", headers=headers).status_code == 200
    (entry,) = _audit(session_factory, "breakglass_used")
    assert entry.actor == "user:breakglass-admin"
    with session_factory() as db:
        (alert,) = db.scalars(select(Notification)).all()
    assert (alert.rule_name, alert.channel, alert.status) == ("breakglass_login", "in_app", "sent")
    assert "awaryjnym" in alert.payload["title"]
    other = tokens.headers(["administrator"], username="breakglass-admin", sid="awaria-2")
    anon_client.get("/api/me", headers=other)
    assert len(_audit(session_factory, "breakglass_used")) == 2


def test_redis_registry_fails_closed() -> None:
    from app.iam.deps import RedisSessionRegistry

    registry = RedisSessionRegistry("redis://127.0.0.1:1/0")
    assert registry.is_revoked("cokolwiek") is True


# --- redakcja -------------------------------------------------------------------------


@pytest.fixture
def asset(session_factory: sessionmaker[Session]) -> Iterator[Asset]:
    with session_factory() as db:
        item = Asset(
            fingerprint="fp-1",
            name="db.sentinel.example",
            type="host",
            owner="Jan Kowalski",
            attributes={"ip": "10.10.0.5", "banner": "OpenSSH 8.2", "os": "Ubuntu"},
        )
        db.add(item)
        db.commit()
        yield item


def test_role_without_technical_view_sees_no_addresses(
    anon_client: TestClient,
    tokens: TokenFactory,
    asset: Asset,
    session_factory: sessionmaker[Session],
) -> None:
    """Rola własna bez `secrets:redacted:view` dostaje odpowiedzi bez adresów i banerów."""
    with session_factory() as db:
        db.add(CustomRole(name="tylko-lista", permissions=["inventory:read"], created_by="t"))
        db.commit()
    headers = tokens.headers(["tylko-lista"])
    body = anon_client.get(f"/api/assets/{asset.id}/details", headers=headers).json()
    assert body["attributes"] == {}
    assert body["asset"]["owner"] == "Jan Kowalski"
    viewer = anon_client.get(f"/api/assets/{asset.id}/details", headers=tokens.headers(["viewer"]))
    assert viewer.json()["attributes"]["ip"] == "10.10.0.5"


def test_redaction_masks_ips_inside_text() -> None:
    value = {"summary": "Host 10.10.0.5 i fd00:99::10 odpowiada", "inputs": {"target": "1.2.3.4"}}
    out = redact(value)
    assert out["summary"] == f"Host {REDACTED_ADDRESS} i {REDACTED_ADDRESS} odpowiada"
    assert out["inputs"] == {"target": REDACTED_ADDRESS}
    assert redact({"version": "2.4.49", "cvss": 9.8}) == {"version": "2.4.49", "cvss": 9.8}


# --- zatwierdzanie akcji według poziomu ---------------------------------------------


def _l2_only_catalog() -> RoleCatalog:
    data = {
        "permissions": {p.name: {"mfa": p.mfa} for p in CATALOG.permissions.values()},
        "roles": {"operator": {"permissions": ["scan:read", "scan:approve:l2"]}},
    }
    return RoleCatalog.from_dict(data)


@pytest.mark.parametrize(("level", "expected"), [(2, 202), (3, 403)])
def test_l3_approval_needs_its_own_permission(
    anon_client: TestClient,
    tokens: TokenFactory,
    signing_key: rsa.RSAPrivateKey,
    session_factory: sessionmaker[Session],
    level: int,
    expected: int,
) -> None:
    from app.models import ScanAction, ScanRun

    catalog = _l2_only_catalog()
    verifier = TokenVerifier(
        StaticKeyProvider(signing_key.public_key()), TEST_POLICY, lambda: catalog
    )
    anon_client.app.dependency_overrides[get_token_verifier] = lambda: verifier  # type: ignore[attr-defined]
    with session_factory() as db:
        run = ScanRun(trigger="manual", status="done")
        db.add(run)
        db.flush()
        action = ScanAction(
            scan_run_id=run.id,
            target="172.30.99.10",
            tool="nmap",
            rule_name="r",
            intrusiveness=level,
            status="awaiting_approval",
            reason="test",
        )
        db.add(action)
        db.commit()
        action_id = action.id
    response = anon_client.post(
        f"/api/scan-actions/{action_id}/approve",
        json={"reason": "Okno serwisowe"},
        headers=tokens.headers(["operator"], username="olek", amr=["pwd", "otp"]),
    )
    assert response.status_code == expected
    if expected == 403:
        (entry,) = _audit(session_factory, "access_denied")
        assert entry.inputs["permission"] == "scan:approve:l3"


# --- katalog ról ----------------------------------------------------------------------


def test_catalog_rejects_unknown_permissions_and_kinds() -> None:
    base: dict[str, Any] = {"permissions": {"a:read": {}}}
    with pytest.raises(RbacConfigError, match="nieznane uprawnienia"):
        RoleCatalog.from_dict({**base, "roles": {"x": {"permissions": ["a:write"]}}})
    with pytest.raises(RbacConfigError, match="nieznany rodzaj"):
        RoleCatalog.from_dict({**base, "roles": {"x": {"kind": "robot", "permissions": []}}})
    with pytest.raises(RbacConfigError, match="Brak ról"):
        RoleCatalog.from_dict(base)


def test_unknown_roles_grant_nothing() -> None:
    assert CATALOG.resolve(frozenset({"root", "superuser"}), mfa=True) == frozenset()


def test_catalog_is_copied_to_database(session: Session) -> None:
    first = sync_catalog(session, CATALOG)
    second = sync_catalog(session, CATALOG)
    assert first == second
    assert session.scalar(select(Role).where(Role.name == "viewer")) is not None
    links = session.scalars(
        select(RolePermission.permission_name).where(RolePermission.role_name == "viewer")
    ).all()
    assert set(links) == set(CATALOG.roles["viewer"].permissions)
    assert session.get(Permission, "scan:run").mfa is True  # type: ignore[union-attr]


# --- JWKS -----------------------------------------------------------------------------


def _jwks_client(keys: list[rsa.RSAPrivateKey], calls: list[int]) -> httpx.Client:
    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(1)
        jwk = []
        for index, key in enumerate(keys):
            item = jwt.algorithms.RSAAlgorithm.to_jwk(key.public_key(), as_dict=True)
            jwk.append({**item, "kid": f"k{index}", "use": "sig", "alg": "RS256"})
        return httpx.Response(200, json={"keys": jwk})

    return httpx.Client(transport=httpx.MockTransport(handler))


def test_jwks_refreshes_on_new_kid_but_rate_limited() -> None:
    first = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    second = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    keys = [first]
    calls: list[int] = []
    provider = JwksKeyProvider(
        "http://keycloak:8080/certs", client=_jwks_client(keys, calls), min_refresh_seconds=0
    )
    claims = {"iss": TEST_ISSUER, "aud": TEST_AUDIENCE, "sub": "s", "iat": 1, "exp": 2**31}
    token0 = jwt.encode(claims, first, algorithm="RS256", headers={"kid": "k0"})
    assert provider.key_for(token0) is not None
    keys.append(second)  # rotacja kluczy w Keycloaku
    token1 = jwt.encode(claims, second, algorithm="RS256", headers={"kid": "k1"})
    assert provider.key_for(token1) is not None
    assert len(calls) == 2

    limited = JwksKeyProvider("http://k/certs", client=_jwks_client([first], calls))
    limited.key_for(token0)
    before = len(calls)
    for _ in range(5):
        with pytest.raises(TokenError, match="nieznanym kluczem"):
            limited.key_for(jwt.encode(claims, first, algorithm="RS256", headers={"kid": "zly"}))
    assert len(calls) == before  # fałszywy kid nie zalewa Keycloaka
