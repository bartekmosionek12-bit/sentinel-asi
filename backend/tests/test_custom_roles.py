"""Edytor ról (P1, brief pkt 12): role własne, nadania w konsoli, granice i audyt."""

from __future__ import annotations

from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from app.models import AuditLog, RoleGrant, User
from tests.conftest import TokenFactory


def _actions(factory: sessionmaker[Session]) -> list[str]:
    with factory() as db:
        return list(db.scalars(select(AuditLog.action).order_by(AuditLog.id)))


def _user(client: TestClient, tokens: TokenFactory, username: str, roles: list[str]) -> str:
    """Konto powstaje przy pierwszym wywołaniu API z tokenem (jak po logowaniu w Keycloaku)."""
    assert (
        client.get("/api/me", headers=tokens.headers(roles, username=username)).status_code == 200
    )
    users = client.get("/api/iam/users").json()
    return str(next(u["id"] for u in users if u["username"] == username))


def test_lists_builtin_roles_with_polish_labels(client: TestClient) -> None:
    roles = {r["name"]: r for r in client.get("/api/iam/roles").json()}
    assert roles["viewer"]["label"] == "Odczyt"
    assert roles["modifier"]["label"] == "Modyfikacja i odczyt"
    assert roles["editor"]["label"] == "Dodawanie, usuwanie, modyfikacja"
    assert roles["administrator"]["label"] == "Administracja"
    assert roles["administrator"]["grantable"] is False
    assert roles["viewer"]["grantable"] is True
    permissions = {p["name"]: p for p in client.get("/api/iam/permissions").json()}
    assert permissions["iam:manage"]["reserved"] is True


def test_custom_role_grants_permissions_from_next_request(
    client: TestClient, tokens: TokenFactory, session_factory: sessionmaker[Session]
) -> None:
    saved = client.put(
        "/api/iam/roles/triage",
        json={"description": "Przegląd wyników", "permissions": ["findings:update", "scan:read"]},
    )
    assert saved.status_code == 200, saved.text
    assert saved.json()["permissions"] == ["findings:update", "scan:read"]
    user_id = _user(client, tokens, "ola", ["viewer"])
    headers = tokens.headers(["viewer"], username="ola")
    me = client.get("/api/me", headers=headers).json()
    assert "findings:update" not in me["permissions"]
    granted = client.post(f"/api/iam/users/{user_id}/roles", json={"role": "triage"})
    assert granted.status_code == 200, granted.text
    assert granted.json()["granted_roles"] == ["triage"]
    me = client.get("/api/me", headers=headers).json()
    assert "triage" in me["roles"]
    assert "findings:update" in me["permissions"]
    # Odebranie działa od razu.
    assert client.delete(f"/api/iam/users/{user_id}/roles/triage").status_code == 200
    me = client.get("/api/me", headers=headers).json()
    assert "findings:update" not in me["permissions"]
    actions = _actions(session_factory)
    assert {"role_created", "role_granted", "role_revoked"} <= set(actions)


def test_custom_role_cannot_escalate_or_shadow_builtin(client: TestClient) -> None:
    escalate = client.put("/api/iam/roles/szef", json={"permissions": ["iam:manage"]})
    assert escalate.status_code == 422
    assert "iam:manage" in escalate.json()["detail"]
    unknown = client.put("/api/iam/roles/dziwna", json={"permissions": ["root:all"]})
    assert unknown.status_code == 422
    shadow = client.put("/api/iam/roles/viewer", json={"permissions": ["scan:run"]})
    assert shadow.status_code == 422
    bad_name = client.put("/api/iam/roles/Zła Nazwa!", json={"permissions": []})
    assert bad_name.status_code == 422


def test_administrator_is_granted_only_in_keycloak(
    client: TestClient, tokens: TokenFactory
) -> None:
    user_id = _user(client, tokens, "kasia", ["viewer"])
    response = client.post(f"/api/iam/users/{user_id}/roles", json={"role": "administrator"})
    assert response.status_code == 422
    editor = client.post(f"/api/iam/users/{user_id}/roles", json={"role": "editor"})
    assert editor.status_code == 200
    assert editor.json()["granted_roles"] == ["editor"]
    assert editor.json()["token_roles"] == ["viewer"]


def test_agent_gets_no_roles(
    client: TestClient, tokens: TokenFactory, session_factory: sessionmaker[Session]
) -> None:
    client.get("/api/me", headers=tokens.headers(["agent"], username="agent-1"))
    with session_factory() as db:
        agent = db.scalars(select(User).where(User.username == "agent-1")).one()
        agent_id = str(agent.id)
    response = client.post(f"/api/iam/users/{agent_id}/roles", json={"role": "viewer"})
    assert response.status_code == 422


def test_deleting_custom_role_revokes_it(
    client: TestClient, tokens: TokenFactory, session_factory: sessionmaker[Session]
) -> None:
    client.put("/api/iam/roles/tymczasowa", json={"permissions": ["scan:read"]})
    user_id = _user(client, tokens, "piotr", ["viewer"])
    client.post(f"/api/iam/users/{user_id}/roles", json={"role": "tymczasowa"})
    assert client.delete("/api/iam/roles/tymczasowa").status_code == 204
    with session_factory() as db:
        assert db.scalars(select(RoleGrant)).all() == []
        entry = db.scalars(select(AuditLog).where(AuditLog.action == "role_deleted")).one()
        assert entry.inputs["revoked_from"] == ["piotr"]
    assert client.delete("/api/iam/roles/tymczasowa").status_code == 404


def test_only_administrator_manages_roles(client: TestClient, tokens: TokenFactory) -> None:
    for role in ("editor", "modifier", "viewer"):
        headers = tokens.headers([role], username=f"u-{role}")
        assert client.get("/api/iam/roles", headers=headers).status_code == 403
        denied = client.put("/api/iam/roles/x-y-z", json={"permissions": []}, headers=headers)
        assert denied.status_code == 403


def test_editor_approves_agent_plans_and_l2_but_modifier_cannot(
    client: TestClient, tokens: TokenFactory
) -> None:
    """Decyzja z 21.11.2026: plany agenta i akcje L2/L3 zatwierdza administrator albo editor."""
    editor = client.get("/api/me", headers=tokens.headers(["editor"], username="ed")).json()
    assert {"agent:task", "scan:approve:l2", "scan:approve:l3"} <= set(editor["permissions"])
    modifier = client.get("/api/me", headers=tokens.headers(["modifier"], username="mo")).json()
    assert not {"agent:task", "scan:approve:l2", "scan:approve:l3"} & set(modifier["permissions"])
