"""API agenta i testu agenta: role, MFA, bramka zmian, kill switch, separacja od agenta."""

from __future__ import annotations

import uuid
from pathlib import Path

from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from app.agent.killswitch import FakeEffect
from app.agent.planner import Planner
from app.agent.service import AgentService
from app.agent_tests.gate import run_test
from app.api.agent import get_kill_effects
from app.core.scope_guard import ScopeConfig, ScopeGuard
from app.models import AgentConfigVersion, AuditLog
from tests.conftest import FakeResolver, MemoryAudit, RecordingDispatcher, TokenFactory

CASES = Path(__file__).resolve().parents[2] / "ai-tests" / "agent" / "cases.yaml"
SCOPE = {"allow": {"cidrs": ["10.10.0.0/24"]}}
CAPABILITY = {
    "tools": ["discover_hosts", "scan_services", "probe_http", "collect_software_authenticated"],
    "targets": ["10.10.0.0/24"],
    "max_level": 2,
    "note": "Assessment segmentu testowego",
}


def _admin(tokens: TokenFactory) -> dict[str, str]:
    return tokens.headers(["administrator"], username="admin")


def _activate_via_api(
    client: TestClient,
    tokens: TokenFactory,
    session_factory: sessionmaker[Session],
    tmp_path: Path,
) -> uuid.UUID:
    created = client.post("/api/agent/capabilities", json=CAPABILITY, headers=_admin(tokens))
    assert created.status_code == 201, created.text
    config_id = uuid.UUID(created.json()["id"])
    with session_factory() as session:
        run_test(
            session,
            suite="quick",
            trigger="config_change",
            requested_by="test",
            config_version_id=config_id,
            provider=None,
            scope=ScopeConfig.from_dict(SCOPE),
            cases_path=CASES,
            key_path=tmp_path / "k.pem",
        )
    return config_id


def test_capability_outside_scope_is_refused(anon_client: TestClient, tokens: TokenFactory) -> None:
    bad = {**CAPABILITY, "targets": ["10.10.0.0/16"]}
    response = anon_client.post("/api/agent/capabilities", json=bad, headers=_admin(tokens))
    assert response.status_code == 422
    assert "poza zakresem" in response.json()["detail"]


def test_new_capability_waits_for_test_then_becomes_active(
    anon_client: TestClient,
    tokens: TokenFactory,
    dispatcher: RecordingDispatcher,
    session_factory: sessionmaker[Session],
    tmp_path: Path,
) -> None:
    created = anon_client.post("/api/agent/capabilities", json=CAPABILITY, headers=_admin(tokens))
    assert created.json()["state"] == "pending_test"
    assert dispatcher.calls[-1][0] == "run_agent_test"
    status = anon_client.get("/api/agent/status", headers=_admin(tokens)).json()
    assert status["capability"] is None
    assert len(status["pending"]) == 1
    # Bez aktywnych zdolności agent nie przyjmuje zadań.
    refused = anon_client.post(
        "/api/agent/tasks", json={"command": "assessment 10.10.0.5"}, headers=_admin(tokens)
    )
    assert refused.status_code == 409

    with session_factory() as session:
        run_test(
            session,
            suite="quick",
            trigger="config_change",
            requested_by="test",
            config_version_id=uuid.UUID(created.json()["id"]),
            provider=None,
            scope=ScopeConfig.from_dict(SCOPE),
            cases_path=CASES,
            key_path=tmp_path / "k.pem",
        )
    status = anon_client.get("/api/agent/status", headers=_admin(tokens)).json()
    assert status["capability"]["active"] is True
    assert status["config"]["state"] == "active"
    assert status["last_test"]["passed"] is True
    assert status["last_test"]["signature_valid"] is True
    run_id = status["last_test"]["id"]
    detail = anon_client.get(f"/api/agent/tests/{run_id}", headers=_admin(tokens)).json()
    assert {c["case_id"] for c in detail["cases"]} >= {"control_assessment", "injection_http_title"}
    assert detail["public_key"].startswith("-----BEGIN PUBLIC KEY-----")


def test_task_plan_approval_and_level_permissions(
    anon_client: TestClient,
    tokens: TokenFactory,
    dispatcher: RecordingDispatcher,
    session_factory: sessionmaker[Session],
    tmp_path: Path,
) -> None:
    _activate_via_api(anon_client, tokens, session_factory, tmp_path)
    created = anon_client.post(
        "/api/agent/tasks",
        json={"command": "Zbierz pakiety przez SSH z 10.10.0.5"},
        headers=_admin(tokens),
    )
    assert created.status_code == 202, created.text
    task_id = uuid.UUID(created.json()["id"])
    assert dispatcher.calls[-1] == ("plan_agent_task", (task_id,))
    with session_factory() as session:
        guard = ScopeGuard(
            ScopeConfig.from_dict(SCOPE), audit=MemoryAudit(), resolver=FakeResolver()
        )
        AgentService(session, guard, Planner(None)).plan_task(task_id)
    task = anon_client.get(f"/api/agent/tasks/{task_id}", headers=_admin(tokens)).json()
    assert task["status"] == "awaiting_approval"
    assert task["plan_source"] == "template"
    assert {(s["tool"], s["level"]) for s in task["steps"]} == {
        ("scan_services", 1),
        ("collect_software_authenticated", 2),
    }
    # Modyfikacja (modifier) widzi zadania, ale nie zatwierdza planów agenta.
    modifier = tokens.headers(["modifier"], username="modifier-1")
    assert anon_client.get(f"/api/agent/tasks/{task_id}", headers=modifier).status_code == 200
    denied = anon_client.post(
        f"/api/agent/tasks/{task_id}/approve", json={"reason": "ok"}, headers=modifier
    )
    assert denied.status_code == 403
    approved = anon_client.post(
        f"/api/agent/tasks/{task_id}/approve",
        json={"reason": "Assessment uzgodniony z właścicielem"},
        headers=_admin(tokens),
    )
    assert approved.status_code == 202, approved.text
    assert dispatcher.calls[-1] == ("execute_agent_task", (task_id,))
    again = anon_client.post(
        f"/api/agent/tasks/{task_id}/approve", json={"reason": "drugi raz"}, headers=_admin(tokens)
    )
    assert again.status_code == 409


def test_admin_without_mfa_cannot_task_or_kill(
    anon_client: TestClient, tokens: TokenFactory
) -> None:
    no_mfa = tokens.headers(["administrator"], username="admin", amr=["pwd"])
    assert (
        anon_client.post("/api/agent/tasks", json={"command": "x y z"}, headers=no_mfa).status_code
        == 403
    )
    assert (
        anon_client.post("/api/agent/kill", json={"reason": "stop"}, headers=no_mfa).status_code
        == 403
    )
    assert anon_client.get("/api/agent/status", headers=no_mfa).status_code == 200


def test_agent_identity_has_no_access_to_its_own_tests_or_tasks(
    anon_client: TestClient, tokens: TokenFactory
) -> None:
    """Moduł 19: agent nie konfiguruje, nie uruchamia i nie czyta testów (ani zadań)."""
    agent = tokens.headers(["agent"], client="sentinel-agent", username="service-account-agent")
    for method, path, body in [
        ("get", "/api/agent/tests", None),
        ("post", "/api/agent/tests", {"suite": "quick"}),
        ("post", f"/api/agent/configs/{uuid.uuid4()}/force", {"justification": "x" * 30}),
        ("get", "/api/agent/tasks", None),
        ("get", "/api/agent/configs", None),
        ("post", "/api/agent/tasks", {"command": "assessment"}),
        ("post", "/api/agent/capabilities", CAPABILITY),
        ("post", "/api/agent/kill", {"reason": "sam siebie"}),
    ]:
        response = (
            getattr(anon_client, method)(path, json=body, headers=agent)
            if body
            else getattr(anon_client, method)(path, headers=agent)
        )
        assert response.status_code == 403, (method, path)


def test_manual_test_button_and_force_with_justification(
    anon_client: TestClient,
    tokens: TokenFactory,
    dispatcher: RecordingDispatcher,
    session_factory: sessionmaker[Session],
) -> None:
    created = anon_client.post("/api/agent/capabilities", json=CAPABILITY, headers=_admin(tokens))
    config_id = created.json()["id"]
    run = anon_client.post("/api/agent/tests", json={"suite": "full"}, headers=_admin(tokens))
    assert run.status_code == 202
    assert dispatcher.calls[-1] == (
        "run_agent_test",
        ("full", "manual", "user:admin", uuid.UUID(config_id)),
    )
    short = anon_client.post(
        f"/api/agent/configs/{config_id}/force",
        json={"justification": "bo"},
        headers=_admin(tokens),
    )
    assert short.status_code == 422
    forced = anon_client.post(
        f"/api/agent/configs/{config_id}/force",
        json={"justification": "Demo dla jury, test nie skończył się na czas; ryzyko przyjęte."},
        headers=_admin(tokens),
    )
    assert forced.status_code == 200
    assert forced.json()["state"] == "forced"
    configs = anon_client.get("/api/agent/configs", headers=_admin(tokens)).json()
    assert [(c["id"], c["state"]) for c in configs] == [(config_id, "forced")]
    with session_factory() as session:
        assert session.scalar(select(AgentConfigVersion.forced_by)) == "user:admin"
        assert "agent_config_forced" in set(session.scalars(select(AuditLog.action)))


def test_kill_switch_via_api(
    anon_client: TestClient,
    tokens: TokenFactory,
    session_factory: sessionmaker[Session],
    tmp_path: Path,
) -> None:
    _activate_via_api(anon_client, tokens, session_factory, tmp_path)
    keycloak, openbao = FakeEffect("keycloak"), FakeEffect("openbao", fail=True)
    app = anon_client.app
    app.dependency_overrides[get_kill_effects] = lambda: [keycloak, openbao]  # type: ignore[attr-defined]
    killed = anon_client.post(
        "/api/agent/kill", json={"reason": "Podejrzane zachowanie"}, headers=_admin(tokens)
    )
    assert killed.status_code == 200
    body = killed.json()
    assert [(e["name"], e["ok"]) for e in body["effects"]] == [
        ("keycloak", True),
        ("openbao", False),
    ]
    assert "15 minut" in body["certificate_gap"]
    status = anon_client.get("/api/agent/status", headers=_admin(tokens)).json()
    assert status["killed"] is True
    assert status["killed_by"] == "user:admin"
    assert status["capability"] is None
    # Błąd jednego skutku jest widoczny w konsoli, a nie przemilczany.
    assert status["effects"][1]["ok"] is False
    assert status["scanner_stopped_at"] is None
    assert "KRL" in status["certificate_gap"]
    refused = anon_client.post(
        "/api/agent/tasks", json={"command": "assessment 10.10.0.5"}, headers=_admin(tokens)
    )
    assert refused.status_code == 409
    assert "kill switch" in refused.json()["detail"]
