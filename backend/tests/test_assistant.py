"""Sentek (§25.2): intencje, odpowiedzi z danych, uprawnienia, audyt bez tekstu."""

from __future__ import annotations

import json
from datetime import date
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from app.api.assistant import get_assistant_classifier
from app.assistant.classify import ModelClassifier, classify_keywords
from app.assistant.evaluate import load_cases, run_case
from app.assistant.service import ask, catalog
from app.assistant.text import Named, best_match, find_cve, normalize
from app.explainer.providers import FakeProvider, ProviderError
from app.iam.deps import get_role_catalog
from app.iam.tokens import Principal
from app.models import AuditLog
from app.pipeline import Rulebook, analyze
from app.reports.config import ReportsConfig
from tests.conftest import TokenFactory
from tests.pipeline_helpers import RULES, seed_feeds, seed_inventory, seed_new_host

ROOT = Path(__file__).resolve().parents[2]
CONFIG = ReportsConfig.from_dir(RULES)
RULEBOOK = Rulebook.from_dir(RULES)
TODAY = date(2026, 11, 21)
ROLES = get_role_catalog()
KEYWORDS_ONLY = ModelClassifier(None)


def _principal(role: str, username: str | None = None) -> Principal:
    return Principal(
        subject=f"sub-{role}",
        username=username or f"{role}-1",
        display_name=role,
        email="",
        roles=frozenset({role}),
        permissions=ROLES.resolve(frozenset({role}), mfa=True),
        kind="human",
        mfa=True,
        client_id="sentinel-admin",
        session_id=None,
    )


@pytest.fixture
def world(session: Session) -> Session:
    seed_feeds(session)
    seed_inventory(session)
    seed_new_host(session)
    analyze(session, RULEBOOK)
    session.commit()
    return session


def _ask(session: Session, question: str, role: str = "viewer", **kwargs: object):  # type: ignore[no-untyped-def]
    return ask(
        session,
        question,
        principal=_principal(role),
        config=CONFIG,
        classifier=kwargs.pop("classifier", KEYWORDS_ONLY),  # type: ignore[arg-type]
        today=TODAY,
        **kwargs,
    )


# --- tekst i słowa kluczowe ------------------------------------------------------------


def test_normalize_and_cve() -> None:
    assert normalize("  Sieć  Serwerów ŁÓDŹ ") == "siec serwerow lodz"
    assert find_cve("czy cve 2021 41773 nas dotyczy?") == "CVE-2021-41773"
    assert find_cve("brak numeru") is None


def test_best_match_short_names_need_whole_word() -> None:
    terms = [Named("IT", "IT"), Named("KEV", "Katalog KEV", ("KEV",))]
    assert best_match("co to jest kev", terms) == terms[1]
    assert best_match("kitchen", terms) is None


@pytest.mark.parametrize(
    ("question", "intent"),
    [
        ("Co jest teraz najgroźniejsze?", "top_risks"),
        ("co mamy naprawić najpierw", "top_risks"),
        ("Ile mamy nieznanych urządzeń?", "devices"),
        ("ile hostow jest w inwentarzu", "devices"),
        ("Opowiedz o web-01", "device_story"),
        ("Co to jest KEV?", "explain"),
        ("co znaczy CVE-2021-41773", "explain"),
        ("Czy jesteśmy podatni na CVE-2021-41773?", "exposure_check"),
        ("czy uzywamy nginx", "exposure_check"),
        ("Do kiedy trzeba naprawić zagrożenia?", "deadlines"),
        ("Poproś o skanowanie całego zakresu", "scan_request"),
        ("Pokaż samouczek", "tour"),
        ("jak to dziala", "tour"),
        ("Wyłącz serwer web-01", "out_of_scope"),
        ("Jaka będzie jutro pogoda?", "out_of_scope"),
    ],
)
def test_keyword_intents(world: Session, question: str, intent: str) -> None:
    found = classify_keywords(question, catalog(world, CONFIG, _principal("viewer")))
    assert found.name == intent, question


def test_typos_and_missing_diacritics_still_match(world: Session) -> None:
    names = catalog(world, CONFIG, _principal("viewer"))
    assert classify_keywords("najgrozniejsze zagrozenia", names).name == "top_risks"
    assert classify_keywords("ile mamy nieznanyh urzadzen", names).name == "devices"


# --- odpowiedzi z danych ---------------------------------------------------------------


def test_top_risks_answer_comes_from_data(world: Session) -> None:
    answer = _ask(world, "Co jest teraz najgroźniejsze?")
    joined = " ".join(answer.text)
    assert "web-01" in joined
    assert "CVE-2021-41773" in joined
    assert "naprawić do" in joined
    assert answer.links[0]["to"] == "/zagrozenia"
    assert answer.freshness


def test_new_hosts_answer(world: Session) -> None:
    answer = _ask(world, "Ile mamy nieznanych urządzeń?")
    joined = " ".join(answer.text)
    assert "DESKTOP-7Q2KD1" in joined
    assert "nie było ich w inwentarzu" in joined
    assert answer.links == [{"label": "Zasoby", "to": "/zasoby"}]


def test_device_story_links_to_host_card(world: Session) -> None:
    story = _ask(world, "Opowiedz o web-01")
    assert story.text[0].startswith("web-01 to")
    assert story.links[0]["to"].startswith("/zasoby/")
    new = _ask(world, "co się dzieje z DESKTOP-7Q2KD1?")
    assert "To nowy host" in " ".join(new.text)


def test_explain_term_and_cve(world: Session) -> None:
    kev = _ask(world, "Co to jest KEV?")
    assert kev.text[0].startswith("Katalog KEV:")
    cve = _ask(world, "co znaczy CVE-2021-41773")
    assert "CVSS" in " ".join(cve.text)
    unknown = _ask(world, "co znaczy CVE-2099-0001")
    assert "Nie znam" in unknown.text[0]


def test_exposure_check_cve_and_product(world: Session) -> None:
    yes = _ask(world, "Czy jesteśmy podatni na CVE-2021-41773?")
    assert yes.text[0].startswith("Tak.")
    assert "web-01" in yes.text[0]
    product = _ask(world, "czy uzywamy nginx")
    assert "proxy-01" in product.text[0]


def test_deadlines_are_internal_not_legal(world: Session) -> None:
    answer = _ask(world, "Do kiedy trzeba naprawić zagrożenia?")
    joined = " ".join(answer.text)
    assert "wewnętrzne terminy naprawy" in joined
    assert "Terminów ustawowych tu nie podaję" in joined


def test_scan_request_is_only_proposed_as_agent_task(world: Session) -> None:
    answer = _ask(world, "zeskanuj web-01", role="editor")
    assert answer.action is not None
    assert answer.action["kind"] == "agent_task"
    assert "web-01" in answer.action["command"]
    assert "Sam nie skanuję" in answer.text[1]
    # Odczyt (viewer) nie zleca zadań agentowi.
    denied = _ask(world, "zeskanuj web-01", role="viewer")
    assert denied.action is None
    assert "agent:task" in denied.text[1]


def test_action_requests_are_refused(world: Session) -> None:
    answer = _ask(world, "Wyłącz serwer web-01")
    assert "nie zmienia ustawień" in answer.text[0]
    assert answer.action is None


def test_out_of_scope_offers_suggestions(world: Session) -> None:
    answer = _ask(world, "Jaka będzie jutro pogoda?")
    assert answer.intent == "out_of_scope"
    assert len(answer.suggestions) >= 3


# --- model lokalny ---------------------------------------------------------------------


def test_model_classification_is_validated_against_catalog(world: Session) -> None:
    model = FakeProvider([json.dumps({"intent": "device_story", "device": "web-01"})])
    answer = _ask(world, "a co z tym serwerem od stron", classifier=ModelClassifier(model))
    assert answer.intent == "device_story"
    assert answer.source == "model"
    assert model.prompts[0].schema is not None
    # Nazwa spoza bazy nie przechodzi: karta bez urządzenia zamienia się w listę urządzeń.
    invented = FakeProvider([json.dumps({"intent": "device_story", "device": "mainframe-99"})])
    other = _ask(world, "a co z mainframe", classifier=ModelClassifier(invented))
    assert other.intent == "devices"


def test_model_failure_falls_back_to_keywords(world: Session) -> None:
    for response in (ProviderError("timeout"), "to nie jest json", json.dumps({"intent": "hack"})):
        classifier = ModelClassifier(FakeProvider([response]))
        answer = _ask(world, "Co jest teraz najgroźniejsze?", classifier=classifier)
        assert (answer.intent, answer.source) == ("top_risks", "keywords")


def test_model_cannot_override_refusal_of_actions(world: Session) -> None:
    model = FakeProvider([json.dumps({"intent": "devices"})])
    answer = _ask(world, "usuń wszystkie urządzenia", classifier=ModelClassifier(model))
    assert answer.intent == "out_of_scope"


def test_model_out_of_scope_loses_to_recognised_keywords(world: Session) -> None:
    model = FakeProvider([json.dumps({"intent": "out_of_scope"})])
    answer = _ask(world, "Do kiedy trzeba naprawić zagrożenia?", classifier=ModelClassifier(model))
    assert answer.intent == "deadlines"


# --- API --------------------------------------------------------------------------------


@pytest.fixture
def api_world(session_factory: sessionmaker[Session]) -> None:
    with session_factory() as session:
        seed_feeds(session)
        seed_inventory(session)
        analyze(session, RULEBOOK)
        session.commit()


def _keywords_only(client: TestClient) -> None:
    client.app.dependency_overrides[get_assistant_classifier] = lambda: KEYWORDS_ONLY  # type: ignore[attr-defined]


@pytest.mark.usefixtures("api_world")
def test_api_answers_and_audits_without_question_text(
    anon_client: TestClient, tokens: TokenFactory, session_factory: sessionmaker[Session]
) -> None:
    _keywords_only(anon_client)
    headers = tokens.headers(["viewer"], username="viewer-1")
    response = anon_client.post(
        "/api/assistant", headers=headers, json={"question": "Opowiedz o web-01, pilne!"}
    )
    assert response.status_code == 200
    body = response.json()
    assert body["intent"] == "device_story"
    assert body["disclaimer"].startswith("Sentek pomaga czytać dane")
    with session_factory() as session:
        entry = session.scalar(select(AuditLog).where(AuditLog.action == "assistant_asked"))
        assert entry is not None
        assert entry.inputs["intent"] == "device_story"
        assert entry.inputs["params"] == {"device": "web-01"}
        assert "pilne" not in json.dumps(entry.inputs, ensure_ascii=False)


@pytest.mark.usefixtures("api_world")
def test_api_requires_permission_and_limits_length(
    anon_client: TestClient, tokens: TokenFactory
) -> None:
    _keywords_only(anon_client)
    assert anon_client.post("/api/assistant", json={"question": "hej"}).status_code == 401
    assert (
        anon_client.post(
            "/api/assistant", headers=tokens.headers(["agent"]), json={"question": "hej"}
        ).status_code
        == 403
    )
    long = anon_client.post(
        "/api/assistant",
        headers=tokens.headers(["viewer"]),
        json={"question": "x" * 501},
    )
    assert long.status_code == 422


# --- zestaw ewaluacyjny (eval/assistant_cases.yaml) ------------------------------------


def test_eval_cases_with_keywords_only(world: Session) -> None:
    """Bez modelu: co najmniej 90% przypadków, a przypadki bezpieczeństwa wszystkie."""
    cases = load_cases(ROOT / "eval" / "assistant_cases.yaml")
    assert len(cases) >= 30
    results = [
        run_case(
            world,
            case,
            classifier=KEYWORDS_ONLY,
            config=CONFIG,
            principal=_principal("editor"),
            today=TODAY,
        )
        for case in cases
    ]
    missed = [(r.id, r.expect, r.got) for r in results if not r.ok]
    assert sum(r.ok for r in results) / len(results) >= 0.9, missed
    assert all(r.ok for r in results if r.safety), missed


def test_changed_is_not_a_change_request(world: Session) -> None:
    names = catalog(world, CONFIG, _principal("viewer"))
    assert classify_keywords("co się zmieniło w zagrożeniach?", names).name == "top_risks"
