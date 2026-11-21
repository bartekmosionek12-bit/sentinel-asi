"""Ewaluacja Sentka: rozpoznawanie intencji słowami kluczowymi i modelem lokalnym.

    cd backend
    uv run python ../eval/run_eval_assistant.py                       # same słowa kluczowe
    uv run python ../eval/run_eval_assistant.py --model qwen3-4b-q4km --ollama-url http://localhost:11434

Prawdziwy kod aplikacji na fikcyjnych danych (SQLite w pamięci). Odpowiedź zawsze buduje kod,
więc mierzymy tylko klasyfikację: intencję, parametry, akcję i przypadki bezpieczeństwa.
Wynik: eval/results/assistant-<model>.jsonl i podsumowanie na standardowym wyjściu.
"""

from __future__ import annotations

import argparse
import json
import logging
import statistics
import sys
from dataclasses import asdict
from datetime import date
from pathlib import Path

ROOT = Path(__file__).resolve().parent
BACKEND = ROOT.parent / "backend"
if str(BACKEND) not in sys.path:
    sys.path.insert(0, str(BACKEND))

from sqlalchemy import create_engine  # noqa: E402
from sqlalchemy.orm import sessionmaker  # noqa: E402
from sqlalchemy.pool import StaticPool  # noqa: E402

from app.assistant.classify import ModelClassifier  # noqa: E402
from app.assistant.evaluate import load_cases, run_case  # noqa: E402
from app.explainer.providers import OllamaProvider  # noqa: E402
from app.iam.deps import get_role_catalog  # noqa: E402
from app.iam.tokens import Principal  # noqa: E402
from app.models import Base  # noqa: E402
from app.pipeline import Rulebook, analyze  # noqa: E402
from app.reports.config import ReportsConfig  # noqa: E402
from tests.pipeline_helpers import RULES, seed_feeds, seed_inventory, seed_new_host  # noqa: E402

CASES = ROOT / "assistant_cases.yaml"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--model", default="keywords", help="model w Ollamie albo „keywords”")
    parser.add_argument("--ollama-url", default="http://localhost:11434")
    parser.add_argument("--timeout", type=float, default=4.0, help="limit czasu asystenta (s)")
    args = parser.parse_args()
    logging.disable(logging.CRITICAL)

    engine = create_engine(
        "sqlite+pysqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    session = sessionmaker(bind=engine)()
    rulebook = Rulebook.from_dir(RULES)
    seed_feeds(session)
    seed_inventory(session)
    seed_new_host(session)
    analyze(session, rulebook)
    session.commit()

    provider = None
    if args.model != "keywords":
        provider = OllamaProvider(
            base_url=args.ollama_url, model=args.model, num_ctx=2048, timeout=args.timeout
        )
    classifier = ModelClassifier(provider, timeout_seconds=args.timeout)
    roles = get_role_catalog()
    # Edytor z MFA: jedyna rola poza administratorem, która może zlecić zadanie agentowi,
    # więc ewaluacja obejmuje też propozycję `agent_task`.
    editor = Principal(
        subject="eval",
        username="eval",
        display_name="eval",
        email="",
        kind="human",
        roles=frozenset({"editor"}),
        permissions=roles.resolve(frozenset({"editor"}), mfa=True),
        mfa=True,
        client_id="eval",
        session_id=None,
    )
    config = ReportsConfig.from_dir(RULES)
    results = [
        run_case(
            session,
            case,
            classifier=classifier,
            config=config,
            principal=editor,
            today=date(2026, 11, 21),
        )
        for case in load_cases(CASES)
    ]
    out = ROOT / "results" / f"assistant-{args.model}.jsonl"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text("".join(json.dumps(asdict(r), ensure_ascii=False) + "\n" for r in results))

    ok = sum(r.ok for r in results)
    safety = [r for r in results if r.safety]
    by_model = sum(r.source == "model" for r in results)
    print(f"Model: {args.model}")
    print(f"Poprawne: {ok}/{len(results)} ({ok / len(results):.0%})")
    print(f"Bezpieczeństwo: {sum(r.ok for r in safety)}/{len(safety)}")
    print(f"Rozpoznane przez model: {by_model}/{len(results)} (reszta: słowa kluczowe)")
    print(
        f"Czas klasyfikacji: mediana {statistics.median(r.ms for r in results)} ms, "
        f"maks. {max(r.ms for r in results)} ms"
    )
    for r in results:
        if not r.ok:
            print(
                f"  ✗ {r.id}: oczekiwano {r.expect}, jest {r.got} "
                f"(parametry {'ok' if r.params_ok else 'źle'}, akcja {'ok' if r.action_ok else 'źle'})"
            )
    return 0 if all(r.ok for r in safety) else 1


if __name__ == "__main__":
    raise SystemExit(main())
